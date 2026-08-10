package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"miaomiaowux/internal/storage"
	"miaomiaowux/internal/taskrun"
)

type TrafficLimitEnforcer struct {
	repo          *storage.TrafficRepository
	remoteManage  *RemoteManageHandler
	pusher        *LimiterConfigPusher
	serverResetMu sync.Mutex
}

func NewTrafficLimitEnforcer(repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher) *TrafficLimitEnforcer {
	return &TrafficLimitEnforcer{repo: repo, remoteManage: remoteManage, pusher: pusher}
}

func (e *TrafficLimitEnforcer) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	log.Printf("[TrafficLimitEnforcer] Starting with interval: %v", interval)
	// 独立兜底协程不依赖用户套餐/限流扫描。即使常规 CheckAll 因某个 Agent
	// 或用户处理变慢，服务器账单日重置仍会按小时补偿执行。
	go e.startServerResetGuard(ctx)
	e.recordedCheck(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.recordedCheck(ctx)
		}
	}
}

func (e *TrafficLimitEnforcer) startServerResetGuard(ctx context.Context) {
	// 启动后先审计一次，覆盖主控在账单日停机、重启后错过执行的场景。
	e.recordedServerResetGuard(ctx)
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.recordedServerResetGuard(ctx)
		}
	}
}

func (e *TrafficLimitEnforcer) recordedServerResetGuard(ctx context.Context) {
	taskrun.Record(ctx, "server_traffic_reset_guard", func() (string, error) {
		count, err := e.CheckServerTrafficResets(ctx, time.Now())
		return fmt.Sprintf("servers_reset=%d", count), err
	})
}

func (e *TrafficLimitEnforcer) recordedCheck(ctx context.Context) {
	taskrun.Record(ctx, "traffic_enforcer", func() (string, error) {
		return e.CheckAll(ctx)
	})
}

// shouldResetThisMonth 判断当前时刻是否应触发用户的本月流量重置。
//
// 规则:
//  1. 必须 user.IsReset=true,resetDay∈[1,31]
//  2. 当月的"有效重置日" = min(resetDay, 当月最后一天) — 处理 reset_day=31 但 2 月只有 28 天的边界
//  3. now.Day() >= 有效重置日 才进入触发窗口
//  4. lastResetAt 为 nil,或早于本月实际重置边界 → 应该重置;否则跳过
//
// 注:用 now 的本地时区(time.Now() 默认)。生产环境 server 时区需配为本地时区,否则用户感知的"7号"会偏移。
// effectiveResetDay 返回 resetDay 在 t 所属月份的实际生效日:短月份夹到月末。
// 例如 resetDay=31 在 2 月 → 28(闰年 29)。
//
// 抽出来共用:续费提醒(notify_scheduler.go)必须和真正的流量重置落在同一天,
// 各写一份夹取逻辑迟早会算出不同的日子,提醒就发错了。
func effectiveResetDay(t time.Time, resetDay int) int {
	// 当月最后一天 = 下月第 0 天
	lastDayOfMonth := time.Date(t.Year(), t.Month()+1, 0, 0, 0, 0, 0, t.Location()).Day()
	if resetDay > lastDayOfMonth {
		return lastDayOfMonth
	}
	return resetDay
}

func shouldResetThisMonth(now time.Time, isReset bool, resetDay int, lastResetAt *time.Time) bool {
	if !isReset || resetDay <= 0 || resetDay > 31 {
		return false
	}
	effectiveDay := effectiveResetDay(now, resetDay)
	resetBoundary := time.Date(now.Year(), now.Month(), effectiveDay, 0, 0, 0, 0, now.Location())
	if now.Before(resetBoundary) {
		return false
	}
	if lastResetAt == nil {
		return true
	}
	// 不能只比较年月。服务器若在本月重置日前创建，last_traffic_reset_at
	// 虽然属于本月，却并不代表本月账单日已经执行过重置。
	return lastResetAt.In(now.Location()).Before(resetBoundary)
}

func (e *TrafficLimitEnforcer) CheckAll(ctx context.Context) (string, error) {
	var (
		userResetCount   int
		serverResetCount int
		runErrors        []error
	)
	users, err := e.repo.ListUsersWithPackage(ctx)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] Failed to list users: %v", err)
		runErrors = append(runErrors, fmt.Errorf("list users: %w", err))
	}

	pkgCache := make(map[int64]*storage.Package)
	now := time.Now()

	for _, user := range users {
		// 禁用用户必须同时从普通入站和全部 routed 子账户摘除。状态接口首次同步
		// 失败时保留 enforced=0，由这里每个周期补偿，直到所有 Agent 确认完成。
		if !user.IsActive {
			enforced, _ := e.repo.IsUserDisabledAccessEnforced(ctx, user.Username)
			if !enforced {
				plainOK := e.removeUserFromAllInbounds(ctx, user.Username)
				routedOK := e.suspendUserRoutedAccess(ctx, user.Username)
				if plainOK && routedOK {
					_ = e.repo.UpdateUserDisabledAccessEnforced(ctx, user.Username, true)
					if e.pusher != nil {
						go e.pusher.PushToAllServersForUser(context.Background(), user.Username)
					}
				} else {
					log.Printf("[TrafficLimitEnforcer] Disabled user %s enforcement incomplete (plain=%t routed=%t), retry next cycle",
						user.Username, plainOK, routedOK)
				}
			}
			continue
		}

		// 套餐到期检查：到期后移除入站并清除套餐绑定
		if user.PackageEndDate != nil && now.After(*user.PackageEndDate) {
			log.Printf("[TrafficLimitEnforcer] User %s package expired at %s, removing from inbounds and clearing package",
				user.Username, user.PackageEndDate.Format("2006-01-02"))
			pkg, pkgErr := e.repo.GetPackage(ctx, user.PackageID)
			if pkgErr != nil || pkg == nil {
				log.Printf("[TrafficLimitEnforcer] User %s expiry cannot load package %d: %v", user.Username, user.PackageID, pkgErr)
				continue
			}
			updater := &PackageUpdateHandler{repo: e.repo, remoteManage: e.remoteManage, pusher: e.pusher}
			if err := updater.syncPackageUserNodesTransactionally(ctx, []storage.User{user}, pkg.Nodes, nil); err != nil {
				// agent 摘除未确认成功(多半离线):保留 user_inbound_configs 与套餐绑定,下个周期重试。
				// 不在此清 DB —— 否则 agent 残留孤儿 client 而 DB 无行,既造成「同 email 不同 uuid」漂移,
				// 过期用户还因孤儿 client 继续有访问权。也暂不发到期通知,避免每周期反复打扰。
				log.Printf("[TrafficLimitEnforcer] User %s expiry transaction failed, keep package and retry next cycle: %v", user.Username, err)
				continue
			}
			if err := e.repo.RemoveExpiredPackageFromUser(ctx, user.Username); err != nil {
				log.Printf("[TrafficLimitEnforcer] Failed to remove package from %s: %v", user.Username, err)
			}
			// 套餐过期 tg 通知 — 用户的当前 package_id 在 RemovePackageFromUser 之前的快照里
			pkgName := ""
			if p, perr := e.repo.GetPackage(ctx, user.PackageID); perr == nil && p != nil {
				pkgName = p.Name
			}
			SendPackageExpiredNotification(ctx, user.Username, pkgName)
			// 套餐过期跟 user delete 一样,需要通知所有 agent limiter 同步移除该用户
			// 否则 agent 内存里的 limiter UserInfo 还有这个用户,旧 IP 复用时仍能匹配 bucket。
			if e.pusher != nil {
				go e.pusher.PushToAllServersForUser(context.Background(), user.Username)
			}
			continue
		}

		pkg, ok := pkgCache[user.PackageID]
		if !ok {
			p, err := e.repo.GetPackage(ctx, user.PackageID)
			if err != nil {
				log.Printf("[TrafficLimitEnforcer] Failed to get package %d: %v", user.PackageID, err)
				continue
			}
			pkg = p
			pkgCache[user.PackageID] = pkg
		}

		// 自愈:is_reset=true 但 reset_day 非法(历史上 assign 接口不校验、套餐保存又会把它清成 0)。
		// 这类用户在 shouldResetThisMonth 第一道门就被静默挡掉,永远不会重置。补成当天(封顶 28,
		// 避开月末不存在的日期),与 TG 续期路径的兜底一致。写回 DB 后下一轮即合法,不会反复打日志。
		if user.IsReset && (user.ResetDay < 1 || user.ResetDay > 31) {
			day := now.Day()
			if day > 28 {
				day = 28
			}
			log.Printf("[TrafficLimitEnforcer] User %s has is_reset=true but invalid reset_day=%d, fixing to %d", user.Username, user.ResetDay, day)
			if err := e.repo.UpdateUserResetDay(ctx, user.Username, day); err != nil {
				log.Printf("[TrafficLimitEnforcer] Failed to fix reset_day for %s: %v", user.Username, err)
			} else {
				user.ResetDay = day
			}
		}

		// 每月流量周期自动重置 — 到 reset_day 当天 0 点之后(实际由 enforcer ticker 触发,粒度=interval)
		// 触发后立刻把当前周期 uplink/downlink 归 0 + cycle_start=now,并写 last_reset_at 防止同月反复。
		// 还原"超额"标志:重置后用户应该重新有流量配额,wasOverLimit → 立即恢复入站。
		if shouldResetThisMonth(now, user.IsReset, user.ResetDay, user.LastResetAt) {
			log.Printf("[TrafficLimitEnforcer] User %s monthly reset (day=%d, last=%v)", user.Username, user.ResetDay, user.LastResetAt)
			if err := e.repo.ResetUserTrafficCycleAt(ctx, user.Username, now); err != nil {
				log.Printf("[TrafficLimitEnforcer] Failed to reset user %s: %v", user.Username, err)
				runErrors = append(runErrors, fmt.Errorf("reset user %s: %w", user.Username, err))
			} else {
				userResetCount++
				// 若此前超额，下面统一的 under-limit 分支负责恢复全部普通入站和 routed
				// 子账户；恢复未完整成功前保留 is_over_limit，下一轮继续补偿。
				// limiter 配置在 agent 端按 user_traffic 累计算,重置归零后下次 push 自然刷新
			}
		}

		// 有效上限 = 用户级覆写 ?? 套餐流量。<=0 = 不限流量。
		// 位置必须留在月度重置之后:提前 continue 会让不限流量的用户永远不重置周期。
		limitBytes := resolveTrafficLimitBytes(&user, pkg)
		if limitBytes <= 0 {
			// 管理员把额度改为“不限量”也属于恢复条件，不能因为提前 continue
			// 让此前已超限的用户永久保持断流。
			if wasOver, _ := e.repo.IsUserOverLimit(ctx, user.Username); wasOver {
				plainOK := e.restoreUserToInbounds(ctx, user)
				routedOK := e.resumeUserRoutedAccess(ctx, user)
				if plainOK && routedOK {
					_ = e.repo.UpdateUserOverLimitState(ctx, user.Username, false, false)
					if e.pusher != nil {
						go e.pusher.PushToAllServersForUser(context.Background(), user.Username)
					}
				}
			}
			continue
		}

		// 计费流量:倍率(per-node × 套餐 oneway/twoway)已由 collector 在采集时折算进 weighted_*,
		// 这里拿到即最终值 —— **不能再乘任何倍率**。改倍率只影响后续 tick,不追溯重算历史。
		usedWeighted, err := e.repo.GetUserBillableTraffic(ctx, user.Username)
		if err != nil {
			log.Printf("[TrafficLimitEnforcer] Failed to get traffic for %s: %v", user.Username, err)
			continue
		}

		wasOverLimit, _ := e.repo.IsUserOverLimit(ctx, user.Username)
		isOverLimit := usedWeighted >= limitBytes

		// 流量 80% 预警:同一次越线只发一条。用专用 traffic_warned_80 标记去重(与 is_over_limit
		// 边沿语义对称、跨进程重启不重复):首次 >=80% 发一条并置位;掉回 80% 以下(含月度重置使
		// usedWeighted 归零)清位,下次再越线可再次预警。此前无去重 → enforcer 每个周期(默认 5min,
		// 部署可调 2min)都发,用户收到刷屏。
		if !isOverLimit {
			pct := float64(usedWeighted) / float64(limitBytes) * 100
			wasWarned80, _ := e.repo.IsUserTrafficWarned80(ctx, user.Username)
			if pct >= 80 {
				if !wasWarned80 {
					usedGB := float64(usedWeighted) / (1024 * 1024 * 1024)
					limitGB := float64(limitBytes) / (1024 * 1024 * 1024)
					SendTrafficThreshold80Notification(ctx, user.Username, usedGB, limitGB)
					if err := e.repo.UpdateUserTrafficWarned80(ctx, user.Username, true); err != nil {
						log.Printf("[TrafficLimitEnforcer] Failed to mark traffic_warned_80 for %s: %v", user.Username, err)
					}
				}
			} else if wasWarned80 {
				if err := e.repo.UpdateUserTrafficWarned80(ctx, user.Username, false); err != nil {
					log.Printf("[TrafficLimitEnforcer] Failed to clear traffic_warned_80 for %s: %v", user.Username, err)
				}
			}
		}

		if isOverLimit {
			enforced, _ := e.repo.IsUserOverLimitEnforced(ctx, user.Username)
			if !wasOverLimit {
				log.Printf("[TrafficLimitEnforcer] User %s exceeded limit (%d/%d bytes), removing all inbound and routed clients",
					user.Username, usedWeighted, limitBytes)
				_ = e.repo.UpdateUserOverLimitState(ctx, user.Username, true, false)
				enforced = false
			}
			if !enforced {
				plainOK := e.removeUserFromAllInbounds(ctx, user.Username)
				routedOK := e.suspendUserRoutedAccess(ctx, user.Username)
				if plainOK && routedOK {
					_ = e.repo.UpdateUserOverLimitState(ctx, user.Username, true, true)
					if e.pusher != nil {
						go e.pusher.PushToAllServersForUser(context.Background(), user.Username)
					}
				} else {
					log.Printf("[TrafficLimitEnforcer] User %s over-limit enforcement incomplete (plain=%t routed=%t), retry next cycle",
						user.Username, plainOK, routedOK)
				}
			}
			if !wasOverLimit {
				usedGB := float64(usedWeighted) / (1024 * 1024 * 1024)
				limitGB := float64(limitBytes) / (1024 * 1024 * 1024)
				SendOverLimitNotification(ctx, user.Username, usedGB, limitGB)
			}
		} else if !isOverLimit && wasOverLimit {
			log.Printf("[TrafficLimitEnforcer] User %s back under limit (%d/%d bytes), restoring inbounds",
				user.Username, usedWeighted, limitBytes)
			plainOK := e.restoreUserToInbounds(ctx, user)
			routedOK := e.resumeUserRoutedAccess(ctx, user)
			if plainOK && routedOK {
				_ = e.repo.UpdateUserOverLimitState(ctx, user.Username, false, false)
				if e.pusher != nil {
					go e.pusher.PushToAllServersForUser(context.Background(), user.Username)
				}
			} else {
				log.Printf("[TrafficLimitEnforcer] User %s restore incomplete (plain=%t routed=%t), retry next cycle",
					user.Username, plainOK, routedOK)
			}
		}
	}

	serverResetCount, serverResetErr := e.CheckServerTrafficResets(ctx, now)
	if serverResetErr != nil {
		runErrors = append(runErrors, serverResetErr)
	}
	packageNodeChecked, packageNodeErr := e.CheckPackageNodeTrafficLimits(ctx)
	if packageNodeErr != nil {
		runErrors = append(runErrors, packageNodeErr)
	}

	summary := fmt.Sprintf("users_reset=%d servers_reset=%d package_nodes_checked=%d", userResetCount, serverResetCount, packageNodeChecked)
	return summary, errors.Join(runErrors...)
}

// CheckPackageNodeTrafficLimits applies each package node quota independently
// to every bound user. Exhausting node A never disables the user's other nodes
// and never consumes another user's quota on A.
func (e *TrafficLimitEnforcer) CheckPackageNodeTrafficLimits(ctx context.Context) (int, error) {
	users, err := e.repo.ListUsersWithPackage(ctx)
	if err != nil {
		return 0, err
	}
	packages := make(map[int64]*storage.Package)
	checked := 0
	var errs []error
	for _, user := range users {
		if !user.IsActive || user.PackageID <= 0 {
			continue
		}
		pkg := packages[user.PackageID]
		if pkg == nil {
			pkg, err = e.repo.GetPackage(ctx, user.PackageID)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			packages[user.PackageID] = pkg
		}
		for nodeID, limitGB := range pkg.NodeTrafficLimits {
			if limitGB <= 0 {
				continue
			}
			checked++
			used, limit, usageErr := e.repo.GetPackageNodeTrafficUsage(ctx, user.Username, pkg.ID, nodeID)
			if usageErr != nil {
				errs = append(errs, fmt.Errorf("read %s package node %d usage: %w", user.Username, nodeID, usageErr))
				continue
			}
			suspended := e.repo.HasPackageNodeTrafficSuspension(ctx, user.Username, nodeID)
			if used >= limit && !suspended {
				if err := e.suspendPackageNodeTrafficAccess(ctx, user, pkg.ID, nodeID); err != nil {
					errs = append(errs, err)
				}
			} else if used < limit && suspended {
				if err := e.restorePackageNodeTrafficAccess(ctx, user, pkg.ID, nodeID); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	// Also restore stale records after a quota/package was removed.
	suspensions, listErr := e.repo.ListPackageNodeTrafficSuspensions(ctx)
	if listErr != nil {
		errs = append(errs, listErr)
	} else {
		for _, s := range suspensions {
			user, userErr := e.repo.GetUser(ctx, s.Username)
			if userErr != nil || !user.IsActive {
				continue
			}
			pkg := packages[user.PackageID]
			if pkg == nil {
				pkg, _ = e.repo.GetPackage(ctx, user.PackageID)
			}
			if user.PackageID != s.PackageID || pkg == nil {
				_ = e.repo.DeletePackageNodeTrafficSuspension(ctx, s.Username, s.PackageID, s.NodeID, s.Kind)
				continue
			}
			if pkg.NodeTrafficLimits[s.NodeID] <= 0 {
				if err := e.restorePackageNodeTrafficAccess(ctx, user, s.PackageID, s.NodeID); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	return checked, errors.Join(errs...)
}

func (e *TrafficLimitEnforcer) suspendPackageNodeTrafficAccess(ctx context.Context, user storage.User, packageID, nodeID int64) error {
	node, err := e.repo.GetNodeByID(ctx, nodeID)
	if err != nil {
		return err
	}
	kind := "physical"
	credentialJSON := ""
	if node.NodeType == "routed" {
		kind = "routed"
		s := storage.PackageNodeTrafficSuspension{Username: user.Username, PackageID: packageID, NodeID: nodeID, Kind: kind}
		if err := e.repo.SavePackageNodeTrafficSuspension(ctx, s); err != nil {
			return err
		}
		if err := removeUserFromRoutedNode(ctx, e.remoteManage, e.repo, user.Username, node.ID); err != nil {
			_ = e.repo.DeletePackageNodeTrafficSuspension(ctx, user.Username, packageID, nodeID, kind)
			return fmt.Errorf("suspend %s on routed node %d: %w", user.Username, node.ID, err)
		}
		return nil
	} else {
		server, err := e.repo.GetRemoteServerByName(ctx, node.OriginalServer)
		if err != nil || server == nil {
			return fmt.Errorf("server %s not found", node.OriginalServer)
		}
		cfg, err := e.repo.GetUserInboundConfig(ctx, user.Username, server.ID, node.InboundTag)
		if err != nil {
			return err
		}
		var credential map[string]interface{}
		if err := json.Unmarshal([]byte(cfg.CredentialJSON), &credential); err != nil {
			return err
		}
		credentialJSON = cfg.CredentialJSON
		s := storage.PackageNodeTrafficSuspension{Username: user.Username, PackageID: packageID, NodeID: nodeID, Kind: kind, CredentialJSON: credentialJSON}
		if err := e.repo.SavePackageNodeTrafficSuspension(ctx, s); err != nil {
			return err
		}
		if err := mutateInboundClient(ctx, e.remoteManage, server.ID, node.InboundTag, "remove-client", credential); err != nil && !isInboundNotFoundErr(err) {
			_ = e.repo.DeletePackageNodeTrafficSuspension(ctx, user.Username, packageID, nodeID, kind)
			return err
		}
		return nil
	}
}

func (e *TrafficLimitEnforcer) restorePackageNodeTrafficAccess(ctx context.Context, user storage.User, packageID, nodeID int64) error {
	node, err := e.repo.GetNodeByID(ctx, nodeID)
	if err != nil {
		return err
	}
	if over, _ := e.repo.IsUserOverLimit(ctx, user.Username); over {
		return nil
	}
	if node.NodeType == "routed" {
		if err := addUserToRoutedNode(ctx, e.remoteManage, e.repo, user, node.ID); err != nil {
			return err
		}
		return e.repo.DeletePackageNodeTrafficSuspension(ctx, user.Username, packageID, nodeID, "routed")
	}
	server, err := e.repo.GetRemoteServerByName(ctx, node.OriginalServer)
	if err != nil || server == nil {
		return fmt.Errorf("server %s not found", node.OriginalServer)
	}
	var credentialJSON string
	for _, s := range mustListPackageNodeSuspensions(ctx, e.repo) {
		if s.Username == user.Username && s.PackageID == packageID && s.NodeID == nodeID && s.Kind == "physical" {
			credentialJSON = s.CredentialJSON
			break
		}
	}
	var credential map[string]interface{}
	if err := json.Unmarshal([]byte(credentialJSON), &credential); err != nil {
		return err
	}
	if err := mutateInboundClient(ctx, e.remoteManage, server.ID, node.InboundTag, "add-client", credential); err != nil {
		return err
	}
	return e.repo.DeletePackageNodeTrafficSuspension(ctx, user.Username, packageID, nodeID, "physical")
}

func mustListPackageNodeSuspensions(ctx context.Context, repo *storage.TrafficRepository) []storage.PackageNodeTrafficSuspension {
	items, _ := repo.ListPackageNodeTrafficSuspensions(ctx)
	return items
}

// CheckServerTrafficResets 是常规扫描与独立兜底任务共用的服务器重置入口。
// 互斥锁保证两条调度链同时命中时不会重复计算 offset。
func (e *TrafficLimitEnforcer) CheckServerTrafficResets(ctx context.Context, now time.Time) (int, error) {
	e.serverResetMu.Lock()
	defer e.serverResetMu.Unlock()

	servers, err := e.repo.ListRemoteServers(ctx)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] list servers for reset failed: %v", err)
		return 0, fmt.Errorf("list servers for reset: %w", err)
	}
	utcNow := now.UTC()
	isAfter0005 := utcNow.Hour() > 0 || (utcNow.Hour() == 0 && utcNow.Minute() >= 5)
	resetCount := 0
	var runErrors []error
	for _, s := range servers {
		if s.IsFederated {
			continue
		}
		var lastResetUTC *time.Time
		if s.LastTrafficResetAt != nil {
			t := s.LastTrafficResetAt.UTC()
			lastResetUTC = &t
		}
		if !isAfter0005 || !shouldResetThisMonth(utcNow, true, s.TrafficResetDay, lastResetUTC) {
			continue
		}
		if resetErr := e.repo.ResetRemoteServerTrafficCycleAt(ctx, s.ID, now); resetErr != nil {
			log.Printf("[TrafficLimitEnforcer] reset server %d(%s) traffic failed: %v", s.ID, s.Name, resetErr)
			runErrors = append(runErrors, fmt.Errorf("reset server %d(%s): %w", s.ID, s.Name, resetErr))
			continue
		}
		resetCount++
		log.Printf("[TrafficLimitEnforcer] server %d(%s) monthly traffic reset (day=%d, utc_time=%s)",
			s.ID, s.Name, s.TrafficResetDay, utcNow.Format(time.RFC3339))
	}
	return resetCount, errors.Join(runErrors...)
}

// removeUserFromAllInbounds 从该用户所有 inbound 摘除 client。
// 返回 true = 可安全清理 DB:所有 client 要么摘除成功,要么对应 inbound 本就不存在(不可能留孤儿)。
// 返回 false = 至少一个 inbound 摘除失败且 client 可能仍残留(典型:agent 离线)——调用方应保留
// user_inbound_configs 与套餐绑定,下个周期重试,避免「agent 有孤儿 client 但 DB 无行」的漂移
// (该漂移会让续费/再分配时生成同 email 新 uuid 的重复凭据,且过期用户因孤儿 client 仍能连)。
// 注:over-limit 摘除调用处忽略返回值即可(它不清 user_inbound_configs)。
func (e *TrafficLimitEnforcer) removeUserFromAllInbounds(ctx context.Context, username string) bool {
	configs, err := e.repo.GetUserInboundConfigs(ctx, username)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] Failed to get inbound configs for %s: %v", username, err)
		return false
	}
	safe := true
	for _, cfg := range configs {
		if err := removeUserFromInbound(ctx, e.remoteManage, cfg); err != nil && !isInboundNotFoundErr(err) {
			log.Printf("[TrafficLimitEnforcer] Failed to remove %s from %s on server %d: %v",
				username, cfg.InboundTag, cfg.ServerID, err)
			safe = false
		}
	}
	return safe
}

// suspendUserRoutedAccess 摘除用户的全部 routed 子账户，而不仅是 routed_owner=user
// 的私有路由。套餐中管理员创建的 shared routed 节点同样使用 user_subaccounts，
// 超限/到期时如果漏掉它们，用户仍可通过父入站继续连接。
func (e *TrafficLimitEnforcer) suspendUserRoutedAccess(ctx context.Context, username string) bool {
	privateOK := suspendUserPrivateRouted(ctx, e.remoteManage, e.repo, username)
	subaccounts, err := e.repo.ListUserSubaccounts(ctx, username)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] Failed to list routed subaccounts for %s: %v", username, err)
		return false
	}
	ok := privateOK
	for _, sa := range subaccounts {
		if !sa.IsActive {
			continue
		}
		node, err := e.repo.GetNodeByID(ctx, sa.RoutedNodeID)
		if err != nil {
			log.Printf("[TrafficLimitEnforcer] Failed to resolve routed node %d for %s: %v", sa.RoutedNodeID, username, err)
			ok = false
			continue
		}
		if node.RoutedOwner == "user" {
			continue // 私有节点已由 suspendUserPrivateRouted 安全删除整条 rule。
		}
		if err := removeUserFromRoutedNode(ctx, e.remoteManage, e.repo, username, sa.RoutedNodeID); err != nil {
			log.Printf("[TrafficLimitEnforcer] Failed to suspend routed node %d for %s: %v", sa.RoutedNodeID, username, err)
			ok = false
		}
	}
	return ok
}

func (e *TrafficLimitEnforcer) resumeUserRoutedAccess(ctx context.Context, user storage.User) bool {
	privateOK := resumeUserPrivateRouted(ctx, e.remoteManage, e.repo, user.Username)
	subaccounts, err := e.repo.ListUserSubaccounts(ctx, user.Username)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] Failed to list routed subaccounts for restore %s: %v", user.Username, err)
		return false
	}
	ok := privateOK
	for _, sa := range subaccounts {
		if sa.IsActive {
			continue
		}
		node, err := e.repo.GetNodeByID(ctx, sa.RoutedNodeID)
		if err != nil {
			log.Printf("[TrafficLimitEnforcer] Failed to resolve routed node %d for restore %s: %v", sa.RoutedNodeID, user.Username, err)
			ok = false
			continue
		}
		if node.RoutedOwner == "user" {
			continue // 私有节点已由 resumeUserPrivateRouted 重建整条 rule。
		}
		if e.repo.HasPackageNodeTrafficSuspension(ctx, user.Username, sa.RoutedNodeID) {
			continue
		}
		if err := addUserToRoutedNode(ctx, e.remoteManage, e.repo, user, sa.RoutedNodeID); err != nil {
			// addUserToRoutedNode 的历史语义可能已把 DB 置 active 后才发现 routing
			// 写入失败；恢复流程必须改回 inactive，给下一轮留下重试依据。
			_ = e.repo.SetSubaccountActive(ctx, sa.ID, false)
			log.Printf("[TrafficLimitEnforcer] Failed to restore routed node %d for %s: %v", sa.RoutedNodeID, user.Username, err)
			ok = false
		}
	}
	return ok
}

func (e *TrafficLimitEnforcer) restoreUserToInbounds(ctx context.Context, user storage.User) bool {
	configs, err := e.repo.GetUserInboundConfigs(ctx, user.Username)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] Failed to get inbound configs for %s: %v", user.Username, err)
		return false
	}
	ok := true
	for _, cfg := range configs {
		if e.repo.HasPhysicalPackageNodeTrafficSuspension(ctx, user.Username, cfg.ServerID, cfg.InboundTag) {
			continue
		}
		if err := addUserToInbound(ctx, e.remoteManage, e.repo, user, cfg.ServerID, cfg.InboundTag); err != nil {
			// Agent 明确确认 inbound 已不存在时，这条 DB 绑定已经是孤儿配置。
			// 它不可能通过重试恢复；若继续把它算作失败，会让 is_over_limit 永远无法清除，
			// limiter 也会持续跳过该用户，最终表现为“流量已重置但连接数不显示”。
			if orphan, removed := removeOrphanInboundConfig(ctx, e.repo, cfg, err); orphan {
				if !removed {
					ok = false
				}
				continue
			}
			log.Printf("[TrafficLimitEnforcer] Failed to restore %s to %s on server %d: %v",
				user.Username, cfg.InboundTag, cfg.ServerID, err)
			ok = false
		}
	}
	return ok
}

// removeOrphanInboundConfig 仅处理 Agent 明确返回的 inbound not found。
// 网络超时、Agent 离线、配置下发失败等错误仍保留绑定并重试，避免误删仍有效的凭据。
func removeOrphanInboundConfig(ctx context.Context, repo *storage.TrafficRepository, cfg storage.UserInboundConfig, restoreErr error) (orphan, removed bool) {
	if !isInboundNotFoundErr(restoreErr) {
		return false, false
	}
	if err := repo.DeleteUserInboundConfig(ctx, cfg.Username, cfg.ServerID, cfg.InboundTag); err != nil {
		log.Printf("[TrafficLimitEnforcer] Failed to delete orphan inbound config user=%s server=%d tag=%s: %v",
			cfg.Username, cfg.ServerID, cfg.InboundTag, err)
		return true, false
	}
	log.Printf("[TrafficLimitEnforcer] Deleted orphan inbound config user=%s server=%d tag=%s (agent confirmed inbound not found)",
		cfg.Username, cfg.ServerID, cfg.InboundTag)
	return true, true
}
