package handler

import (
	"context"
	"encoding/json"
	"log"
	"slices"
	"time"

	"miaomiaowux/internal/storage"
	"miaomiaowux/internal/taskrun"
)

// InboundClientReconciler 每天扫一次:把「DB 里登记了绑定、但 agent 的 xray inbound 上没有对应
// client」的子账户补下发回去。
//
// 触发场景:
//   - 入站被删除后用同 tag 重建 → agent 侧是空入站,DB 里的凭据成了孤儿。订阅仍发那份旧 UUID,
//     而 xray 里不存在 → 表现为 TCPing 通(端口在)但真实连接握手失败。
//   - agent 重装 / xray 配置回滚 / 人工改配置导致的其它漂移。
//
// 与 OrphanXrayClientCleaner 的关系:方向相反、互补,但**刻意保持两个独立组件**——
// 清理是破坏性的(有严格白名单),补发是修复性的(幂等),风险等级不同,分开便于单独开关和回滚。
//
// 安全性:补发用 DB 里**已有的**凭据(不重新生成),所以用户订阅里的 UUID 不变、无需重新导入。
// add-client 按 id 幂等,即使快照偶尔陈旧导致误判"缺失",代价也只是多下发一次。
//
// ⚠ 有效性过滤是本组件最关键的部分,见 buildEligibleUsers:
// 套餐到期和流量超限时,TrafficLimitEnforcer 会**有意**把 client 从 inbound 摘除,
// 但 user_inbound_configs 的行会保留。若不过滤就补发,等于绕过套餐过期/流量限制 —— 必须排除。
//
// 数据源:server_xray_config_snapshots.current(agent 真实配置,由 refreshXraySnapshot 主动拉取),
// 不遍历打 agent,避免离线时阻塞。
type InboundClientReconciler struct {
	repo         *storage.TrafficRepository
	remoteManage *RemoteManageHandler
}

func NewInboundClientReconciler(repo *storage.TrafficRepository, rm *RemoteManageHandler) *InboundClientReconciler {
	return &InboundClientReconciler{repo: repo, remoteManage: rm}
}

// Start 起 goroutine,等到下一个本地 04:00 跑首次,之后每 24h 一次。
// 04:00 排在 OrphanXrayClientCleaner(03:30)之后:先让它清掉该删的,再补该补的,避免同一轮里打架。
func (c *InboundClientReconciler) Start(ctx context.Context) {
	go c.loop(ctx)
}

func (c *InboundClientReconciler) loop(ctx context.Context) {
	if c.repo == nil || c.remoteManage == nil {
		log.Printf("[InboundClientReconciler] repo or remoteManage nil, scheduler skipped")
		return
	}

	now := time.Now()
	target := time.Date(now.Year(), now.Month(), now.Day(), 4, 0, 0, 0, now.Location())
	if !target.After(now) {
		target = target.Add(24 * time.Hour)
	}
	log.Printf("[InboundClientReconciler] scheduler started, first run at %s (in %s)",
		target.Format("2006-01-02 15:04:05"), time.Until(target).Round(time.Second))

	firstTimer := time.NewTimer(time.Until(target))
	select {
	case <-ctx.Done():
		firstTimer.Stop()
		return
	case <-firstTimer.C:
		c.recordedRun(ctx)
	}

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.recordedRun(ctx)
		}
	}
}

func (c *InboundClientReconciler) recordedRun(ctx context.Context) {
	taskrun.Record(ctx, "inbound_client_reconciler", func() (string, error) {
		return c.runOnce(ctx)
	})
}

// reconcileTarget 是一条待补发的绑定。
type reconcileTarget struct {
	Username       string
	ServerID       int64
	InboundTag     string
	Protocol       string
	Credential     map[string]interface{}
	CredentialJSON string
}

// credEmail 取该凭据实际使用的 email;凭据里没有就回退到规范格式
// (必须与 getOrCreateInboundCredential 里的构造一致)。
func credEmail(credJSON, username, inboundTag string) string {
	var m map[string]interface{}
	if json.Unmarshal([]byte(credJSON), &m) == nil {
		if e, _ := m["email"].(string); e != "" {
			return e
		}
	}
	return username + "__" + inboundTag
}

// parseSnapshotInboundEmails 从一份 xray config JSON 解析出 tag → (email 集合)。
// 返回的 map 里没有某个 tag,表示该 inbound 在 agent 上根本不存在。
func parseSnapshotInboundEmails(configJSON string) map[string]map[string]bool {
	var cfg struct {
		Inbounds []struct {
			Tag      string                 `json:"tag"`
			Settings map[string]interface{} `json:"settings"`
		} `json:"inbounds"`
	}
	if json.Unmarshal([]byte(configJSON), &cfg) != nil {
		return nil
	}
	out := make(map[string]map[string]bool, len(cfg.Inbounds))
	for _, ib := range cfg.Inbounds {
		if ib.Tag == "" {
			continue
		}
		emails := make(map[string]bool)
		// 各协议放 client 的键不同,与 extractClientByEmail 保持一致。
		for _, key := range []string{"clients", "users", "accounts"} {
			arr, _ := ib.Settings[key].([]interface{})
			for _, cl := range arr {
				cm, _ := cl.(map[string]interface{})
				if cm == nil {
					continue
				}
				if e, _ := cm["email"].(string); e != "" {
					emails[e] = true
				}
			}
		}
		out[ib.Tag] = emails
	}
	return out
}

// findMissingInboundClients 纯函数:挑出「DB 有、agent 缺」且用户仍有效的绑定。
//
// snapshots: serverID → (tag → email 集合);某 server 不在 map 里表示拿不到快照(跳过,不猜)。
// eligible:  username → 是否仍应享有服务(套餐未到期、未超限、账号可用)。
//
// 三种跳过情形:
//   - 用户不在 eligible:被有意摘除的(过期/超限)绝不补回去
//   - server 无快照:状态未知,不猜
//   - inbound 在快照里不存在:入站本身已删,补 client 没有意义(这类孤儿由第 1 层级联清理负责)
func findMissingInboundClients(
	configs []storage.UserInboundConfig,
	snapshots map[int64]map[string]map[string]bool,
	eligible map[string]bool,
) []reconcileTarget {
	var out []reconcileTarget
	for _, cfg := range configs {
		if !eligible[cfg.Username] {
			continue
		}
		byTag, ok := snapshots[cfg.ServerID]
		if !ok || byTag == nil {
			continue
		}
		emails, tagExists := byTag[cfg.InboundTag]
		if !tagExists {
			continue // 入站已不存在
		}
		if emails[credEmail(cfg.CredentialJSON, cfg.Username, cfg.InboundTag)] {
			continue // agent 上已有
		}
		var cred map[string]interface{}
		if json.Unmarshal([]byte(cfg.CredentialJSON), &cred) != nil || cred == nil {
			continue // 凭据损坏,补发无意义(留给正常绑定流程重新生成)
		}
		out = append(out, reconcileTarget{
			Username:       cfg.Username,
			ServerID:       cfg.ServerID,
			InboundTag:     cfg.InboundTag,
			Protocol:       cfg.Protocol,
			Credential:     cred,
			CredentialJSON: cfg.CredentialJSON,
		})
	}
	return out
}

// buildEligibleUsers 算出「仍应在 agent 上拥有 client」的用户集合。
//
// 取 TrafficLimitEnforcer 摘除条件的反面:套餐到期(CheckAll 里 PackageEndDate 已过)
// 和流量超限(IsUserOverLimit)时它会主动摘 client,这类用户绝不能被补回去。
func (c *InboundClientReconciler) buildEligibleUsers(ctx context.Context) map[string]bool {
	users, err := c.repo.ListUsersWithPackage(ctx)
	if err != nil {
		log.Printf("[InboundClientReconciler] list users failed: %v", err)
		return nil
	}
	now := time.Now()
	eligible := make(map[string]bool, len(users))
	for _, u := range users {
		if u.PackageEndDate != nil && now.After(*u.PackageEndDate) {
			continue // 套餐已到期 → enforcer 已摘除,不补
		}
		if over, _ := c.repo.IsUserOverLimit(ctx, u.Username); over {
			continue // 流量超限 → enforcer 已摘除,不补
		}
		eligible[u.Username] = true
	}
	return eligible
}

func (c *InboundClientReconciler) runOnce(ctx context.Context) (string, error) {
	start := time.Now()

	eligible := c.buildEligibleUsers(ctx)
	if len(eligible) == 0 {
		log.Printf("[InboundClientReconciler] no eligible users, skip")
		return "no eligible users", nil
	}

	configs, err := c.repo.ListAllUserInboundConfigs(ctx)
	if err != nil {
		log.Printf("[InboundClientReconciler] list user inbound configs failed: %v", err)
		return "", err
	}
	configs = slices.DeleteFunc(configs, func(cfg storage.UserInboundConfig) bool {
		return c.repo.HasPhysicalNodeTrafficSuspension(ctx, cfg.Username, cfg.ServerID, cfg.InboundTag)
	})

	servers, err := c.repo.ListRemoteServers(ctx)
	if err != nil {
		log.Printf("[InboundClientReconciler] list servers failed: %v", err)
		return "", err
	}

	// 每 server 一份快照解析结果;拿不到快照的 server 不放进 map(findMissing 会跳过)。
	snapshots := make(map[int64]map[string]map[string]bool, len(servers))
	for _, srv := range servers {
		snap, serr := c.repo.GetCurrentXraySnapshot(ctx, srv.ID)
		if serr != nil || snap == nil || snap.ConfigJSON == "" {
			continue
		}
		if parsed := parseSnapshotInboundEmails(snap.ConfigJSON); parsed != nil {
			snapshots[srv.ID] = parsed
		}
	}

	missing := findMissingInboundClients(configs, snapshots, eligible)
	if len(missing) == 0 {
		log.Printf("[InboundClientReconciler] all in sync (%d bindings checked, %.1fs)",
			len(configs), time.Since(start).Seconds())
		return "in sync", nil
	}

	// 按 server 聚合后一次 batch-apply(失败自动降级逐条),减少跨海外往返。
	byServer := make(map[int64][]InboundClientAddItem, 4)
	for _, m := range missing {
		log.Printf("[InboundClientReconciler] 补发 user=%s server=%d tag=%s", m.Username, m.ServerID, m.InboundTag)
		byServer[m.ServerID] = append(byServer[m.ServerID], InboundClientAddItem{
			Username:       m.Username,
			ServerID:       m.ServerID,
			InboundTag:     m.InboundTag,
			Protocol:       m.Protocol,
			Credential:     m.Credential,
			CredentialJSON: m.CredentialJSON,
		})
	}

	var warned int
	for serverID, items := range byServer {
		// agent 离线时这里只影响该 server,其它继续。
		if ws := applyInboundBatchOrFallback(ctx, c.remoteManage, c.repo, serverID, items, "InboundClientReconciler"); len(ws) > 0 {
			warned += len(ws)
		}
	}

	msg := "resynced " + itoa(len(missing)) + " client(s)"
	log.Printf("[InboundClientReconciler] done: resynced=%d warnings=%d servers=%d (%.1fs)",
		len(missing), warned, len(byServer), time.Since(start).Seconds())
	return msg, nil
}

// itoa 避免为一处引入 strconv。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
