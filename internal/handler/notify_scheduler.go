package handler

import (
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"miaomiaowux/internal/notify"
	"miaomiaowux/internal/storage"
	"miaomiaowux/internal/taskrun"
)

// 服务器上下线通知去抖动 — 同一 server 同一状态短时间内频繁触发(国际线路抖动 / 心跳延迟卡阈值 /
// 多条代码路径重复上报)会 spam 用户 telegram。这里维护 per-(事件类型, server) 上次通知时间,
// 窗口内重复的"同 server + 同事件"(连续 online 或连续 offline)被吞掉。
// 关键:online 与 offline 各自独立 throttle —— 一次真实的"离线 → 恢复"两条都会照常发。
// (此前 online/offline 共用同一 key,离线先发后,窗口内的上线通知被连带吞掉 → 用户"只有离线没有上线"。)
//
// 默认 5 分钟,可用 MMWX_SERVER_NOTIFY_THROTTLE_SECONDS 覆盖;<=0 → 禁用 throttle。
var (
	serverNotifyMu       sync.Mutex
	serverNotifyLastSent = make(map[string]time.Time) // key = 事件类型|serverName
)

func serverNotifyThrottleInterval() time.Duration {
	if v := os.Getenv("MMWX_SERVER_NOTIFY_THROTTLE_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			if n <= 0 {
				return 0
			}
			return time.Duration(n) * time.Second
		}
	}
	return 5 * time.Minute
}

// shouldThrottleServerNotify 检查同一 server + 同一事件距上次通知是否在 throttle 窗口内。
// 按 (event, serverName) 分别记账:online 与 offline 互不影响,所以离线后窗口内的上线不会被吞。
// true = 跳过本次;false = 通过,顺手记录当前时间。
func shouldThrottleServerNotify(serverName string, event notify.EventType) bool {
	interval := serverNotifyThrottleInterval()
	if interval <= 0 {
		return false
	}
	key := string(event) + "|" + serverName
	serverNotifyMu.Lock()
	defer serverNotifyMu.Unlock()
	if last, ok := serverNotifyLastSent[key]; ok && time.Since(last) < interval {
		return true
	}
	serverNotifyLastSent[key] = time.Now()
	return false
}

// notifyAsync 是所有 tg 通知的统一入口,集中三件事:
//  1. nil Notifier(未初始化 / 配置加载失败)→ throttled log "notifier_nil"
//  2. CheckEnabled 拒绝(全局关 / token 空 / chatID 空 / 该事件开关 off)→ throttled log 对应 reason
//  3. 实际 send 错误(TG API 429/5xx / 网络) → log
//
// 设计目的:解决用户报告「有时候订阅获取 tg 不发」的可观察性缺口 —
// 以前所有静默 return 都吞日志,用户不知道为什么没发。现在统一 throttled log,
// SSH 看 journalctl 一眼能定位:是 token 空? chat_id 空?事件没开?还是 TG API 失败?
//
// 异步 fire-and-forget:调用方零阻塞,适合订阅获取这类响应热路径。
func notifyAsync(ctx context.Context, t notify.EventType, title, msg string) {
	notifyAsyncEvent(ctx, notify.Event{Type: t, Title: title, Message: msg})
}

func notifyAsyncEvent(ctx context.Context, event notify.Event) {
	n := GetNotifier()
	if n == nil {
		logNotifyReasonThrottled(event.Type, "notifier_nil")
		return
	}
	ok, reason := n.CheckEnabled(event.Type)
	if !ok {
		logNotifyReasonThrottled(event.Type, string(reason))
		return
	}
	// 异步 send 必须脱离请求生命周期:调用方多为 HTTP handler(如订阅获取),响应写完后
	// r.Context() 立即被取消,继续用它会让 goroutine 里的 TG 请求以 "context canceled" 失败
	// (订阅本身已 200,通知却报错)。WithoutCancel 保留 ctx 上的值、只剥离取消与 deadline,
	// 实际超时由 httpClient.Timeout(10s)兜底。
	sendCtx := context.WithoutCancel(ctx)
	go func() {
		if err := n.Send(sendCtx, event); err != nil {
			log.Printf("[Notify] send failed event=%s: %v", event.Type, err)
		}
	}()
}

// logNotifyReasonThrottled 同一 (event, reason) pair 5 分钟内最多 log 一次,
// 避免订阅获取等高频事件 + 通知未启用时刷屏(每次拉订阅都打一条 log 会炸 journal)。
var notifyLogMu sync.Mutex
var notifyLogLast = make(map[string]time.Time)

func logNotifyReasonThrottled(t notify.EventType, reason string) {
	key := string(t) + ":" + reason
	notifyLogMu.Lock()
	defer notifyLogMu.Unlock()
	if last, ok := notifyLogLast[key]; ok && time.Since(last) < 5*time.Minute {
		return
	}
	notifyLogLast[key] = time.Now()
	log.Printf("[Notify] skip event=%s reason=%s (5min log throttle to avoid spam)", t, reason)
}

func StartNotifyScheduler(ctx context.Context, repo *storage.TrafficRepository) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	var lastDailyRun string
	var lastPkgExpiringRun string   // 跨日去重(YYYY-MM-DD)避免同天重复扫
	var lastServerRenewalRun string // 同上,服务器续费提醒

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			n := GetNotifier()
			if n == nil {
				continue
			}
			cfg := n.GetConfig()

			if cfg.NotifyDailyTraffic {
				today := now.Format("2006-01-02")
				nowTime := now.Format("15:04")
				targetTime := cfg.DailyTrafficTime
				if targetTime == "" {
					targetTime = "08:00"
				}
				if nowTime == targetTime && lastDailyRun != today {
					lastDailyRun = today
					go taskrun.Record(ctx, "notify_daily_traffic", func() (string, error) {
						sendDailyTrafficNotification(ctx, repo, n)
						return "", nil
					})
				}
			}

			if cfg.NotifyTrafficThreshold && cfg.TrafficThresholdPercent > 0 {
				go checkTrafficThreshold(ctx, repo, n, cfg.TrafficThresholdPercent)
			}

			// Phase 2: 套餐即将到期 — 每天 09:00 扫一次(取整时分钟比较),内存 lastPkgExpiringRun 防同日重复
			if cfg.NotifyPackageExpiring && cfg.PackageExpiringDaysAhead > 0 {
				today := now.Format("2006-01-02")
				if now.Format("15:04") == "09:00" && lastPkgExpiringRun != today {
					lastPkgExpiringRun = today
					go checkPackageExpiring(ctx, repo, cfg.PackageExpiringDaysAhead)
				}
			}

			// 服务器续费提醒 — 09:00 后当天尚未执行就补跑，避免主控恰在 09:00
			// 重启或调度延迟后整天漏掉 7/3 天提醒。
			if cfg.NotifyServerRenewal {
				today := now.Format("2006-01-02")
				if now.Hour() >= 9 && lastServerRenewalRun != today {
					lastServerRenewalRun = today
					go checkServerRenewal(ctx, repo)
				}
			}

			// Phase 2: agent 长期离线 — 每分钟扫,内存 throttle
			if cfg.NotifyAgentLongOffline && cfg.AgentLongOfflineMinutes > 0 {
				go checkAgentLongOffline(ctx, repo, cfg.AgentLongOfflineMinutes)
			}
		}
	}
}

// checkPackageExpiring 扫所有绑套餐用户,package_end_date 在 (now, now + daysAhead] 内 → 发提醒。
// 去重:同 user 同 end_date 只发一次,落库到 user_package_expiring_notified 表会更稳;
// 当前实现 in-memory map(主控重启后会重发,但每天 09:00 才扫一次,影响小)。
var pkgExpiringNotifyMu sync.Mutex
var pkgExpiringNotified = make(map[string]string) // username → 上次通知的 end_date 字符串

func checkPackageExpiring(ctx context.Context, repo *storage.TrafficRepository, daysAhead int) {
	users, err := repo.ListUsersWithPackage(ctx)
	if err != nil {
		log.Printf("[Notify] checkPackageExpiring list users failed: %v", err)
		return
	}
	now := time.Now()
	deadline := now.AddDate(0, 0, daysAhead)
	for _, u := range users {
		if u.PackageEndDate == nil {
			continue
		}
		if u.PackageEndDate.Before(now) || u.PackageEndDate.After(deadline) {
			continue
		}
		endKey := u.PackageEndDate.Format("2006-01-02")

		pkgExpiringNotifyMu.Lock()
		alreadySent := pkgExpiringNotified[u.Username] == endKey
		if !alreadySent {
			pkgExpiringNotified[u.Username] = endKey
		}
		pkgExpiringNotifyMu.Unlock()
		if alreadySent {
			continue
		}

		daysLeft := int(u.PackageEndDate.Sub(now).Hours()/24) + 1
		pkgName := ""
		if u.PackageID > 0 {
			if p, perr := repo.GetPackage(ctx, u.PackageID); perr == nil && p != nil {
				pkgName = p.Name
			}
		}
		SendPackageExpiringNotification(ctx, u.Username, pkgName, daysLeft, endKey)
	}
}

// checkAgentLongOffline 扫所有 remote_servers,last_heartbeat < now - thresholdMinutes 且 5min throttle 通过 → 发通知
// 跟 shouldThrottleServerNotify 共用 throttle map(同 server 短时间内只发一次,不论是哪种事件)
var agentLongOfflineNotifyMu sync.Mutex
var agentLongOfflineLast = make(map[int64]time.Time) // serverID → 上次发"长期离线"通知的时间

func checkAgentLongOffline(ctx context.Context, repo *storage.TrafficRepository, thresholdMinutes int) {
	servers, err := repo.ListRemoteServers(ctx)
	if err != nil {
		return
	}
	now := time.Now()
	threshold := time.Duration(thresholdMinutes) * time.Minute
	// 长期离线通知去重间隔:跟 server online/offline throttle 一致,默认 5min,可 ENV 覆盖
	repeatInterval := serverNotifyThrottleInterval()
	if repeatInterval < 30*time.Minute {
		// 长期离线本质就是状态稳定持续,5min 太短会刷屏;最小 30min 间隔
		repeatInterval = 30 * time.Minute
	}
	for _, s := range servers {
		if s.LastHeartbeat == nil {
			continue
		}
		offline := now.Sub(*s.LastHeartbeat)
		if offline < threshold {
			continue
		}
		agentLongOfflineNotifyMu.Lock()
		last, ok := agentLongOfflineLast[s.ID]
		shouldSend := !ok || now.Sub(last) >= repeatInterval
		if shouldSend {
			agentLongOfflineLast[s.ID] = now
		}
		agentLongOfflineNotifyMu.Unlock()
		if !shouldSend {
			continue
		}
		SendAgentLongOfflineNotification(ctx, s.Name, s.IPAddress, int(offline.Minutes()))
	}
}

// buildDailyTrafficData 汇总每日推送需要的数据。ok=false 表示无数据可发(两个列表都空)。
// 与渲染分离,好让模板渲染是个能单测的纯函数。
func buildDailyTrafficData(ctx context.Context, repo *storage.TrafficRepository) (dailyTrafficData, bool) {
	servers, err := repo.ListRemoteServers(ctx)
	if err != nil {
		log.Printf("[Notify] 获取服务器列表失败: %v", err)
		return dailyTrafficData{}, false
	}

	type serverTraffic struct {
		name  string
		used  int64
		limit int64
	}
	var serverList []serverTraffic
	var totalUsed int64

	for _, s := range servers {
		used, _ := repo.GetServerTrafficUsed(ctx, s.ID)
		used += s.TrafficUsedOffset // 与面板「已用流量」同口径(offset 可为负)
		totalUsed += used
		serverList = append(serverList, serverTraffic{name: s.Name, used: used, limit: s.TrafficLimit})
	}

	sort.Slice(serverList, func(i, j int) bool { return serverList[i].used > serverList[j].used })

	data := dailyTrafficData{
		Date:    time.Now().Format("2006-01-02"),
		TotalGB: fmt.Sprintf("%.2f", float64(totalUsed)/(1024*1024*1024)),
	}
	if inc, incErr := buildDailyIncrementData(ctx, repo, time.Now()); incErr != nil {
		log.Printf("[Notify] 构建每日增量统计失败: %v", incErr)
	} else {
		data.IncrementDate = inc.Date
		data.NodeIncrementTotalGB = fmt.Sprintf("%.2f", float64(inc.NodeTotal)/(1024*1024*1024))
		data.NodeIncrementLines = inc.NodeLines
		data.UserIncrementTotalGB = fmt.Sprintf("%.2f", float64(inc.UserTotal)/(1024*1024*1024))
		data.UserIncrementLines = inc.UserLines
	}

	for _, s := range serverList {
		usedGB := float64(s.used) / (1024 * 1024 * 1024)
		if s.limit > 0 {
			limitGB := float64(s.limit) / (1024 * 1024 * 1024)
			pct := float64(s.used) / float64(s.limit) * 100
			data.ServerLines = append(data.ServerLines, fmt.Sprintf("• %s: %.1fGB/%.0fGB (%.0f%%)", notify.EscapeMarkdown(s.name), usedGB, limitGB, pct))
		} else {
			data.ServerLines = append(data.ServerLines, fmt.Sprintf("• %s: %.1fGB", notify.EscapeMarkdown(s.name), usedGB))
		}
	}

	// 计费流量:倍率已由 collector 在采集时折算,拿到即最终值,不再乘倍率。
	// 也不再需要手工合并「子账号 email → 父用户」—— attributed_username 在采集时就把
	// routed 子账号的流量归到了父用户名下(见 EmailAttributor 的 routedEmailUser)。
	userTotals, err := repo.GetAllUserBillableTraffic(ctx)
	if err == nil && len(userTotals) > 0 {
		type userUsage struct {
			name string
			used int64
		}
		var users []userUsage
		for name, used := range userTotals {
			users = append(users, userUsage{name: name, used: used})
		}
		sort.Slice(users, func(i, j int) bool { return users[i].used > users[j].used })

		for _, u := range users {
			if u.used == 0 {
				continue
			}
			usedGB := float64(u.used) / (1024 * 1024 * 1024)
			data.UserLines = append(data.UserLines, fmt.Sprintf("• %s: %.2fGB", notify.EscapeMarkdown(u.name), usedGB))
		}
	}

	if len(data.ServerLines) == 0 && len(data.UserLines) == 0 {
		return data, false
	}
	return data, true
}

type dailyIncrementData struct {
	Date      string
	NodeTotal int64
	UserTotal int64
	NodeLines []string
	UserLines []string
}

// buildDailyIncrementData reads the immutable ingestion-time ledger for the
// previous calendar day. Node traffic is reported only when the server/tag can
// still be resolved to an item in the node list; unknown Xray tags are ignored.
func buildDailyIncrementData(ctx context.Context, repo *storage.TrafficRepository, now time.Time) (dailyIncrementData, error) {
	yesterdayAt := now.AddDate(0, 0, -1)
	yesterday := yesterdayAt.Format("2006-01-02")
	out := dailyIncrementData{Date: yesterday}

	nodeDaily, _, _, err := repo.ListDailyNodeTraffic(ctx, "today", yesterdayAt)
	if err != nil {
		return out, fmt.Errorf("load daily node traffic: %w", err)
	}
	servers, err := repo.ListRemoteServers(ctx)
	if err != nil {
		return out, fmt.Errorf("list servers for node labels: %w", err)
	}
	serverNames := make(map[int64]string, len(servers))
	for _, s := range servers {
		serverNames[s.ID] = s.Name
	}
	nodes, err := repo.ListAllNodes(ctx)
	if err != nil {
		return out, fmt.Errorf("list nodes for labels: %w", err)
	}
	nodeNames := make(map[string]string, len(nodes))
	for _, n := range nodes {
		if n.InboundTag == "" || n.NodeName == "" {
			continue
		}
		key := n.OriginalServer + "\x00" + n.InboundTag
		if _, exists := nodeNames[key]; !exists {
			nodeNames[key] = n.NodeName
		}
	}
	type usage struct {
		name string
		used int64
	}
	var nodeUsage []usage
	for _, s := range nodeDaily {
		if s.Type != "inbound" || strings.EqualFold(strings.TrimSpace(s.Tag), "api") {
			continue
		}
		serverName := serverNames[s.ServerID]
		name := nodeNames[serverName+"\x00"+s.Tag]
		// Only traffic attributable to an actual node-list entry is included.
		if name == "" {
			continue
		}
		used := s.Uplink + s.Downlink
		if used <= 0 {
			continue
		}
		nodeUsage = append(nodeUsage, usage{name: name, used: used})
		out.NodeTotal += used
	}

	// External subscriptions have no Xray inbound tag. Their provider counters
	// are sampled during sync and stored as daily deltas under the subscription.
	externalDaily, err := repo.ListDailyExternalSubscriptionTraffic(ctx, yesterday)
	if err != nil {
		return out, fmt.Errorf("load external subscription daily traffic: %w", err)
	}
	externalSubs, err := repo.ListAllExternalSubscriptions(ctx)
	if err != nil {
		return out, fmt.Errorf("list external subscriptions for labels: %w", err)
	}
	externalByID := make(map[int64]storage.ExternalSubscription, len(externalSubs))
	for _, sub := range externalSubs {
		externalByID[sub.ID] = sub
	}
	for _, daily := range externalDaily {
		sub, ok := externalByID[daily.ExternalSubscriptionID]
		if !ok {
			continue
		}
		var used int64
		switch strings.ToLower(strings.TrimSpace(sub.TrafficMode)) {
		case "upload":
			used = daily.Uplink
		case "download":
			used = daily.Downlink
		default:
			used = daily.Uplink + daily.Downlink
		}
		if used <= 0 {
			continue
		}
		name := sub.Name
		if strings.TrimSpace(sub.Username) != "" {
			name = sub.Name + " (" + sub.Username + ")"
		}
		nodeUsage = append(nodeUsage, usage{name: name, used: used})
		out.NodeTotal += used
	}
	sort.Slice(nodeUsage, func(i, j int) bool { return nodeUsage[i].used > nodeUsage[j].used })
	for _, n := range nodeUsage {
		out.NodeLines = append(out.NodeLines, fmt.Sprintf("• %s: %.2fGB", notify.EscapeMarkdown(n.name), float64(n.used)/(1024*1024*1024)))
	}

	// User increments use the weighted email ledger, which is independent of
	// package/manual resets and already contains routed-account attribution.
	emailDaily, _, _, err := repo.ListDailyEmailTraffic(ctx, "today", yesterdayAt)
	if err != nil {
		return out, fmt.Errorf("load daily user traffic: %w", err)
	}
	userUsage := make(map[string]int64)
	for _, s := range emailDaily {
		if strings.TrimSpace(s.Username) == "" {
			continue
		}
		weighted := int64(math.Round(s.WeightedUplink + s.WeightedDownlink))
		if weighted > 0 {
			userUsage[s.Username] += weighted
		}
	}
	var users []usage
	for username, used := range userUsage {
		if used <= 0 {
			continue
		}
		users = append(users, usage{name: username, used: used})
		out.UserTotal += used
	}
	sort.Slice(users, func(i, j int) bool { return users[i].used > users[j].used })
	for _, u := range users {
		out.UserLines = append(out.UserLines, fmt.Sprintf("• %s: %.2fGB", notify.EscapeMarkdown(u.name), float64(u.used)/(1024*1024*1024)))
	}
	return out, nil
}

func sendDailyTrafficNotification(ctx context.Context, repo *storage.TrafficRepository, n *notify.Notifier) {
	data, ok := buildDailyTrafficData(ctx, repo)
	if !ok {
		return
	}

	// 模板读不出(DB 错)→ tpl 为空 → renderDailyTrafficTemplate 回退默认模板,推送照发。
	tpl, _ := repo.GetSystemSetting(ctx, notifyDailyTemplateKey)
	msg := renderDailyTrafficTemplate(tpl, data)
	if strings.TrimSpace(msg) == "" {
		log.Printf("[Notify] daily_traffic 模板渲染结果为空,跳过发送")
		return
	}

	// Title 留空:文案首行标题由模板自己带(见 defaultDailyTrafficTemplate),
	// 否则 Notifier.Send 会再前置一行标题,管理员改不掉。
	if err := n.Send(ctx, notify.Event{
		Type:    notify.EventDailyTraffic,
		Message: msg,
	}); err != nil {
		log.Printf("[Notify] send failed event=daily_traffic: %v", err)
	}
}

func checkTrafficThreshold(ctx context.Context, repo *storage.TrafficRepository, n *notify.Notifier, thresholdPct int) {
	servers, err := repo.ListRemoteServers(ctx)
	if err != nil {
		return
	}

	for _, s := range servers {
		if s.TrafficLimit <= 0 || s.Status != "connected" {
			continue
		}
		used, _ := repo.GetServerTrafficUsed(ctx, s.ID)
		used += s.TrafficUsedOffset // 与面板「已用流量」同口径(offset 可为负)
		pct := int(float64(used) / float64(s.TrafficLimit) * 100)
		if pct >= thresholdPct {
			alreadyNotified, _ := repo.IsTrafficThresholdNotified(ctx, s.ID)
			if alreadyNotified {
				continue
			}
			usedGB := float64(used) / (1024 * 1024 * 1024)
			limitGB := float64(s.TrafficLimit) / (1024 * 1024 * 1024)
			if err := n.Send(ctx, notify.Event{
				Type:  notify.EventTrafficThreshold,
				Title: "流量告警",
				Message: fmt.Sprintf("服务器 `%s` 流量已达 %d%%\n已用: %.1fGB / %.0fGB",
					s.Name, pct, usedGB, limitGB),
			}); err != nil {
				log.Printf("[Notify] send failed event=traffic_threshold server=%s: %v", s.Name, err)
			}
			_ = repo.MarkTrafficThresholdNotified(ctx, s.ID)
		} else {
			// 掉回阈值以下 → 清除去重标记,下次越线可再次告警(offset 校准/重置后自愈)
			_ = repo.ClearTrafficThresholdNotified(ctx, s.ID)
		}
	}
}

// 同步发送 — 调用方需要保证顺序的场景(下线 → 上线)直接靠"上一个 Send 返回再发下一个"来对齐;
// 短消息发 telegram 通常 100-500ms,阻塞 caller 一两秒是可接受的代价。
// 想异步不想阻塞的 caller 自己包一层 go func(){...}() 即可。
func SendServerOnlineNotification(ctx context.Context, serverName, ip string) {
	if shouldThrottleServerNotify(serverName, notify.EventServerOnline) {
		log.Printf("[Notify] server=%q online suppressed by throttle (within %s window)", serverName, serverNotifyThrottleInterval())
		return
	}
	notifyAsync(ctx, notify.EventServerOnline,
		"🟢 服务器上线",
		fmt.Sprintf("服务器: `%s`\nIP: `%s`", serverName, ip),
	)
}

func SendServerOfflineNotification(ctx context.Context, serverName, ip string) {
	if shouldThrottleServerNotify(serverName, notify.EventServerOffline) {
		log.Printf("[Notify] server=%q offline suppressed by throttle (within %s window)", serverName, serverNotifyThrottleInterval())
		return
	}
	notifyAsync(ctx, notify.EventServerOffline,
		"🔴 服务器离线",
		fmt.Sprintf("服务器: `%s`\nIP: `%s`", serverName, ip),
	)
}

// SendXrayStatusChangeNotification 在 xray 启停切换时发 TG 通知。
// 复用 server_online / server_offline 两个开关:用户已勾选服务器上下线通知,xray 状态变化一起通知,
// 不引入新开关、不增加配置面板复杂度。
func SendXrayStatusChangeNotification(ctx context.Context, serverName, ip string, running bool) {
	if running {
		notifyAsync(ctx, notify.EventServerOnline,
			"🟢 Xray 已启动",
			fmt.Sprintf("服务器: `%s`\nIP: `%s`", serverName, ip),
		)
	} else {
		notifyAsync(ctx, notify.EventServerOffline,
			"🔴 Xray 已停止",
			fmt.Sprintf("服务器: `%s`\nIP: `%s`", serverName, ip),
		)
	}
}

func SendLoginNotification(ctx context.Context, username, ip string) {
	notifyAsync(ctx, notify.EventLogin,
		"用户登录",
		fmt.Sprintf("用户: `%s`\nIP: `%s`", username, ip),
	)
}

func SendSubscribeFetchNotification(ctx context.Context, repo *storage.TrafficRepository, username, clientType, ip string) {
	message := buildSubscribeFetchNotification(ctx, repo, username, clientType, ip)
	notifyAsync(ctx, notify.EventSubscribeFetch,
		"订阅获取",
		message,
	)
}

func buildSubscribeFetchNotification(ctx context.Context, repo *storage.TrafficRepository, username, clientType, ip string) string {
	safeCode := func(value string) string { return strings.ReplaceAll(value, "`", "'") }
	lines := []string{
		fmt.Sprintf("用户: `%s`", safeCode(username)),
		fmt.Sprintf("客户端: `%s`", safeCode(clientType)),
		fmt.Sprintf("IP: `%s`", safeCode(ip)),
	}
	if repo == nil || strings.TrimSpace(username) == "" {
		return strings.Join(lines, "\n")
	}
	user, err := repo.GetUser(ctx, username)
	if err != nil {
		return strings.Join(lines, "\n")
	}
	packageName := "未绑定"
	var pkg *storage.Package
	if user.PackageID > 0 {
		if loaded, loadErr := repo.GetPackage(ctx, user.PackageID); loadErr == nil && loaded != nil {
			pkg = loaded
			packageName = loaded.Name
		}
	}
	lines = append(lines, fmt.Sprintf("套餐: `%s`", safeCode(packageName)))
	used, trafficErr := repo.GetUserBillableTraffic(ctx, username)
	if trafficErr != nil {
		lines = append(lines, "流量: `读取失败`")
		return strings.Join(lines, "\n")
	}
	usedGB := float64(used) / (1024 * 1024 * 1024)
	limit := resolveTrafficLimitBytes(&user, pkg)
	if limit <= 0 {
		lines = append(lines, fmt.Sprintf("流量: `%.2f GB / 不限量`", usedGB))
		return strings.Join(lines, "\n")
	}
	remaining := limit - used
	if remaining < 0 {
		remaining = 0
	}
	lines = append(lines,
		fmt.Sprintf("流量: `%.2f GB / %.2f GB`", usedGB, float64(limit)/(1024*1024*1024)),
		fmt.Sprintf("剩余: `%.2f GB`", float64(remaining)/(1024*1024*1024)),
	)
	return strings.Join(lines, "\n")
}

// ============ Phase 2: 9 个新通知 helper ============

// SendTrafficThreshold80Notification 用户流量达 80%(预警)
func SendTrafficThreshold80Notification(ctx context.Context, username string, usedGB, limitGB float64) {
	notifyAsync(ctx, notify.EventTrafficThreshold80,
		"⚠️ 用户流量预警 80%",
		fmt.Sprintf("用户: `%s`\n已用: %.2fGB / %.0fGB (≥80%%)", username, usedGB, limitGB),
	)
}

// SendOverLimitNotification 用户流量超 100%(已被踢出入站)
func SendOverLimitNotification(ctx context.Context, username string, usedGB, limitGB float64) {
	notifyAsync(ctx, notify.EventOverLimit,
		"🚫 用户流量超限",
		fmt.Sprintf("用户: `%s`\n已用: %.2fGB / %.0fGB (100%%+)\n→ 已从入站移除", username, usedGB, limitGB),
	)
}

// SendPackageExpiringNotification 套餐将在 N 天内到期
func SendPackageExpiringNotification(ctx context.Context, username, pkgName string, daysLeft int, endDate string) {
	notifyAsync(ctx, notify.EventPackageExpiring,
		"⏰ 套餐即将到期",
		fmt.Sprintf("用户: `%s`\n套餐: `%s`\n到期: %s (剩 %d 天)", username, pkgName, endDate, daysLeft),
	)
}

// SendPackageExpiredNotification 套餐已到期(清理时点)
func SendPackageExpiredNotification(ctx context.Context, username, pkgName string) {
	notifyAsync(ctx, notify.EventPackageExpired,
		"❌ 套餐已到期",
		fmt.Sprintf("用户: `%s`\n套餐: `%s`\n→ 已清除入站/路由分配", username, pkgName),
	)
}

// SendUserRegisteredNotification 新用户注册
func SendUserRegisteredNotification(ctx context.Context, username, email, source string) {
	notifyAsync(ctx, notify.EventUserRegistered,
		"🆕 新用户注册",
		fmt.Sprintf("用户: `%s`\n邮箱: `%s`\n来源: %s", username, email, source),
	)
}

// SendTelegramBoundNotification 用户首次绑定 telegram_id
func SendTelegramBoundNotification(ctx context.Context, username string, tgID int64, tgHandle string) {
	notifyAsync(ctx, notify.EventTelegramBound,
		"🔗 用户已绑定 Telegram",
		fmt.Sprintf("用户: `%s`\nTG ID: `%d`\nTG: @%s", username, tgID, tgHandle),
	)
}

// SendCertResultNotification 证书申请成功/失败
func SendCertResultNotification(ctx context.Context, domain string, success bool, detail string) {
	if success {
		notifyAsync(ctx, notify.EventCertResult,
			"✅ 证书申请成功",
			fmt.Sprintf("域名: `%s`\n%s", domain, detail),
		)
	} else {
		notifyAsync(ctx, notify.EventCertResult,
			"❗️ 证书申请失败",
			fmt.Sprintf("域名: `%s`\n错误: %s", domain, detail),
		)
	}
}

// SendAgentLongOfflineNotification agent 长期离线(超过 N 分钟无心跳)
func SendAgentLongOfflineNotification(ctx context.Context, serverName, ip string, offlineMinutes int) {
	notifyAsync(ctx, notify.EventAgentLongOffline,
		"⏱ Agent 长期离线",
		fmt.Sprintf("服务器: `%s`\nIP: `%s`\n已离线: %d 分钟", serverName, ip, offlineMinutes),
	)
}

// SendConnLimitExceededNotification 用户在某节点触发**连接数上限**、新连接被拒绝时通知管理员。
// delta = 本次上报周期内被拒次数;nodeName 为空则省略节点行。
// EventDeviceLimitExceeded 是历史兼容名称，实际开关和通知语义均为连接数超限。
func SendConnLimitExceededNotification(ctx context.Context, username, nodeName string, delta int) {
	msg := fmt.Sprintf("用户: `%s`\n本周期内新连接被拒: %d 次", username, delta)
	if nodeName != "" {
		msg = fmt.Sprintf("用户: `%s`\n节点: `%s`\n本周期内新连接被拒: %d 次", username, notify.EscapeMarkdown(nodeName), delta)
	}
	notifyAsync(ctx, notify.EventDeviceLimitExceeded, "🔌 连接数超限", msg)
}
