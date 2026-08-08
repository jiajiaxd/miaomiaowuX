package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/logger"
	"miaomiaowux/internal/storage"
)

const bytesPerGigabyte = 1073741824.0

type TrafficSummaryHandler struct {
	client *http.Client
	repo   *storage.TrafficRepository
}

type trafficSummaryResponse struct {
	Metrics trafficSummaryMetrics `json:"metrics"`
	History []trafficDailyUsage   `json:"history"`
}

type trafficSummaryMetrics struct {
	TotalLimitGB     float64 `json:"total_limit_gb"`
	TotalUsedGB      float64 `json:"total_used_gb"`
	TotalRemainingGB float64 `json:"total_remaining_gb"`
	UsagePercentage  float64 `json:"usage_percentage"`
	// UnlimitedUsedGB 仅管理员视角:不限流量服务器(traffic_limit=0)的已用流量合计,
	// 不计入上面的百分比;前端在"已用流量"旁用图标 hover 展示。
	UnlimitedUsedGB float64 `json:"unlimited_used_gb"`
}

type trafficDailyUsage struct {
	Date string `json:"date"`
	// 指针 + null:该日期没有任何记录(快照任务没跑成)时为 null,前端画断点。
	// 用 0 会把"没采到"谎报成"当天真没跑流量",两者在排查时含义完全不同。
	UsedGB *float64 `json:"used_gb"`
}

func NewTrafficSummaryHandler(repo *storage.TrafficRepository) *TrafficSummaryHandler {
	if repo == nil {
		panic("traffic summary handler requires repository")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	return newTrafficSummaryHandler(client, repo)
}

func newTrafficSummaryHandler(client *http.Client, repo *storage.TrafficRepository) *TrafficSummaryHandler {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	return &TrafficSummaryHandler{client: client, repo: repo}
}

func (h *TrafficSummaryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("only GET is supported"))
		return
	}

	ctx := r.Context()
	username := auth.UsernameFromContext(ctx)

	var user storage.User
	haveUser := false
	if username != "" && h.repo != nil {
		if u, err := h.repo.GetUser(ctx, username); err == nil {
			user = u
			haveUser = true
		}
	}
	isAdmin := haveUser && user.Role == storage.RoleAdmin

	var totalLimit, totalUsed, unlimitedUsed int64
	// 管理员历史趋势保持全服务器口径；include_in_traffic_stats 只控制顶部四张卡片。
	var snapshotLimit, snapshotUsed int64
	// serverListOK 跟踪 ListRemoteServers 是否成功 — 后面 recordSnapshot 用它兜底,
	// 防止"DB 临时报错 → 全 0 → ON CONFLICT 覆盖正确历史"事故(实际 2026-05-31 已发生)。
	serverListOK := false

	if isAdmin {
		// 管理员:汇总所有服务器(含主控本机,它也是 remote_servers 一行)。
		// 限流服务器(traffic_limit>0)计入 已用/限额;不限流量服务器(=0)的已用单独汇总,
		// 前端在"已用流量"旁用图标 hover 展示,不计入百分比(否则分母没有限额会失真)。
		if servers, err := h.repo.ListRemoteServers(ctx); err == nil {
			serverListOK = true
			for _, s := range servers {
				aggregated, _ := h.repo.GetServerTrafficUsed(ctx, s.ID)
				used := aggregated + s.TrafficUsedOffset
				if used < 0 {
					used = 0 // 与 RecordDailyUsage 保持一致:offset 设过头时兜底。
					// 两个写入者都写同一行 traffic_records,公式不一致会让"谁最后写"决定值大小,
					// 相邻两天写入者不同就会凭空造出负 delta。
				}
				if s.TrafficLimit > 0 {
					snapshotLimit += s.TrafficLimit
					snapshotUsed += used
				}
				if !s.IncludeInTrafficStats {
					continue
				}
				if s.TrafficLimit > 0 {
					totalLimit += s.TrafficLimit
					totalUsed += used
				} else {
					unlimitedUsed += used
				}
			}
		} else {
			logger.Warn("[流量] ListRemoteServers 失败,跳过本次快照避免覆盖历史", "error", err)
		}
		// 外部订阅流量:仅当系统级"外部订阅同步"开关开启时并入。
		if enabled, _ := h.repo.IsSyncTrafficEnabled(ctx); enabled {
			extLimit, extUsed := h.fetchExternalSubscriptionTraffic(ctx, username)
			totalLimit += extLimit
			totalUsed += extUsed
			snapshotLimit += extLimit
			snapshotUsed += extUsed
		}
	} else if haveUser {
		// 普通用户:套餐流量。已用按套餐流量倍率(oneway×1 / twoway×2)计费,
		// 与限额判定口径一致(见 traffic_limit_enforcer:已用×TrafficMultiplier 比限额)。
		if user.PackageID > 0 {
			if pkg, perr := h.repo.GetPackage(ctx, user.PackageID); perr == nil {
				// 有效上限 = 用户级覆写 ?? 套餐流量,与 enforcer 断流口径一致。
				totalLimit += resolveTrafficLimitBytes(&user, pkg)
				// 计费流量:倍率已由 collector 在采集时折算进 weighted_*,拿到即最终值,不再乘倍率。
				if billable, terr := h.repo.GetUserBillableTraffic(ctx, username); terr == nil {
					totalUsed += billable
				}
			}
		}
		// 外部订阅(该用户开启 sync_traffic 时)叠加。
		extLimit, extUsed := h.fetchExternalSubscriptionTraffic(ctx, username)
		totalLimit += extLimit
		totalUsed += extUsed
	}

	totalRemaining := totalLimit - totalUsed
	if totalRemaining < 0 {
		totalRemaining = 0
	}

	if isAdmin {
		// 只在 ListRemoteServers 出错时跳过 —— 此时 totalLimit/totalUsed 全 0 是"读不到"的假象,不可信。
		// 「合法的全 0」(没配限额 + 没用量)不再当异常:RecordDaily 已有存储层护栏,全 0 不会覆盖
		// 当天已有的非 0 历史;所以这里照常写,避免此前每次汇总(前端 5s 轮询)刷一条 WARN 的问题。
		if !serverListOK {
			logger.Warn("[流量] 跳过快照: ListRemoteServers 失败,无法判断当前流量")
		} else {
			snapshotRemaining := snapshotLimit - snapshotUsed
			if snapshotRemaining < 0 {
				snapshotRemaining = 0
			}
			if err := h.recordSnapshot(ctx, snapshotLimit, snapshotUsed, snapshotRemaining); err != nil {
				logger.Info("[流量] 记录快照失败", "error", err)
			}
		}
	} else if haveUser {
		if err := h.repo.RecordUserDaily(ctx, username, time.Now(), totalLimit, totalUsed, totalRemaining); err != nil {
			logger.Info("[流量] 记录用户快照失败", "error", err)
		}
	}

	var history []trafficDailyUsage
	if isAdmin {
		history, _ = h.loadHistory(ctx, 30)
	} else if username != "" {
		history, _ = h.loadUserHistory(ctx, username, 30)
	}

	metrics := trafficSummaryMetrics{
		TotalLimitGB:     roundUpTwoDecimals(bytesToGigabytes(totalLimit)),
		TotalUsedGB:      roundUpTwoDecimals(bytesToGigabytes(totalUsed)),
		TotalRemainingGB: roundUpTwoDecimals(bytesToGigabytes(totalRemaining)),
		UsagePercentage:  roundUpTwoDecimals(usagePercentage(totalUsed, totalLimit)),
		UnlimitedUsedGB:  roundUpTwoDecimals(bytesToGigabytes(unlimitedUsed)),
	}

	response := trafficSummaryResponse{
		Metrics: metrics,
		History: history,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// 获取最新的流量摘要并保留快照。
func (h *TrafficSummaryHandler) RecordDailyUsage(ctx context.Context) error {
	var totalLimit, totalRemaining, totalUsed int64

	// **聚合所有 remote servers 流量**(老 bug:这块完全没算,只算 external 订阅 → 写 0 进 db
	// → 每日趋势图除了少数几天有 external 数据外全是 0,显示成大尖峰加 flat line)。
	// 算法跟 BuildSummary admin 分支一致:aggregated + offset,限流的计入,不限流的丢弃。
	// ListRemoteServers 失败时 skip 整个写入,避免 ON CONFLICT 覆盖正确历史。
	serverListOK := false
	if h.repo != nil {
		if servers, err := h.repo.ListRemoteServers(ctx); err == nil {
			serverListOK = true
			for _, s := range servers {
				aggregated, _ := h.repo.GetServerTrafficUsed(ctx, s.ID)
				used := aggregated + s.TrafficUsedOffset
				if used < 0 {
					used = 0 // offset 设过头时兜底,防止负值拉低总数
				}
				if s.TrafficLimit > 0 {
					totalLimit += s.TrafficLimit
					totalUsed += used
				}
				// 不限流服务器不计入 totalLimit / totalUsed(同 BuildSummary 行为)
			}
		} else {
			logger.Warn("[流量记录] ListRemoteServers 失败,跳过本次快照避免覆盖历史", "error", err)
		}
	}

	// 同步并添加外部订阅流量(系统级 sync_traffic 开关开时才有数据)
	externalLimit, externalUsed := h.syncAndFetchExternalSubscriptionTraffic(ctx)
	if externalLimit > 0 || externalUsed > 0 {
		totalLimit += externalLimit
		totalUsed += externalUsed
		logger.Info("[流量记录] 外部订阅流量",
			"limit_gb", bytesToGigabytes(externalLimit),
			"used_gb", bytesToGigabytes(externalUsed))
	}

	totalRemaining = totalLimit - totalUsed
	if totalRemaining < 0 {
		totalRemaining = 0
	}

	// 守卫:仅 ListRemoteServers 失败时跳过(此时全 0 是"读不到"的假象)。合法的全 0 照常写 ——
	// RecordDaily 已有存储层护栏,不会用全 0 覆盖当天已有非 0 历史。跟 ServeHTTP 的守卫一致。
	if !serverListOK {
		logger.Warn("[流量记录] 跳过快照: ListRemoteServers 失败,无法判断当前流量")
		return nil
	}

	logger.Info("[流量记录] 总计流量",
		"limit_gb", roundUpTwoDecimals(bytesToGigabytes(totalLimit)),
		"used_gb", roundUpTwoDecimals(bytesToGigabytes(totalUsed)),
		"remaining_gb", roundUpTwoDecimals(bytesToGigabytes(totalRemaining)),
		"usage_percent", roundUpTwoDecimals(usagePercentage(totalUsed, totalLimit)))

	if err := h.recordSnapshot(ctx, totalLimit, totalUsed, totalRemaining); err != nil {
		logger.Error("[流量记录] 保存快照到数据库失败", "error", err)
		return err
	}

	logger.Info("[流量记录] 快照已成功保存到数据库")
	return nil
}

// 启用sync_traffic（系统级设置）时，syncAndFetchExternalSubscriptionTraffic 会同步来自外部订阅的流量信息
// 返回未过期订阅的totalLimit 和totalUsed
func (h *TrafficSummaryHandler) syncAndFetchExternalSubscriptionTraffic(ctx context.Context) (int64, int64) {
	if h.repo == nil {
		return 0, 0
	}

	// 检查sync_traffic是否启用（系统级设置）
	enabled, err := h.repo.IsSyncTrafficEnabled(ctx)
	if err != nil {
		logger.Warn("[流量记录] 检查sync_traffic设置失败", "error", err)
		return 0, 0
	}

	if !enabled {
		logger.Info("[流量记录] sync_traffic未启用，跳过外部订阅同步")
		return 0, 0
	}

	// 获取所有用户的所有外部订阅
	subs, err := h.repo.ListAllExternalSubscriptions(ctx)
	if err != nil {
		logger.Warn("[流量记录] 获取外部订阅失败", "error", err)
		return 0, 0
	}

	if len(subs) == 0 {
		logger.Info("[Traffic Record] No external subscriptions found")
		return 0, 0
	}

	logger.Info("[流量记录] 同步外部订阅", "count", len(subs))

	var totalLimit, totalUsed int64
	now := time.Now()

	for _, sub := range subs {
		// 从订阅 URL 获取并更新流量信息
		updatedSub, err := h.fetchExternalSubscriptionTrafficInfo(ctx, sub)
		if err != nil {
			logger.Info("[流量记录] 获取订阅流量失败", "name", sub.Name, "error", err)
			// 如果获取失败，则使用现有数据
			updatedSub = sub
		} else {
			// 更新数据库中的订阅
			if updateErr := h.repo.UpdateExternalSubscription(ctx, updatedSub); updateErr != nil {
				logger.Info("[流量记录] 更新订阅失败", "name", sub.Name, "error", updateErr)
			}
		}

		// 跳过过期的订阅
		if updatedSub.Expire != nil && updatedSub.Expire.Before(now) {
			logger.Info("[流量记录] 跳过已过期订阅", "name", updatedSub.Name, "expired_at", updatedSub.Expire.Format("2006-01-02 15:04:05"))
			continue
		}

		// 添加来自此订阅的流量
		totalLimit += updatedSub.Total
		totalUsed += updatedSub.Upload + updatedSub.Download

		if updatedSub.Expire == nil {
			logger.Info("[流量记录] 添加长期订阅流量",
				"name", updatedSub.Name,
				"limit_gb", bytesToGigabytes(updatedSub.Total),
				"used_gb", bytesToGigabytes(updatedSub.Upload+updatedSub.Download))
		} else {
			logger.Info("[流量记录] 添加订阅流量",
				"name", updatedSub.Name,
				"limit_gb", bytesToGigabytes(updatedSub.Total),
				"used_gb", bytesToGigabytes(updatedSub.Upload+updatedSub.Download),
				"expires", updatedSub.Expire.Format("2006-01-02 15:04:05"))
		}
	}

	logger.Info("[流量记录] 外部订阅流量总计",
		"limit_gb", bytesToGigabytes(totalLimit),
		"used_gb", bytesToGigabytes(totalUsed))

	return totalLimit, totalUsed
}

// 从外部订阅 URL 获取流量信息
func (h *TrafficSummaryHandler) fetchExternalSubscriptionTrafficInfo(ctx context.Context, sub storage.ExternalSubscription) (storage.ExternalSubscription, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sub.URL, nil)
	if err != nil {
		return sub, fmt.Errorf("create request: %w", err)
	}

	userAgent := sub.UserAgent
	if userAgent == "" {
		userAgent = "clash-meta/2.4.0"
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := h.client.Do(req)
	if err != nil {
		return sub, fmt.Errorf("fetch subscription: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return sub, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// 解析订阅用户信息标头
	userInfo := resp.Header.Get("subscription-userinfo")
	if userInfo == "" {
		return sub, nil // 没有可用的交通信息
	}

	// 解析交通信息
	upload, download, total, expire := ParseTrafficInfoHeader(userInfo)

	sub.Upload = upload
	sub.Download = download
	sub.Total = total
	sub.Expire = expire

	logger.Info("[流量记录] 解析流量信息",
		"name", sub.Name,
		"upload_mb", float64(upload)/(1024*1024),
		"download_mb", float64(download)/(1024*1024),
		"total_gb", float64(total)/(1024*1024*1024))

	return sub, nil
}

func roundUpTwoDecimals(value float64) float64 {
	return math.Ceil(value*100) / 100
}

func bytesToGigabytes(total int64) float64 {
	if total <= 0 {
		return 0
	}

	return float64(total) / bytesPerGigabyte
}

func usagePercentage(used, limit int64) float64 {
	if limit <= 0 {
		return 0
	}

	return (float64(used) / float64(limit)) * 100
}

func (h *TrafficSummaryHandler) recordSnapshot(ctx context.Context, totalLimit, totalUsed, totalRemaining int64) error {
	if h.repo == nil {
		return nil
	}

	return h.repo.RecordDaily(ctx, time.Now(), totalLimit, totalUsed, totalRemaining)
}

func (h *TrafficSummaryHandler) loadHistory(ctx context.Context, days int) ([]trafficDailyUsage, error) {
	if h.repo == nil {
		return nil, nil
	}

	// 日账本在采集时直接记录每个日历日的增量，是每日折线图的权威数据源。
	// 旧实现优先用累计快照做相邻日期差分；新安装的第一份快照只能当基线，
	// 即使日账本里已有安装首日/次日的真实流量，图上也要等到第二份快照后才
	// 出现一个点，表现为“前两天消失、只剩今天”。
	if usages, err := h.loadHistoryFromDailyLedger(ctx, days); err == nil && len(usages) > 0 {
		return usages, nil
	} else if err != nil {
		logger.Warn("[流量统计] 日账本读取失败,回落快照差分", "error", err)
	}

	// 兼容升级前没有日账本的历史库：先尝试 per-server 快照差分，再回落旧的
	// traffic_records 总量差分。
	if usages, err := h.loadHistoryFromSnapshots(ctx, days); err == nil && len(usages) > 0 {
		return usages, nil
	} else if err != nil {
		logger.Warn("[流量统计] 快照差分失败,回落总量差分", "error", err)
	}

	records, err := h.repo.ListRecent(ctx, days)
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, nil
	}

	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Date.Before(records[j].Date)
	})

	usages := make([]trafficDailyUsage, 0, len(records))
	var prevUsed int64
	var hasPrev bool

	for _, record := range records {
		delta := record.TotalUsed
		if hasPrev {
			delta = record.TotalUsed - prevUsed
			if delta < 0 {
				// 累计值倒退 = 期间发生了流量重置(某台机的 offset 被改成 -aggregated)。
				//
				// 这一天的真实用量在累计值模型下**算不出来**:total_used 是所有服务器
				// aggregated+offset 的总和,一台机重置只让总和下降一截,既无法从中分离出
				// "重置掉多少",也就无法还原"当天实际用了多少"。
				//
				// 早先钳成 0 会谎称"当天没流量";换成 record.TotalUsed 更糟 ——
				// 那是全部服务器的累计总量,会画出几百上千 GB 的假尖峰。
				// 唯一诚实的做法是标记为不可用,让前端断线。
				logger.Warn("[流量统计] 累计值倒退(疑似流量重置),当日用量不可计算",
					"date", record.Date.Format("2006-01-02"),
					"prev_used", prevUsed, "current_used", record.TotalUsed)
				prevUsed = record.TotalUsed
				hasPrev = true
				usages = append(usages, trafficDailyUsage{
					Date:   record.Date.Format("2006-01-02"),
					UsedGB: nil,
				})
				continue
			}
		}

		prevUsed = record.TotalUsed
		hasPrev = true

		gb := roundUpTwoDecimals(bytesToGigabytes(delta))
		usages = append(usages, trafficDailyUsage{
			Date:   record.Date.Format("2006-01-02"),
			UsedGB: &gb,
		})
	}

	return fillMissingDays(usages), nil
}

// loadHistoryFromDailyLedger aggregates ingestion-time server/day deltas while
// preserving each server's configured traffic source and accounting mode.
func (h *TrafficSummaryHandler) loadHistoryFromDailyLedger(ctx context.Context, days int) ([]trafficDailyUsage, error) {
	rows, err := h.repo.ListServerDailyTraffic(ctx, days, time.Now())
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return nil, err
	}
	modes := make(map[int64]string, len(servers))
	for _, server := range servers {
		modes[server.ID] = server.TrafficStatsMode
	}
	return aggregateDailyLedgerHistory(rows, modes, days), nil
}

func aggregateDailyLedgerHistory(rows []storage.ServerDailyTraffic, modes map[int64]string, days int) []trafficDailyUsage {
	perDate := make(map[string]float64, days+1)
	for _, row := range rows {
		perDate[row.Date] += applyTrafficMode(float64(row.Uplink), float64(row.Downlink), modes[row.ServerID])
	}
	dates := make([]string, 0, len(perDate))
	for date := range perDate {
		dates = append(dates, date)
	}
	sort.Strings(dates)
	usages := make([]trafficDailyUsage, 0, len(dates))
	for _, date := range dates {
		gb := roundUpTwoDecimals(bytesToGigabytes(int64(perDate[date])))
		usages = append(usages, trafficDailyUsage{Date: date, UsedGB: &gb})
	}
	return fillMissingDays(usages)
}

// fillMissingDays 把首尾之间缺失的日历日补成 UsedGB=nil 的空点。
// 缺失 = 那天既没跑成定时快照、也没有 admin 访问过后台。原先这些日期直接从数组里消失,
// X 轴悄悄跳过,看起来像"数据连续"实则有洞;补成 null 后图上是断点,一眼可辨。
func fillMissingDays(usages []trafficDailyUsage) []trafficDailyUsage {
	if len(usages) < 2 {
		return usages
	}
	first, err1 := time.Parse("2006-01-02", usages[0].Date)
	last, err2 := time.Parse("2006-01-02", usages[len(usages)-1].Date)
	if err1 != nil || err2 != nil {
		return usages
	}
	// 防御:异常跨度(如脏数据把日期写到几年前)时不展开,免得生成上万个空点。
	if last.Sub(first) > 400*24*time.Hour {
		return usages
	}
	byDate := make(map[string]trafficDailyUsage, len(usages))
	for _, u := range usages {
		byDate[u.Date] = u
	}
	out := make([]trafficDailyUsage, 0, len(usages))
	for d := first; !d.After(last); d = d.AddDate(0, 0, 1) {
		key := d.Format("2006-01-02")
		if u, ok := byDate[key]; ok {
			out = append(out, u)
		} else {
			out = append(out, trafficDailyUsage{Date: key, UsedGB: nil})
		}
	}
	return out
}

func (h *TrafficSummaryHandler) loadUserHistory(ctx context.Context, username string, days int) ([]trafficDailyUsage, error) {
	if h.repo == nil {
		return nil, nil
	}
	records, err := h.repo.ListUserRecent(ctx, username, days)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Date.Before(records[j].Date)
	})
	usages := make([]trafficDailyUsage, 0, len(records))
	var prevUsed int64
	var hasPrev bool
	for _, record := range records {
		delta := record.TotalUsed
		if hasPrev {
			delta = record.TotalUsed - prevUsed
			if delta < 0 {
				// 同 loadHistory:累计值倒退时当日用量不可计算,置 null 让前端断线。
				prevUsed = record.TotalUsed
				hasPrev = true
				usages = append(usages, trafficDailyUsage{
					Date:   record.Date.Format("2006-01-02"),
					UsedGB: nil,
				})
				continue
			}
		}
		prevUsed = record.TotalUsed
		hasPrev = true
		gb := roundUpTwoDecimals(bytesToGigabytes(delta))
		usages = append(usages, trafficDailyUsage{
			Date:   record.Date.Format("2006-01-02"),
			UsedGB: &gb,
		})
	}
	return fillMissingDays(usages), nil
}

// fetchExternalSubscriptionTraffic 从外部订阅中获取订阅文件中实际使用的流量
// 返回未过期订阅（或没有过期日期的长期订阅）的totalLimit和totalUsed
func (h *TrafficSummaryHandler) fetchExternalSubscriptionTraffic(ctx context.Context, username string) (int64, int64) {
	// 检查sync_traffic是否启用
	settings, err := h.repo.GetUserSettings(ctx, username)
	if err != nil || !settings.SyncTraffic {
		return 0, 0
	}

	subscribeFiles, err := h.repo.ListSubscribeFiles(ctx)
	if err != nil {
		logger.Info("[流量] 获取订阅文件列表失败", "error", err)
		return 0, 0
	}

	// 收集所有订阅文件中使用的所有外部订阅 URL
	usedExternalURLs := make(map[string]bool)
	for _, file := range subscribeFiles {
		// 读取订阅文件内容
		filePath := filepath.Join("subscribes", file.Filename)
		data, err := os.ReadFile(filePath)
		if err != nil {
			logger.Info("[流量] 读取订阅文件失败", "filename", file.Filename, "error", err)
			continue
		}

		// 获取此文件中引用的外部订阅 URL
		fileURLs, err := GetExternalSubscriptionsFromFile(ctx, data, username, h.repo)
		if err != nil {
			logger.Info("[流量] 解析订阅文件失败", "filename", file.Filename, "error", err)
			continue
		}

		// 合并到使用过的 URL
		for url := range fileURLs {
			usedExternalURLs[url] = true
		}
	}

	if len(usedExternalURLs) == 0 {
		logger.Debug("[流量] 未找到使用中的外部订阅")
		return 0, 0
	}

	logger.Debug("[流量] 找到使用中的外部订阅", "count", len(usedExternalURLs))

	// 获取所有外部订阅
	subs, err := h.repo.ListExternalSubscriptions(ctx, username)
	if err != nil {
		logger.Info("[流量] 获取外部订阅失败", "error", err)
		return 0, 0
	}

	var totalLimit int64
	var totalUsed int64
	now := time.Now()

	for _, sub := range subs {
		// 如果此订阅未在任何订阅文件中使用，则跳过
		if !usedExternalURLs[sub.URL] {
			continue
		}

		// 如果订阅已过期则跳过
		// 如果 Expire 为 nil，则为长期订阅，不应跳过
		if sub.Expire != nil && sub.Expire.Before(now) {
			logger.Info("[流量] 跳过已过期订阅", "name", sub.Name, "expired_at", sub.Expire.Format("2006-01-02 15:04:05"))
			continue
		}

		// 添加来自此订阅的流量
		totalLimit += sub.Total
		totalUsed += sub.Upload + sub.Download

		if sub.Expire == nil {
			logger.Debug("[流量] 添加长期订阅流量", "name", sub.Name, "limit", sub.Total, "used", sub.Upload+sub.Download)
		} else {
			logger.Debug("[流量] 添加订阅流量",
				"name", sub.Name,
				"limit", sub.Total,
				"used", sub.Upload+sub.Download,
				"expires", sub.Expire.Format("2006-01-02 15:04:05"))
		}
	}

	logger.Debug("[流量] 外部订阅流量总计", "limit", totalLimit, "used", totalUsed)
	return totalLimit, totalUsed
}

// loadHistoryFromSnapshots 用 per-server 快照算每日流量:每台机各自做日间差分,再按天求和。
//
// 关键在"各自差分":某台机月度重置(或 agent 重装导致 node_traffic 归零)时,只有它那条
// 序列会出现倒退,单独归零处理即可,不会像总量差分那样把整天的数据毁掉。
func (h *TrafficSummaryHandler) loadHistoryFromSnapshots(ctx context.Context, days int) ([]trafficDailyUsage, error) {
	rows, err := h.repo.ListServerDailyCumulative(ctx, days)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}

	// serverID -> 上一天的累计值。rows 已按 (server_id, date) 排好序。
	prev := make(map[int64]int64, 16)
	seen := make(map[int64]bool, 16)
	perDate := make(map[string]int64, days+1)

	for _, r := range rows {
		if !seen[r.ServerID] {
			// 该服务器的第一条只作基线,不产生增量 —— 否则会把它的历史累计量
			// 一次性算进这一天,又是一根假尖峰。
			seen[r.ServerID] = true
			prev[r.ServerID] = r.Used
			continue
		}
		delta := r.Used - prev[r.ServerID]
		prev[r.ServerID] = r.Used
		if delta < 0 {
			// 单机累计值倒退:agent 重装 / xray 重置计数器。当天该机的量无从还原,
			// 计 0 而不是负数;影响面被限制在这一台机,不波及当天其它机器。
			continue
		}
		perDate[r.Date] += delta
	}

	if len(perDate) == 0 {
		return nil, nil
	}

	dates := make([]string, 0, len(perDate))
	for d := range perDate {
		dates = append(dates, d)
	}
	sort.Strings(dates)

	usages := make([]trafficDailyUsage, 0, len(dates))
	for _, d := range dates {
		gb := roundUpTwoDecimals(bytesToGigabytes(perDate[d]))
		usages = append(usages, trafficDailyUsage{Date: d, UsedGB: &gb})
	}
	return fillMissingDays(usages), nil
}
