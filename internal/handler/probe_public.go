package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"miaomiaowux/internal/license"
	"miaomiaowux/internal/storage"
)

// ProbePublicHandler 提供"伪装成探针"的公开(无鉴权)只读服务器状态。
// 安全红线:只序列化下方白名单字段,绝不返回 IP / token / host / inbound 等敏感信息。
type ProbePublicHandler struct {
	repo           *storage.TrafficRepository
	wsHandler      *RemoteWSHandler
	probeStore     *ProbeMetricsStore // 真探针数据(cpu/mem/disk/ping),来自 agent 上报的内存 ring
	licenseManager *license.Manager
	dailyMu        sync.Mutex
	dailyAt        time.Time
	dailyTraffic   map[int64][]probeDailyTraffic
}

func (h *ProbePublicHandler) SetLicenseManager(manager *license.Manager) { h.licenseManager = manager }

func NewProbePublicHandler(repo *storage.TrafficRepository, ws *RemoteWSHandler, store *ProbeMetricsStore) *ProbePublicHandler {
	return &ProbePublicHandler{repo: repo, wsHandler: ws, probeStore: store}
}

// probePingSeries 是一条 ping 曲线的**聚合结果**(每目标一条):只带展示名(省市/运营商) +
// 当前延迟 + 丢包率 + 定宽时间桶。**绝不含目标 host/IP、agent 出口 IP**。
//
// 为什么不返回原始点:这个端点 5 秒一轮询,原始点全量返回会让 payload 随
// 点数×目标数×服务器数爆炸。故服务端聚合成定宽桶 + 当前值 + 丢包率,payload 恒定小。
// 列表视图给近 1 小时(probeListBuckets);更长的窗口走 /api/public/probe-series。
type probePingSeries struct {
	// Key 是目标标识(如 he-cu-v4),前端拿它去 /api/public/probe-series 拉详细曲线。
	// 只是个标识符,不含 host/port,不违反本文件的白名单纪律。
	Key       string            `json:"key,omitempty"`
	Label     string            `json:"label"`
	ISP       string            `json:"isp,omitempty"`
	CurrentMs int64             `json:"current_ms"` // 最新一次延迟,-1=当前探测失败
	LossPct   float64           `json:"loss_pct"`   // 整个窗口内失败占比(0~100)
	Buckets   []probeHourBucket `json:"buckets"`    // 按时间递增,末桶=当前;桶宽由调用方决定
}

// probeListBuckets 是列表/卡片视图的桶数:12 × 5 分钟 = 近 1 小时。
// 列表页是 5 秒一轮询的公开端点,窗口给小些,payload 才压得住;
// 要看更长的历史走详细曲线端点(点开延迟弹窗时才请求)。
const probeListBuckets = 12

// probeHourBucket 是一个时间桶的聚合。无数据的桶 Ms=-1、Loss=-1(前端据此画"无数据"格)。
type probeHourBucket struct {
	Ms   int64   `json:"ms"`   // 该小时成功探测的平均延迟;-1=该小时无数据或全失败
	Loss float64 `json:"loss"` // 该小时丢包率(0~100);-1=无数据
}

// probeServer 是对外暴露的白名单字段集合(刻意不含 id/ip/token/host/reset_day 等)。
// 新增的 cpu/mem/disk/ping 全用指针/切片 + omitempty:未开启或无数据时整个字段消失,不泄露 0 值。
type probeServer struct {
	Name            string `json:"name,omitempty"` // show_name 关闭时省略
	Region          string `json:"region,omitempty"`
	RegionCountry   string `json:"region_country,omitempty"`
	RegionName      string `json:"region_name,omitempty"`
	RegionCity      string `json:"region_city,omitempty"`
	ProviderName    string `json:"provider_name,omitempty"`
	ProviderURL     string `json:"provider_url,omitempty"`
	TelecomPaidPeer bool   `json:"telecom_paid_peer,omitempty"`
	// 网速/流量是展示开关控制的:关闭时置 nil + omitempty,整个字段消失,前端据此隐藏。
	UploadSpeed   *int64 `json:"upload_speed,omitempty"`   // B/s(当前上行速率)
	DownloadSpeed *int64 `json:"download_speed,omitempty"` // B/s(当前下行速率)
	TrafficUsed   *int64 `json:"traffic_used,omitempty"`
	TrafficLimit  *int64 `json:"traffic_limit,omitempty"`
	// 累计上/下行流量(系统级 rx/tx cycle):图2 底部"已用上下行"。仅 system-source 有值,
	// 其余为 0 → 前端隐藏该行。受 onTraffic 门控。
	CumulativeUp   *int64 `json:"cumulative_up,omitempty"`   // 累计上行(SystemTxCycle)
	CumulativeDown *int64 `json:"cumulative_down,omitempty"` // 累计下行(SystemRxCycle)
	Online         bool   `json:"online"`
	// 真探针字段(聚合数值,用户已接受公开;不含任何主机标识)
	CPUPct          *float64            `json:"cpu_pct,omitempty"`
	LoadAvg         string              `json:"loadavg,omitempty"`
	MemUsed         *int64              `json:"mem_used,omitempty"`
	MemTotal        *int64              `json:"mem_total,omitempty"`
	DiskUsed        *int64              `json:"disk_used,omitempty"`
	DiskTotal       *int64              `json:"disk_total,omitempty"`
	Uptime          *int64              `json:"uptime,omitempty"`
	CPUModel        string              `json:"cpu_model,omitempty"`
	CPUCores        int                 `json:"cpu_cores,omitempty"`
	CPUThreads      int                 `json:"cpu_threads,omitempty"`
	OS              string              `json:"os,omitempty"`
	Kernel          string              `json:"kernel,omitempty"`
	Arch            string              `json:"arch,omitempty"`
	Ping            []probePingSeries   `json:"ping,omitempty"`
	ExpiresAt       string              `json:"expires_at,omitempty"`
	RenewalPrice    *float64            `json:"renewal_price,omitempty"`
	RenewalCycle    string              `json:"renewal_cycle,omitempty"`
	RenewalCurrency string              `json:"renewal_currency,omitempty"`
	RenewalPriceCNY *float64            `json:"renewal_price_cny,omitempty"`
	ReturnRoutes    []probeReturnRoute  `json:"return_routes,omitempty"`
	DailyTraffic    []probeDailyTraffic `json:"daily_traffic,omitempty"`
}

type probeDailyTraffic struct {
	Date     string `json:"date"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
	Total    int64  `json:"total"`
}

type probeReturnRoute struct {
	Carrier   string `json:"carrier"`
	Region    string `json:"region,omitempty"`
	RouteType string `json:"route_type"`
	TestedAt  string `json:"tested_at,omitempty"`
}

// ServeHTTP 处理 GET /api/public/probe-servers(无鉴权)。
// 伪装未开启 → {enabled:false};开启 → {enabled:true, title, show_name, servers:[白名单]}。
func (h *ProbePublicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	w.Header().Set("Content-Type", "application/json")

	payload, err := h.buildPayload(ctx)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"enabled": false})
		return
	}
	json.NewEncoder(w).Encode(payload)
}

// buildPayload 组装伪装页数据。HTTP 端点和 WS 推送共用 —— 两条路径必须给出完全一样的结构,
// 否则前端要维护两套解析。ctx 为 nil 时用 Background(WS 广播没有请求上下文)。
func (h *ProbePublicHandler) buildPayload(ctx context.Context) (map[string]any, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if v, _ := h.repo.GetSystemSetting(ctx, probeDisguiseEnabledKey); v != "1" {
		return map[string]any{"enabled": false}, nil
	}

	title, _ := h.repo.GetSystemSetting(ctx, probeDisguiseTitleKey)
	logo, _ := h.repo.GetSystemSetting(ctx, probeDisguiseLogoKey)
	theme, _ := h.repo.GetSystemSetting(ctx, probeDisguiseThemeKey)
	if theme == "" || theme == "follow" {
		theme, _ = h.repo.GetSystemSetting(ctx, DefaultThemeKey)
	}
	if theme != "flat" && theme != "anime" && theme != "pixel" {
		theme = "pixel"
	}
	// 未登录访客要据此决定 /login 是否放行,所以必须走公开端点
	blockLogin, _ := h.repo.GetSystemSetting(ctx, probeDisguiseBlockLoginKey)
	showName := func() bool { v, _ := h.repo.GetSystemSetting(ctx, probeDisguiseShowNameKey); return v == "1" }()

	// 采集子开关:关掉的指标即使 ring 里还有陈旧数据也不展示。
	onCPU := h.setting(ctx, probeDisguiseMetricCPUKey)
	onMem := h.setting(ctx, probeDisguiseMetricMemKey)
	onDisk := h.setting(ctx, probeDisguiseMetricDiskKey)
	onPing := h.setting(ctx, probeDisguiseMetricPingKey)
	// 流量/网速展示开关:默认开(历史行为),仅显式存 "0" 才关。
	trafficRaw, _ := h.repo.GetSystemSetting(ctx, probeDisguiseMetricTrafficKey)
	speedRaw, _ := h.repo.GetSystemSetting(ctx, probeDisguiseMetricSpeedKey)
	onTraffic := trafficRaw != "0"
	onSpeed := speedRaw != "0"
	showExpiry := h.setting(ctx, probeDisguiseShowExpiryKey)
	showPrice := h.setting(ctx, probeDisguiseShowPriceKey)
	showGlobe := h.setting(ctx, probeDisguiseShowGlobeKey)
	showReturnRoute := h.setting(ctx, probeDisguiseShowReturnRouteKey)
	showExternalLicense := h.setting(ctx, probeDisguiseShowExternalLicenseKey)
	var exchangeRates map[string]float64
	if showPrice && h.licenseManager != nil {
		rateCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		exchangeRates, _ = h.licenseManager.ExchangeRates(rateCtx)
		cancel()
	}

	// ping 目标的 Key→(Label,ISP) 映射,用于给 ring 里的 targetKey 配展示名(不回传 host/IP)。
	// 各服务器可单独指定目标,故按服务器解析。
	var resolver *probeTargetResolver
	if onPing {
		globalRaw, _ := h.repo.GetSystemSetting(ctx, probeDisguisePingTargetsKey)
		overrideRaw, _ := h.repo.GetSystemSetting(ctx, probeDisguisePingTargetsOverrideKey)
		resolver = newProbeTargetResolver(globalRaw, overrideRaw)
	}

	idSet := map[int64]bool{}
	if raw, _ := h.repo.GetSystemSetting(ctx, probeDisguiseServerIDsKey); raw != "" {
		var ids []int64
		if json.Unmarshal([]byte(raw), &ids) == nil {
			for _, id := range ids {
				idSet[id] = true
			}
		}
	}

	servers, _ := h.repo.ListRemoteServers(ctx)
	dailyTraffic := h.loadDailyTraffic(ctx, servers)
	var returnRoutes map[int64][]storage.ServerReturnRoute
	if showReturnRoute {
		ids := make([]int64, 0, len(idSet))
		for id := range idSet {
			ids = append(ids, id)
		}
		returnRoutes, _ = h.repo.ListServerReturnRoutes(ctx, ids)
	}
	out := make([]probeServer, 0, len(idSet))
	for i := range servers {
		s := &servers[i]
		if !idSet[s.ID] {
			continue
		}
		used, _ := h.repo.GetServerTrafficUsed(ctx, s.ID)
		used += s.TrafficUsedOffset
		online := (h.wsHandler != nil && h.wsHandler.IsConnected(s.Token)) || s.Status == "connected"
		ps := probeServer{
			Online: online, Region: s.Region, RegionCountry: s.RegionCountry,
			RegionName: s.RegionName, RegionCity: s.RegionCity,
			TelecomPaidPeer: s.TelecomPaidPeer,
		}
		ps.DailyTraffic = dailyTraffic[s.ID]
		if onSpeed {
			up, down := s.CurrentUploadSpeed, s.CurrentDownloadSpeed
			ps.UploadSpeed, ps.DownloadSpeed = &up, &down
		}
		if showExpiry {
			ps.ProviderName, ps.ProviderURL = s.ProviderName, safeProviderURL(s.ProviderURL)
			if s.ExpiresAt != nil {
				ps.ExpiresAt = s.ExpiresAt.Format("2006-01-02")
			} else if s.TrafficResetDay >= 1 && s.TrafficResetDay <= 31 {
				ps.ExpiresAt = nextResetDate(time.Now().UTC(), s.TrafficResetDay).Format("2006-01-02")
			}
		}
		if showPrice && s.RenewalPrice > 0 {
			price := s.RenewalPrice
			ps.RenewalPrice, ps.RenewalCycle, ps.RenewalCurrency = &price, s.RenewalCycle, s.RenewalCurrency
			if rate, ok := exchangeRates[strings.ToUpper(strings.TrimSpace(s.RenewalCurrency))]; ok && rate > 0 {
				cny := price * rate
				ps.RenewalPriceCNY = &cny
			}
		}
		if onTraffic {
			tu, tl := used, s.TrafficLimit
			ps.TrafficUsed, ps.TrafficLimit = &tu, &tl
			// 累计上下行:仅 system-source 服务器有 rx/tx cycle;>0 才带(前端据此显示"已用上下行"行)。
			if s.SystemTxCycle > 0 || s.SystemRxCycle > 0 {
				up, down := s.SystemTxCycle, s.SystemRxCycle
				ps.CumulativeUp, ps.CumulativeDown = &up, &down
			}
		}
		if showName {
			ps.Name = s.Name
		}
		if showReturnRoute {
			order := map[string]int{"telecom": 0, "unicom": 1, "mobile": 2}
			for _, route := range returnRoutes[s.ID] {
				ps.ReturnRoutes = append(ps.ReturnRoutes, probeReturnRoute{
					Carrier: route.Carrier, Region: route.Region, RouteType: route.RouteType,
					TestedAt: route.TestedAt.Format(time.RFC3339),
				})
			}
			sort.Slice(ps.ReturnRoutes, func(i, j int) bool { return order[ps.ReturnRoutes[i].Carrier] < order[ps.ReturnRoutes[j].Carrier] })
		}
		// 从 ring 填真探针字段(用 s.ID 查,s.ID 不入响应)。仅在「开关开 且 agent 报了该项」时才带。
		if h.probeStore != nil {
			if view, ok := h.probeStore.Snapshot(s.ID, probeListBuckets); ok {
				fillProbeMetrics(&ps, view, onCPU, onMem, onDisk, onPing, resolver.For(s.ID))
				if onTraffic && ps.CumulativeUp == nil && view.Sys.HasNetwork {
					up, down := view.Sys.CumulativeUp, view.Sys.CumulativeDown
					ps.CumulativeUp, ps.CumulativeDown = &up, &down
				}
			}
		}
		out = append(out, ps)
	}

	payload := map[string]any{
		"enabled": true,
		"title":   title,
		"logo":    logo,
		// 独立探针前端据此同步主控默认主题。revision 当前等于主题名；以后主题配置
		// 增加更多可变字段时可扩成独立版本号，而不破坏现有客户端。
		"appearance": map[string]any{
			"theme":      theme,
			"color_mode": "light",
			"revision":   theme,
		},
		"block_login": blockLogin == "1",
		"show_name":   showName,
		"show_globe":  showGlobe,
		"servers":     out,
	}
	if showExternalLicense && h.licenseManager != nil {
		status := h.licenseManager.GetStatus()
		if status.Valid && status.Plan != nil && status.Plan.Name != "TRIAL" && (status.Plan.Name != "" || status.Plan.DisplayName != "") {
			payload["license_badge"] = map[string]string{
				"name":         status.Plan.Name,
				"display_name": status.Plan.DisplayName,
			}
		}
	}
	return payload, nil
}

// loadDailyTraffic caches the current reset-cycle ledger projection for one minute.
// buildPayload is shared by HTTP polling and WS broadcasting, so querying the
// ledger on every 5-second payload would create needless database read load.
func (h *ProbePublicHandler) loadDailyTraffic(ctx context.Context, servers []storage.RemoteServer) map[int64][]probeDailyTraffic {
	h.dailyMu.Lock()
	defer h.dailyMu.Unlock()
	if h.dailyTraffic != nil && time.Since(h.dailyAt) < time.Minute {
		return h.dailyTraffic
	}
	now := time.Now()
	// 月度重置周期最长 31 天；多取几天覆盖跨月与 29/30/31 日夹月末。
	const queryDays = 35
	rows, err := h.repo.ListServerDailyTraffic(ctx, queryDays, now)
	if err != nil {
		return h.dailyTraffic
	}
	values := make(map[int64]map[string]probeDailyTraffic)
	for _, row := range rows {
		if values[row.ServerID] == nil {
			values[row.ServerID] = make(map[string]probeDailyTraffic)
		}
		values[row.ServerID][row.Date] = probeDailyTraffic{
			Date: row.Date, Uplink: row.Uplink, Downlink: row.Downlink, Total: row.Uplink + row.Downlink,
		}
	}
	out := make(map[int64][]probeDailyTraffic, len(servers))
	for _, server := range servers {
		serverID, byDate := server.ID, values[server.ID]
		start := now.AddDate(0, 0, -(queryDays - 1))
		if server.TrafficResetDay >= 1 && server.TrafficResetDay <= 31 {
			start = prevResetDate(now, server.TrafficResetDay)
		}
		days := int(dayStart(now).Sub(dayStart(start)).Hours()/24) + 1
		list := make([]probeDailyTraffic, 0, days)
		for i := 0; i < days; i++ {
			date := start.AddDate(0, 0, i).Format("2006-01-02")
			item, ok := byDate[date]
			if !ok {
				item = probeDailyTraffic{Date: date}
			}
			list = append(list, item)
		}
		out[serverID] = list
	}
	h.dailyAt, h.dailyTraffic = now, out
	return out
}

func safeProviderURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	return u.String()
}

func (h *ProbePublicHandler) setting(ctx context.Context, key string) bool {
	v, _ := h.repo.GetSystemSetting(ctx, key)
	return v == "1"
}

// fillProbeMetrics 把 ring 快照按开关填进白名单 probeServer。
// 安全关键:ping 只取 targetMeta 里配的 Label/ISP(不碰 ProbePingTarget.Host/Port),
// 系统指标只填聚合数值。任何主机标识(IP/host/hostname)都不进 ps。
func fillProbeMetrics(ps *probeServer, view *ProbeServerView, onCPU, onMem, onDisk, onPing bool, targetMeta map[string]ProbePingTarget) {
	if view.HasSys {
		sys := view.Sys
		if sys.Uptime > 0 {
			ps.Uptime = &sys.Uptime
		}
		ps.CPUModel, ps.CPUCores, ps.CPUThreads = sys.CPUModel, sys.CPUCores, sys.CPUThreads
		ps.OS, ps.Kernel, ps.Arch = sys.OS, sys.Kernel, sys.Arch
		if onCPU && sys.HasCPU {
			cpu := sys.CPUPct
			ps.CPUPct = &cpu
			ps.LoadAvg = sys.LoadAvg
		}
		if onMem && sys.HasMem {
			mu, mt := sys.MemUsed, sys.MemTotal
			ps.MemUsed, ps.MemTotal = &mu, &mt
		}
		if onDisk && sys.HasDisk {
			du, dt := sys.DiskUsed, sys.DiskTotal
			ps.DiskUsed, ps.DiskTotal = &du, &dt
		}
	}
	if onPing && len(view.Latency) > 0 {
		for key, series := range view.Latency {
			meta, ok := targetMeta[key]
			if !ok {
				// 目标已从配置移除 → 不展示这条陈旧曲线
				continue
			}
			ps.Ping = append(ps.Ping, aggregatePingSeries(key, meta.Label, meta.ISP, series, probeListBuckets, probeAggSlotSec))
		}
		// view.Latency 是 map,遍历顺序随机 —— 不排序的话公开页每次 5s 轮询延迟行都会重排。
		sort.Slice(ps.Ping, func(i, j int) bool {
			if ps.Ping[i].Label != ps.Ping[j].Label {
				return ps.Ping[i].Label < ps.Ping[j].Label
			}
			return ps.Ping[i].ISP < ps.Ping[j].ISP
		})
	}
}

// probeTargetResolver 按服务器解析 ping 目标的展示元数据(Label/ISP)。
//
// 安全关键:只从 DB/settings 构建,**绝不**从 agent 上报的 view.Latency 的 key 构建。
// fillProbeMetrics 里「未在本表中的 key 直接 continue」是防止被攻破的 agent 往公开页
// 注入任意延迟序列的关键防线,per-server 化之后这条防线必须原样保留。
type probeTargetResolver struct {
	global    map[string]ProbePingTarget
	perServer map[int64]map[string]ProbePingTarget
}

func newProbeTargetResolver(globalRaw, overrideRaw string) *probeTargetResolver {
	index := func(ts []ProbePingTarget) map[string]ProbePingTarget {
		m := make(map[string]ProbePingTarget, len(ts))
		for _, t := range ts {
			m[t.Key] = t
		}
		return m
	}

	r := &probeTargetResolver{global: map[string]ProbePingTarget{}}
	if globalRaw != "" {
		var ts []ProbePingTarget
		if json.Unmarshal([]byte(globalRaw), &ts) == nil {
			r.global = index(ts)
		}
	}
	if ov := parseProbePingTargetOverrides(overrideRaw); ov != nil {
		r.perServer = make(map[int64]map[string]ProbePingTarget, len(ov))
		for id, ts := range ov {
			r.perServer[id] = index(ts)
		}
	}
	return r
}

// For 返回该服务器生效的 key→meta 表:配了覆盖用覆盖(空覆盖=该机不展示任何延迟),
// 否则回落全局。nil receiver(未开启 ping 采集)返回 nil,调用方按空表处理。
func (r *probeTargetResolver) For(serverID int64) map[string]ProbePingTarget {
	if r == nil {
		return nil
	}
	if m, ok := r.perServer[serverID]; ok {
		return m
	}
	return r.global
}

// aggregatePingSeries 把一个目标的原始延迟点聚合成对外的 probePingSeries:
// 当前延迟 + 全窗口丢包率 + 定宽时间桶。
//
// bucketCount × bucketSec 决定展示窗口(如 12×300 = 近 1 小时)。数据源是 store 里的
// 5 分钟聚合槽,所以 bucketSec 必须是 probeAggSlotSec 的整数倍 —— 一个桶由若干个槽合并而成。
// 缺数据的桶给 {-1,-1},前端据此画"无数据"格。纯函数,可单测。
func aggregatePingSeries(key, label, isp string, series ProbeTargetSeries, bucketCount, bucketSec int) probePingSeries {
	s := probePingSeries{Key: key, Label: label, ISP: isp, CurrentMs: series.CurrentMs, LossPct: 0}
	if bucketCount <= 0 {
		bucketCount = 12
	}
	if bucketSec < probeAggSlotSec {
		bucketSec = probeAggSlotSec
	}

	// 全窗口丢包率:按槽内点数加权,不是按槽数平均 —— 否则采样稀疏的槽会被放大。
	var totCnt, totFail int64
	for _, sl := range series.Slots {
		totCnt += sl.Cnt
		totFail += sl.Fail
	}
	if totCnt+totFail > 0 {
		s.LossPct = float64(totFail) * 100 / float64(totCnt+totFail)
	}

	// 桶索引:末桶 = 当前时刻所在桶,向前依次递减。
	now := time.Now().Unix()
	lastBucket := now - now%int64(bucketSec)
	type acc struct{ sum, cnt, fail int64 }
	accs := make([]acc, bucketCount)
	for _, sl := range series.Slots {
		bucketStart := sl.Slot - sl.Slot%int64(bucketSec)
		age := (lastBucket - bucketStart) / int64(bucketSec)
		if age < 0 || age >= int64(bucketCount) {
			continue
		}
		idx := bucketCount - 1 - int(age)
		accs[idx].sum += sl.Sum
		accs[idx].cnt += sl.Cnt
		accs[idx].fail += sl.Fail
	}

	s.Buckets = make([]probeHourBucket, bucketCount)
	for i := range accs {
		total := accs[i].cnt + accs[i].fail
		if total == 0 {
			s.Buckets[i] = probeHourBucket{Ms: -1, Loss: -1}
			continue
		}
		ms := int64(-1)
		if accs[i].cnt > 0 {
			ms = accs[i].sum / accs[i].cnt
		}
		s.Buckets[i] = probeHourBucket{Ms: ms, Loss: float64(accs[i].fail) * 100 / float64(total)}
	}
	return s
}
