package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"miaomiaowux/internal/agentlog"
	"miaomiaowux/internal/storage"
	"miaomiaowux/internal/traffic"
)

type SystemSettingsHandler struct {
	repo               *storage.TrafficRepository
	crypto             *CryptoConfig
	collector          *traffic.Collector // 可选,SetIntervals 时调 hot-reload ticker;nil 时仅落库
	wsHandler          *RemoteWSHandler   // 可选,SetDashboardRefresh 后广播 config_update 给所有 WS-mode agent
	onMasterURLChanged func(ctx context.Context, newURL string)
}

func NewSystemSettingsHandler(repo *storage.TrafficRepository, crypto *CryptoConfig) *SystemSettingsHandler {
	return &SystemSettingsHandler{repo: repo, crypto: crypto}
}

// SetCollector 注入 traffic.Collector 让 SetIntervals 修改间隔后立即热重载 ticker。
// main.go 在创建 collector 之后调用一次。
func (h *SystemSettingsHandler) SetCollector(c *traffic.Collector) { h.collector = c }

// SetWSHandler 注入 WS handler 让 SetDashboardRefresh 后向所有 agent 广播 config_update。
func (h *SystemSettingsHandler) SetWSHandler(ws *RemoteWSHandler) { h.wsHandler = ws }

// SetOnMasterURLChanged 注入主控地址变更后的 Agent 同步器。
func (h *SystemSettingsHandler) SetOnMasterURLChanged(fn func(ctx context.Context, newURL string)) {
	h.onMasterURLChanged = fn
}

type GetAPITokenResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
}

// 返回当前的 API token
func (h *SystemSettingsHandler) GetAPIToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	token, err := h.repo.GetAPIToken(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(GetAPITokenResponse{
			Success: false,
			Message: "获取 API token 失败",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(GetAPITokenResponse{
		Success: true,
		Token:   token,
	})
}

// 生成新的 API token
func (h *SystemSettingsHandler) RegenerateAPIToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	token, err := h.repo.RegenerateAPIToken(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(GetAPITokenResponse{
			Success: false,
			Message: "重新生成 API token 失败",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(GetAPITokenResponse{
		Success: true,
		Token:   token,
		Message: "API token 重新生成成功",
	})
}

// 获取主服务器地址
func (h *SystemSettingsHandler) GetMasterURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	value, err := h.repo.GetSystemSetting(r.Context(), "master_url")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取主服务器地址失败"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	localOnly, _ := h.repo.GetSystemSetting(r.Context(), "master_local_only")
	subscriptionURL, _ := h.repo.GetSystemSetting(r.Context(), "subscription_url")
	recoveryEnabled, _ := h.repo.GetSystemSetting(r.Context(), settingHTTPSRecoveryEnabled)
	recoveryURLCustom, _ := h.repo.GetSystemSetting(r.Context(), settingRecoveryURL)
	recoveryURL, recoveryURLIsCustom, _ := effectiveRecoveryURL(r.Context(), h.repo, masterListenPort())
	recoveryFailure, _ := h.repo.GetSystemSetting(r.Context(), settingRecoveryFailureMin)
	recoveryGrace, _ := h.repo.GetSystemSetting(r.Context(), settingRecoveryGraceMin)
	recoveryPending, _ := h.repo.GetSystemSetting(r.Context(), settingRecoveryPending)
	recoveryReason, _ := h.repo.GetSystemSetting(r.Context(), settingRecoveryReason)
	json.NewEncoder(w).Encode(map[string]any{
		"success":                        true,
		"master_url":                     value,
		"subscription_url":               subscriptionURL,
		"local_only":                     localOnly == "1",
		"https_recovery_enabled":         recoveryEnabled == "1",
		"recovery_url":                   recoveryURL,
		"recovery_url_custom":            recoveryURLCustom,
		"recovery_url_auto":              !recoveryURLIsCustom,
		"recovery_failure_minutes":       parsePositiveInt(recoveryFailure, 5),
		"recovery_startup_grace_minutes": parsePositiveInt(recoveryGrace, 10),
		"recovery_pending":               recoveryPending == "1",
		"recovery_reason":                recoveryReason,
		"is_docker":                      isDocker(),
	})
}

func parsePositiveInt(raw string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 1 {
		return fallback
	}
	return n
}

// 设置主服务器地址
func (h *SystemSettingsHandler) SetMasterURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		MasterURL                   *string `json:"master_url"`
		SubscriptionURL             *string `json:"subscription_url"`
		LocalOnly                   *bool   `json:"local_only"`
		HTTPSRecoveryEnabled        *bool   `json:"https_recovery_enabled"`
		RecoveryURL                 *string `json:"recovery_url"`
		RecoveryFailureMinutes      *int    `json:"recovery_failure_minutes"`
		RecoveryStartupGraceMinutes *int    `json:"recovery_startup_grace_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}

	if req.MasterURL == nil && req.SubscriptionURL == nil && req.LocalOnly == nil && req.HTTPSRecoveryEnabled == nil && req.RecoveryURL == nil && req.RecoveryFailureMinutes == nil && req.RecoveryStartupGraceMinutes == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "未提供需要更新的设置"})
		return
	}
	if req.RecoveryURL != nil {
		value := strings.TrimSpace(*req.RecoveryURL)
		if value != "" {
			var err error
			value, err = normalizeRecoveryURL(value, masterListenPort())
			if err != nil {
				writeError(w, http.StatusBadRequest, errors.New("恢复地址必须是可公网访问的 HTTP 地址"))
				return
			}
		}
		if err := h.repo.SetSystemSetting(r.Context(), settingRecoveryURL, value); err != nil {
			writeError(w, 500, err)
			return
		}
	}
	if req.HTTPSRecoveryEnabled != nil {
		value := "0"
		if *req.HTTPSRecoveryEnabled {
			value = "1"
		}
		if err := h.repo.SetSystemSetting(r.Context(), settingHTTPSRecoveryEnabled, value); err != nil {
			writeError(w, 500, err)
			return
		}
	}
	if req.RecoveryFailureMinutes != nil {
		if *req.RecoveryFailureMinutes < 1 || *req.RecoveryFailureMinutes > 60 {
			writeError(w, 400, errors.New("故障确认时间必须为 1-60 分钟"))
			return
		}
		if err := h.repo.SetSystemSetting(r.Context(), settingRecoveryFailureMin, strconv.Itoa(*req.RecoveryFailureMinutes)); err != nil {
			writeError(w, 500, err)
			return
		}
	}
	if req.RecoveryStartupGraceMinutes != nil {
		if *req.RecoveryStartupGraceMinutes < 1 || *req.RecoveryStartupGraceMinutes > 120 {
			writeError(w, 400, errors.New("启动保护时间必须为 1-120 分钟"))
			return
		}
		if err := h.repo.SetSystemSetting(r.Context(), settingRecoveryGraceMin, strconv.Itoa(*req.RecoveryStartupGraceMinutes)); err != nil {
			writeError(w, 500, err)
			return
		}
	}
	if req.RecoveryURL != nil && h.wsHandler != nil {
		go h.wsHandler.PushProbeConfigToAll(context.Background())
	}
	if req.SubscriptionURL != nil {
		value := strings.TrimRight(strings.TrimSpace(*req.SubscriptionURL), "/")
		if value != "" {
			parsed, err := url.ParseRequestURI(value)
			if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
				parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
				writeError(w, http.StatusBadRequest, errors.New("订阅域名必须是有效的 HTTP 或 HTTPS 地址"))
				return
			}
			value = parsed.Scheme + "://" + parsed.Host
		}
		if err := h.repo.SetSystemSetting(r.Context(), "subscription_url", value); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("保存订阅域名失败"))
			return
		}
	}

	if req.MasterURL != nil {
		newMasterURL := strings.TrimRight(strings.TrimSpace(*req.MasterURL), "/")
		oldMasterURL, _ := h.repo.GetSystemSetting(r.Context(), "master_url")
		if err := h.repo.SetSystemSetting(r.Context(), "master_url", newMasterURL); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
			return
		}
		if h.onMasterURLChanged != nil && strings.TrimRight(strings.TrimSpace(oldMasterURL), "/") != newMasterURL {
			go h.onMasterURLChanged(context.Background(), newMasterURL)
		}
	}
	if req.LocalOnly != nil {
		if *req.LocalOnly && isDocker() {
			writeError(w, http.StatusBadRequest, errors.New("Docker 环境不支持禁止公网访问，请通过 Docker 端口映射或宿主机防火墙限制访问"))
			return
		}
		value := "0"
		if *req.LocalOnly {
			value = "1"
		}
		if err := h.repo.SetSystemSetting(r.Context(), "master_local_only", value); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":          true,
		"message":          "主服务器设置已更新",
		"restart_required": req.LocalOnly != nil,
	})
}

// 获取「外部已配 HTTPS/反代」开关(用户自建反代、外部终结 TLS 时置 1,证书页据此不再提示开启 HTTPS)
func (h *SystemSettingsHandler) GetExternalHTTPS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	value, _ := h.repo.GetSystemSetting(r.Context(), "external_https")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "external_https": value == "1"})
}

// 设置「外部已配 HTTPS/反代」开关
func (h *SystemSettingsHandler) SetExternalHTTPS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ExternalHTTPS bool `json:"external_https"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	val := "0"
	if req.ExternalHTTPS {
		val = "1"
	}
	if err := h.repo.SetSystemSetting(r.Context(), "external_https", val); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "已更新"})
}

// 伪装探针配置的 4 个 KV 键。
const (
	probeDisguiseEnabledKey = "probe_disguise_enabled" // "1"/"" 开关
	probeInternalEnabledKey = "probe_internal_enabled" // 内置探针独立开关
	probeExternalEnabledKey = "probe_external_enabled" // 外置探针独立开关
	probeDisguiseTitleKey   = "probe_disguise_title"   // 伪装页标题(管理员自定义)
	probeDisguiseThemeKey   = "probe_disguise_theme"   // follow/flat/pixel/anime 或外置探针自定义主题名
	// 伪装页 logo:图片 URL 或 data: URI。空=只显示标题。
	// data: URI 有大小上限(probeLogoMaxBytes)——公开端点每 5 秒轮询一次,大图会持续吃带宽。
	probeDisguiseLogoKey = "probe_disguise_logo"
	// 禁止访问原登录页:开启后未登录访客访问 /login 会被弹回探针页。
	// 仅前端路由层生效(登录 API 不关闭,否则管理员无法从隐蔽入口登录)。
	probeDisguiseBlockLoginKey = "probe_disguise_block_login"
	probeDisguiseServerIDsKey  = "probe_disguise_server_ids" // JSON int64 数组:展示哪些服务器
	probeDisguiseShowNameKey   = "probe_disguise_show_name"  // "1"/"" 是否显示服务器名
	// 真探针数据后端:4 个采集子开关 + ping 目标 + ping 间隔。
	// 新字段在 SetProbeDisguise 里用指针语义(nil=不改)——旧前端 PUT 不带这些字段时不会被冲成零值。
	probeDisguiseMetricCPUKey  = "probe_disguise_metric_cpu"  // "1"/"" 采集 CPU
	probeDisguiseMetricMemKey  = "probe_disguise_metric_mem"  // "1"/"" 采集内存
	probeDisguiseMetricDiskKey = "probe_disguise_metric_disk" // "1"/"" 采集硬盘
	probeDisguiseMetricPingKey = "probe_disguise_metric_ping" // "1"/"" 采集 ping
	// 流量/网速是展示开关(数据来自主控实时,不需 agent 采集):"1"/"" 控制伪装页是否显示该块。
	probeDisguiseMetricTrafficKey       = "probe_disguise_metric_traffic" // "1"/"" 伪装页显示流量
	probeDisguiseMetricSpeedKey         = "probe_disguise_metric_speed"   // "1"/"" 伪装页显示网速
	probeDisguiseShowExpiryKey          = "probe_disguise_show_expiry"
	probeDisguiseShowPriceKey           = "probe_disguise_show_price"
	probeDisguiseShowGlobeKey           = "probe_disguise_show_globe"
	probeDisguiseShowDailyTrendKey      = "probe_disguise_show_daily_trend"
	probeDisguiseShowTrafficHotspotsKey = "probe_disguise_show_traffic_hotspots"
	probeDisguiseShowTraffic7DKey       = "probe_disguise_show_traffic_7d"
	probeDisguiseShowResourceHeatmapKey = "probe_disguise_show_resource_heatmap"
	probeDisguiseShowTrafficQuotaKey    = "probe_disguise_show_traffic_quota"
	probeDisguiseShowRenewalTimelineKey = "probe_disguise_show_renewal_timeline"
	probeDisguiseShowReturnRouteKey     = "probe_disguise_show_return_route"
	probeDisguiseShowExternalLicenseKey = "probe_disguise_show_external_license"
	probeDisguisePingTargetsKey         = "probe_disguise_ping_targets" // JSON [{key,label,isp,host,port}]
	// per-server 覆盖:JSON {"<serverID>": [{key,label,isp,host,port}]}。
	// key 存在且为 [] = 该机不做 ping 探测;key 不存在 = 跟随全局 probeDisguisePingTargetsKey。
	// 这两种状态必须可区分,所以用 map 的键存在性而不是空数组来表达"跟随全局"。
	probeDisguisePingTargetsOverrideKey = "probe_disguise_ping_targets_override"
	probeDisguisePingIntervalKey        = "probe_disguise_ping_interval_ms" // int 字符串,默认 5000
	probeCDNRegionsEndpointKey          = "probe_cdn_regions_endpoint"      // CDN 数据端点(可配置)
	// 探针源站保护:开启后允许同源内置探针或携带 Worker 专用密钥的独立探针。
	probeExternalOnlyKey      = "probe_external_access_only"
	probeExternalTokenHashKey = "probe_external_token_sha256"
)

// validProbeThemeName keeps the value safe for the external probe's
// `theme-<name>` CSS class while allowing deployments to provide their own
// theme names. Empty values are handled by the caller as "follow".
func validProbeThemeName(theme string) bool {
	if len(theme) == 0 || len(theme) > 64 {
		return false
	}
	for i := 0; i < len(theme); i++ {
		c := theme[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

// GetProbeDisguise 返回伪装探针配置(管理端)。
func (h *SystemSettingsHandler) GetProbeDisguise(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	enabled, _ := h.repo.GetSystemSetting(ctx, probeDisguiseEnabledKey)
	internalEnabled, _ := h.repo.GetSystemSetting(ctx, probeInternalEnabledKey)
	externalEnabled, _ := h.repo.GetSystemSetting(ctx, probeExternalEnabledKey)
	// 新开关首次升级尚未写入时，沿用旧总开关，避免升级后探针意外关闭。
	if internalEnabled == "" && externalEnabled == "" && enabled == "1" {
		internalEnabled, externalEnabled = "1", "1"
	}
	title, _ := h.repo.GetSystemSetting(ctx, probeDisguiseTitleKey)
	theme, _ := h.repo.GetSystemSetting(ctx, probeDisguiseThemeKey)
	if !validProbeThemeName(theme) {
		theme = "follow"
	}
	logo, _ := h.repo.GetSystemSetting(ctx, probeDisguiseLogoKey)
	blockLogin, _ := h.repo.GetSystemSetting(ctx, probeDisguiseBlockLoginKey)
	showName, _ := h.repo.GetSystemSetting(ctx, probeDisguiseShowNameKey)
	idsRaw, _ := h.repo.GetSystemSetting(ctx, probeDisguiseServerIDsKey)
	externalOnly, _ := h.repo.GetSystemSetting(ctx, probeExternalOnlyKey)
	externalTokenHash, _ := h.repo.GetSystemSetting(ctx, probeExternalTokenHashKey)

	ids := []int64{}
	if idsRaw != "" {
		_ = json.Unmarshal([]byte(idsRaw), &ids)
	}

	metricCPU, _ := h.repo.GetSystemSetting(ctx, probeDisguiseMetricCPUKey)
	metricMem, _ := h.repo.GetSystemSetting(ctx, probeDisguiseMetricMemKey)
	metricDisk, _ := h.repo.GetSystemSetting(ctx, probeDisguiseMetricDiskKey)
	metricPing, _ := h.repo.GetSystemSetting(ctx, probeDisguiseMetricPingKey)
	// 流量/网速默认显示(历史行为=一直显示):未设置("")视为开,仅显式 "0" 才关。
	metricTraffic, _ := h.repo.GetSystemSetting(ctx, probeDisguiseMetricTrafficKey)
	metricSpeed, _ := h.repo.GetSystemSetting(ctx, probeDisguiseMetricSpeedKey)
	showExpiry, _ := h.repo.GetSystemSetting(ctx, probeDisguiseShowExpiryKey)
	showPrice, _ := h.repo.GetSystemSetting(ctx, probeDisguiseShowPriceKey)
	showGlobe, _ := h.repo.GetSystemSetting(ctx, probeDisguiseShowGlobeKey)
	showDailyTrend, _ := h.repo.GetSystemSetting(ctx, probeDisguiseShowDailyTrendKey)
	showTrafficHotspots, _ := h.repo.GetSystemSetting(ctx, probeDisguiseShowTrafficHotspotsKey)
	showTraffic7D, _ := h.repo.GetSystemSetting(ctx, probeDisguiseShowTraffic7DKey)
	showResourceHeatmap, _ := h.repo.GetSystemSetting(ctx, probeDisguiseShowResourceHeatmapKey)
	showTrafficQuota, _ := h.repo.GetSystemSetting(ctx, probeDisguiseShowTrafficQuotaKey)
	showRenewalTimeline, _ := h.repo.GetSystemSetting(ctx, probeDisguiseShowRenewalTimelineKey)
	showReturnRoute, _ := h.repo.GetSystemSetting(ctx, probeDisguiseShowReturnRouteKey)
	showExternalLicense, _ := h.repo.GetSystemSetting(ctx, probeDisguiseShowExternalLicenseKey)
	pingTargetsRaw, _ := h.repo.GetSystemSetting(ctx, probeDisguisePingTargetsKey)
	pingIntervalRaw, _ := h.repo.GetSystemSetting(ctx, probeDisguisePingIntervalKey)

	pingTargets := []ProbePingTarget{}
	if pingTargetsRaw != "" {
		_ = json.Unmarshal([]byte(pingTargetsRaw), &pingTargets)
	}
	// per-server 覆盖:回给前端时保持 {"<serverID>": [...]} 形态,键存在性=该机是否单独指定。
	overrideRaw, _ := h.repo.GetSystemSetting(ctx, probeDisguisePingTargetsOverrideKey)
	pingTargetsOverride := map[string][]ProbePingTarget{}
	for id, ts := range parseProbePingTargetOverrides(overrideRaw) {
		pingTargetsOverride[strconv.FormatInt(id, 10)] = ts
	}
	pingInterval := 60000 // 默认 60 秒探一次(配合 1 天保留窗口)
	if n, err := strconv.Atoi(pingIntervalRaw); err == nil && n > 0 {
		pingInterval = n
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":                   true,
		"enabled":                   enabled == "1",
		"internal_enabled":          internalEnabled == "1",
		"external_enabled":          externalEnabled == "1",
		"title":                     title,
		"theme":                     theme,
		"logo":                      logo,
		"block_login":               blockLogin == "1",
		"server_ids":                ids,
		"show_name":                 showName == "1",
		"external_access_only":      externalOnly == "1",
		"external_token_configured": strings.TrimSpace(externalTokenHash) != "",
		"metric_cpu":                metricCPU == "1",
		"metric_mem":                metricMem == "1",
		"metric_disk":               metricDisk == "1",
		"metric_ping":               metricPing == "1",
		"metric_traffic":            metricTraffic != "0", // 默认显示
		"metric_speed":              metricSpeed != "0",   // 默认显示
		"show_expiry":               showExpiry == "1",
		"show_price":                showPrice == "1",
		"show_globe":                showGlobe == "1",
		"show_daily_trend":          showDailyTrend != "0",
		"show_traffic_hotspots":     showTrafficHotspots != "0",
		"show_traffic_7d":           showTraffic7D != "0",
		"show_resource_heatmap":     showResourceHeatmap != "0",
		"show_traffic_quota":        showTrafficQuota != "0",
		"show_renewal_timeline":     showRenewalTimeline != "0",
		"show_return_route":         showReturnRoute == "1",
		"show_external_license":     showExternalLicense == "1",
		"ping_targets":              pingTargets,
		"ping_targets_override":     pingTargetsOverride,
		"ping_interval_ms":          pingInterval,
	})
}

// SetProbeDisguise 写入伪装探针配置(管理端)。
func (h *SystemSettingsHandler) SetProbeDisguise(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Enabled         bool    `json:"enabled"`
		InternalEnabled *bool   `json:"internal_enabled"`
		ExternalEnabled *bool   `json:"external_enabled"`
		Title           string  `json:"title"`
		Theme           *string `json:"theme"`
		// 指针语义:nil=不改(旧前端 PUT 不带这个字段时不会被冲成空)。
		Logo       *string `json:"logo"`
		BlockLogin *bool   `json:"block_login"`
		ServerIDs  []int64 `json:"server_ids"`
		ShowName   bool    `json:"show_name"`
		// 新字段用指针:nil=不改。旧前端 PUT 不带这些字段时,它们保持原值不被冲成零值。
		MetricCPU           *bool              `json:"metric_cpu"`
		MetricMem           *bool              `json:"metric_mem"`
		MetricDisk          *bool              `json:"metric_disk"`
		MetricPing          *bool              `json:"metric_ping"`
		MetricTraffic       *bool              `json:"metric_traffic"`
		MetricSpeed         *bool              `json:"metric_speed"`
		ShowExpiry          *bool              `json:"show_expiry"`
		ShowPrice           *bool              `json:"show_price"`
		ShowGlobe           *bool              `json:"show_globe"`
		ShowDailyTrend      *bool              `json:"show_daily_trend"`
		ShowTrafficHotspots *bool              `json:"show_traffic_hotspots"`
		ShowTraffic7D       *bool              `json:"show_traffic_7d"`
		ShowResourceHeatmap *bool              `json:"show_resource_heatmap"`
		ShowTrafficQuota    *bool              `json:"show_traffic_quota"`
		ShowRenewalTimeline *bool              `json:"show_renewal_timeline"`
		ShowReturnRoute     *bool              `json:"show_return_route"`
		ShowExternalLicense *bool              `json:"show_external_license"`
		PingTargets         *[]ProbePingTarget `json:"ping_targets"`
		// per-server 覆盖:键为 serverID 字符串。键存在(值可为空数组)=该机单独指定,
		// 不存在=跟随全局。整个字段为 nil 时不改(旧前端 PUT 不带它)。
		PingTargetsOverride *map[string][]ProbePingTarget `json:"ping_targets_override"`
		PingInterval        *int                          `json:"ping_interval_ms"`
		ExternalAccessOnly  *bool                         `json:"external_access_only"`
		ExternalAccessToken *string                       `json:"external_access_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}

	ctx := r.Context()
	boolStr := func(b bool) string {
		if b {
			return "1"
		}
		return ""
	}
	fail := func() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
	}
	if req.ServerIDs == nil {
		req.ServerIDs = []int64{}
	}
	// enabled 保留给旧前端；新前端分别提交两个开关，总开关保存为二者的并集，供共享
	// payload/采集任务判断是否仍有任一探针需要数据。
	if req.InternalEnabled != nil || req.ExternalEnabled != nil {
		oldInternal, _ := h.repo.GetSystemSetting(ctx, probeInternalEnabledKey)
		oldExternal, _ := h.repo.GetSystemSetting(ctx, probeExternalEnabledKey)
		internalOn, externalOn := oldInternal == "1", oldExternal == "1"
		if oldInternal == "" && oldExternal == "" {
			oldEnabled, _ := h.repo.GetSystemSetting(ctx, probeDisguiseEnabledKey)
			internalOn, externalOn = oldEnabled == "1", oldEnabled == "1"
		}
		if req.InternalEnabled != nil {
			internalOn = *req.InternalEnabled
		}
		if req.ExternalEnabled != nil {
			externalOn = *req.ExternalEnabled
		}
		req.Enabled = internalOn || externalOn
		if h.repo.SetSystemSetting(ctx, probeInternalEnabledKey, boolStr(internalOn)) != nil ||
			h.repo.SetSystemSetting(ctx, probeExternalEnabledKey, boolStr(externalOn)) != nil {
			fail()
			return
		}
	}
	idsJSON, _ := json.Marshal(req.ServerIDs)
	// 密钥明文只用于本次计算 SHA-256，不写数据库、不返回给后续 GET。
	newExternalToken := ""
	if req.ExternalAccessToken != nil {
		newExternalToken = strings.TrimSpace(*req.ExternalAccessToken)
		if newExternalToken != "" && len(newExternalToken) < 32 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "独立探针密钥至少需要 32 个字符"})
			return
		}
	}
	// 现有 4 字段:值语义,每次写(兼容旧前端整对象 PUT)。
	for _, kv := range []struct{ k, v string }{
		{probeDisguiseEnabledKey, boolStr(req.Enabled)},
		{probeDisguiseTitleKey, req.Title},
		{probeDisguiseShowNameKey, boolStr(req.ShowName)},
		{probeDisguiseServerIDsKey, string(idsJSON)},
	} {
		if err := h.repo.SetSystemSetting(ctx, kv.k, kv.v); err != nil {
			fail()
			return
		}
	}

	if req.Logo != nil {
		logo := strings.TrimSpace(*req.Logo)
		if len(logo) > probeLogoMaxBytes {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"success": false,
				"message": fmt.Sprintf("logo 过大(上限 %d KB),请压缩图片或改用图片 URL", probeLogoMaxBytes/1024),
			})
			return
		}
		// 只放行 http(s)、data:image 和站内相对路径。挡掉 javascript: 这类会在公开页
		// 变成 XSS 的 scheme —— 这个值最终原样进伪装页的 <img src>。
		if logo != "" && !strings.HasPrefix(logo, "/") &&
			!strings.HasPrefix(logo, "http://") && !strings.HasPrefix(logo, "https://") &&
			!strings.HasPrefix(logo, "data:image/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"success": false,
				"message": "logo 只支持 http(s) 链接、data:image 或站内相对路径",
			})
			return
		}
		if h.repo.SetSystemSetting(ctx, probeDisguiseLogoKey, logo) != nil {
			fail()
			return
		}
	}
	if req.Theme != nil {
		theme := strings.TrimSpace(*req.Theme)
		if theme == "" {
			theme = "follow"
		}
		if !validProbeThemeName(theme) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "主题名称只能包含字母、数字、下划线和连字符，且长度不能超过 64"})
			return
		}
		if h.repo.SetSystemSetting(ctx, probeDisguiseThemeKey, theme) != nil {
			fail()
			return
		}
	}

	if req.BlockLogin != nil {
		v := ""
		if *req.BlockLogin {
			v = "1"
		}
		if h.repo.SetSystemSetting(ctx, probeDisguiseBlockLoginKey, v) != nil {
			fail()
			return
		}
	}
	if newExternalToken != "" {
		hash := sha256.Sum256([]byte(newExternalToken))
		if h.repo.SetSystemSetting(ctx, probeExternalTokenHashKey, hex.EncodeToString(hash[:])) != nil {
			fail()
			return
		}
	}
	if req.ExternalAccessOnly != nil {
		if h.repo.SetSystemSetting(ctx, probeExternalOnlyKey, boolStr(*req.ExternalAccessOnly)) != nil {
			fail()
			return
		}
	}

	// 新字段:指针语义,仅非 nil 才写。
	setBoolPtr := func(key string, p *bool) bool {
		if p == nil {
			return true
		}
		return h.repo.SetSystemSetting(ctx, key, boolStr(*p)) == nil
	}
	if !setBoolPtr(probeDisguiseMetricCPUKey, req.MetricCPU) ||
		!setBoolPtr(probeDisguiseMetricMemKey, req.MetricMem) ||
		!setBoolPtr(probeDisguiseMetricDiskKey, req.MetricDisk) ||
		!setBoolPtr(probeDisguiseMetricPingKey, req.MetricPing) ||
		!setBoolPtr(probeDisguiseShowExpiryKey, req.ShowExpiry) ||
		!setBoolPtr(probeDisguiseShowPriceKey, req.ShowPrice) ||
		!setBoolPtr(probeDisguiseShowGlobeKey, req.ShowGlobe) ||
		!setBoolPtr(probeDisguiseShowReturnRouteKey, req.ShowReturnRoute) ||
		!setBoolPtr(probeDisguiseShowExternalLicenseKey, req.ShowExternalLicense) {
		fail()
		return
	}
	// 流量/网速是展示开关且默认开:必须存显式 "1"/"0"(不能用 setBoolPtr 的 "1"/"",
	// 否则关闭时存 "" 会被 GET 的 `!= "0"` 当成"未设置=显示",关不掉)。
	setDisplayPtr := func(key string, p *bool) bool {
		if p == nil {
			return true
		}
		v := "0"
		if *p {
			v = "1"
		}
		return h.repo.SetSystemSetting(ctx, key, v) == nil
	}
	if !setDisplayPtr(probeDisguiseMetricTrafficKey, req.MetricTraffic) ||
		!setDisplayPtr(probeDisguiseMetricSpeedKey, req.MetricSpeed) ||
		!setDisplayPtr(probeDisguiseShowDailyTrendKey, req.ShowDailyTrend) ||
		!setDisplayPtr(probeDisguiseShowTrafficHotspotsKey, req.ShowTrafficHotspots) ||
		!setDisplayPtr(probeDisguiseShowTraffic7DKey, req.ShowTraffic7D) ||
		!setDisplayPtr(probeDisguiseShowResourceHeatmapKey, req.ShowResourceHeatmap) ||
		!setDisplayPtr(probeDisguiseShowTrafficQuotaKey, req.ShowTrafficQuota) ||
		!setDisplayPtr(probeDisguiseShowRenewalTimelineKey, req.ShowRenewalTimeline) {
		fail()
		return
	}
	if req.PingTargets != nil {
		// 目标数上限,防 agent 拨测滥用(与 agent 侧限流呼应)。
		targets := *req.PingTargets
		if len(targets) > probePingMaxTargets {
			targets = targets[:probePingMaxTargets]
		}
		if err := validatePingTargetList(targets); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "message": err.Error()})
			return
		}
		tJSON, _ := json.Marshal(targets)
		if h.repo.SetSystemSetting(ctx, probeDisguisePingTargetsKey, string(tJSON)) != nil {
			fail()
			return
		}
	}
	if req.PingTargetsOverride != nil {
		// 只保留仍在展示列表里的服务器,顺带清掉已删服务器的残留(KV 没有 FK 级联)。
		keep := make(map[int64]bool, len(req.ServerIDs))
		for _, id := range req.ServerIDs {
			keep[id] = true
		}
		cleaned := make(map[string][]ProbePingTarget, len(*req.PingTargetsOverride))
		for k, targets := range *req.PingTargetsOverride {
			id, err := strconv.ParseInt(k, 10, 64)
			if err != nil || !keep[id] {
				continue
			}
			// 与全局同样的上限,防止绕过 SetProbeDisguise 的全局校验给单机塞几百个目标。
			if len(targets) > probePingMaxTargets {
				targets = targets[:probePingMaxTargets]
			}
			if targets == nil {
				targets = []ProbePingTarget{}
			}
			if err := validatePingTargetList(targets); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{"success": false, "message": err.Error()})
				return
			}
			cleaned[k] = targets
		}
		oJSON, _ := json.Marshal(cleaned)
		if h.repo.SetSystemSetting(ctx, probeDisguisePingTargetsOverrideKey, string(oJSON)) != nil {
			fail()
			return
		}
	}
	if req.PingInterval != nil {
		ms := *req.PingInterval
		if ms < 2000 {
			ms = 2000
		}
		// 上限放宽到 5 分钟:配合 1 天保留窗口,支持 60 秒等更低频探测(默认 60 秒)。
		if ms > 300000 {
			ms = 300000
		}
		if h.repo.SetSystemSetting(ctx, probeDisguisePingIntervalKey, strconv.Itoa(ms)) != nil {
			fail()
			return
		}
	}

	// 配置变更后把最新采集开关 + ping 目标下发给所有已连 agent。
	if h.wsHandler != nil {
		h.wsHandler.PushProbeConfigToAll(ctx)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "伪装探针配置已更新"})
}

// probePingMaxTargets ping 目标数上限,防止管理员配置把 agent 网络打满。
const probePingMaxTargets = 30

// probeLogoMaxBytes 是伪装页 logo 的大小上限。URL 远达不到;
// 这个限制是给 data: URI 的 —— 公开端点 5 秒一轮询,大图会变成持续的带宽浪费。
const probeLogoMaxBytes = 128 * 1024

// defaultRedeemTemplate 兑换码复制文案的默认模板。占位符:
//
//	{兑换码}     — 具体兑换码
//	{机器人地址} — TG 机器人链接(由 tgbot miniapp 端按 getMe 自动注入,如 https://t.me/xxx_bot)
//	{主控域名}   — master_url 完整 URL
const defaultRedeemTemplate = `使用教程
打开这个机器人 {机器人地址}
点左下角我的面板，然后输入兑换码注册
{兑换码}

如果需要自定义出站落地，需要登录妙妙屋X
{主控域名}`

// GetRedeemTemplate 返回兑换码复制文案模板;未配置时返回内置默认模板。
func (h *SystemSettingsHandler) GetRedeemTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	value, err := h.repo.GetSystemSetting(r.Context(), "redeem_copy_template")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取兑换码文案失败"})
		return
	}
	if value == "" {
		value = defaultRedeemTemplate
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "redeem_template": value})
}

// SetRedeemTemplate 保存兑换码复制文案模板(多行文本)。
func (h *SystemSettingsHandler) SetRedeemTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RedeemTemplate string `json:"redeem_template"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	if err := h.repo.SetSystemSetting(r.Context(), "redeem_copy_template", req.RedeemTemplate); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "兑换码文案已更新"})
}

func (h *SystemSettingsHandler) GetShortLinkEnabled(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "enable_short_link": cfg.EnableShortLink})
}

func (h *SystemSettingsHandler) SetShortLinkEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnableShortLink bool `json:"enable_short_link"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.EnableShortLink = req.EnableShortLink
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "短链接设置已更新"})
}

// dashboardRefreshKey 是前端 dashboard 轮询间隔的 system_settings key,毫秒。
// 跟 traffic_collect_interval(master collector 内部 polling)解耦:
// agent 5s push 决定数据新鲜度,collector 60s 只是兜底;前端轮询频率是 UX 选项,默认 5000ms。
const dashboardRefreshKey = "dashboard_refresh_interval_ms"
const dashboardRefreshDefault = 5000

// GetPublicIntervals 给所有登录用户(包括普通用户),返回前端 dashboard 应用的轮询间隔(ms)。
func (h *SystemSettingsHandler) GetPublicIntervals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	val, _ := h.repo.GetSystemSetting(r.Context(), dashboardRefreshKey)
	ms := dashboardRefreshDefault
	if val != "" {
		if n, err := strconv.Atoi(val); err == nil && n >= 1000 && n <= 60000 {
			ms = n
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":             true,
		"refetch_interval_ms": ms,
	})
}

// SetDashboardRefresh admin-only,设置前端 dashboard 轮询间隔(ms)。生效:下次前端拉到该值。
// clamp 到 [1000, 60000] 范围,默认 5000。
func (h *SystemSettingsHandler) SetDashboardRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RefetchIntervalMs int `json:"refetch_interval_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	if req.RefetchIntervalMs < 1000 {
		req.RefetchIntervalMs = 1000
	}
	if req.RefetchIntervalMs > 60000 {
		req.RefetchIntervalMs = 60000
	}
	if err := h.repo.SetSystemSetting(r.Context(), dashboardRefreshKey, strconv.Itoa(req.RefetchIntervalMs)); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	// 同步给所有 agent (用于 traffic 上报 ticker):WS-mode 立即推 config_update,
	// HTTP-mode 通过下次 traffic POST 的 response 携带 (见 RemoteTrafficHandler),
	// Pull-mode 因 master 是 GET agent,无现成回带通道,需要 agent 端轮询/重启生效。
	if h.wsHandler != nil {
		h.wsHandler.BroadcastConfigUpdate(map[string]string{
			"traffic_report_interval_ms": strconv.Itoa(req.RefetchIntervalMs),
		})
	}
	// 主控本机自采也跟随同一个「上报间隔」,与 agent 保持一致(热重载,无需重启)。
	if h.collector != nil {
		h.collector.SetInterval(time.Duration(req.RefetchIntervalMs) * time.Millisecond)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "refetch_interval_ms": req.RefetchIntervalMs})
}

func (h *SystemSettingsHandler) GetIntervals(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	// report_interval(秒):即 dashboard_refresh_interval_ms / 1000,这是会同步给所有 agent
	// 的「上报间隔」,主控本机自采也跟随它(见 SetIntervals / SetDashboardRefresh)。
	reportSec := dashboardRefreshDefault / 1000
	if val, _ := h.repo.GetSystemSetting(r.Context(), dashboardRefreshKey); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n >= 1000 && n <= 60000 {
			reportSec = n / 1000
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":                  true,
		"speed_collect_interval":   cfg.SpeedCollectInterval,
		"traffic_collect_interval": cfg.TrafficCollectInterval,
		"traffic_check_interval":   cfg.TrafficCheckInterval,
		"heartbeat_interval":       cfg.HeartbeatInterval,
		"report_interval":          reportSec,
	})
}

func (h *SystemSettingsHandler) SetIntervals(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SpeedCollectInterval   int `json:"speed_collect_interval"`
		TrafficCollectInterval int `json:"traffic_collect_interval"`
		TrafficCheckInterval   int `json:"traffic_check_interval"`
		HeartbeatInterval      int `json:"heartbeat_interval"`
		ReportInterval         int `json:"report_interval"` // 秒,会同步给所有 agent 的「上报间隔」;主控自采也跟随它
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	if req.SpeedCollectInterval < 1 {
		req.SpeedCollectInterval = 3
	}
	if req.TrafficCollectInterval < 10 {
		req.TrafficCollectInterval = 60
	}
	if req.TrafficCheckInterval < 10 {
		req.TrafficCheckInterval = 120
	}
	if req.HeartbeatInterval < 5 {
		req.HeartbeatInterval = 30
	}
	// 上报间隔(秒)→ dashboard_refresh_interval_ms,clamp 到 [1,60]s。
	if req.ReportInterval < 1 {
		req.ReportInterval = dashboardRefreshDefault / 1000
	} else if req.ReportInterval > 60 {
		req.ReportInterval = 60
	}

	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.SpeedCollectInterval = req.SpeedCollectInterval
	cfg.TrafficCollectInterval = req.TrafficCollectInterval
	cfg.TrafficCheckInterval = req.TrafficCheckInterval
	cfg.HeartbeatInterval = req.HeartbeatInterval
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	// 「上报间隔」落库为 dashboard_refresh_interval_ms,并同步给所有 agent。
	reportMs := req.ReportInterval * 1000
	if err := h.repo.SetSystemSetting(r.Context(), dashboardRefreshKey, strconv.Itoa(reportMs)); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	if h.wsHandler != nil {
		h.wsHandler.BroadcastConfigUpdate(map[string]string{
			"traffic_report_interval_ms": strconv.Itoa(reportMs),
		})
	}
	// 热重载 master 端 collector ticker,无需重启服务。speed 用 speed_collect_interval,
	// traffic 采集跟随「上报间隔」(与 agent 一致)。
	// (traffic_check_interval / heartbeat_interval 需要其他子系统也支持热重载,目前仅落库。)
	hotReloaded := false
	if h.collector != nil {
		h.collector.SetInterval(time.Duration(reportMs) * time.Millisecond)
		h.collector.SetSpeedInterval(time.Duration(req.SpeedCollectInterval) * time.Second)
		hotReloaded = true
	}
	msg := "定时配置已更新"
	if hotReloaded {
		msg += "(traffic/speed 采集 ticker 已热重载,立即生效)"
	} else {
		msg += "(重启服务后生效)"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": msg,
	})
}

func (h *SystemSettingsHandler) GetAgentLogEnabled(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "agent_log_enabled": cfg.AgentLogEnabled})
}

func (h *SystemSettingsHandler) SetAgentLogEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentLogEnabled bool `json:"agent_log_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.AgentLogEnabled = req.AgentLogEnabled
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	agentlog.SetEnabled(req.AgentLogEnabled)
	// 同步下发给所有在线 agent —— agent 侧的流量上报等高频日志也受此开关控制(默认关闭)
	if h.wsHandler != nil {
		val := "0"
		if req.AgentLogEnabled {
			val = "1"
		}
		h.wsHandler.BroadcastConfigUpdate(map[string]string{"agent_log_enabled": val})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "Agent日志设置已更新"})
}

func (h *SystemSettingsHandler) GetOverrideScriptsEnabled(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "enable_override_scripts": cfg.EnableOverrideScripts})
}

func (h *SystemSettingsHandler) SetOverrideScriptsEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnableOverrideScripts bool `json:"enable_override_scripts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.EnableOverrideScripts = req.EnableOverrideScripts
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "覆写脚本设置已更新"})
}

// GetSubscriptionOutputFormat / SetSubscriptionOutputFormat — Clash 订阅序列化格式 yaml/json 切换
func (h *SystemSettingsHandler) GetSubscriptionOutputFormat(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	format := cfg.SubscriptionOutputFormat
	if format == "" {
		format = "yaml"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "subscription_output_format": format})
}

func (h *SystemSettingsHandler) SetSubscriptionOutputFormat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubscriptionOutputFormat string `json:"subscription_output_format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	// 二值校验:仅接受 'yaml' 或 'json',其余拒绝(避免误存 db / 后端误判 → 静默回落 yaml 的暗坑)
	if req.SubscriptionOutputFormat != "yaml" && req.SubscriptionOutputFormat != "json" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "格式必须为 yaml 或 json"})
		return
	}
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.SubscriptionOutputFormat = req.SubscriptionOutputFormat
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "订阅序列化格式已更新"})
}

// DefaultThemeKey 是「默认主题」系统设置的 KV 键。支持 flat / pixel / anime / premium。
// 无 mmw-theme-style cookie 的用户首屏用它决定初始主题(由 web.SetDefaultTheme 注入 index.html)。
const DefaultThemeKey = "default_theme"

func (h *SystemSettingsHandler) GetDefaultTheme(w http.ResponseWriter, r *http.Request) {
	value, _ := h.repo.GetSystemSetting(r.Context(), DefaultThemeKey)
	if value != "flat" && value != "pixel" && value != "anime" && value != "premium" {
		value = "pixel"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "default_theme": value})
}

func (h *SystemSettingsHandler) SetDefaultTheme(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DefaultTheme string `json:"default_theme"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	if req.DefaultTheme != "flat" && req.DefaultTheme != "pixel" && req.DefaultTheme != "anime" && req.DefaultTheme != "premium" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "主题必须为 flat / pixel / anime / premium"})
		return
	}
	if err := h.repo.SetSystemSetting(r.Context(), DefaultThemeKey, req.DefaultTheme); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "默认主题已更新"})
}

// UpdateCDNEnabledKey 是「更新走 CDN 加速」开关的 KV 键。值 "1"(默认开启)/ "0"(关闭走 GitHub)。
// CDN 域名写死在代码(见 update_cdn.go),此开关只控制启用与否。
const UpdateCDNEnabledKey = "update_cdn_enabled"

func (h *SystemSettingsHandler) GetUpdateCDNStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"enabled":  UpdateCDNEnabled(),
		"cdn_base": updateCDNBaseURL,
	})
}

func (h *SystemSettingsHandler) SetUpdateCDNStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	val := "0"
	if req.Enabled {
		val = "1"
	}
	if err := h.repo.SetSystemSetting(r.Context(), UpdateCDNEnabledKey, val); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	SetUpdateCDNEnabled(req.Enabled) // 同步包级开关,立即生效(下次检查更新即走新设置)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "已更新"})
}

// LoginWallpaperKey 是「自定义登录页壁纸」的 KV 键(存图片 URL,可为空)。
const LoginWallpaperKey = "login_wallpaper"

func (h *SystemSettingsHandler) GetLoginWallpaper(w http.ResponseWriter, r *http.Request) {
	value, _ := h.repo.GetSystemSetting(r.Context(), LoginWallpaperKey)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "login_wallpaper": value})
}

func (h *SystemSettingsHandler) SetLoginWallpaper(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LoginWallpaper string `json:"login_wallpaper"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	v := strings.TrimSpace(req.LoginWallpaper)
	if len(v) > 2000 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "URL 过长"})
		return
	}
	if err := h.repo.SetSystemSetting(r.Context(), LoginWallpaperKey, v); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "登录页壁纸已更新"})
}

// GetLoginWallpaperPublic 公开读取(登录页未鉴权时用)。
func (h *SystemSettingsHandler) GetLoginWallpaperPublic(w http.ResponseWriter, r *http.Request) {
	value, _ := h.repo.GetSystemSetting(r.Context(), LoginWallpaperKey)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"login_wallpaper": value})
}

func (h *SystemSettingsHandler) GetSilentMode(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":             true,
		"silent_mode":         cfg.SilentMode,
		"silent_mode_timeout": cfg.SilentModeTimeout,
	})
}

func (h *SystemSettingsHandler) SetSilentMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SilentMode        bool `json:"silent_mode"`
		SilentModeTimeout int  `json:"silent_mode_timeout"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	if req.SilentModeTimeout <= 0 {
		req.SilentModeTimeout = 15
	}
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.SilentMode = req.SilentMode
	cfg.SilentModeTimeout = req.SilentModeTimeout
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "静默模式设置已更新"})
}

func (h *SystemSettingsHandler) GetRequireEncryption(w http.ResponseWriter, r *http.Request) {
	value, _ := h.repo.GetSystemSetting(r.Context(), "require_encryption")
	enabled := value == "true"
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "require_encryption": enabled})
}

func (h *SystemSettingsHandler) SetRequireEncryption(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RequireEncryption bool `json:"require_encryption"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}

	value := "false"
	if req.RequireEncryption {
		value = "true"
	}
	if err := h.repo.SetSystemSetting(r.Context(), "require_encryption", value); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}

	if h.crypto != nil {
		h.crypto.SetRequireEncryption(req.RequireEncryption)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "加密设置已更新"})
}

func (h *SystemSettingsHandler) GetMiaomiaowuFeaturesEnabled(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "enable_miaomiaowu_features": cfg.EnableMiaomiaowuFeatures})
}

func (h *SystemSettingsHandler) SetMiaomiaowuFeaturesEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnableMiaomiaowuFeatures bool `json:"enable_miaomiaowu_features"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.EnableMiaomiaowuFeatures = req.EnableMiaomiaowuFeatures
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "妙妙屋功能设置已更新"})
}

func (h *SystemSettingsHandler) GetDefaultTemplate(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":                         true,
		"default_template_filename":       cfg.DefaultTemplateFilename,
		"default_surge_template_filename": cfg.DefaultSurgeTemplateFilename,
	})
}

func (h *SystemSettingsHandler) SetDefaultTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DefaultTemplateFilename      *string `json:"default_template_filename"`
		DefaultSurgeTemplateFilename *string `json:"default_surge_template_filename"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}

	// 指针语义:nil=本次不改该字段(clash/surge 可分别独立保存)。空串=清除默认模板。
	checkExists := func(name string) bool {
		if name == "" {
			return true
		}
		_, err := os.Stat(filepath.Join("rule_templates", name))
		return !os.IsNotExist(err)
	}
	if req.DefaultTemplateFilename != nil && !checkExists(*req.DefaultTemplateFilename) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "模板文件不存在"})
		return
	}
	if req.DefaultSurgeTemplateFilename != nil && !checkExists(*req.DefaultSurgeTemplateFilename) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "Surge 模板文件不存在"})
		return
	}

	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	if req.DefaultTemplateFilename != nil {
		cfg.DefaultTemplateFilename = *req.DefaultTemplateFilename
	}
	if req.DefaultSurgeTemplateFilename != nil {
		cfg.DefaultSurgeTemplateFilename = *req.DefaultSurgeTemplateFilename
	}
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "默认模板已更新"})
}

// 节点名称倍率前缀:开关 + 左右分隔符。
// 开启后订阅生成时,套餐内 multiplier != 1 的节点 name 前面会拼上 "{left}{mult}{right}"。
func (h *SystemSettingsHandler) GetNodeNameMultiplierPrefix(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"enabled": cfg.NodeNameMultiplierPrefixEnabled,
		"left":    cfg.NodeNameMultiplierLeft,
		"right":   cfg.NodeNameMultiplierRight,
	})
}

func (h *SystemSettingsHandler) SetNodeNameMultiplierPrefix(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool   `json:"enabled"`
		Left    string `json:"left"`
		Right   string `json:"right"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.NodeNameMultiplierPrefixEnabled = req.Enabled
	// 留 1 个字符的小白名单宽松:空字符串兜底回默认,避免 UI 提交空导致 "2原名" 无分隔
	if strings.TrimSpace(req.Left) == "" {
		cfg.NodeNameMultiplierLeft = "「"
	} else {
		cfg.NodeNameMultiplierLeft = req.Left
	}
	if strings.TrimSpace(req.Right) == "" {
		cfg.NodeNameMultiplierRight = "」"
	} else {
		cfg.NodeNameMultiplierRight = req.Right
	}
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "倍率前缀设置已更新"})
}
