package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	stdhttp "net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"miaomiaowux/internal/ddns"
	"miaomiaowux/internal/license"
	"miaomiaowux/internal/storage"
	"miaomiaowux/internal/traffic"
)

// randReader 是用于生成安全令牌的加密读取器
var randReader io.Reader = rand.Reader

// base64URLEncoding 用于 URL 安全的 base64 编码
var base64URLEncoding = base64.URLEncoding

type XrayServerHandler struct {
	repo           *storage.TrafficRepository
	collector      *traffic.Collector
	limiterPusher  *LimiterConfigPusher
	remoteManager  *RemoteManageHandler
	wsHandler      *RemoteWSHandler
	crypto         *CryptoConfig
	licenseManager *license.Manager
	ddnsManager    *ddns.Manager
}

func (h *XrayServerHandler) SetWSHandler(ws *RemoteWSHandler) {
	h.wsHandler = ws
}

func (h *XrayServerHandler) SetDDNSManager(m *ddns.Manager) {
	h.ddnsManager = m
}

func NewXrayServerHandler(repo *storage.TrafficRepository, collector *traffic.Collector, crypto *CryptoConfig) *XrayServerHandler {
	return &XrayServerHandler{
		repo:      repo,
		collector: collector,
		crypto:    crypto,
	}
}

func (h *XrayServerHandler) SetLimiterPusher(p *LimiterConfigPusher) {
	h.limiterPusher = p
}

func (h *XrayServerHandler) SetRemoteManager(rm *RemoteManageHandler) {
	h.remoteManager = rm
}

func (h *XrayServerHandler) SetLicenseManager(mgr *license.Manager) {
	h.licenseManager = mgr
}

// 远程服务器管理API

// RemoteServerCreateRequest代表创建远程服务器的请求
type RemoteServerCreateRequest struct {
	Name              string `json:"name"`
	TrafficLimit      int64  `json:"traffic_limit"`       // 流量限制（以字节为单位）
	TrafficUsedOffset int64  `json:"traffic_used_offset"` // 手动偏移校准
	TrafficResetDay   int    `json:"traffic_reset_day"`   // 要重置的月份日期 (1-31)
	IPAddress         string `json:"ip_address"`          // 子服务器 IP 地址
	ConnectionMode    string `json:"connection_mode"`     // push | pull | websocket
	ListenPort        int    `json:"listen_port"`         // Agent HTTP 监听端口(0 = 用默认 23889);通过 install 脚本注入 MMWX_LISTEN_PORT
	PullAddress       string `json:"pull_address"`        // 对于pull模式
	PullAddressV6     string `json:"pull_address_v6"`     // DDNS 专用:v6 单独域名(空则 AAAA 也写 pull_address)
	PullPort          int    `json:"pull_port"`           // 对于pull模式
	PullToken         string `json:"pull_token"`          // 对于pull模式
	StealSelf         bool   `json:"steal_self"`          // 代理安装后自动安装xray+nginx
	FrontService      string `json:"front_service"`       // xray | nginx 使用nginx还是xray做443前置（nginx 保留，尚未启用）
	Domain            string `json:"domain"`              // 服务器域（443模式）
	DomainV6          string `json:"domain_v6"`           // IPv6 专用域名(AAAA);v6 节点默认用它,空则回落 IPv6 字面地址
	Use443            bool   `json:"use_443"`             // 使用 443 端口与 nginx 隧道
	StealMode         string `json:"steal_mode"`          // "tunnel" | "fallback"，默认 tunnel
	SiteType          string `json:"site_type"`           // "static" | "proxy"
	SiteValue         string `json:"site_value"`          // 静态路径或反向代理地址
	XrayMode          string `json:"xray_mode"`           // "external" 或 "embedded"，默认 "external"
	TrafficStatsMode  string `json:"traffic_stats_mode"`  // "both"(默认) | "upload" | "download" — 节点流量统计方向
	TrafficSource     string `json:"traffic_source"`      // "xray"(默认,聚合 node_traffic) | "system"(用 agent 上报系统级网卡累计)
	IPv6Enabled       *bool  `json:"ipv6_enabled"`        // 指针:nil=默认启用;false=创建时即关闭 v6
	// DDNS 自动同步:开启时 PullAddress 必须是域名,agent 上报新 IP 时自动更新 A/AAAA 记录。
	// DDNSProviderID=0 → 自动模式(按 PullAddress 找匹配的通配符证书,取证书的 dns_provider_id);>0 → 显式指定
	DDNSEnabled    bool  `json:"ddns_enabled"`
	DDNSProviderID int64 `json:"ddns_provider_id"`
}

// RemoteServerResponse 表示带有远程服务器数据的响应
type RemoteServerResponse struct {
	Success        bool                  `json:"success"`
	Message        string                `json:"message"`
	Server         *storage.RemoteServer `json:"server,omitempty"`
	InstallCommand string                `json:"install_command,omitempty"`
	IsLocal        bool                  `json:"is_local,omitempty"`
}

// RemoteServerInboundInfo 表示远程服务器的入站信息
type RemoteServerInboundInfo struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
}

// RemoteServerExtended 表示具有附加流量和入站信息的远程服务器
type RemoteServerExtended struct {
	storage.RemoteServer
	TrafficUsed int64                     `json:"traffic_used"`
	Inbounds    []RemoteServerInboundInfo `json:"inbounds"`
	Encrypted   bool                      `json:"encrypted"`
	WsConnected bool                      `json:"ws_connected"`
}

// RemoteServersListResponse 表示所有远程服务器的响应
type RemoteServersListResponse struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
	Servers []RemoteServerExtended `json:"servers,omitempty"`
}

// RemoteServerDeleteRequest 表示删除远程服务器的请求
type RemoteServerDeleteRequest struct {
	ID int64 `json:"id"`
	// DeleteNodes 是否连带删除该服务器下的节点(original_server 匹配)。
	// 前端删除确认默认勾选(true);不传(nil)时保持旧行为=不删节点,兼容其它调用方。
	DeleteNodes *bool `json:"delete_nodes,omitempty"`
	// UninstallAgent 为 true 时，必须先让目标服务器调度 Agent 自卸载；受理失败则不删除服务器记录。
	UninstallAgent *bool `json:"uninstall_agent,omitempty"`
}

// RemoteServerUpdateRequest 表示更新远程服务器的请求
type RemoteServerUpdateRequest struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	Domain           string `json:"domain"`
	DomainV6         string `json:"domain_v6"`
	TrafficLimit     int64  `json:"traffic_limit"`
	TrafficResetDay  int    `json:"traffic_reset_day"`
	TrafficUsed      *int64 `json:"traffic_used"`
	ConnectionMode   string `json:"connection_mode"`
	ListenPort       int    `json:"listen_port"` // Agent HTTP 监听端口;变更时主控会通知 agent 改配置+重启
	PullAddress      string `json:"pull_address"`
	PullAddressV6    string `json:"pull_address_v6"` // DDNS 专用:v6 单独域名
	PullPort         int    `json:"pull_port"`
	PullToken        string `json:"pull_token"`
	XrayMode         string `json:"xray_mode"`
	TrafficStatsMode string `json:"traffic_stats_mode"` // both | upload | download
	TrafficSource    string `json:"traffic_source"`     // xray | system
	IPv6Enabled      *bool  `json:"ipv6_enabled"`       // 指针:nil=不改;false=关闭(服务管理不显示 v6、加节点不可选 v6)
	// 锁定入口 IP + 随机端口范围(节点 server 地址 / 端口分配)。指针:nil=不改。
	LockEntryIP  *bool `json:"lock_entry_ip"`
	PortRangeMin *int  `json:"port_range_min"`
	PortRangeMax *int  `json:"port_range_max"`
	// DDNS 同 Create
	DDNSEnabled    bool  `json:"ddns_enabled"`
	DDNSProviderID int64 `json:"ddns_provider_id"`
}

// 生成加密安全令牌
func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := randRead(b); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return base64Encode(b), nil
}

// randRead 是一个允许在测试中进行模拟的变量
var randRead = func(b []byte) (int, error) {
	return randReader.Read(b)
}

// base64Encode 将字节编码为 Base64 URL 安全字符串
var base64Encode = func(b []byte) string {
	return base64URLEncoding.EncodeToString(b)
}

// 返回所有远程服务器
func (h *XrayServerHandler) ListRemoteServers(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != "GET" {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}

	resp := h.BuildRemoteServersList(r.Context())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// BuildRemoteServersList 组装服务器列表响应(状态/网速/流量/入站),供 HTTP handler 与浏览器 WS 推送共用。
func (h *XrayServerHandler) BuildRemoteServersList(ctx context.Context) RemoteServersListResponse {
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return RemoteServersListResponse{
			Success: false,
			Message: fmt.Sprintf("获取服务器列表失败: %s", err.Error()),
		}
	}

	// 使用流量和入站信息构建扩展服务器列表
	extendedServers := make([]RemoteServerExtended, 0, len(servers))
	for _, server := range servers {
		extended := RemoteServerExtended{
			RemoteServer: server,
			Inbounds:     []RemoteServerInboundInfo{},
		}
		if server.IsFederated {
			// 分享服务器:消费方不直连 agent(无 WS 会话,server.Token 是占位),原加密探测恒 false 会误报"不安全"。
			// 实际消费方↔拥有方主控这一跳走 HTTPS + 令牌派生 ECDH,视为已加密。
			extended.Encrypted = true
		} else if h.wsHandler != nil {
			extended.Encrypted = h.wsHandler.IsConnectionEncrypted(server.Token)
			extended.WsConnected = h.wsHandler.IsConnected(server.Token)
		}

		trafficUsed, _ := h.repo.GetServerTrafficUsed(ctx, server.ID)
		extended.TrafficUsed = trafficUsed + server.TrafficUsedOffset

		nodeTraffic, err := h.repo.GetNodeTrafficByServer(ctx, server.ID)
		if err == nil {
			for _, nt := range nodeTraffic {
				if nt.Type == "inbound" && nt.Tag != "api" {
					extended.Inbounds = append(extended.Inbounds, RemoteServerInboundInfo{
						Tag:      nt.Tag,
						Protocol: "",
						Port:     0,
						Uplink:   nt.TotalUplink,
						Downlink: nt.TotalDownlink,
					})
				}
			}
		}

		// 列表不再明文回传令牌(Encrypted/WsConnected 已在上面用原始 server.Token 算好)。
		// 前端需要时走 reveal-token 按单台显式获取。
		maskServerSecrets(&extended.RemoteServer)
		extendedServers = append(extendedServers, extended)
	}

	return RemoteServersListResponse{
		Success: true,
		Servers: extendedServers,
	}
}

// maskServerSecrets 清空响应里的令牌字段。列表/详情接口不再明文回传 token,
// 需要时由前端走 /api/admin/remote-servers/reveal-token 按单台显式获取(T2#6 token 脱敏)。
func maskServerSecrets(s *storage.RemoteServer) {
	if s == nil {
		return
	}
	s.Token = ""
	s.PullToken = ""
	s.AgentToken = ""
}

// RevealServerToken 按需返回单台服务器的令牌(管理员鉴权)。前端仅在用户点击
// "复制安装命令 / 复制 Token" 时调用,避免 token 随列表轮询批量外泄到浏览器历史/日志/屏幕。
func (h *XrayServerHandler) RevealServerToken(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != "GET" {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "invalid server_id"})
		return
	}
	server, err := h.repo.GetRemoteServer(r.Context(), id)
	if err != nil || server == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "server not found"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":     true,
		"token":       server.Token,
		"pull_token":  server.PullToken,
		"agent_token": server.AgentToken,
	})
}

// 使用生成的令牌创建一个新的远程服务器
// validateSiteValue 校验偷自己/fallback 站点的反代地址。site_type=proxy 时,site_value 必须是
// 合法的反代目标(host:port 或带 scheme 的 URL);host 形如"纯数字+点"却不是合法 IPv4 时判为 typo
// (如 127.0.01 少一个 0)。static(本地静态路径)与空值跳过校验。
func validateSiteValue(siteType, siteValue string) error {
	v := strings.TrimSpace(siteValue)
	if v == "" || siteType != "proxy" {
		return nil
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		if u, err = url.Parse("http://" + v); err != nil || u.Host == "" {
			return fmt.Errorf("反代地址格式无效: %s", v)
		}
	}
	host := u.Hostname()
	if isDottedNumeric(host) && net.ParseIP(host) == nil {
		return fmt.Errorf("反代地址 IP 无效: %s(如 127.0.01 应为 127.0.0.1)", host)
	}
	return nil
}

// isDottedNumeric 判断 s 是否仅由数字和点组成,用于识别"看起来是 IPv4 但写错"的 host。
func isDottedNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func (h *XrayServerHandler) CreateRemoteServer(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != "POST" {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}

	if h.licenseManager != nil {
		status := h.licenseManager.GetStatus()
		maxServers := 5
		if status.Plan != nil {
			maxServers = status.Plan.MaxServers
		}
		count, err := h.repo.CountRemoteServers(r.Context())
		if err == nil && count >= int64(maxServers) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusForbidden)
			json.NewEncoder(w).Encode(RemoteServerResponse{
				Success: false,
				Message: fmt.Sprintf("已达到服务器数量上限 (%d/%d)，请升级许可证", count, maxServers),
			})
			return
		}
	}

	var req RemoteServerCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "无效的请求参数",
		})
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "服务器名称不能为空",
		})
		return
	}

	if err := validateSiteValue(req.SiteType, req.SiteValue); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	ctx := r.Context()
	reqDomain := strings.ToLower(strings.TrimSpace(req.Domain))
	mmwxDomain := getDomainFromMasterURL(h.repo, ctx)

	isLocalByAddr := false
	mmwxIPs := resolveIPs(mmwxDomain)
	mmwxIPSet := make(map[string]struct{})
	for _, ip := range mmwxIPs {
		mmwxIPSet[ip] = struct{}{}
	}
	checkAddrLocal := func(addr string) bool {
		if normalizeAddressHost(addr) == normalizeAddressHost(mmwxDomain) && normalizeAddressHost(mmwxDomain) != "" {
			return true
		}
		for _, ip := range resolveIPs(addr) {
			if _, ok := mmwxIPSet[ip]; ok {
				return true
			}
		}
		return false
	}
	if mmwxDomain != "" {
		if req.IPAddress != "" {
			isLocalByAddr = checkAddrLocal(req.IPAddress)
		}
		if !isLocalByAddr && req.PullAddress != "" {
			isLocalByAddr = checkAddrLocal(req.PullAddress)
		}
	}

	if reqDomain != "" && mmwxDomain != "" && reqDomain == mmwxDomain && !isLocalByAddr {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "域名不能与 MMWX 安装域名相同",
		})
		return
	}

	// 生成安全令牌
	token, err := generateSecureToken()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: fmt.Sprintf("生成Token失败: %s", err.Error()),
		})
		return
	}

	// 生成用于拉取/API 身份验证的代理令牌
	agentToken := req.PullToken
	if agentToken == "" {
		agentToken, err = generateSecureToken()
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(RemoteServerResponse{
				Success: false,
				Message: fmt.Sprintf("生成Agent Token失败: %s", err.Error()),
			})
			return
		}
	}

	// 如果没有指定则设置默认连接模式
	connectionMode := req.ConnectionMode
	if connectionMode == "" {
		connectionMode = storage.ConnectionModePush
	}

	// steal_mode 三种值:tunnel / fallback / default。
	// 历史 BUG:这里曾"非 fallback 就强制 tunnel",导致没勾偷自己的服务器实际也存 tunnel,
	// 用户在编辑 dialog 看到默认选中 tunnel,语义混淆。
	// 现在:
	//   - 显式 fallback / tunnel / default → 原样保留
	//   - 其它值(包括空)→ 偷自己时默认 tunnel,否则默认 default
	stealMode := req.StealMode
	switch stealMode {
	case "tunnel", "fallback", "default":
		// ok
	default:
		if req.StealSelf {
			stealMode = "tunnel"
		} else {
			stealMode = "default"
		}
	}

	xrayMode := req.XrayMode
	if xrayMode != "embedded" {
		xrayMode = "external"
	}
	// 内联(embedded)Xray 本身不再要求许可证 — 无 license 也可创建并运行。
	// 限速 / 限制连接数等仍是 PRO(见 remote_ws.go 的限速推送 gate),但不影响 embedded 节点的创建与基本运行。

	// Agent 监听端口:有效范围 1024-65535;0 表示用 agent 内置默认 23889
	listenPort := req.ListenPort
	if listenPort < 0 || listenPort > 65535 {
		listenPort = 0
	}

	resetDay := req.TrafficResetDay
	if resetDay < 0 || resetDay > 31 {
		resetDay = 0
	}
	trafficUsedOffset := req.TrafficUsedOffset
	if trafficUsedOffset < 0 {
		trafficUsedOffset = 0
	}
	trafficLimit := req.TrafficLimit
	if trafficLimit < 0 {
		trafficLimit = 0
	}
	trafficStatsMode := strings.TrimSpace(req.TrafficStatsMode)
	if trafficStatsMode != "upload" && trafficStatsMode != "download" && trafficStatsMode != "max" {
		trafficStatsMode = "both"
	}
	// 新建 server 默认 system — VPS 计费口径,跟 UI 默认保持一致。
	// 前端 dialog 默认勾选「系统网卡流量」;API 直调时 req 没传 traffic_source 也走 system。
	// 仅 req 显式传 "xray" 才走 xray 路径(中转机 / 需要协议级口径的特殊场景)。
	trafficSource := strings.TrimSpace(req.TrafficSource)
	if trafficSource != "xray" {
		trafficSource = "system"
	}

	// DDNS 开启时必须用域名 — agent 上报 IP 漂移后,DDNS 把这个域名的 A/AAAA 指到新 IP
	if req.DDNSEnabled {
		pa := strings.TrimSpace(req.PullAddress)
		if pa == "" || net.ParseIP(pa) != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusBadRequest)
			json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "DDNS 开启时,服务器地址必须填域名"})
			return
		}
		// 显式 provider_id 必须存在
		if req.DDNSProviderID > 0 {
			if _, perr := h.repo.GetDNSProvider(ctx, req.DDNSProviderID); perr != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(stdhttp.StatusBadRequest)
				json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: fmt.Sprintf("DDNS 服务商不存在: %v", perr)})
				return
			}
		}
		// provider_id=0 自动模式:按证书 + DNS 服务商识别。没匹配证书时不硬拦——同步会遍历 DNS 服务商兜底,
		// 只要至少配了一个 DNS 服务商就放行。
		if req.DDNSProviderID == 0 {
			if _, cerr := h.repo.FindCertificateForDomain(ctx, pa); cerr != nil {
				providers, _ := h.repo.ListDNSProviders(ctx)
				if len(providers) == 0 {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(stdhttp.StatusBadRequest)
					json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "DDNS 自动模式:没有匹配证书,也没有配置任何 DNS 服务商,请先添加 DNS 服务商或签发证书"})
					return
				}
			}
		}
	}

	server := &storage.RemoteServer{
		Name:              req.Name,
		Token:             token,
		Status:            storage.RemoteServerStatusPending,
		IPAddress:         req.IPAddress,
		ConnectionMode:    connectionMode,
		ListenPort:        listenPort,
		PullAddress:       req.PullAddress,
		PullAddressV6:     req.PullAddressV6,
		PullPort:          req.PullPort,
		PullToken:         agentToken,
		Domain:            strings.TrimSpace(req.Domain),
		DomainV6:          strings.TrimSpace(req.DomainV6),
		Use443:            req.Use443,
		StealMode:         stealMode,
		SiteType:          req.SiteType,
		SiteValue:         req.SiteValue,
		XrayMode:          xrayMode,
		TrafficLimit:      trafficLimit,
		TrafficUsedOffset: trafficUsedOffset,
		TrafficResetDay:   resetDay,
		TrafficStatsMode:  trafficStatsMode,
		TrafficSource:     trafficSource,
		IPv6Enabled:       req.IPv6Enabled == nil || *req.IPv6Enabled, // 默认启用;仅显式 false 才关闭
		DDNSEnabled:       req.DDNSEnabled,
		DDNSProviderID:    req.DDNSProviderID,
	}

	if err := h.repo.CreateRemoteServer(ctx, server); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: fmt.Sprintf("创建服务器失败: %s", err.Error()),
		})
		return
	}
	// 需求1:添加后立即触发一次 DDNS(若此刻还没上报 IP 则是空跑,agent 连上后会再触发)。
	if h.ddnsManager != nil && server.DDNSEnabled {
		go h.ddnsManager.Trigger(context.Background(), server)
	}

	// 构建安装命令 — 优先用系统设置里的 master_url(用户配置的对外域名),
	// 这是 agent 实际访问主控的地址,r.Host 可能是 nginx upstream 名(如 miaomiaowu_web),
	// 不可对外访问。仅在 master_url 未配置时回退到请求 Host。
	serverURL := ""
	if masterURL, err := h.repo.GetSystemSetting(ctx, "master_url"); err == nil {
		if mu := strings.TrimRight(strings.TrimSpace(masterURL), "/"); mu != "" {
			serverURL = mu
		}
	}
	if serverURL == "" {
		host := r.Host
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if forwardedProto := r.Header.Get("X-Forwarded-Proto"); forwardedProto != "" {
			scheme = forwardedProto
		}
		if host != "" {
			serverURL = fmt.Sprintf("%s://%s", scheme, host)
		}
	}

	// 根据连接模式构建安装命令
	frontService := strings.ToLower(strings.TrimSpace(req.FrontService))
	if frontService != "xray" && frontService != "nginx" {
		frontService = "xray"
	}
	// nginx 前置暂未支持，先强制回退到 xray
	if frontService == "nginx" {
		frontService = "xray"
	}

	installQuery := url.Values{}
	installQuery.Set("token", token)
	if req.StealSelf {
		installQuery.Set("steal_self", "1")
		installQuery.Set("front_service", frontService)
	}
	// 添加的服务器地址与主控解析到同一台机器时，安装脚本应让 Agent 直接通过
	// loopback 连接主控。否则“偷自己”接管主控域名的 443 后，Agent 再绕公网域名
	// 回连会进入自己刚部署的 Xray/Nginx 链路，容易形成回环或连接中断。
	if isLocalByAddr {
		installQuery.Set("local_master", "1")
	}
	if xrayMode == "embedded" {
		installQuery.Set("xray_mode", "embedded")
	}
	// 自定义 Agent 端口透传到安装脚本(脚本会写进 /etc/mmw-agent/config.yaml 的 listen_port 字段)
	if listenPort > 0 {
		installQuery.Set("listen_port", fmt.Sprintf("%d", listenPort))
	}
	installScriptURL := fmt.Sprintf("%s/api/remote/install.sh?%s", serverURL, installQuery.Encode())

	var installCommand string
	switch connectionMode {
	case storage.ConnectionModeWebSocket:
		installCommand = fmt.Sprintf("curl -fsSL '%s' | bash -s -- --mode=websocket", installScriptURL)
	case storage.ConnectionModePull:
		// 对于pull模式，子服务器只需要暴露一个API，不需要安装命令
		installCommand = fmt.Sprintf("# pull模式：主服务器将从 %s:%d 拉取流量数据\n# 请确保子服务器已配置 MMWX_MODE=child MMWX_CHILD_API_TOKEN=%s", req.PullAddress, req.PullPort, agentToken)
	default:
		installCommand = fmt.Sprintf("curl -fsSL '%s' | bash", installScriptURL)
	}

	// 本机检测：域名解析 IP 与 mmwx_domain 解析 IP 一致则为本机
	isLocal := isLocalByAddr
	if !isLocal && reqDomain != "" && mmwxDomain != "" {
		reqIPs, err1 := net.LookupHost(reqDomain)
		mmwxIPs, err2 := net.LookupHost(mmwxDomain)
		if err1 == nil && err2 == nil {
			mmwxIPSet := make(map[string]struct{})
			for _, ip := range mmwxIPs {
				mmwxIPSet[ip] = struct{}{}
			}
			for _, ip := range reqIPs {
				if _, ok := mmwxIPSet[ip]; ok {
					isLocal = true
					break
				}
			}
		}
	}

	if isLocal {
		if err := deployLocalNginx(reqDomain, h.repo); err != nil {
			log.Printf("[CreateRemoteServer] 本机 Nginx 部署失败: %v", err)
		} else {
			log.Printf("[CreateRemoteServer] 本机 Nginx 部署成功, domain=%s", reqDomain)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RemoteServerResponse{
		Success:        true,
		Message:        "服务器创建成功",
		Server:         server,
		InstallCommand: installCommand,
		IsLocal:        isLocal,
	})
}

// 通过 ID 删除远程服务器
// SyncNodeAddress 手动把指定服务器下所有节点的 clash server 地址校正为服务器当前地址。
// 换机 / IP 漂移后,心跳与入站同步两条自动刷新都按 original_server=服务器名 匹配刷新;但个别场景
// (某次 IP 变化触发被错过、或历史节点)可能没被刷到,导致「服务管理显示新 IP、节点生成仍是旧 IP」。
// 本端点给管理员一键强制校正:v4/域名节点刷到 chooseClashServerHost(Domain→PullAddress域名→IPAddress),
// v6 节点刷到 IPAddressV6。仍按 original_server 匹配(与自动刷新同口径,不误伤别的服务器的节点)。
func (h *XrayServerHandler) SyncNodeAddress(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != "POST" {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}

	var req RemoteServerDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID <= 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "无效的服务器ID"})
		return
	}

	ctx := r.Context()
	server, err := h.repo.GetRemoteServer(ctx, req.ID)
	if err != nil || server == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "服务器不存在"})
		return
	}

	var total int64
	host := chooseClashServerHost(server)
	if host != "" {
		if n, e := h.repo.RefreshNodesServerAddress(ctx, server.Name, host); e != nil {
			log.Printf("[Sync Node Address] v4 refresh failed for %s: %v", server.Name, e)
		} else {
			total += n
		}
	}
	if v6 := v6RefreshTarget(server); v6 != "" {
		if n, e := h.repo.RefreshNodesServerAddressV6(ctx, server.Name, v6); e != nil {
			log.Printf("[Sync Node Address] v6 refresh failed for %s: %v", server.Name, e)
		} else {
			total += n
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RemoteServerResponse{
		Success: true,
		Message: fmt.Sprintf("已同步 %d 个节点地址到 %s", total, host),
	})
}

func (h *XrayServerHandler) DeleteRemoteServer(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != "POST" {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}

	var req RemoteServerDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "无效的请求参数",
		})
		return
	}

	if req.ID <= 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "无效的服务器ID",
		})
		return
	}

	ctx := r.Context()

	// 删服务器前先拿到完整记录：用于卸载 Agent，并供连带删节点使用。
	server, getErr := h.repo.GetRemoteServer(ctx, req.ID)
	if getErr != nil || server == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "服务器不存在"})
		return
	}
	serverName := server.Name

	if req.UninstallAgent != nil && *req.UninstallAgent {
		if _, fedErr := h.repo.GetFederatedServer(ctx, req.ID); fedErr == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(RemoteServerResponse{
				Success: false,
				Message: "分享服务器不能卸载拥有方 Agent，请取消卸载选项后重试",
			})
			return
		}
		if h.remoteManager == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "Agent 卸载服务不可用，服务器未删除"})
			return
		}
		uninstallCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, uninstallErr := h.remoteManager.forwardToRemoteServer(
			uninstallCtx,
			req.ID,
			stdhttp.MethodPost,
			"/api/child/agent/uninstall-stream",
			nil,
		)
		cancel()
		if uninstallErr != nil {
			log.Printf("[Remote Server] uninstall agent before deleting %s failed: %v", serverName, uninstallErr)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(RemoteServerResponse{
				Success: false,
				Message: "卸载 Agent 失败，服务器未删除：" + uninstallErr.Error(),
			})
			return
		}
		log.Printf("[Remote Server] agent uninstall accepted before deleting server %s", serverName)
	}

	deleteNodes := req.DeleteNodes != nil && *req.DeleteNodes
	if err := h.repo.DeleteRemoteServer(ctx, req.ID, deleteNodes); err != nil {
		msg := "删除服务器失败"
		if err == storage.ErrRemoteServerNotFound {
			msg = "服务器不存在"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: msg,
		})
		return
	}

	// 删后清掉该 server 的 inbound 内存缓存,避免残留(否则同 id 复用时会读到旧 inbound 数据)。
	if h.remoteManager != nil && h.remoteManager.inboundCache != nil {
		h.remoteManager.inboundCache.Invalidate(req.ID)
	}

	// 删除后名额顺移:原先超额的服务器可能顶上名额 → 重算并下发 xray 授权。
	if h.wsHandler != nil {
		go h.wsHandler.ReconcileServerQuota(context.Background())
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RemoteServerResponse{
		Success: true,
		Message: "服务器已删除",
	})
}

// 更新远程服务器的基本信息
// ReorderRemoteServers 接受按目标顺序排列的 server ID 数组,把数据库里 sort_order 字段按这个顺序写一遍。
// 前端拖动结束就调一下,ListRemoteServers 已经按 sort_order ASC 排了,刷新自然看到新顺序。
func (h *XrayServerHandler) ReorderRemoteServers(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != stdhttp.MethodPost {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IDs []int64 `json:"ids"`
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "无效的请求参数"})
		return
	}
	if len(req.IDs) == 0 {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "ids 不能为空"})
		return
	}
	if err := h.repo.ReorderRemoteServers(r.Context(), req.IDs); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "message": err.Error()})
		return
	}
	// 拖动改变 sort_order → 谁在配额内随之变化,重算并下发 xray 授权。
	if h.wsHandler != nil {
		go h.wsHandler.ReconcileServerQuota(context.Background())
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (h *XrayServerHandler) UpdateRemoteServer(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != "PUT" && r.Method != "POST" {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}

	var req RemoteServerUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "无效的请求参数",
		})
		return
	}

	if req.ID <= 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "无效的服务器ID",
		})
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "服务器名称不能为空",
		})
		return
	}

	ctx := r.Context()

	// 获取旧的服务器信息，用于检查名称是否变更
	oldServer, err := h.repo.GetRemoteServer(ctx, req.ID)
	if err != nil {
		msg := "获取服务器信息失败"
		if err == storage.ErrRemoteServerNotFound {
			msg = "服务器不存在"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: msg,
		})
		return
	}

	// 内联(embedded)Xray 不再要求许可证,update 路径同样放开(与创建保持一致)。

	// 检测 traffic_source 是否变更 — 用于切换时自动迁移 offset,让 server.traffic_used 显示值连续,
	// 避免用户从 xray 切到 system 时数字突然变小(只剩主控升级以来累积的几小时 system 流量),
	// 反向切回也同样平滑。必须在 UpdateRemoteServer **之前**算 oldDisplay,否则 GetServerTrafficUsed
	// 走的就是新 source 分支了,oldDisplay 取不到旧值。
	newSource := strings.TrimSpace(req.TrafficSource)
	if newSource == "" {
		newSource = oldServer.TrafficSource
	}
	sourceChanged := newSource != "" && newSource != oldServer.TrafficSource
	var oldDisplayForMigration int64
	if sourceChanged {
		oldRaw, _ := h.repo.GetServerTrafficUsed(ctx, req.ID)
		oldDisplayForMigration = oldRaw + oldServer.TrafficUsedOffset
	}

	if err := h.repo.UpdateRemoteServer(ctx, req.ID, req.Name, req.Domain, strings.TrimSpace(req.DomainV6), req.TrafficLimit, req.TrafficResetDay, req.ConnectionMode, req.XrayMode, req.TrafficStatsMode, req.TrafficSource, req.IPv6Enabled); err != nil {
		msg := "更新服务器失败"
		if err == storage.ErrRemoteServerNotFound {
			msg = "服务器不存在"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: msg,
		})
		return
	}

	// 锁定入口 IP + 随机端口范围:三者任一非 nil 即表示前端提交了这组设置,一起落库
	// (未提交的项用当前值兜底,避免只改一项把另两项清零)。
	if req.LockEntryIP != nil || req.PortRangeMin != nil || req.PortRangeMax != nil {
		cur, _ := h.repo.GetRemoteServer(ctx, req.ID)
		lockEntry, pmin, pmax := false, 0, 0
		if cur != nil {
			lockEntry, pmin, pmax = cur.LockEntryIP, cur.PortRangeMin, cur.PortRangeMax
		}
		if req.LockEntryIP != nil {
			lockEntry = *req.LockEntryIP
		}
		if req.PortRangeMin != nil {
			pmin = *req.PortRangeMin
		}
		if req.PortRangeMax != nil {
			pmax = *req.PortRangeMax
		}
		// 范围非法(min>max 或越界)→ 归零表示不启用范围限制,避免存进坏配置。
		if pmin < 0 || pmax < 0 || pmin > 65535 || pmax > 65535 || (pmin > 0 && pmax > 0 && pmin > pmax) {
			pmin, pmax = 0, 0
		}
		if err := h.repo.SetServerNodeSettings(ctx, req.ID, lockEntry, pmin, pmax); err != nil {
			log.Printf("[Remote Server] set node settings for %d failed: %v", req.ID, err)
		}
	}

	// 切换 xray→system 时,把 xray 流量的当前累计 + daily snapshot 历史完整搬到 system 维度:
	//   - cycle 起点 = xray inbound 累计 → 切换瞬间 GetServerTrafficUsed(system) == 切换前 xray raw → 显示数值无变化
	//   - daily snapshot 按 node_traffic_snapshots 每日聚合 → 服务器视图 today/week/month 立即可用
	// 反向(system→xray)不需要迁移 — node_traffic_snapshots 一直在被 daily snapshot job 拍,xray baseline 现成可用。
	if sourceChanged && oldServer.TrafficSource == "xray" && newSource == "system" {
		if err := h.repo.MigrateXraySnapshotsToSystem(ctx, req.ID); err != nil {
			log.Printf("[Remote Server] Migrate xray snapshots to system failed for server %d: %v", req.ID, err)
			// 不阻断 update — 切换基本功能仍然可用,只是 today/week/month baseline 缺失;
			// 主控启动 backfill goroutine 之后会自动补
		} else {
			log.Printf("[Remote Server] Migrated xray snapshots to system for server %d on source switch", req.ID)
		}
	}

	// 更新拉取配置（如果提供）
	if req.PullAddress != "" || req.PullPort > 0 || req.PullToken != "" {
		connMode := req.ConnectionMode
		if connMode == "" {
			connMode = oldServer.ConnectionMode
		}
		if err := h.repo.UpdateRemoteServerConfig(ctx, req.ID, connMode, req.PullAddress, req.PullPort, req.PullToken); err != nil {
			log.Printf("[Remote Server] Failed to update pull config for server %d: %v", req.ID, err)
			// 之前这里只 log 不返 error,导致用户看到 success 但 pull_address 没真更新;
			// 现在向前端透出错误,起码用户能感知失败并 retry。
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(RemoteServerResponse{
				Success: false,
				Message: fmt.Sprintf("更新拉取配置失败: %s", err.Error()),
			})
			return
		}
	}

	// 锁定入口 IP 变更时,立即把已存在节点的 clash server 校正到锁定后的 effective host。
	// 放在 pull_address 落库之后:确保 GetRemoteServer 读到的是本次刚写入的新地址,
	// 否则"同时改服务器地址 + 勾锁定"会刷到旧地址。不触发时(req.LockEntryIP==nil)跳过,
	// 保持与旧行为一致 —— 只有前端明确提交了锁定开关才动节点地址。
	if req.LockEntryIP != nil {
		if latest, gerr := h.repo.GetRemoteServer(ctx, req.ID); gerr == nil && latest != nil {
			if host := chooseClashServerHost(latest); host != "" {
				if n, e := h.repo.RefreshNodesServerAddress(ctx, latest.Name, host); e != nil {
					log.Printf("[Remote Server] lock-entry v4 refresh for %s failed: %v", latest.Name, e)
				} else if n > 0 {
					log.Printf("[Remote Server] lock-entry: refreshed %d node(s) clash.server → %s for %s", n, host, latest.Name)
				}
			}
			if v6 := v6RefreshTarget(latest); v6 != "" {
				if n, e := h.repo.RefreshNodesServerAddressV6(ctx, latest.Name, v6); e != nil {
					log.Printf("[Remote Server] lock-entry v6 refresh for %s failed: %v", latest.Name, e)
				} else if n > 0 {
					log.Printf("[Remote Server] lock-entry: refreshed %d v6 node(s) clash.server → %s for %s", n, v6, latest.Name)
				}
			}
		}
	}

	// 如果服务器名称变更，同步更新关联的节点
	if oldServer.Name != req.Name {
		if updated, err := h.repo.UpdateNodesByServerName(ctx, oldServer.Name, req.Name); err != nil {
			log.Printf("[Remote Server] Failed to update nodes for server name change: %v", err)
		} else if updated > 0 {
			log.Printf("[Remote Server] Updated %d nodes for server name change: %s -> %s", updated, oldServer.Name, req.Name)
		}
	}

	// 域名变更同步刷新该服务器下所有节点 clash_config.server。
	// Domain 优先于 IP(动态 IP 场景下域名稳定),空 Domain 时回退到 IPAddress。
	newDomain := strings.TrimSpace(req.Domain)
	oldDomain := strings.TrimSpace(oldServer.Domain)
	if newDomain != oldDomain {
		addr := newDomain
		if addr == "" {
			addr = oldServer.IPAddress
		}
		if addr != "" {
			finalName := req.Name
			if finalName == "" {
				finalName = oldServer.Name
			}
			if n, err := h.repo.RefreshNodesServerAddress(ctx, finalName, addr); err != nil {
				log.Printf("[Remote Server] Refresh nodes server address failed for %s: %v", finalName, err)
			} else if n > 0 {
				log.Printf("[Remote Server] Refreshed %d node(s) server address → %s after domain change on %s", n, addr, finalName)
			}
		}
	}

	// DDNS 配置变更:校验后 + 单独更新(UpdateRemoteServer 不带 DDNS 字段)
	// 关闭时跳过校验直接关;开启时校验 PullAddress 是域名 + provider 存在
	if req.DDNSEnabled {
		// pull_address:用 update 里的 → 没传时 fallback 到 update 后的 oldServer 值
		effectivePull := strings.TrimSpace(req.PullAddress)
		if effectivePull == "" {
			effectivePull = strings.TrimSpace(oldServer.PullAddress)
		}
		if effectivePull == "" || net.ParseIP(effectivePull) != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusBadRequest)
			json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "DDNS 开启时,服务器地址必须填域名"})
			return
		}
		if req.DDNSProviderID > 0 {
			if _, perr := h.repo.GetDNSProvider(ctx, req.DDNSProviderID); perr != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(stdhttp.StatusBadRequest)
				json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: fmt.Sprintf("DDNS 服务商不存在: %v", perr)})
				return
			}
		} else {
			// 自动模式:按证书 + DNS 服务商识别。没匹配证书时不再硬拦——同步时会遍历 DNS 服务商兜底,
			// 只要至少配了一个 DNS 服务商就放行(都没有才真的无从下手)。
			if _, cerr := h.repo.FindCertificateForDomain(ctx, effectivePull); cerr != nil {
				providers, _ := h.repo.ListDNSProviders(ctx)
				if len(providers) == 0 {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(stdhttp.StatusBadRequest)
					json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "DDNS 自动模式:没有匹配证书,也没有配置任何 DNS 服务商,请先添加 DNS 服务商或签发证书"})
					return
				}
			}
		}
	}
	if err := h.repo.UpdateRemoteServerDDNSConfig(ctx, req.ID, req.DDNSEnabled, req.DDNSProviderID, strings.TrimSpace(req.PullAddressV6)); err != nil {
		log.Printf("[Remote Server] Failed to update DDNS config for server %d: %v", req.ID, err)
	}
	// 需求1:编辑保存后立即触发一次 DDNS 同步(不再只等 IP 变化)。取最新完整 server 再触发。
	if h.ddnsManager != nil && req.DDNSEnabled {
		if latest, gerr := h.repo.GetRemoteServer(ctx, req.ID); gerr == nil && latest != nil {
			go h.ddnsManager.Trigger(context.Background(), latest)
		}
	}

	// 更新已用流量偏移量。优先级:
	//   1. 用户在 dialog 显式填了"已用流量" → 按用户输入算 offset
	//   2. 没填但 traffic_source 变了 → 自动迁移,把旧 source 显示值"搬"到新 source 起点
	//      (oldDisplay 在 UpdateRemoteServer 之前抓的,此时 source 已切到新值,GetServerTrafficUsed 走新分支)
	//   3. 都不满足 → 不动 offset
	if req.TrafficUsed != nil {
		aggregated, _ := h.repo.GetServerTrafficUsed(ctx, req.ID)
		offset := *req.TrafficUsed - aggregated
		if err := h.repo.UpdateRemoteServerTrafficOffset(ctx, req.ID, offset); err != nil {
			log.Printf("[Remote Server] Failed to update traffic offset for server %d: %v", req.ID, err)
		}
	} else if sourceChanged {
		newRaw, _ := h.repo.GetServerTrafficUsed(ctx, req.ID)
		offset := oldDisplayForMigration - newRaw
		if err := h.repo.UpdateRemoteServerTrafficOffset(ctx, req.ID, offset); err != nil {
			log.Printf("[Remote Server] Auto-migrate traffic offset on source switch failed for server %d: %v", req.ID, err)
		} else {
			log.Printf("[Remote Server] Auto-migrated traffic offset for server %d on source switch %s→%s: oldDisplay=%d, newRaw=%d, newOffset=%d",
				req.ID, oldServer.TrafficSource, newSource, oldDisplayForMigration, newRaw, offset)
		}
	}

	// xray_mode 变更：异步通知 Agent 切换模式
	newXrayMode := req.XrayMode
	if newXrayMode == "" {
		newXrayMode = oldServer.XrayMode
	}
	if newXrayMode != oldServer.XrayMode && h.remoteManager != nil {
		go h.switchRemoteXrayMode(req.ID, newXrayMode)
	}

	// listen_port 变更:**必须先用旧端口通知 agent**(此刻 DB 仍是旧值,ForwardToServer 能连上 agent),
	// 等 agent 收到并自重启后,**它会用新端口上报心跳给主控,主控收到心跳时会更新 listen_port**。
	// 这里若立刻落库,会导致 ForwardToServer 读到新端口去连旧 agent 实例,connection refused。
	// 同步调用是因为 agent 端会先 net.Listen 预检新端口能否 bind,
	// 失败(被 xray 等占用)会立刻回 409,主控把错误透传给前端,避免重启后死锁。
	respMsg := "服务器信息已更新"
	newListenPort := req.ListenPort
	if newListenPort < 0 || newListenPort > 65535 {
		newListenPort = oldServer.ListenPort
	}
	if newListenPort != oldServer.ListenPort && h.remoteManager != nil {
		if err := h.switchRemoteListenPort(req.ID, newListenPort); err != nil {
			respMsg = fmt.Sprintf("服务器信息已更新,但端口切换失败: %v", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RemoteServerResponse{
		Success: true,
		Message: respMsg,
	})
}

// switchRemoteXrayMode 通知远程 Agent 切换 xray_mode 并重启。
func (h *XrayServerHandler) switchRemoteXrayMode(serverID int64, newMode string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	body, _ := json.Marshal(map[string]string{"xray_mode": newMode})
	result, err := h.remoteManager.ForwardToServer(ctx, serverID, "POST", "/api/child/agent/switch-xray-mode", body)
	if err != nil {
		log.Printf("[Remote Server] Failed to switch xray_mode to %s for server %d: %v", newMode, serverID, err)
		return
	}
	log.Printf("[Remote Server] Xray mode switch to %s for server %d: %s", newMode, serverID, string(result))
}

// switchRemoteListenPort 通知远程 Agent 改自身监听端口并重启。Agent 重启会短暂断连(~5–15s),
// 重启后用新端口监听,主控下次重连读 server.ListenPort 自动用新端口。
// agent 端会先 net.Listen 预检新端口能否 bind,失败立刻回 409 — 这里 error 不为 nil 即代表
// 切换被 agent 拒绝(端口被占用),DB 不需要回滚因为 agent 也没改 config 也没重启。
func (h *XrayServerHandler) switchRemoteListenPort(serverID int64, newPort int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	body, _ := json.Marshal(map[string]int{"listen_port": newPort})
	result, err := h.remoteManager.ForwardToServer(ctx, serverID, "POST", "/api/child/agent/switch-listen-port", body)
	if err != nil {
		log.Printf("[Remote Server] Failed to switch listen_port to %d for server %d: %v", newPort, serverID, err)
		return err
	}
	log.Printf("[Remote Server] Listen port switch to %d for server %d: %s", newPort, serverID, string(result))
	return nil
}

func resolveIPs(address string) []string {
	address = normalizeAddressHost(address)
	if ip := net.ParseIP(address); ip != nil {
		return []string{ip.String()}
	}
	ips, err := net.LookupHost(address)
	if err != nil {
		return nil
	}
	return ips
}

// normalizeAddressHost 统一处理用户可能输入的域名、host:port 或完整 URL。
func normalizeAddressHost(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}
	parsed, err := url.Parse(address)
	if err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	parsed, err = url.Parse("//" + address)
	if err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	return strings.ToLower(strings.Trim(address, "[]"))
}

func (h *XrayServerHandler) CheckSameIP(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != stdhttp.MethodGet {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}

	address := strings.TrimSpace(r.URL.Query().Get("address"))
	if address == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "address 参数不能为空"})
		return
	}

	ctx := r.Context()
	mmwxDomain := getDomainFromMasterURL(h.repo, ctx)
	masterURL, _ := h.repo.GetSystemSetting(ctx, "master_url")
	httpsEnabled := strings.HasPrefix(masterURL, "https://")

	// 地址与主控域名完全相同应直接判定；不能只依赖 DNS 查询，否则临时解析失败时
	// 表单不会自动填充主控反代。域名带协议或端口时也按 hostname 比较。
	sameIP := normalizeAddressHost(address) == normalizeAddressHost(mmwxDomain) && mmwxDomain != ""
	if mmwxDomain != "" {
		if !sameIP {
			addrIPs := resolveIPs(address)
			mmwxIPs := resolveIPs(mmwxDomain)
			mmwxIPSet := make(map[string]struct{})
			for _, ip := range mmwxIPs {
				mmwxIPSet[ip] = struct{}{}
			}
			for _, ip := range addrIPs {
				if _, ok := mmwxIPSet[ip]; ok {
					sameIP = true
					break
				}
			}
		}
	}
	panelPort := os.Getenv("PORT")
	if panelPort == "" {
		panelPort = "12889"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":       true,
		"same_ip":       sameIP,
		"master_domain": mmwxDomain,
		"https_enabled": httpsEnabled,
		"panel_backend": "http://127.0.0.1:" + panelPort,
	})
}
