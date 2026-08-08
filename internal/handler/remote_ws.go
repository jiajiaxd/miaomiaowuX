package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"miaomiaowux/internal/agentlog"
	"miaomiaowux/internal/ddns"
	"miaomiaowux/internal/license"
	"miaomiaowux/internal/securechan"
	"miaomiaowux/internal/storage"
	"miaomiaowux/internal/traffic"
	"miaomiaowux/internal/version"

	"github.com/gorilla/websocket"
)

// WebSocket 消息类型
const (
	WSMsgTypeAuth                = "auth"
	WSMsgTypeAuthResult          = "auth_result"
	WSMsgTypeHeartbeat           = "heartbeat"
	WSMsgTypeTraffic             = "traffic"
	WSMsgTypeConfig              = "config"
	WSMsgTypePing                = "ping"
	WSMsgTypePong                = "pong"
	WSMsgTypeSpeed               = "speed"                 // 实时速度数据
	WSMsgTypeCertRequest         = "cert_request"          // DEAD CODE — agent 没实现接收方,详见 SendCertRequest 注释
	WSMsgTypeCertUpdate          = "cert_update"           // Agent -> Master：证书结果
	WSMsgTypeCertDeploy          = "cert_deploy"           // Master -> Agent：部署证书
	WSMsgTypeTokenUpdate         = "token_update"          // Master -> Agent：推送新的服务器令牌
	WSMsgTypeScanResult          = "scan_result"           // Agent -> Master：启动扫描结果
	WSMsgTypeDomainLatencyProbe  = "domain_latency_probe"  // Master -> Agent：探测域延迟
	WSMsgTypeDomainLatencyResult = "domain_latency_result" // Agent -> Master：探测结果
	WSMsgTypeHeartbeatAck        = "heartbeat_ack"         // Master -> Agent：心跳确认（含服务器时间）
	WSMsgTypeLimiterConfig       = "limiter_config"        // Master -> Agent：限速配置下发
	WSMsgTypeLicenseStatus       = "license_status"        // Master -> Agent：许可证状态下发
	WSMsgTypeKeyExchange         = "key_exchange"          // Agent -> Master：密钥交换请求
	WSMsgTypeKeyExchangeResp     = "key_exchange_resp"     // Master -> Agent：密钥交换响应
	WSMsgTypeConfigUpdate        = "config_update"         // Master -> Agent：更新 agent 配置
)

// WSMessage 表示 WebSocket 消息
type WSMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// WSAuthPayload 表示身份验证消息负载
type WSAuthPayload struct {
	Token string `json:"token"`
	// Probe validates a migration candidate without registering/replacing the
	// live Agent connection or triggering reconnect synchronization callbacks.
	Probe bool `json:"probe,omitempty"`
	// PublicIPv4 由 agent 在 detect 后随 auth 一起上报。master 优先用它写 db.IPAddress,
	// 避免 master 重启 → preferV4DialContext 偶尔 fallback v6 → auth 用 WS 源 IP (v6) 写 db
	// → 立刻反向请求 agent (HTTP) 用 v6 → 失败。心跳里也会上报,但 auth 早于第一次 heartbeat
	// ~10s,窗口期足以触发"IP 已变 v6 → 反向不通"的可观察故障。老 agent 不发该字段 = 空串 = fallback 旧行为。
	PublicIPv4 string `json:"public_ipv4,omitempty"`
	// PublicIPv6 由 dual-stack agent 单独探测后上报(独立于 PublicIPv4 的 v4-first fallback v6 行为)。
	// 用途:master HTTP 反向请求 v4 失败时,fallback 试这个 v6 地址。
	// 老 agent 不发该字段 = 空 → master 端 IPAddressV6 保留旧值(通常也是空)→ 只走 v4 候选,行为同现状。
	PublicIPv6 string `json:"public_ipv6,omitempty"`
	// Capabilities agent 上报支持的扩展能力。老 agent 不发 = 全 false → master 走 HTTP 旧路径。
	// 新 agent 上报 RPC=true → master 反向调用优先走 WS RPC,失败/超时再 fallback HTTP。
	Capabilities AgentCapabilities `json:"capabilities,omitempty"`
	// WarpInstalled agent 本机是否已注册 Cloudflare WARP(成功跑过 EnsureRegistered 且 warp.json 存在)。
	// 老 agent 不发 = false → server 卡片 W badge 不显示,完全向后兼容。
	WarpInstalled    bool  `json:"warp_installed,omitempty"`
	SameHostAsMaster *bool `json:"same_host_as_master,omitempty"`
	// AgentVersion agent 自身版本号(随 auth 上报)。master 据此显示版本/判断可升级,
	// 不再反向 HTTP 拉 /api/child/system/info —— 端口隐身(HidePortOnWS)关闭入站后仍可拿到。
	// 老 agent 不发该字段 = 空串 → fallback 反向 HTTP(向后兼容)。
	AgentVersion string `json:"agent_version,omitempty"`
	// XrayMode agent 当前实际运行模式(embedded/external),随 auth 上报。master 据此校正
	// "embedded→external 漂移":DB 记 embedded 但 agent 卡 external 时自动下发切回 embedded
	// (license 失效期被迫切 external、恢复后不同步的自愈)。老 agent 不发 = 空串 → 跳过校正。
	XrayMode string `json:"xray_mode,omitempty"`
}

// AgentCapabilities 描述 agent 端支持的扩展能力位。
// 新增字段时 master 老二进制反序列化忽略未知字段,agent 老二进制不发字段 = false,
// 因此该结构可以前向兼容地扩展。
type AgentCapabilities struct {
	// RPC 表示 agent 实现了 WSMsgTypeRPCCall handler — master 可以用 WS 通道
	// 替代反向 HTTP 调用 /api/child/* 系列 endpoint。
	RPC bool `json:"rpc,omitempty"`
	// Stream 表示 agent 实现了 rpc_call (Stream=true) → rpc_stream_data ... → rpc_reply 流式协议。
	// master 可以用 WS 通道替代 /api/child/xxx-stream 这类 SSE endpoint(install / remove / upgrade)。
	Stream bool `json:"stream,omitempty"`
	// ReturnRouteTest 表示 Agent 已实现三网回程 child handler。旧 Agent 即使
	// 支持通用 RPC 也不会声明该位，主控据此在创建任务前提示升级。
	ReturnRouteTest bool `json:"return_route_test,omitempty"`
}

// WSAuthResultPayload 表示身份验证结果消息负载
type WSAuthResultPayload struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// WSTrafficPayload 表示流量数据消息负载
type WSTrafficPayload struct {
	Stats       *traffic.XrayStats  `json:"stats,omitempty"`
	OnlineUsers map[string][]string `json:"online_users,omitempty"`
	UserSpeeds  map[string]int64    `json:"user_speeds,omitempty"`
	// ConnCounts 每 group("<user>|<物理节点ID>")当前并发连接数;主控存内存、按用户聚合供用户视图展示。
	ConnCounts map[string]int64 `json:"conn_counts,omitempty"`
	// NodeConnCounts 按实际节点统计(group="<user>|<nodeID>")，与用于共享配额的 ConnCounts 分离。
	NodeConnCounts map[string]int64 `json:"node_conn_counts,omitempty"`
	// System 系统级网卡累计 RX/TX,跟 HTTP path 的 RemoteTrafficRequest.System 同构。
	// 用于 server.traffic_source='system' 时累加 system_*_cycle;nil = 老 agent 不上报,跳过。
	System *RemoteSystemTraffic `json:"system,omitempty"`
	// 伪装探针真数据(agent 只在采集开启时上报)。nil/空 = 未采集或旧 agent,主控跳过。
	Sysmetrics *ProbeSysWire        `json:"sysmetrics,omitempty"`
	Latency    []ProbeLatencySample `json:"latency,omitempty"`
}

// ProbeSysWire 是 agent 上报的系统指标线格式(字段名与 agent sysmetrics.go 的 ProbeSysMetrics 对齐)。
type ProbeSysWire struct {
	CPUPct     float64 `json:"cpu_pct"`
	LoadAvg    string  `json:"loadavg"`
	MemUsed    int64   `json:"mem_used"`
	MemTotal   int64   `json:"mem_total"`
	DiskUsed   int64   `json:"disk_used"`
	DiskTotal  int64   `json:"disk_total"`
	Uptime     int64   `json:"uptime,omitempty"`
	CPUModel   string  `json:"cpu_model,omitempty"`
	CPUCores   int     `json:"cpu_cores,omitempty"`
	CPUThreads int     `json:"cpu_threads,omitempty"`
	OS         string  `json:"os,omitempty"`
	Kernel     string  `json:"kernel,omitempty"`
	Arch       string  `json:"arch,omitempty"`
	HasCPU     bool    `json:"has_cpu"`
	HasMem     bool    `json:"has_mem"`
	HasDisk    bool    `json:"has_disk"`
}

// connCountsByServer 存各 server 最近一次上报的 group→当前并发连接数(内存、非持久)。用户视图"当前连接数"用。
var connCountsByServer sync.Map     // serverID(int64) -> map[string]int64
var nodeConnCountsByServer sync.Map // serverID(int64) -> map[string]int64

// AggregateUserConnCounts 把所有 server 的 group 连接数按 username 聚合(group="<user>|<nodeID>" 取 user 段求和)。
func AggregateUserConnCounts() map[string]int64 {
	out := make(map[string]int64)
	connCountsByServer.Range(func(_, v interface{}) bool {
		m, _ := v.(map[string]int64)
		for group, n := range m {
			if i := strings.LastIndex(group, "|"); i > 0 {
				out[group[:i]] += n
			}
		}
		return true
	})
	return out
}

// AggregateNodeConnCounts 返回每个节点的总连接数及节点内逐用户连接数。
func AggregateNodeConnCounts() (map[int64]int64, map[int64]map[string]int64) {
	totals := make(map[int64]int64)
	users := make(map[int64]map[string]int64)
	nodeConnCountsByServer.Range(func(_, v interface{}) bool {
		m, _ := v.(map[string]int64)
		for group, n := range m {
			i := strings.LastIndex(group, "|")
			if i <= 0 || n <= 0 {
				continue
			}
			nodeID, err := strconv.ParseInt(group[i+1:], 10, 64)
			if err != nil || nodeID <= 0 {
				continue
			}
			username := group[:i]
			totals[nodeID] += n
			if users[nodeID] == nil {
				users[nodeID] = make(map[string]int64)
			}
			users[nodeID][username] += n
		}
		return true
	})
	return totals, users
}

// WSLimiterConfigPayload 表示限速配置下发消息 (Master -> Agent)
type WSLimiterConfigPayload struct {
	InboundTag     string                       `json:"inbound_tag"`
	NodeLimit      uint64                       `json:"node_limit"`
	Users          []WSUserLimitInfo            `json:"users"`
	AutoSpeedRules []storage.AutoSpeedLimitRule `json:"auto_speed_rules,omitempty"`
}

// WSUserLimitInfo 表示单个用户的限速配置
//
// DeviceLimit 现语义 = **并发连接上限**(0=不限)。历史列名/JSON 保留 device_limit(免迁移),
// 但 agent 侧按「连接数」而非「去重 IP 数」执行,且按 ConnGroup 计数以在同一物理节点上共享配额。
type WSUserLimitInfo struct {
	Email       string `json:"email"`
	SpeedLimit  uint64 `json:"speed_limit"`
	DeviceLimit int    `json:"device_limit"`
	// ConnGroup 连接数计数分组键 = "<username>|<物理父节点ID>"。一个用户在同一物理节点(含其路由
	// 出站子账户)的多个 email 共享同一 group → 共享一份连接配额(问题1:20 而非 20×N)。空=老 agent 兼容,退化按 email。
	ConnGroup string `json:"conn_group,omitempty"`
	// ConnStatGroup 始终使用实际节点 ID；路由节点不会并入物理父节点。
	ConnStatGroup string `json:"conn_stat_group,omitempty"`
}

// WSHeartbeatPayload 表示心跳消息负载
type WSHeartbeatPayload struct {
	BootTime       *time.Time `json:"boot_time,omitempty"`
	XrayBootTime   *time.Time `json:"xray_boot_time,omitempty"`
	ListenPort     int        `json:"listen_port,omitempty"`
	LocalTimestamp int64      `json:"local_time,omitempty"`
	PublicIPv4     string     `json:"public_ipv4,omitempty"`
	// PublicIPv6 dual-stack v6 地址(同 WSAuthPayload.PublicIPv6 字段)。
	// 每次心跳重发可让 master 跟随服务器 v6 地址变化(动态 prefix / 重新 detect)。
	PublicIPv6 string `json:"public_ipv6,omitempty"`
	// WarpInstalled 心跳里也带一份(同 WSAuthPayload),让 master 跟踪 agent 主动 install/remove 后的状态变化。
	WarpInstalled    bool  `json:"warp_installed,omitempty"`
	SameHostAsMaster *bool `json:"same_host_as_master,omitempty"`
}

// WSSpeedPayload 表示实时速度数据负载
type WSSpeedPayload struct {
	UploadSpeed   int64 `json:"upload_speed"`   // 字节/秒
	DownloadSpeed int64 `json:"download_speed"` // 字节/秒
}

// WSCertRequestPayload 表示证书请求负载（Master -> Agent）
type WSCertRequestPayload struct {
	CertID         int64  `json:"cert_id"`
	Domain         string `json:"domain"`
	Email          string `json:"email"`
	Provider       string `json:"provider"`
	ChallengeMode  string `json:"challenge_mode"`
	WebrootPath    string `json:"webroot_path,omitempty"`
	DNSProvider    string `json:"dns_provider,omitempty"`
	DNSCredentials string `json:"dns_credentials,omitempty"` // JSON 字符串
}

// WSCertDeployPayload 表示证书部署负载（Master -> Agent）
type WSCertDeployPayload struct {
	Domain   string `json:"domain"`
	CertPEM  string `json:"cert_pem"`
	KeyPEM   string `json:"key_pem"`
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
	Reload   string `json:"reload"` // nginx、xray、两者、无
}

// WSCertUpdatePayload 表示证书结果负载（Agent -> Master）
type WSCertUpdatePayload struct {
	CertID     int64     `json:"cert_id"`
	Domain     string    `json:"domain"`
	Success    bool      `json:"success"`
	CertPath   string    `json:"cert_path,omitempty"`
	KeyPath    string    `json:"key_path,omitempty"`
	CertPEM    string    `json:"cert_pem,omitempty"`
	KeyPEM     string    `json:"key_pem,omitempty"`
	IssueDate  time.Time `json:"issue_date,omitempty"`
	ExpiryDate time.Time `json:"expiry_date,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// WSDomainLatencyProbePayload 从主服务器发送到代理
type WSDomainLatencyProbePayload struct {
	RequestID string   `json:"request_id"`
	Domains   []string `json:"domains"`
	TimeoutMs int      `json:"timeout_ms"`
}

// WSDomainLatencyResultPayload 从代理发送到主服务器
type WSDomainLatencyResultPayload struct {
	RequestID string                      `json:"request_id"`
	Success   bool                        `json:"success"`
	Results   []WSDomainLatencyResultItem `json:"results,omitempty"`
	Error     string                      `json:"error,omitempty"`
}

// WSDomainLatencyResultItem 表示单个域探测结果
type WSDomainLatencyResultItem struct {
	Domain       string `json:"domain"`
	Target       string `json:"target"`
	Success      bool   `json:"success"`
	LatencyMs    int64  `json:"latency_ms,omitempty"`
	Error        string `json:"error,omitempty"`
	NginxSSLPort int    `json:"nginx_ssl_port,omitempty"`
}

// WSKeyExchangePayload Agent -> Master
type WSKeyExchangePayload struct {
	AgentEphemeralPub string `json:"agent_ephemeral_pub"` // base64
}

// WSKeyExchangeRespPayload Master -> Agent
type WSKeyExchangeRespPayload struct {
	MasterEphemeralPub string `json:"master_ephemeral_pub"` // base64
	Signature          string `json:"signature"`            // base64 Ed25519 签名
}

// RemoteWSConnection 表示来自子服务器的活动 WebSocket 连接
type RemoteWSConnection struct {
	ServerID   int64
	ServerName string
	Token      string
	Conn       *websocket.Conn
	LastPing   time.Time
	session    *securechan.Session
	Encrypted  bool
	mu         sync.Mutex
	// writeMu 串行化本连接上的所有 WriteMessage。gorilla/websocket 不允许并发写同一连接,
	// 读循环里的响应(handleHeartbeat 的 ack、auth result、pong)与各推送 goroutine
	// (SendConfigUpdate / 探针配置 / license 广播 …)会同时写 → "concurrent write to
	// websocket connection" panic(曾致 docker 进程崩溃)。所有写统一走 sendEncryptedMessage,
	// 由它加 writeMu;WriteControl(ping) 按 gorilla 文档与 WriteMessage 并发安全,无需此锁。
	writeMu sync.Mutex
	// Capabilities 从 auth payload 读到的 agent 能力位。RPC=true 时 forwardToRemoteServer 走 WS RPC,
	// 否则走 HTTP(老 agent 兼容)。
	Capabilities AgentCapabilities
	// IPAddress 本连接 auth 时刻确定的 agent IP(PublicIPv4 优先,fallback RemoteAddr)。
	// 留作 cleanup 时离线通知用 — agent 换 IP 重连时,DB.ip_address 已被新 conn 改成新 IP,
	// 但旧 conn 自己记得旧 IP,用 wsConn.IPAddress 才能让"离线通知=旧 IP, 上线通知=新 IP"。
	IPAddress string
	// AgentVersion auth 上报的 agent 版本号;版本展示/升级前后对比走这里,不依赖反向 HTTP 端口。
	AgentVersion string
}

// upgradeWindows 记录每台 server 的"升级抑制窗口"截止时间。
// 期间该 server 的 WS 离线 / 重连不发上下线通知 — 升级本来就是 agent 必然要退出 + 重连,
// 不抑制的话批量升级会给每台 server 各产生一对上下线通知,Telegram 风控立刻爆。
//
// 由 RemoteManageHandler.forwardUpgradeStream 进入升级流程前调用 MarkServerUpgrading 设置;
// remote_ws.go 在 cleanup + handleAuth 两处 SendServer* 之前用 IsServerUpgrading 检查。
// 窗口典型 ~90s(含 GitHub 下载 + agent 重启 + WS 重连):上限留 2min 兜底。
var upgradeWindows sync.Map // map[int64]time.Time(serverID → upgrade window until)

// MarkServerUpgrading 把一台 server 标记为"未来 d 时间内的离线/上线视为升级噪音,别通知"。
// 同一台多次调用会用最晚的 deadline。
func MarkServerUpgrading(serverID int64, d time.Duration) {
	until := time.Now().Add(d)
	if prev, ok := upgradeWindows.Load(serverID); ok {
		if t, _ := prev.(time.Time); t.After(until) {
			return
		}
	}
	upgradeWindows.Store(serverID, until)
}

// IsServerUpgrading 返回该 server 是否仍在升级抑制窗口内。
// 过期窗口会被 LoadAndDelete 清掉,避免 sync.Map 长尾累积。
func IsServerUpgrading(serverID int64) bool {
	v, ok := upgradeWindows.Load(serverID)
	if !ok {
		return false
	}
	until, _ := v.(time.Time)
	if time.Now().Before(until) {
		return true
	}
	upgradeWindows.CompareAndDelete(serverID, v)
	return false
}

// RemoteWSHandler 处理来自远程（子）服务器的 WebSocket 连接
type RemoteWSHandler struct {
	repo              *storage.TrafficRepository
	collector         *traffic.Collector
	upgrader          websocket.Upgrader
	conns             sync.Map // 令牌 -> *RemoteWSConnection
	stealSelfDeployer func(ctx context.Context, serverID int64) error
	pendingProbes     sync.Map // 详见上下文
	pendingRPC        sync.Map // map[requestID]chan WSRPCReplyPayload — WS RPC 反向调用响应路由,详见 ws_rpc.go
	pendingStream     sync.Map // map[requestID]chan wsStreamFrame — 流式 RPC (SSE 替代)
	limiterPusher     *LimiterConfigPusher
	licenseManager    *license.Manager
	crypto            *CryptoConfig
	probeStore        *ProbeMetricsStore // 伪装探针真数据 ring(可选,SetProbeStore 注入)
	userSpeedCache    sync.Map           // key: "serverID:email" -> int64 (Bytes/s)
	// xrayConfigSyncCallback 在 auth 成功后异步触发(args: serverID + 上次 server.status),
	// 实现见 RemoteManageHandler.SyncXrayConfigOnReconnect — 跨 handler 用 callback 注入避免循环依赖。
	xrayConfigSyncCallback func(ctx context.Context, serverID int64, prevStatus string)
	// xrayModeCorrectCallback 在 auth 成功后异步触发,校正 embedded→external 漂移(agent 上报的实际 mode)。
	// 实现见 RemoteManageHandler.CorrectXrayModeDrift。老 agent 不上报 mode → agentMode 空 → 跳过。
	xrayModeCorrectCallback func(ctx context.Context, serverID int64, agentMode string)
	// masterURLSyncCallback 在 Agent 上线后校准回连地址及同机主控反代配置。
	// 这使修改主控地址时离线的 Agent 也能在重连后补发。
	masterURLSyncCallback func(ctx context.Context, serverID int64, prevStatus string)
	// authFailIPs 记录最近 auth 失败的 IP,用于"狂连"场景的 backoff:
	//   - 同 IP 在 cooldown 内的连接直接拒绝 upgrade(节省 CPU 与日志)
	//   - 同 IP 的失败日志按窗口聚合,防止刷屏
	authFailIPs sync.Map // map[string]*ipFailRecord
	// tokenConflicts 记录 agent_token 复用冲突:两台机器配同一份 token 时,
	// 第一次抢占检测到旧 conn IP ≠ 新 conn IP 且旧 conn 仍活跃 → 锁定 winnerIP,
	// cooldown 期内其它 IP 直接拒绝 — 防止互踩 reconnect 风暴打满 SQLite 单写连接,
	// 拖垮其它无关 server 的心跳更新导致它们被误标 offline / fallback_to_pull。
	tokenConflicts sync.Map // map[string]*tokenConflictRecord
	// ddnsManager 心跳检测到 IP 漂移时触发 DNS provider API 更新域名 A/AAAA 记录。
	// 用 setter 注入避免循环依赖(ddns 包不能依赖 handler 包)。
	ddnsManager                 *ddns.Manager
	serverAddressChangeCallback func(ctx context.Context, before, after *storage.RemoteServer)
}

func (h *RemoteWSHandler) SetServerAddressChangeCallback(fn func(ctx context.Context, before, after *storage.RemoteServer)) {
	h.serverAddressChangeCallback = fn
}

// SetDDNSManager 注入 DDNS 管理器,main.go 启动时调一次。
func (h *RemoteWSHandler) SetDDNSManager(m *ddns.Manager) {
	h.ddnsManager = m
}

// tokenConflictRecord 单 token 复用冲突状态:winnerIP 是当前被允许连接的 agent IP,
// rejectUntil 之前其它 IP 的同 token auth 直接拒绝 + 日志聚合。
type tokenConflictRecord struct {
	mu             sync.Mutex
	winnerIP       string
	rejectUntil    time.Time
	suppressedLogs int
	windowStart    time.Time
}

// ipFailRecord 单 IP 的失败状态。
type ipFailRecord struct {
	mu             sync.Mutex
	lastFailAt     time.Time
	failsInWindow  int // 当前聚合窗口内累计失败次数
	windowStart    time.Time
	rejectUntil    time.Time // 在此时间前直接拒绝 upgrade
	suppressedLogs int       // 静默期内被压制的日志数量
}

// 创建一个新的 WebSocket 处理程序
func NewRemoteWSHandler(repo *storage.TrafficRepository, collector *traffic.Collector) *RemoteWSHandler {
	return &RemoteWSHandler{
		repo:      repo,
		collector: collector,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true // 允许远程服务器连接的所有来源
			},
		},
	}
}

func (h *RemoteWSHandler) SetLicenseManager(mgr *license.Manager) {
	h.licenseManager = mgr
}

func (h *RemoteWSHandler) SetLimiterPusher(p *LimiterConfigPusher) {
	h.limiterPusher = p
}

// SetProbeStore 注入伪装探针真数据的内存 ring(接收 agent 上报的 sysmetrics/latency)。
func (h *RemoteWSHandler) SetProbeStore(s *ProbeMetricsStore) {
	h.probeStore = s
}

// PushProbeConfigToAgent 把伪装探针采集配置下发给一台 agent。
//   - 该 server 被选进展示列表 且 总开关开 → 下发各子开关的真实状态 + ping 目标
//   - 否则 → 全下发 "0"(停采),避免未展示的服务器白白采集上报
//
// 从 system_settings 读配置,由 SetProbeDisguise 保存后 + agent 上线(auth 后)调用。
func (h *RemoteWSHandler) PushProbeConfigToAgent(ctx context.Context, serverID int64) {
	_ = h.SendConfigUpdate(serverID, h.buildProbeConfigUpdates(ctx, serverID))
}

// buildProbeConfigUpdates 组装一台 agent 的探针采集配置(不负责发送)。
//
// 拆出来是因为两条下发通道形态不同:WS 走 SendConfigUpdate 主动推,
// HTTP/pull 模式没有持久连接、只能搭 traffic 响应的车(见 RemoteTrafficHandler)。
// 组装逻辑必须只有一份 —— 各写一份迟早会让两种连接模式的 agent 采集行为不一致。
func (h *RemoteWSHandler) buildProbeConfigUpdates(ctx context.Context, serverID int64) map[string]string {
	get := func(k string) string { v, _ := h.repo.GetSystemSetting(ctx, k); return v }
	enabled := get(probeDisguiseEnabledKey) == "1"

	selected := false
	if raw := get(probeDisguiseServerIDsKey); raw != "" {
		var ids []int64
		if json.Unmarshal([]byte(raw), &ids) == nil {
			for _, id := range ids {
				if id == serverID {
					selected = true
					break
				}
			}
		}
	}

	updates := map[string]string{}
	if recoveryURL, _, err := effectiveRecoveryURL(ctx, h.repo, masterListenPort()); err == nil {
		updates["recovery_url"] = recoveryURL
	}
	active := enabled && selected
	b := func(key string) string {
		if active && get(key) == "1" {
			return "1"
		}
		return "0"
	}
	updates["probe_collect_cpu"] = b(probeDisguiseMetricCPUKey)
	if active {
		updates["probe_collect_info"] = "1"
	} else {
		updates["probe_collect_info"] = "0"
	}
	updates["probe_collect_mem"] = b(probeDisguiseMetricMemKey)
	updates["probe_collect_disk"] = b(probeDisguiseMetricDiskKey)
	updates["probe_collect_ping"] = b(probeDisguiseMetricPingKey)
	if active {
		// ping 目标只在启用时下发,且转成 agent 侧格式(仅 key/host/port,不带 label/isp)。
		// per-server 覆盖优先;该服务器没配覆盖才回落全局列表。
		var targets []ProbePingTarget
		resolved := false
		if ov := parseProbePingTargetOverrides(get(probeDisguisePingTargetsOverrideKey)); ov != nil {
			if t, ok := ov[serverID]; ok {
				targets, resolved = t, true
			}
		}
		if !resolved {
			if raw := get(probeDisguisePingTargetsKey); raw != "" {
				_ = json.Unmarshal([]byte(raw), &targets)
			}
		}
		if len(targets) > probePingMaxTargets {
			targets = targets[:probePingMaxTargets]
		}
		agentTargets := make([]map[string]any, 0, len(targets))
		for _, t := range targets {
			agentTargets = append(agentTargets, map[string]any{"key": t.Key, "host": t.Host, "port": t.Port, "type": t.Type})
		}
		// 即使为空也必须下发 "[]":agent 的 handleProbeConfigUpdate 只写入 present 的字段,
		// 省略这个 key 会让它继续 ping 上一次的目标(清空/改回跟随全局时就再也停不下来)。
		if tj, err := json.Marshal(agentTargets); err == nil {
			updates["probe_ping_targets"] = string(tj)
		}
		// 目标列表缩减后,ring 里的孤儿 key 不会自己消失(只有整台服务器 Evict 才清)。
		// 展示侧靠 targetMeta 白名单挡住了,但内存会一直占着。
		if h.probeStore != nil {
			keep := make(map[string]bool, len(targets))
			for _, t := range targets {
				keep[t.Key] = true
			}
			h.probeStore.PruneKeys(serverID, keep)
		}
		if iv := get(probeDisguisePingIntervalKey); iv != "" {
			updates["probe_ping_interval_ms"] = iv
		}
	}
	return updates
}

// PushProbeConfigToAll 对所有已连 agent 下发采集配置(配置变更后调)。
func (h *RemoteWSHandler) PushProbeConfigToAll(ctx context.Context) {
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return
	}
	for i := range servers {
		if _, ok := h.GetConnectionByServerID(servers[i].ID); ok {
			h.PushProbeConfigToAgent(ctx, servers[i].ID)
		}
	}
}

func (h *RemoteWSHandler) SetCrypto(cc *CryptoConfig) {
	h.crypto = cc
}

// SetXrayConfigSyncCallback 注册 agent WS auth 成功后的 xray 配置同步回调。
// 由 RemoteManageHandler 在 main wire 时注入,避免 ws ↔ manage 互引导致的循环依赖。
func (h *RemoteWSHandler) SetXrayConfigSyncCallback(cb func(ctx context.Context, serverID int64, prevStatus string)) {
	h.xrayConfigSyncCallback = cb
}

// SetXrayModeCorrectCallback 注册 agent WS auth 成功后的 xray_mode 漂移校正回调。
func (h *RemoteWSHandler) SetXrayModeCorrectCallback(cb func(ctx context.Context, serverID int64, agentMode string)) {
	h.xrayModeCorrectCallback = cb
}

// 处理 WebSocket 升级和连接
// 失败 backoff 参数 — 保守取值,正常 agent 重连(5-10 秒)完全不受影响,
// 只针对每秒数十次的死循环 agent(被删 server 后还在跑的孤儿 agent)生效。
const (
	wsFailCooldown     = 60 * time.Second // 失败后 60 秒内同 IP 直接拒绝 upgrade
	wsFailLogWindow    = 60 * time.Second // 同 IP 失败日志聚合窗口
	wsFailLogThreshold = 3                // 窗口内失败 >=3 次才进入"聚合模式"

	// token 复用判定:旧 conn 最近 LastPing 比这个新就视为"还活着" — 异 IP 抢占算冲突。
	// 比 collector 默认 90s offline 阈值小,确保只锁定真在线的 server。
	tokenConflictFreshness = 60 * time.Second
	// token 冲突 cooldown:winnerIP 一旦确定,期内其它 IP 一律拒绝;到期自动失效,允许真换机。
	tokenConflictCooldown = 60 * time.Second
)

// ipFromRequest 提取客户端真实 IP,优先级:CF-Connecting-IP > X-Real-IP > X-Forwarded-For > RemoteAddr。
func ipFromRequest(r *http.Request) string {
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return cfIP
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if parts := strings.SplitN(forwarded, ",", 2); len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	// RemoteAddr 形如 "1.2.3.4:54321",剥 port 但容忍 IPv6
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// shouldRejectIP 在 upgrade 前调用,看该 IP 是否在 cooldown 期内。
// 返回 (reject, suppressedLogs)。reject=true 时直接关连接;suppressedLogs > 0 时本次拒绝伴随一行汇总日志。
func (h *RemoteWSHandler) shouldRejectIP(ip string) (bool, int) {
	v, ok := h.authFailIPs.Load(ip)
	if !ok {
		return false, 0
	}
	rec := v.(*ipFailRecord)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	now := time.Now()
	if now.Before(rec.rejectUntil) {
		rec.suppressedLogs++
		// 每 60 秒打一次汇总
		if now.Sub(rec.windowStart) >= wsFailLogWindow {
			n := rec.suppressedLogs
			rec.suppressedLogs = 0
			rec.windowStart = now
			return true, n
		}
		return true, 0
	}
	return false, 0
}

// markAuthFail 在 auth 失败(token 错 / payload 错)时调用,更新 IP 失败记录并按需进入 cooldown。
func (h *RemoteWSHandler) markAuthFail(ip string) {
	v, _ := h.authFailIPs.LoadOrStore(ip, &ipFailRecord{windowStart: time.Now()})
	rec := v.(*ipFailRecord)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	now := time.Now()
	// 窗口滑动
	if now.Sub(rec.windowStart) >= wsFailLogWindow {
		rec.windowStart = now
		rec.failsInWindow = 0
	}
	rec.lastFailAt = now
	rec.failsInWindow++
	// 频繁失败 → 进入 cooldown,期间直接拒绝 upgrade
	if rec.failsInWindow >= wsFailLogThreshold {
		rec.rejectUntil = now.Add(wsFailCooldown)
	}
}

// markAuthSuccess 在 auth 成功时调用,清掉该 IP 的失败记录(让合法 agent 不被错误 cooldown)。
func (h *RemoteWSHandler) markAuthSuccess(ip string) {
	h.authFailIPs.Delete(ip)
}

// isTokenConflictRejected 在 conn 进 conns map 前判断:本 token 是否已被另一 IP 锁定。
// 返回 (reject, winnerIP, suppressed)。reject=true 时调用方应立刻 sendAuthResult+return;
// suppressed > 0 表示伴随一行汇总日志(60s 窗口内被压制的拒绝数)。
// 同 winnerIP 重连(fast reconnect)始终放行,不算冲突。
func (h *RemoteWSHandler) isTokenConflictRejected(token, ip string) (bool, string, int) {
	v, ok := h.tokenConflicts.Load(token)
	if !ok {
		return false, "", 0
	}
	rec := v.(*tokenConflictRecord)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	now := time.Now()
	if now.After(rec.rejectUntil) {
		// cooldown 过期 — 不删除,留待 markTokenConflict 覆盖或下次 GC;不影响判定。
		return false, "", 0
	}
	if ip == rec.winnerIP {
		return false, rec.winnerIP, 0
	}
	rec.suppressedLogs++
	// 每 wsFailLogWindow 打一次汇总,避免刷屏
	if now.Sub(rec.windowStart) >= wsFailLogWindow {
		n := rec.suppressedLogs
		rec.suppressedLogs = 0
		rec.windowStart = now
		return true, rec.winnerIP, n
	}
	return true, rec.winnerIP, 0
}

// markTokenConflict 锁定 token 给指定 winnerIP,cooldown 期内拒绝其它 IP 的同 token auth。
// 调用方应在第一次检测到异 IP 抢占时调用,winnerIP 通常选已在线的旧 conn IP(不踢老的)。
func (h *RemoteWSHandler) markTokenConflict(token, winnerIP string) {
	now := time.Now()
	rec := &tokenConflictRecord{
		winnerIP:    winnerIP,
		rejectUntil: now.Add(tokenConflictCooldown),
		windowStart: now,
	}
	h.tokenConflicts.Store(token, rec)
}

func (h *RemoteWSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("User-Agent") != version.AgentUserAgent {
		http.Error(w, "Forbidden", http.StatusForbidden)
		log.Printf("[Remote WS] Rejected connection from %s: invalid User-Agent", r.RemoteAddr)
		return
	}

	clientIP := ipFromRequest(r)

	// 在 upgrade 之前做 IP 级 backoff:
	//   - 孤儿 agent(被删 server 后仍在跑)每秒数十次重连 → 不再消耗 WS 握手 + 密钥协商 CPU
	//   - 合法 agent 不受影响(永远不会失败),网络抖动也不受影响(失败需累计 ≥3 次)
	if rejected, suppressed := h.shouldRejectIP(clientIP); rejected {
		http.Error(w, "Too many failed auth", http.StatusTooManyRequests)
		if suppressed > 0 {
			log.Printf("[Remote WS] Suppressed %d connection attempts from %s in last 60s (auth keeps failing — orphan agent / wrong token)", suppressed, clientIP)
		}
		return
	}

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[Remote WS] Failed to upgrade connection: %v", err)
		return
	}

	log.Printf("[Remote WS] New connection from %s", clientIP)

	// 在 goroutine 中处理连接
	go h.handleConnection(conn, clientIP)
}

// 处理单个 WebSocket 连接
func (h *RemoteWSHandler) handleConnection(conn *websocket.Conn, remoteAddr string) {
	defer conn.Close()

	// 设置连接参数
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// 双向保活:agent 端每 3s 发 traffic frame 维持上行,但中间代理(Cloudflare 等)看的是
	// "agent → master 和 master → agent 都要有 frame"才不算 idle;空闲时段 master 这侧若长时间
	// 没下行,Cloudflare 默认 ~100s 会撕掉 TCP,agent 端就报 `close 1006 unexpected EOF`,
	// 主控随即触发上下线通知。
	//
	// 修复:每 30s 主动从 master 发一个 PingMessage(gorilla/websocket 文档明确 WriteControl 与
	// 主循环的 WriteMessage 并发安全 — 不需要额外加锁)。conn 关闭后 WriteControl 会返回 error,
	// goroutine 自然退出;defer close(pingStop) 兜底,避免 readLoop 在 break 前就阻塞了 goroutine。
	pingStop := make(chan struct{})
	defer close(pingStop)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-pingStop:
				return
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
					return
				}
			}
		}
	}()

	var wsConn *RemoteWSConnection
	authenticated := false

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[Remote WS] Connection error from %s: %v", remoteAddr, err)
			}
			break
		}

		// 加密/明文检测：首字节 0x01 = 加密信封，'{' = 明文 JSON
		if len(message) > 0 && message[0] == securechan.EnvelopeVersion && wsConn != nil && wsConn.session != nil {
			plaintext, err := wsConn.session.Decrypt(message)
			if err != nil {
				log.Printf("[Remote WS] Decrypt error from %s: %v", remoteAddr, err)
				continue
			}
			message = plaintext
		}

		var msg WSMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("[Remote WS] Invalid message from %s: %v", remoteAddr, err)
			continue
		}

		switch msg.Type {
		case WSMsgTypeKeyExchange:
			h.handleKeyExchange(conn, remoteAddr, msg.Payload, &wsConn)
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		case WSMsgTypeAuth:
			wsConn, authenticated = h.handleAuth(conn, wsConn, remoteAddr, msg.Payload)
			if authenticated {
				conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
			}

		case WSMsgTypeTraffic:
			if !authenticated {
				h.sendAuthRequired(conn)
				continue
			}
			h.handleTraffic(wsConn, msg.Payload)
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		case WSMsgTypeHeartbeat:
			if !authenticated {
				h.sendAuthRequired(conn)
				continue
			}
			h.handleHeartbeat(wsConn, msg.Payload, remoteAddr)
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		case WSMsgTypePing:
			// 已注册的连接一律走 sendEncryptedMessage(内部加 writeMu 串行化);仅未建 wsConn 的
			// 预认证阶段(单 goroutine,无并发写)才用裸 sendMessage。
			if wsConn != nil {
				h.sendEncryptedMessage(wsConn, WSMessage{Type: WSMsgTypePong})
			} else {
				h.sendMessage(conn, WSMessage{Type: WSMsgTypePong})
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		case WSMsgTypeSpeed:
			if !authenticated {
				h.sendAuthRequired(conn)
				continue
			}
			h.handleSpeed(wsConn, msg.Payload)
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		case WSMsgTypeCertUpdate:
			if !authenticated {
				h.sendAuthRequired(conn)
				continue
			}
			h.handleCertUpdate(wsConn, msg.Payload)
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		case WSMsgTypeRPCReply:
			// 反向 RPC 响应(也是流式 RPC 的 end 帧):按 RequestID 路由回等待 channel。
			// 不需要 authenticated 限制 — RequestID 唯一性已经保证只能匹配本次 connection
			// 通过 master 主动发起的 pending 调用。routeRPCReply 内部先查 pendingStream(end 帧),
			// 没命中再查 pendingRPC(普通 reply)。
			h.routeRPCReply(msg.Payload)
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		case WSMsgTypeRPCStreamData:
			// 流式中间数据帧 — push 到 pendingStream 对应 channel。
			h.routeRPCStreamData(msg.Payload)
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		case WSMsgTypeScanResult:
			if !authenticated {
				h.sendAuthRequired(conn)
				continue
			}
			h.handleScanResult(wsConn, msg.Payload)
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		case WSMsgTypeDomainLatencyResult:
			if !authenticated {
				h.sendAuthRequired(conn)
				continue
			}
			h.handleDomainLatencyResult(msg.Payload)
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		default:
			log.Printf("[Remote WS] Unknown message type from %s: %s", remoteAddr, msg.Type)
		}
	}

	// 断开连接时清理。注意 agent 快速重启时可能"新连接已经 auth 成功"在前,旧连接 read 报错才唤醒 cleanup。
	// 需要先确认 conns map 里挂的还是 THIS 实例 — 是的话才真的清理 + 标离线;否则新连接已经接管,什么都别动。
	if wsConn != nil {
		h.clearUserSpeedCache(wsConn.ServerID)
		log.Printf("[Remote WS] Connection closed for server %s (%d)", wsConn.ServerName, wsConn.ServerID)
		if cur, ok := h.conns.Load(wsConn.Token); ok && cur == wsConn {
			h.conns.Delete(wsConn.Token)
			connCountsByServer.Delete(wsConn.ServerID)
			nodeConnCountsByServer.Delete(wsConn.ServerID)
			// 没有新连接接管 → 真的下线了,立即标 offline + 发通知(否则要等 traffic collector 下一轮 60s+ 检测)
			// MarkOffline 用带超时的 ctx;通知发送用 context.Background() —— SendServer* 内部异步 go routine 发 telegram,
			// 函数返回后 ctx 取消会把 telegram HTTP 请求一起 abort,通知发不出去。
			dbCtx, dbCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer dbCancel()
			// 只标记离线 + 记 offline_since;**不在这里发下线通知**。下线通知统一由 traffic collector 按"容忍
			// 阈值"防抖发送(离线持续满阈值秒才发)。这样抖动 / agent 升级 / 主控重启后 agent 快速重连时,
			// offline_since 被重连清空,collector 永远走不到发通知那一步 → 一条不发,天然覆盖原升级窗口抑制。
			if prev, name, _, err := h.repo.MarkRemoteServerOfflineByID(dbCtx, wsConn.ServerID); err != nil {
				log.Printf("[Remote WS] mark offline on disconnect failed for %s: %v", wsConn.ServerName, err)
			} else if prev == storage.RemoteServerStatusConnected {
				log.Printf("[Remote WS] %s disconnected: marked offline (下线通知交由容忍阈值防抖的 collector)", name)
			}
		} else {
			log.Printf("[Remote WS] Connection for %s already replaced by newer conn; skip offline marking", wsConn.ServerName)
		}
	}
}

// 处理密钥交换请求
func (h *RemoteWSHandler) handleKeyExchange(conn *websocket.Conn, remoteAddr string, payload json.RawMessage, wsConnPtr **RemoteWSConnection) {
	if h.crypto == nil || h.crypto.Identity == nil {
		log.Printf("[Remote WS] Key exchange from %s but no master identity configured", remoteAddr)
		return
	}

	var kxPayload WSKeyExchangePayload
	if err := json.Unmarshal(payload, &kxPayload); err != nil {
		log.Printf("[Remote WS] Invalid key exchange payload from %s: %v", remoteAddr, err)
		return
	}

	agentEphPub, err := base64.StdEncoding.DecodeString(kxPayload.AgentEphemeralPub)
	if err != nil || len(agentEphPub) != 32 {
		log.Printf("[Remote WS] Invalid agent ephemeral key from %s", remoteAddr)
		return
	}

	masterEphPriv, masterEphPub, err := securechan.GenerateEphemeral()
	if err != nil {
		log.Printf("[Remote WS] Failed to generate ephemeral key: %v", err)
		return
	}

	sharedSecret, err := securechan.ComputeSharedSecret(masterEphPriv, agentEphPub)
	if err != nil {
		log.Printf("[Remote WS] ECDH failed: %v", err)
		return
	}

	session, err := securechan.DeriveSession(sharedSecret, agentEphPub, masterEphPub, true)
	if err != nil {
		log.Printf("[Remote WS] Session derivation failed: %v", err)
		return
	}

	sig := securechan.Sign(h.crypto.Identity.PrivateKey, masterEphPub)

	respPayload, _ := json.Marshal(WSKeyExchangeRespPayload{
		MasterEphemeralPub: base64.StdEncoding.EncodeToString(masterEphPub),
		Signature:          base64.StdEncoding.EncodeToString(sig),
	})
	h.sendMessage(conn, WSMessage{Type: WSMsgTypeKeyExchangeResp, Payload: respPayload})

	// 创建临时 wsConn 持有 session，auth 后会绑定到正式连接
	tempConn := &RemoteWSConnection{
		Conn:      conn,
		session:   session,
		Encrypted: true,
	}
	*wsConnPtr = tempConn

	agentlog.Printf("[Remote WS] Key exchange completed with %s", remoteAddr)
}

// 发送加密消息（如有 session 则加密，否则明文）。
// 这是本连接所有写的唯一入口(读循环响应 + 推送 goroutine),用 writeMu 串行化,
// 防止 gorilla/websocket "concurrent write to websocket connection" panic。
func (h *RemoteWSHandler) sendEncryptedMessage(wsConn *RemoteWSConnection, msg WSMessage) error {
	wsConn.writeMu.Lock()
	defer wsConn.writeMu.Unlock()

	if wsConn.session != nil {
		data, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		envelope, err := wsConn.session.Encrypt(data)
		if err != nil {
			return err
		}
		return wsConn.Conn.WriteMessage(websocket.BinaryMessage, envelope)
	}
	return h.sendMessage(wsConn.Conn, msg)
}

// 处理认证消息
func (h *RemoteWSHandler) handleAuth(conn *websocket.Conn, preAuthConn *RemoteWSConnection, remoteAddr string, payload json.RawMessage) (*RemoteWSConnection, bool) {
	var authPayload WSAuthPayload
	if err := json.Unmarshal(payload, &authPayload); err != nil {
		log.Printf("[Remote WS] Invalid auth payload from %s: %v", remoteAddr, err)
		h.sendAuthResult(conn, false, "Invalid auth payload")
		return nil, false
	}

	if authPayload.Token == "" {
		h.markAuthFail(remoteAddr)
		h.sendAuthResult(conn, false, "Token required")
		return nil, false
	}

	// 验证令牌
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := h.repo.GetRemoteServerByToken(ctx, authPayload.Token)
	if err != nil {
		h.markAuthFail(remoteAddr)
		// 同 IP 失败累计 >=3 次后,这行也按 60s 窗口聚合(see shouldRejectIP suppressed log)
		v, _ := h.authFailIPs.Load(remoteAddr)
		if rec, ok := v.(*ipFailRecord); ok {
			rec.mu.Lock()
			fails := rec.failsInWindow
			rec.mu.Unlock()
			if fails < wsFailLogThreshold {
				log.Printf("[Remote WS] Invalid token from %s", remoteAddr)
			}
		} else {
			log.Printf("[Remote WS] Invalid token from %s", remoteAddr)
		}
		h.sendAuthResult(conn, false, "Invalid token")
		return nil, false
	}
	if authPayload.Probe {
		h.markAuthSuccess(remoteAddr)
		h.sendAuthResult(conn, true, "migration candidate authenticated")
		return nil, false
	}
	// auth 通过 → 清掉该 IP 的失败记录,合法 agent 永远不进 cooldown
	h.markAuthSuccess(remoteAddr)

	// 提前解析 IP — wsConn 要带它,cleanup 时离线通知用 conn 自己的 IP 而不是 DB 里(可能已被新 conn 覆盖)。
	// 也用于 token 复用检测:同 token 异 IP 抢占 → 拒绝并锁定 winnerIP。
	// 从远程地址提取 IP(剥 port,正确处理 [::1]:port 形式 IPv6)
	srcIP := stripPort(remoteAddr)
	srcParsed := net.ParseIP(srcIP)
	srcIsV4 := srcParsed != nil && srcParsed.To4() != nil

	// 严格选 v4 字段:agent 上报的 PublicIPv4 优先;失败 fallback 到源 IP **仅当**源是 v4。
	// 老 bug:agent 端 detectPublicIPv4 在 v4 探测失败时会 fallback 到 v6 → 装进 PublicIPv4 字段
	// → master 用 v6 覆盖 db.ip_address → IPv4-only master 反向 HTTP 全部 502。
	// 修复后:agent 端只返 v4(已修);master 端再加一层校验 — 字段不是合法 v4 字符串就丢弃,
	// 让"上次正确的 v4"留在 db 里(UpdateRemoteServerHeartbeat 用 COALESCE/NULLIF 模式跳过空值)。
	v4 := ""
	if reported := strings.TrimSpace(authPayload.PublicIPv4); reported != "" {
		if p := net.ParseIP(reported); p != nil && p.To4() != nil {
			v4 = reported
		}
	}
	if v4 == "" && srcIsV4 {
		v4 = srcIP
	}
	// wsConn.IPAddress 仍带一份(可能空) — cleanup 通知会用它,但若空就回退用 DB 里的旧值
	ip := v4

	// L1:token 已被另一 IP 锁定 → 直接拒绝(冷却期内每 60s 出一行汇总日志,避免刷屏)。
	// 配 unique token 的合法 agent 命中不到这里;只有 token 复用场景才会被挡。
	if rejected, winnerIP, suppressed := h.isTokenConflictRejected(authPayload.Token, ip); rejected {
		if suppressed > 0 {
			log.Printf("[Remote WS] WARN: agent_token reuse — server %s locked to %s, rejected %d auth attempt(s) from other IP(s) in last %v; latest from %s",
				server.Name, winnerIP, suppressed, wsFailLogWindow, ip)
		}
		h.markAuthFail(remoteAddr)
		h.sendAuthResult(conn, false, "token conflict: another agent is using this token; each server must have a unique agent_token")
		return nil, false
	}

	// 检查是否已有连接 — 有的话表示老 cleanup 还没跑就新 auth 来了(快速重启),记下这个状态供后面发对应通知。
	// L2:异 IP 抢占 + 旧 conn 仍活跃 → token 复用,锁定旧 winner + 拒绝新 conn(不 Close 旧 conn,不动 conns map)。
	// 同 IP fast-reconnect / 旧 conn 已僵(LastPing 超 tokenConflictFreshness)→ 走正常抢占流程。
	existingAny, hadPrev := h.conns.Load(authPayload.Token)
	if hadPrev {
		existing := existingAny.(*RemoteWSConnection)
		existing.mu.Lock()
		existingIP := existing.IPAddress
		existingLastPing := existing.LastPing
		existing.mu.Unlock()

		if existingIP != "" && existingIP != ip && time.Since(existingLastPing) < tokenConflictFreshness {
			log.Printf("[Remote WS] WARN: agent_token reuse detected for server %s — existing conn from %s (last ping %v ago), rejected new conn from %s; locking token to %s for %v. Each server must use a unique agent_token.",
				server.Name, existingIP, time.Since(existingLastPing).Round(time.Second), ip, existingIP, tokenConflictCooldown)
			h.markTokenConflict(authPayload.Token, existingIP)
			h.markAuthFail(remoteAddr)
			h.sendAuthResult(conn, false, "token conflict: another agent is using this token; each server must have a unique agent_token")
			return nil, false
		}

		// 同 IP fast-reconnect 或旧 conn 已僵 → 正常抢占
		if _, ok := h.conns.LoadAndDelete(authPayload.Token); ok {
			existing.mu.Lock()
			existing.Conn.Close()
			existing.mu.Unlock()
			log.Printf("[Remote WS] Closed existing connection for server %s", server.Name)
		}
	}

	// 强制加密检查
	if h.crypto != nil && h.crypto.RequireEncryption() && (preAuthConn == nil || preAuthConn.session == nil) {
		log.Printf("[Remote WS] Encryption required but agent %s has no encrypted session", remoteAddr)
		h.sendAuthResult(conn, false, "Encryption required")
		return nil, false
	}

	// 创建新连接，继承密钥交换阶段的 session
	wsConn := &RemoteWSConnection{
		ServerID:     server.ID,
		ServerName:   server.Name,
		Token:        authPayload.Token,
		Conn:         conn,
		LastPing:     time.Now(),
		Capabilities: authPayload.Capabilities,
		AgentVersion: authPayload.AgentVersion,
		IPAddress:    ip,
	}
	if preAuthConn != nil && preAuthConn.session != nil {
		wsConn.session = preAuthConn.session
		wsConn.Encrypted = true
	}

	h.conns.Store(authPayload.Token, wsConn)
	blockedMasterSteal := (server.StealMode == "tunnel" || server.StealMode == "fallback") &&
		(forbidMasterHTTPSSteal(context.Background(), h.repo, server) ||
			(authPayload.SameHostAsMaster != nil && *authPayload.SameHostAsMaster && masterHTTPSEnabled(context.Background(), h.repo)))
	if blockedMasterSteal {
		if err := h.repo.UpdateRemoteServerStealMode(context.Background(), server.ID, "default"); err != nil {
			log.Printf("[Remote WS] Failed to disable steal-self for same-host HTTPS master %s: %v", server.Name, err)
		} else {
			server.StealMode = "default"
			log.Printf("[Remote WS] Disabled steal-self for same-host HTTPS master %s to protect port 443", server.Name)
		}
		go func(id int64) {
			_ = h.SendConfigUpdate(id, map[string]string{"steal_mode": ""})
		}(server.ID)
	}

	updateCtx, updateCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer updateCancel()
	// auth 时拿到 PublicIPv6 立刻写,**不等首次 heartbeat**(避免 ~10s 窗口期 master 仍不知 v6,
	// 此时若 v4 已经不通,反向请求会失败但有 v6 可用的事实却没被利用)。
	v6 := strings.TrimSpace(authPayload.PublicIPv6)
	ipChanged, latest, err := h.repo.UpdateRemoteServerHeartbeat(updateCtx, authPayload.Token, ip, v6)
	if err != nil {
		log.Printf("[Remote WS] Failed to update server status for %s: %v", server.Name, err)
	} else if ipChanged && latest != nil {
		if h.serverAddressChangeCallback != nil {
			before, after := *server, *latest
			go h.serverAddressChangeCallback(context.Background(), &before, &after)
		}
		// DDNS:agent 换 IP 后把新 IP 同步到 pull_address 域名的 A/AAAA 记录
		if h.ddnsManager != nil && latest.DDNSEnabled {
			go h.ddnsManager.Trigger(context.Background(), latest)
		}
	}
	// 同步 WARP 安装状态 — 跟 IP 字段分开 update 是为了不破坏 UpdateRemoteServerHeartbeat 签名
	if err := h.repo.UpdateRemoteServerWarpInstalled(updateCtx, authPayload.Token, authPayload.WarpInstalled); err != nil {
		log.Printf("[Remote WS] Failed to update warp_installed for %s: %v", server.Name, err)
	}
	if authPayload.SameHostAsMaster != nil {
		if err := h.repo.UpdateRemoteServerSameHost(updateCtx, authPayload.Token, *authPayload.SameHostAsMaster); err != nil {
			log.Printf("[Remote WS] Failed to update same_host_as_master for %s: %v", server.Name, err)
		}
	}

	// 通知策略:
	//   - 抢占式重连(hadPrev=true):**不通知**。这是 supervise-daemon 双开 race / agent 升级 /
	//     用户 rc-service restart / 网络抖动 之类的瞬态事件 — 服务器实际不算"下线",用户看到
	//     上下线通知对刷屏是噪音(历史 BUG:LXC supervise-daemon stop/start race 触发数十次
	//     fast reconnect → 几十对通知 → 风控)。OLD conn 的 cleanup goroutine 会检查 conns map,
	//     看到自己已经被替换会跳过 offline 标记;新 conn 的 auth 路径(else 分支)在状态变化时
	//     才发上线通知 — 这俩配合保证只有"真正离线 → 恢复"才有通知。
	//   - 普通重连(prev offline,新 conn 上来):发上线通知。这是真离线 → 恢复。
	if hadPrev {
		log.Printf("[Remote WS] Detected fast reconnect (old conn replaced) for %s — suppressing notification pair", server.Name)
	} else if server.Status != "connected" {
		if IsServerUpgrading(server.ID) {
			log.Printf("[Remote WS] %s came back online during upgrade window — suppressing online notification", server.Name)
		} else if server.Status == storage.RemoteServerStatusOffline && !server.OfflineNotified {
			// 容忍阈值内恢复:下线通知从未发出(offline_notified=0)→ 上线也不发。抖动 / 主控重启后 agent 快速重连走这里。
			log.Printf("[Remote WS] %s recovered within tolerance (offline never notified) — suppressing online notification", server.Name)
		} else {
			log.Printf("[Remote WS] %s status was %s (offline_notified=%v), sending online notification", server.Name, server.Status, server.OfflineNotified)
			go SendServerOnlineNotification(context.Background(), server.Name, ip)
		}
	}

	// 重置回退状态，以便当 WS 处于活动状态时拉收集器停止
	if err := h.repo.ResetRemoteServerPushFailCount(updateCtx, server.ID); err != nil {
		log.Printf("[Remote WS] Failed to reset fallback for %s: %v", server.Name, err)
	}

	log.Printf("[Remote WS] Server %s (%d) authenticated via WebSocket from %s", server.Name, server.ID, remoteAddr)
	authResultPayload, _ := json.Marshal(WSAuthResultPayload{Success: true, Message: "Authenticated"})
	h.sendEncryptedMessage(wsConn, WSMessage{Type: WSMsgTypeAuthResult, Payload: authResultPayload})

	// WS 认证成功即清除「回退到 HTTP 拉取」标志:auto 模式服务器曾因 WS 断连累计失败触发 fallback_to_pull=1,
	// WS 重连后若不清,collector 会继续 HTTP 轮询 agent 的 :23889(WS stealth 下已关闭)→ 疯狂 refused
	// 刷屏 + 持续写库拖住 WAL checkpoint。WS 在线时 traffic/speed 走 WS 推送,无需 HTTP 拉取。
	if err := h.repo.ResetRemoteServerPushFailCount(ctx, server.ID); err != nil {
		log.Printf("[Remote WS] Failed to reset push fail count for server %d: %v", server.ID, err)
	}

	// 推送许可证状态给 Agent
	if h.licenseManager != nil {
		go h.SendLicenseStatus(wsConn)
		// 地域只在尚未配置时预填；服务商则必须在每次有效 IP 上线时刷新。
		// 否则服务器换 IP、复用旧服务器记录后会残留上一个服务商及其线路标记。
		if ip != "" {
			go func(s *storage.RemoteServer, publicIP string) {
				lookupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				region, err := h.licenseManager.ResolveIPRegion(lookupCtx, publicIP)
				if err != nil {
					return
				}
				if s.Region == "" && region.Flag() != "" {
					_ = h.repo.UpdateRemoteServerProbeMeta(lookupCtx, s.ID, region.Flag(), s.RenewalPrice, s.RenewalCycle, s.RenewalCurrency, s.ExpiresAt)
				}
				_ = h.repo.UpdateRemoteServerLocation(lookupCtx, s.ID, region.Country, region.Region, region.City)
				_ = h.repo.UpdateRemoteServerProvider(lookupCtx, s.ID, region.ProviderName, region.ProviderURL, region.TelecomPaidPeer)
			}(server, ip)
		}
	}

	// 连接/重连时把当前「上报间隔」(dashboard_refresh_interval_ms) 下发给该 agent,
	// 使其立即采用配置值。否则 agent 在 admin 没改动过该设置的情况下会一直用自己的默认值
	// (老 agent 默认 60s)——BroadcastConfigUpdate 只在 admin 主动改动时触发,
	// 覆盖不到"新连接/重连采用现有配置"这一场景。
	if h.repo != nil {
		if val, _ := h.repo.GetSystemSetting(context.Background(), "dashboard_refresh_interval_ms"); val != "" {
			go func(c *RemoteWSConnection, v string) {
				payload, _ := json.Marshal(map[string]string{"traffic_report_interval_ms": v})
				c.mu.Lock()
				defer c.mu.Unlock()
				_ = h.sendEncryptedMessage(c, WSMessage{Type: WSMsgTypeConfigUpdate, Payload: payload})
			}(wsConn, val)
		}
	}

	// 连接/重连时下发当前 debug 日志开关(agent_log_enabled)。agent 侧流量上报等高频日志受此开关控制,
	// 默认关闭;新连/重连的 agent 据此立即采用现有配置(BroadcastConfigUpdate 只覆盖 admin 主动改动的场景)。
	if h.repo != nil {
		if cfg, cerr := h.repo.GetSystemConfig(context.Background()); cerr == nil {
			logVal := "0"
			if cfg.AgentLogEnabled {
				logVal = "1"
			}
			go func(c *RemoteWSConnection, v string) {
				payload, _ := json.Marshal(map[string]string{"agent_log_enabled": v})
				_ = h.sendEncryptedMessage(c, WSMessage{Type: WSMsgTypeConfigUpdate, Payload: payload})
			}(wsConn, logVal)
		}
	}

	// embedded 模式：认证成功后推送限速配置
	// 散布验签:WS auth 路径上再校验一次 embedded license。即便 Step A 入口被绕过、
	// DB 里有 embedded server,连接成功推限速前再拦截一道(limiterPusher 内部 PushToServer
	// 也会 gate,这里提前 return 避免无效 goroutine)。
	if server.XrayMode == "embedded" && h.limiterPusher != nil {
		if h.licenseManager == nil || (h.licenseManager.HasFeature("embedded") && h.licenseManager.HasFeature("limiter")) {
			go h.limiterPusher.PushToServer(context.Background(), server.ID)
		}
	}

	// agent 上线 → 下发当前伪装探针采集配置(开关 + ping 目标)。新 agent 才认这些 key,
	// 旧 agent 忽略。若伪装未开/该 server 未选中,下发全 "0" 让 agent 不采集。
	go h.PushProbeConfigToAgent(context.Background(), server.ID)

	// agent 上线 → 立即下发该 server 的 xray 授权(是否在许可证配额内)。超额 → agent 停 xray;
	// 在配额内 → agent 启 xray。无 license key(开源自建)时 reconcileOne 内部直接跳过、不介入。
	go h.reconcileOne(server.ID)

	// xray 配置 snapshot 同步: server.Status 在 UpdateRemoteServerHeartbeat 之前抓取的就是上次状态
	// (上面 644 行 update 实际是异步,但 server 这个对象是 GetRemoteServerByToken 拿到的快照,字段不会被改写)。
	// prevStatus == "offline" → 写 pending_recovery(VPS 跑路换机场景);其它 → upsert current(SSH 修复 / 首连)
	if h.xrayConfigSyncCallback != nil {
		go h.xrayConfigSyncCallback(context.Background(), server.ID, server.Status)
	}

	// embedded 漂移校正:agent 随 auth 上报当前实际 xray_mode,与 DB 不一致时(DB=embedded 但 agent 卡 external,
	// 通常是 license 失效期被迫切 external、恢复后没同步)自动下发切回 embedded。老 agent 不上报 → 空串 → 跳过。
	if h.xrayModeCorrectCallback != nil && authPayload.XrayMode != "" {
		go h.xrayModeCorrectCallback(context.Background(), server.ID, authPayload.XrayMode)
	}

	if h.masterURLSyncCallback != nil {
		go h.masterURLSyncCallback(context.Background(), server.ID, server.Status)
	}

	// 在第一次连接时自动部署窃取配置（服务器处于挂起状态）。同机 Agent 使用的域名
	// 就是主控域名时，再顺序部署主控反代。必须等偷自己配置完成后再做，二者都会写
	// servers/{domain}.conf，并发下发会让最后完成的一方随机覆盖另一方。
	if server.Use443 && server.Domain != "" && server.Status == "pending" && h.stealSelfDeployer != nil && !blockedMasterSteal &&
		!(authPayload.SameHostAsMaster != nil && *authPayload.SameHostAsMaster && masterHTTPSEnabled(context.Background(), h.repo)) {
		go func() {
			// Agent 首次认证发生在安装脚本尚未结束时很常见。旧逻辑只等 5 秒并尝试一次：
			// Nginx 未装完或证书尚未就绪就永久错过自动部署（状态随后已变 connected）。
			// 在两分钟窗口内有限重试；各步骤均为覆盖式下发，可安全重复。
			time.Sleep(5 * time.Second)
			var deployErr error
			for attempt := 1; attempt <= 12; attempt++ {
				deployCtx, deployCancel := context.WithTimeout(context.Background(), 60*time.Second)
				deployErr = h.stealSelfDeployer(deployCtx, server.ID)
				deployCancel()
				if deployErr == nil {
					log.Printf("[Remote WS] Auto-deployed steal-self config for server %s (%d), attempt=%d", server.Name, server.ID, attempt)
					break
				}
				log.Printf("[Remote WS] Auto-deploy steal-self config not ready for server %s (%d), attempt=%d/12: %v", server.Name, server.ID, attempt, deployErr)
				if attempt < 12 {
					time.Sleep(10 * time.Second)
				}
			}
			if deployErr != nil {
				log.Printf("[Remote WS] Failed to auto-deploy steal-self config for server %s (%d) after retries: %v", server.Name, server.ID, deployErr)
				return
			}

		}()
	}

	return wsConn, true
}

// 处理流量数据消息
func (h *RemoteWSHandler) handleTraffic(wsConn *RemoteWSConnection, payload json.RawMessage) {
	var trafficPayload WSTrafficPayload
	if err := json.Unmarshal(payload, &trafficPayload); err != nil {
		log.Printf("[Remote WS] Invalid traffic payload from server %s: %v", wsConn.ServerName, err)
		return
	}

	if trafficPayload.Stats == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, _, _, _, err := h.repo.UpdateRemoteServerLastActivity(ctx, wsConn.ServerID); err != nil {
		log.Printf("[Remote WS] Failed to update last activity for server %s: %v", wsConn.ServerName, err)
	}
	// 上线通知由 auth handler 那一头负责发(WS 重连必然走 auth),这里不重复

	// 从 db 读 xray_boot_time 用于真重启判定(避免 collector 启发式误判把 client 增删当 xray 重启)
	var xrayBootTime *time.Time
	if server, gerr := h.repo.GetRemoteServer(ctx, wsConn.ServerID); gerr == nil && server != nil {
		xrayBootTime = server.XrayBootTime
	}
	if err := h.collector.ProcessRemoteMetrics(ctx, wsConn.ServerID, trafficPayload.Stats, xrayBootTime); err != nil {
		log.Printf("[Remote WS] Failed to process traffic from server %s: %v", wsConn.ServerName, err)
		return
	}

	// 存最近一次 group 并发连接数(nil = 该 server 当前无连接,覆盖清零)。
	connCountsByServer.Store(wsConn.ServerID, trafficPayload.ConnCounts)
	nodeConnCountsByServer.Store(wsConn.ServerID, trafficPayload.NodeConnCounts)

	// 系统级网卡累计 — 同 HTTP path 的 RemoteTrafficHandler 处理。WS path 之前漏了这段,
	// 导致 source=system 的 server 在 WS 连接模式下 system_*_cycle 永远不动 → traffic_used 静止。
	// 失败只 log 不阻塞(跟 HTTP path 一致);老 agent payload.System==nil → 自动跳过。
	if trafficPayload.System != nil {
		if err := h.repo.UpsertRemoteServerSystemTraffic(ctx, wsConn.ServerID,
			trafficPayload.System.RxTotal, trafficPayload.System.TxTotal, trafficPayload.System.BootTimeUnix); err != nil {
			log.Printf("[Remote WS] Failed to upsert system traffic for server %s: %v", wsConn.ServerName, err)
		}
	}

	// 伪装探针真数据 → 内存 ring(旧 agent 不上报这两个字段,自动跳过)。
	if h.probeStore != nil {
		if sm := trafficPayload.Sysmetrics; sm != nil || trafficPayload.System != nil {
			snap := ProbeSysSnapshot{}
			if sm != nil {
				snap = ProbeSysSnapshot{
					CPUPct: sm.CPUPct, LoadAvg: sm.LoadAvg,
					MemUsed: sm.MemUsed, MemTotal: sm.MemTotal,
					DiskUsed: sm.DiskUsed, DiskTotal: sm.DiskTotal,
					HasCPU: sm.HasCPU, HasMem: sm.HasMem, HasDisk: sm.HasDisk,
					Uptime: sm.Uptime, CPUModel: sm.CPUModel, CPUCores: sm.CPUCores, CPUThreads: sm.CPUThreads,
					OS: sm.OS, Kernel: sm.Kernel, Arch: sm.Arch,
				}
			}
			if trafficPayload.System != nil {
				snap.CumulativeUp, snap.CumulativeDown = trafficPayload.System.TxTotal, trafficPayload.System.RxTotal
				snap.HasNetwork = true
			}
			h.probeStore.IngestSys(wsConn.ServerID, snap)
		}
		if len(trafficPayload.Latency) > 0 {
			h.probeStore.IngestLatency(wsConn.ServerID, trafficPayload.Latency)
		}
	}

	if len(trafficPayload.UserSpeeds) > 0 {
		serverID := wsConn.ServerID
		for email, speed := range trafficPayload.UserSpeeds {
			h.userSpeedCache.Store(fmt.Sprintf("%d:%s", serverID, email), speed)
		}
	}

	agentlog.Printf("[Remote WS] Processed traffic from server %s: %d inbounds, %d outbounds, %d users",
		wsConn.ServerName,
		len(trafficPayload.Stats.Inbound),
		len(trafficPayload.Stats.Outbound),
		len(trafficPayload.Stats.User))
}

// 处理心跳消息
func (h *RemoteWSHandler) handleHeartbeat(wsConn *RemoteWSConnection, payload json.RawMessage, remoteAddr string) {
	var hbPayload WSHeartbeatPayload
	if err := json.Unmarshal(payload, &hbPayload); err != nil {
		log.Printf("[Remote WS] Invalid heartbeat payload from server %s: %v", wsConn.ServerName, err)
	}

	wsConn.mu.Lock()
	wsConn.LastPing = time.Now()
	wsConn.mu.Unlock()

	// 更新数据库中的心跳
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 严格选 v4 字段(同 handleAuth):agent 上报的 PublicIPv4 必须是合法 v4 才用;
	// 否则 fallback 到 WS 源 IP 也只在源 IP 是 v4 时启用;都不是 v4 → 空,
	// 走 DB UPDATE 时 COALESCE 保留旧值。
	srcIP := stripPort(remoteAddr)
	srcParsed := net.ParseIP(srcIP)
	srcIsV4 := srcParsed != nil && srcParsed.To4() != nil

	v4 := ""
	if reported := strings.TrimSpace(hbPayload.PublicIPv4); reported != "" {
		if p := net.ParseIP(reported); p != nil && p.To4() != nil {
			v4 = reported
		}
	}
	if v4 == "" && srcIsV4 {
		v4 = srcIP
	}

	update := storage.HeartbeatUpdate{
		Token:      wsConn.Token,
		IPAddress:  v4, // 空则 storage 层 COALESCE 保留 db 旧值
		ListenPort: hbPayload.ListenPort,
	}
	if v := strings.TrimSpace(hbPayload.PublicIPv6); v != "" {
		if p := net.ParseIP(v); p != nil && p.To4() == nil {
			update.IPAddressV6 = v // 合法 v6 才存
		}
	}
	if hbPayload.BootTime != nil {
		update.BootTime = hbPayload.BootTime
	}
	if hbPayload.XrayBootTime != nil {
		update.XrayBootTime = hbPayload.XrayBootTime
	}
	if hbPayload.LocalTimestamp > 0 {
		offset := hbPayload.LocalTimestamp - time.Now().Unix()
		update.TimeOffsetSeconds = &offset
	}

	if hbResult, err := h.repo.UpdateRemoteServerHeartbeatWithRestart(ctx, update); err != nil {
		log.Printf("[Remote WS] Failed to update heartbeat for server %s: %v", wsConn.ServerName, err)
	} else if hbResult != nil && hbResult.IPChanged && hbResult.Server != nil {
		if h.serverAddressChangeCallback != nil && hbResult.PreviousServer != nil {
			before, after := *hbResult.PreviousServer, *hbResult.Server
			go h.serverAddressChangeCallback(context.Background(), &before, &after)
		}
		// DDNS:同步新 IP 到域名 A/AAAA 记录
		if h.ddnsManager != nil && hbResult.Server.DDNSEnabled {
			go h.ddnsManager.Trigger(context.Background(), hbResult.Server)
		}
	}
	// 心跳里也带 warp_installed,跟踪 agent 主动 install/remove 后的状态变化
	if err := h.repo.UpdateRemoteServerWarpInstalled(ctx, wsConn.Token, hbPayload.WarpInstalled); err != nil {
		log.Printf("[Remote WS] Failed to update warp_installed for server %s: %v", wsConn.ServerName, err)
	}
	if hbPayload.SameHostAsMaster != nil {
		if err := h.repo.UpdateRemoteServerSameHost(ctx, wsConn.Token, *hbPayload.SameHostAsMaster); err != nil {
			log.Printf("[Remote WS] Failed to update same_host_as_master for server %s: %v", wsConn.ServerName, err)
		}
	}

	ackPayload, _ := json.Marshal(map[string]int64{"server_time": time.Now().Unix()})
	h.sendEncryptedMessage(wsConn, WSMessage{Type: WSMsgTypeHeartbeatAck, Payload: json.RawMessage(ackPayload)})
}

// 处理实时速度数据消息
func (h *RemoteWSHandler) handleSpeed(wsConn *RemoteWSConnection, payload json.RawMessage) {
	var speedPayload WSSpeedPayload
	if err := json.Unmarshal(payload, &speedPayload); err != nil {
		log.Printf("[Remote WS] Invalid speed payload from server %s: %v", wsConn.ServerName, err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// UpdateRemoteServerSpeed 同一条语句同时刷新在线状态和 last_heartbeat，
	// 避免每次速度上报产生两次数据库写入。
	if err := h.repo.UpdateRemoteServerSpeed(ctx, wsConn.ServerID, speedPayload.UploadSpeed, speedPayload.DownloadSpeed); err != nil {
		log.Printf("[Remote WS] Failed to update speed for server %s: %v", wsConn.ServerName, err)
		return
	}

	agentlog.Printf("[Remote WS] Updated speed from server %s: ↑%d B/s ↓%d B/s",
		wsConn.ServerName, speedPayload.UploadSpeed, speedPayload.DownloadSpeed)
}

// 发送认证结果消息
func (h *RemoteWSHandler) sendAuthResult(conn *websocket.Conn, success bool, message string) {
	payload, _ := json.Marshal(WSAuthResultPayload{
		Success: success,
		Message: message,
	})
	h.sendMessage(conn, WSMessage{
		Type:    WSMsgTypeAuthResult,
		Payload: payload,
	})
}

// 发送需要身份验证的消息
func (h *RemoteWSHandler) sendAuthRequired(conn *websocket.Conn) {
	h.sendAuthResult(conn, false, "Authentication required")
}

// 发送 WebSocket 消息
func (h *RemoteWSHandler) sendMessage(conn *websocket.Conn, msg WSMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, data)
}

// 检查服务器是否通过 WebSocket 连接
func (h *RemoteWSHandler) IsConnected(token string) bool {
	_, ok := h.conns.Load(token)
	return ok
}

// 返回已连接服务器令牌的列表
func (h *RemoteWSHandler) GetConnectedServers() []string {
	var tokens []string
	h.conns.Range(func(key, value interface{}) bool {
		tokens = append(tokens, key.(string))
		return true
	})
	return tokens
}

func (h *RemoteWSHandler) IsConnectionEncrypted(token string) bool {
	connInterface, ok := h.conns.Load(token)
	if !ok {
		return false
	}
	wsConn := connInterface.(*RemoteWSConnection)
	return wsConn.Encrypted
}

// 将配置更新发送到特定服务器
func (h *RemoteWSHandler) BroadcastConfig(token string, config interface{}) error {
	connInterface, ok := h.conns.Load(token)
	if !ok {
		return nil
	}

	wsConn := connInterface.(*RemoteWSConnection)
	payload, err := json.Marshal(config)
	if err != nil {
		return err
	}

	wsConn.mu.Lock()
	defer wsConn.mu.Unlock()

	return h.sendEncryptedMessage(wsConn, WSMessage{
		Type:    WSMsgTypeConfig,
		Payload: payload,
	})
}

// SendLimiterConfig 向指定服务器推送限速配置
func (h *RemoteWSHandler) SendLimiterConfig(serverID int64, configs []WSLimiterConfigPayload) error {
	wsConn, ok := h.GetConnectionByServerID(serverID)
	if !ok {
		return nil
	}

	wsConn.mu.Lock()
	defer wsConn.mu.Unlock()

	for _, cfg := range configs {
		payload, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		if err := h.sendEncryptedMessage(wsConn, WSMessage{
			Type:    WSMsgTypeLimiterConfig,
			Payload: payload,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (h *RemoteWSHandler) SendConfigUpdate(serverID int64, updates map[string]string) error {
	wsConn, ok := h.GetConnectionByServerID(serverID)
	if !ok {
		return nil
	}

	wsConn.mu.Lock()
	defer wsConn.mu.Unlock()

	payload, err := json.Marshal(updates)
	if err != nil {
		return err
	}
	return h.sendEncryptedMessage(wsConn, WSMessage{
		Type:    WSMsgTypeConfigUpdate,
		Payload: payload,
	})
}

// BroadcastConfigUpdate 把 config_update 推给所有当前 WS-mode 在线 agent。
// 用于 admin 在主控修改全局配置(如 traffic_report_interval_ms)后立即生效。
// 非 WS mode (HTTP/Pull) 通过其他通道 (HTTP traffic response 携带) 同步,见 RemoteTrafficHandler。
func (h *RemoteWSHandler) BroadcastConfigUpdate(updates map[string]string) {
	payload, err := json.Marshal(updates)
	if err != nil {
		log.Printf("[Remote WS] BroadcastConfigUpdate marshal failed: %v", err)
		return
	}
	h.conns.Range(func(_, v any) bool {
		wsConn, ok := v.(*RemoteWSConnection)
		if !ok {
			return true
		}
		wsConn.mu.Lock()
		_ = h.sendEncryptedMessage(wsConn, WSMessage{
			Type:    WSMsgTypeConfigUpdate,
			Payload: payload,
		})
		wsConn.mu.Unlock()
		return true
	})
}

// SendLicenseStatus 向指定连接推送许可证状态
func (h *RemoteWSHandler) SendLicenseStatus(wsConn *RemoteWSConnection) {
	if h.licenseManager == nil {
		return
	}
	status := h.licenseManager.StatusForAgent()
	payload, err := json.Marshal(status)
	if err != nil {
		return
	}
	wsConn.mu.Lock()
	defer wsConn.mu.Unlock()
	_ = h.sendEncryptedMessage(wsConn, WSMessage{
		Type:    WSMsgTypeLicenseStatus,
		Payload: payload,
	})
}

// BroadcastLicenseStatus 向所有已连接的 Agent 广播许可证状态
func (h *RemoteWSHandler) BroadcastLicenseStatus() {
	h.conns.Range(func(_, value any) bool {
		wsConn := value.(*RemoteWSConnection)
		h.SendLicenseStatus(wsConn)
		return true
	})
}

// 删除最近未执行 ping 操作的陈旧连接
func (h *RemoteWSHandler) CleanupStaleConnections(timeout time.Duration) {
	cutoff := time.Now().Add(-timeout)

	h.conns.Range(func(key, value interface{}) bool {
		wsConn := value.(*RemoteWSConnection)
		wsConn.mu.Lock()
		lastPing := wsConn.LastPing
		wsConn.mu.Unlock()

		if lastPing.Before(cutoff) {
			log.Printf("[Remote WS] Cleaning up stale connection for server %s", wsConn.ServerName)
			wsConn.Conn.Close()
			h.conns.Delete(key)
		}
		return true
	})

	// 顺带清理过期的 auth 失败 / token 冲突记录(平时只在成功时删,持续失败/冲突的源会累积)
	now := time.Now()
	h.authFailIPs.Range(func(key, value interface{}) bool {
		rec := value.(*ipFailRecord)
		rec.mu.Lock()
		stale := now.After(rec.rejectUntil) && now.Sub(rec.lastFailAt) > wsFailLogWindow
		rec.mu.Unlock()
		if stale {
			h.authFailIPs.Delete(key)
		}
		return true
	})
	h.tokenConflicts.Range(func(key, value interface{}) bool {
		rec := value.(*tokenConflictRecord)
		rec.mu.Lock()
		stale := now.After(rec.rejectUntil)
		rec.mu.Unlock()
		if stale {
			h.tokenConflicts.Delete(key)
		}
		return true
	})
}

// 启动一个 goroutine，定期清理过时的连接
func (h *RemoteWSHandler) StartCleanupLoop(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.CleanupStaleConnections(5 * time.Minute)
			}
		}
	}()
}

// DEAD CODE — 向特定远程服务器发送证书请求。
// agent 端 client.go 没有 case WSMsgTypeCertRequest,消息发到 agent 走 default case 忽略。
// 唯一调用方:certificates_manage.go requestRemoteCertificate(remote_server_id > 0 路径)。
// 详见 requestRemoteCertificate 的注释,要修复请改成 master 本地申请 + deploy 推送。
func (h *RemoteWSHandler) SendCertRequest(token string, payload WSCertRequestPayload) error {
	connInterface, ok := h.conns.Load(token)
	if !ok {
		return errors.New("server not connected")
	}

	wsConn := connInterface.(*RemoteWSConnection)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	wsConn.mu.Lock()
	defer wsConn.mu.Unlock()

	return h.sendEncryptedMessage(wsConn, WSMessage{
		Type:    WSMsgTypeCertRequest,
		Payload: payloadBytes,
	})
}

// 向特定远程服务器发送证书部署命令
func (h *RemoteWSHandler) SendCertDeploy(token string, payload WSCertDeployPayload) error {
	connInterface, ok := h.conns.Load(token)
	if !ok {
		return errors.New("server not connected")
	}

	wsConn := connInterface.(*RemoteWSConnection)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	wsConn.mu.Lock()
	defer wsConn.mu.Unlock()

	return h.sendEncryptedMessage(wsConn, WSMessage{
		Type:    WSMsgTypeCertDeploy,
		Payload: payloadBytes,
	})
}

// CertUpdateHandler 是处理证书更新的回调函数类型
type CertUpdateHandler func(serverID int64, payload WSCertUpdatePayload)

// certUpdateHandler 存储证书更新的回调
var certUpdateHandler CertUpdateHandler

// 设置处理证书更新消息的回调
func (h *RemoteWSHandler) SetCertUpdateHandler(handler CertUpdateHandler) {
	certUpdateHandler = handler
}

// 处理来自远程服务器的证书更新消息
func (h *RemoteWSHandler) handleCertUpdate(wsConn *RemoteWSConnection, payload json.RawMessage) {
	var certPayload WSCertUpdatePayload
	if err := json.Unmarshal(payload, &certPayload); err != nil {
		log.Printf("[Remote WS] Invalid cert_update payload from %s: %v", wsConn.ServerName, err)
		return
	}

	log.Printf("[Remote WS] Received cert_update from %s: domain=%s, success=%v",
		wsConn.ServerName, certPayload.Domain, certPayload.Success)

	// 调用已注册的处理程序（如果可用）
	if certUpdateHandler != nil {
		certUpdateHandler(wsConn.ServerID, certPayload)
	}
}

// WSScanResultPayload 表示扫描结果负载（Agent -> Master）
type WSScanResultPayload struct {
	XrayRunning bool                     `json:"xray_running"`
	XrayVersion string                   `json:"xray_version,omitempty"`
	Inbounds    []map[string]interface{} `json:"inbounds,omitempty"`
	// 每个 email 累计「连接数超限被拒」次数(自 agent 启动起单调递增)。
	// 主控按 delta = current - prev_seen 算单周期增量,delta>0 触发 tg 通知。
	// 向后兼容:老 agent 无此字段 → 主控当 0;新 agent + 老主控也无害。
	DeviceKicks map[string]int64 `json:"device_kicks,omitempty"`
}

// ScanResultHandler 是处理扫描结果的回调函数类型
type ScanResultHandler func(serverID int64, payload WSScanResultPayload)

// scanResultHandler 存储扫描结果的回调
var scanResultHandler ScanResultHandler

// 设置处理扫描结果消息的回调
func (h *RemoteWSHandler) SetScanResultHandler(handler ScanResultHandler) {
	scanResultHandler = handler
}

// 设置首次连接时自动部署steal-self 配置的回调
func (h *RemoteWSHandler) SetStealSelfDeployer(deployer func(ctx context.Context, serverID int64) error) {
	h.stealSelfDeployer = deployer
}

// SetMasterURLSyncCallback 注入 Agent 上线时的主控地址闭环同步。
func (h *RemoteWSHandler) SetMasterURLSyncCallback(cb func(ctx context.Context, serverID int64, prevStatus string)) {
	h.masterURLSyncCallback = cb
}

// 处理来自远程服务器的扫描结果消息
func (h *RemoteWSHandler) handleScanResult(wsConn *RemoteWSConnection, payload json.RawMessage) {
	var scanPayload WSScanResultPayload
	if err := json.Unmarshal(payload, &scanPayload); err != nil {
		log.Printf("[Remote WS] Invalid scan_result payload from %s: %v", wsConn.ServerName, err)
		return
	}

	log.Printf("[Remote WS] Received scan_result from %s: xray_running=%v, inbounds=%d",
		wsConn.ServerName, scanPayload.XrayRunning, len(scanPayload.Inbounds))

	if scanResultHandler != nil {
		scanResultHandler(wsConn.ServerID, scanPayload)
	}
}

// WSTokenUpdatePayload 表示令牌更新负载（Master -> Agent）
type WSTokenUpdatePayload struct {
	ServerToken string    `json:"server_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// 向连接的代理发送新的服务器令牌
func (h *RemoteWSHandler) SendTokenUpdate(oldToken string, newToken string, expiresAt time.Time) error {
	connInterface, ok := h.conns.Load(oldToken)
	if !ok {
		return errors.New("server not connected")
	}

	wsConn := connInterface.(*RemoteWSConnection)

	payload := WSTokenUpdatePayload{
		ServerToken: newToken,
		ExpiresAt:   expiresAt,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	wsConn.mu.Lock()
	defer wsConn.mu.Unlock()

	err = h.sendEncryptedMessage(wsConn, WSMessage{
		Type:    WSMsgTypeTokenUpdate,
		Payload: payloadBytes,
	})

	if err != nil {
		return err
	}

	// 更新连接的令牌引用
	h.conns.Delete(oldToken)
	wsConn.Token = newToken
	h.conns.Store(newToken, wsConn)

	log.Printf("[Remote WS] Sent token_update to server %s, new token will expire at %s",
		wsConn.ServerName, expiresAt.Format(time.RFC3339))

	return nil
}

// 处理来自代理的域延迟探测结果
func (h *RemoteWSHandler) handleDomainLatencyResult(payload json.RawMessage) {
	var result WSDomainLatencyResultPayload
	if err := json.Unmarshal(payload, &result); err != nil {
		log.Printf("[Remote WS] Invalid domain_latency_result payload: %v", err)
		return
	}

	if ch, ok := h.pendingProbes.Load(result.RequestID); ok {
		ch.(chan WSDomainLatencyResultPayload) <- result
	}
}

// 通过 WebSocket 向代理发送域延迟探测请求并等待结果。
func (h *RemoteWSHandler) SendDomainLatencyProbe(serverID int64, domains []string, timeoutMs int) (*WSDomainLatencyResultPayload, error) {
	wsConn, ok := h.GetConnectionByServerID(serverID)
	if !ok {
		return nil, errors.New("server not connected via WebSocket")
	}

	requestID := time.Now().UnixNano()
	reqID := fmt.Sprintf("%d-%d", serverID, requestID)

	resultCh := make(chan WSDomainLatencyResultPayload, 1)
	h.pendingProbes.Store(reqID, resultCh)
	defer func() {
		h.pendingProbes.Delete(reqID)
		close(resultCh)
	}()

	probePayload := WSDomainLatencyProbePayload{
		RequestID: reqID,
		Domains:   domains,
		TimeoutMs: timeoutMs,
	}
	payloadBytes, err := json.Marshal(probePayload)
	if err != nil {
		return nil, fmt.Errorf("marshal probe payload: %w", err)
	}

	wsConn.mu.Lock()
	err = h.sendEncryptedMessage(wsConn, WSMessage{
		Type:    WSMsgTypeDomainLatencyProbe,
		Payload: payloadBytes,
	})
	wsConn.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("send probe message: %w", err)
	}

	// 等待超时结果（探测超时 + 5 秒缓冲区）
	waitTimeout := time.Duration(timeoutMs)*time.Millisecond + 5*time.Second
	select {
	case result := <-resultCh:
		return &result, nil
	case <-time.After(waitTimeout):
		return nil, fmt.Errorf("domain latency probe timed out after %v", waitTimeout)
	}
}

// 按服务器 ID 返回服务器的 WebSocket 连接
func (h *RemoteWSHandler) GetConnectionByServerID(serverID int64) (*RemoteWSConnection, bool) {
	var found *RemoteWSConnection
	h.conns.Range(func(key, value any) bool {
		wsConn := value.(*RemoteWSConnection)
		if wsConn.ServerID == serverID {
			found = wsConn
			return false // 停止迭代
		}
		return true
	})
	return found, found != nil
}

func (h *RemoteWSHandler) clearUserSpeedCache(serverID int64) {
	prefix := fmt.Sprintf("%d:", serverID)
	h.userSpeedCache.Range(func(key, _ any) bool {
		if k, ok := key.(string); ok && strings.HasPrefix(k, prefix) {
			h.userSpeedCache.Delete(key)
		}
		return true
	})
}

func (h *RemoteWSHandler) GetUserSpeeds(serverID int64) map[string]int64 {
	prefix := fmt.Sprintf("%d:", serverID)
	result := make(map[string]int64)
	h.userSpeedCache.Range(func(key, value any) bool {
		if k, ok := key.(string); ok && strings.HasPrefix(k, prefix) {
			email := k[len(prefix):]
			if speed, ok := value.(int64); ok {
				result[email] = speed
			}
		}
		return true
	})
	return result
}
