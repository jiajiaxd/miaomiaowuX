package handler

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"encoding/base64"
	"sync"

	"github.com/google/uuid"

	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/event"
	"miaomiaowux/internal/license"
	"miaomiaowux/internal/securechan"
	"miaomiaowux/internal/storage"
	"miaomiaowux/internal/version"
	"miaomiaowux/templates"
)

// RemoteManageHandler 处理需要转发到子服务器的管理请求
type RemoteManageHandler struct {
	repo                *storage.TrafficRepository
	wsHandler           *RemoteWSHandler
	httpClient          *http.Client
	certHandler         *CertificateHandler
	crypto              *CryptoConfig
	pullSessions        sync.Map // serverID (int64) → *securechan.Session
	fedSessions         sync.Map // serverID (int64) → *securechan.Session (联邦:消费方↔拥有方)
	stealSelfDeployer   func(ctx context.Context, serverID int64) error
	licenseManager      *license.Manager // 同步入站时检查 routed 节点 license 上限,setter 注入
	inboundCache        *InboundCache    // 从 xray config snapshot 派生,套餐绑/换绑 cred 计算用,setter 注入
	onMasterMigrated    func(context.Context, string)
	yamlSyncManager     *YAMLSyncManager
	serverAddressSyncMu sync.Mutex
}

// SetSubscribeDir enables synchronization of persisted YAML subscriptions when
// server addresses change.
func (h *RemoteManageHandler) SetSubscribeDir(dir string) {
	h.yamlSyncManager = NewYAMLSyncManager(dir)
}

func (h *RemoteManageHandler) SetOnMasterMigrated(fn func(context.Context, string)) {
	h.onMasterMigrated = fn
}

type masterMigrationRequest struct {
	Action       string `json:"action"`
	NewMasterURL string `json:"new_master_url"`
	ChangeDomain bool   `json:"change_domain"`
	MoveHost     bool   `json:"move_host"`
	Force        bool   `json:"force"`
}

type masterMigrationAgentResult struct {
	ServerID  int64  `json:"server_id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Protected bool   `json:"protected_transport,omitempty"`
}

// HandleMasterMigration implements a two-phase migration. Preview probes the
// candidate from every connected Agent; commit probes again before changing any
// Agent config. Same-host transports are preserved unless the master moves host.
func (h *RemoteManageHandler) HandleMasterMigration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req masterMigrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	req.NewMasterURL = strings.TrimRight(strings.TrimSpace(req.NewMasterURL), "/")
	candidate, err := url.ParseRequestURI(req.NewMasterURL)
	if err != nil || candidate.Host == "" || (candidate.Scheme != "http" && candidate.Scheme != "https") || candidate.RawQuery != "" || candidate.Fragment != "" {
		remoteWriteError(w, http.StatusBadRequest, "new_master_url must be a clean HTTP(S) origin")
		return
	}
	currentRaw, _ := h.repo.GetSystemSetting(r.Context(), "master_url")
	current, _ := url.Parse(strings.TrimSpace(currentRaw))
	if !req.ChangeDomain && current != nil && !strings.EqualFold(current.Hostname(), candidate.Hostname()) {
		remoteWriteError(w, http.StatusBadRequest, "未选择更换域名，新地址必须使用当前主控域名")
		return
	}
	if req.ChangeDomain && current != nil && strings.EqualFold(current.Hostname(), candidate.Hostname()) {
		remoteWriteError(w, http.StatusBadRequest, "已选择更换域名，但新旧主控域名相同")
		return
	}
	servers, err := h.repo.ListRemoteServers(r.Context())
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	results := make([]masterMigrationAgentResult, 0, len(servers))
	ready := true
	for i := range servers {
		s := &servers[i]
		result := masterMigrationAgentResult{ServerID: s.ID, Name: s.Name}
		if s.IsFederated {
			result.Status, result.Message = "skipped", "联邦服务器不由当前主控改写"
			results = append(results, result)
			continue
		}
		if s.SameHostAsMaster && !req.MoveHost {
			result.Status, result.Message, result.Protected = "preserved", "保留本机/容器内网连接地址", true
			results = append(results, result)
			continue
		}
		if s.Status != storage.RemoteServerStatusConnected {
			result.Status, result.Message = "offline", "Agent 离线，无法预下发迁移地址"
			ready = false
			results = append(results, result)
			continue
		}
		payload, _ := json.Marshal(map[string]string{"master_url": req.NewMasterURL})
		resp, probeErr := h.forwardToRemoteServer(r.Context(), s.ID, http.MethodPost, "/api/child/agent/probe-master-url", payload)
		if probeErr != nil {
			result.Status, result.Message = "failed", probeErr.Error()
			ready = false
		} else {
			var probe struct {
				Success   bool   `json:"success"`
				Message   string `json:"message"`
				LatencyMS int64  `json:"latency_ms"`
			}
			if json.Unmarshal(resp, &probe) != nil || !probe.Success {
				result.Status, result.Message = "failed", probe.Message
				if result.Message == "" {
					result.Message = "Agent 无法访问新主控"
				}
				ready = false
			} else {
				result.Status, result.LatencyMS = "ready", probe.LatencyMS
			}
		}
		results = append(results, result)
	}
	if req.Action == "commit" {
		if !ready && !req.Force {
			remoteWriteJSON(w, http.StatusConflict, map[string]interface{}{"success": false, "ready": false, "agents": results, "message": "仍有 Agent 未通过迁移检查"})
			return
		}
		for i, result := range results {
			if result.Status != "ready" {
				continue
			}
			s := &servers[i]
			if err := h.syncMasterURLToAgentWithPolicy(r.Context(), s, req.NewMasterURL, req.MoveHost); err != nil {
				results[i].Status, results[i].Message = "failed", err.Error()
				ready = false
			}
		}
		if !ready && !req.Force {
			remoteWriteJSON(w, http.StatusConflict, map[string]interface{}{"success": false, "ready": false, "agents": results, "message": "部分 Agent 地址写入失败，主控地址未切换"})
			return
		}
		if err := h.repo.SetSystemSetting(r.Context(), "master_url", req.NewMasterURL); err != nil {
			remoteWriteError(w, http.StatusInternalServerError, "保存主控地址失败")
			return
		}
		// Turnstile widgets are restricted by the hostnames configured in
		// Cloudflare.  After a domain migration the old widget can make the new
		// login page unusable, so disable it before redirecting the administrator
		// to the new origin.  Keep the secret key: clearing the public site key is
		// sufficient to disable verification and lets the administrator replace
		// both values from Security Settings after logging in.
		if req.ChangeDomain {
			if err := h.repo.SetSystemSetting(r.Context(), "turnstile_site_key", ""); err != nil {
				remoteWriteError(w, http.StatusInternalServerError, "主控地址已更新，但关闭 Cloudflare 验证码失败；请通过旧会话手动关闭")
				return
			}
		}
		if h.onMasterMigrated != nil {
			go h.onMasterMigrated(context.Background(), req.NewMasterURL)
		}
	}
	remoteWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success":            true,
		"ready":              ready,
		"committed":          req.Action == "commit",
		"agents":             results,
		"turnstile_disabled": req.Action == "commit" && req.ChangeDomain,
	})
}

// SetLicenseManager 注入 license 管理器供 syncInboundsToNodes 做节点数量上限检查。
// nil = 不检查(开发场景),跟 nodes / routed_outbound 同款 pattern。
func (h *RemoteManageHandler) SetLicenseManager(mgr *license.Manager) {
	h.licenseManager = mgr
}

// SetInboundCache 注入 inbound cache。nil = 不启用 cache(套餐绑回退到逐节点 GET inbounds 老路径)。
func (h *RemoteManageHandler) SetInboundCache(c *InboundCache) {
	h.inboundCache = c
}

// 创建一个新的远程管理处理程序
func NewRemoteManageHandler(repo *storage.TrafficRepository, wsHandler *RemoteWSHandler) *RemoteManageHandler {
	return &RemoteManageHandler{
		repo:      repo,
		wsHandler: wsHandler,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// 设置安装后自动部署的证书处理程序。
func (h *RemoteManageHandler) SetCertificateHandler(ch *CertificateHandler) {
	h.certHandler = ch
}

func (h *RemoteManageHandler) SetCrypto(cc *CryptoConfig) {
	h.crypto = cc
}

func (h *RemoteManageHandler) SetStealSelfDeployer(deployer func(ctx context.Context, serverID int64) error) {
	h.stealSelfDeployer = deployer
}

func (h *RemoteManageHandler) deployDefaultConfig(serverID int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 已存在配置则不下发 — 保护现网 inbound/outbound/routing,只在全新装机时初始化默认模板。
	// 历史 BUG:scan_result xray_running=false 一旦上报(xray 启动失败 / 短暂故障 / 配置冲突),
	// 这里就会无脑下发默认模板覆盖现有配置,导致服务器再次上线时业务入站全部丢失。
	if cur, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/xray/config", nil); err == nil {
		// 解析返回:{ "success": true, "config": "<json string>" }
		var resp struct {
			Success bool   `json:"success"`
			Config  string `json:"config"`
		}
		if json.Unmarshal(cur, &resp) == nil && resp.Success {
			cfg := strings.TrimSpace(resp.Config)
			// 判 "有效配置" 标准:能 parse + 至少包含 1 个非 api 的 inbound 或 1 个非默认 outbound
			if cfg != "" && hasNonTemplateContent(cfg) {
				log.Printf("[Remote Manage] Server %d already has non-empty xray config, skip auto-deploy default template", serverID)
				return
			}
		}
	}

	configTpl, err := templates.ReadFile("default/config.json")
	if err != nil {
		log.Printf("[Remote Manage] Failed to read default/config.json template: %v", err)
		return
	}

	configPayload, _ := json.Marshal(map[string]string{
		"config": string(configTpl),
	})
	if _, err := h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/xray/config", configPayload); err != nil {
		log.Printf("[Remote Manage] Failed to deploy default config to server %d: %v", serverID, err)
		return
	}

	if err := h.restartXrayWithRecovery(ctx, serverID, "AutoDeployDefault"); err != nil {
		log.Printf("[Remote Manage] %v", err)
		return
	}
	log.Printf("[Remote Manage] Auto-deployed default config to server %d (was empty)", serverID)
}

// serverHasXrayContent 查 server 当前 xray config 是否已有用户内容(非空模板),复用 hasNonTemplateContent。
// GET /api/child/xray/config 读的是 agent 上的 config.json 文件、不依赖 xray 进程,xray 挂时也能返回。
// GET / 解析失败保守返回 true(视为有内容、不覆盖),优先保护存量配置(宁可漏一次自动部署,也不误覆盖用户配置)。
func (h *RemoteManageHandler) serverHasXrayContent(ctx context.Context, serverID int64) bool {
	cur, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/xray/config", nil)
	if err != nil {
		return true
	}
	var resp struct {
		Success bool   `json:"success"`
		Config  string `json:"config"`
	}
	if json.Unmarshal(cur, &resp) != nil || !resp.Success {
		return true
	}
	cfg := strings.TrimSpace(resp.Config)
	return cfg != "" && hasNonTemplateContent(cfg)
}

// hasNonTemplateContent 判断一份 xray config 是不是"用户有内容"的(而非空模板)。
// 标准:
//   - 至少 1 个 tag != "api" 的 inbound,或
//   - 至少 1 个 tag != "direct" && tag != "block" 的 outbound,或
//   - 任何 routing.rules
//
// 任一满足即认为有内容,不应被默认模板覆盖。
func hasNonTemplateContent(cfgJSON string) bool {
	var cfg map[string]any
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		// parse 失败也别覆盖 — 让用户介入修复
		return true
	}
	if ibs, ok := cfg["inbounds"].([]any); ok {
		for _, raw := range ibs {
			if m, ok := raw.(map[string]any); ok {
				if tag, _ := m["tag"].(string); tag != "" && tag != "api" {
					return true
				}
			}
		}
	}
	if obs, ok := cfg["outbounds"].([]any); ok {
		for _, raw := range obs {
			if m, ok := raw.(map[string]any); ok {
				if tag, _ := m["tag"].(string); tag != "" && tag != "direct" && tag != "block" {
					return true
				}
			}
		}
	}
	if r, ok := cfg["routing"].(map[string]any); ok {
		if rules, ok := r["rules"].([]any); ok && len(rules) > 0 {
			return true
		}
	}
	return false
}

// deviceKickPrev 主控内存:per (serverID, email) → 上次见到的累计 kick 值。
// agent 每次 scan_result 上报累计值,主控算 delta = current - prev_seen;delta > 0 → tg 通知。
// agent 重启会让累计值回到 0,主控这里检测到 current < prev → 重置 prev = current(避免负 delta 误触发)。
var deviceKickPrevMu sync.Mutex
var deviceKickPrev = make(map[string]int64) // key = fmt.Sprintf("%d|%s", serverID, email)

// handleConnLimitKickDelta:agent 上报的累计"连接数超限被拒次数"(payload.DeviceKicks,现语义=连接超限),
// 主控算 delta>0 → 解析 用户名 + 节点名 → 连接数超限通知(5min 节流兜底)。
func (h *RemoteManageHandler) handleConnLimitKickDelta(ctx context.Context, serverID int64, kicks map[string]int64) {
	deviceKickPrevMu.Lock()
	defer deviceKickPrevMu.Unlock()
	var serverName string
	if srv, err := h.repo.GetRemoteServer(ctx, serverID); err == nil && srv != nil {
		serverName = srv.Name
	}
	for email, current := range kicks {
		key := fmt.Sprintf("%d|%s", serverID, email)
		prev, seen := deviceKickPrev[key]
		if !seen || current < prev {
			// 第一次见或 agent 重启了累计值,记当前值即可,不产生 delta(避免误触发)
			deviceKickPrev[key] = current
			continue
		}
		delta := int(current - prev)
		if delta > 0 {
			deviceKickPrev[key] = current
			username := h.repo.ResolveUsernameByEmail(ctx, email)
			if username == "" {
				username = email
			}
			nodeName := h.repo.ResolveNodeNameByEmail(ctx, serverName, email)
			SendConnLimitExceededNotification(ctx, username, nodeName, delta)
		}
	}
}

// 处理通过 WebSocket 从代理收到的扫描结果。
func (h *RemoteManageHandler) HandleScanResult(serverID int64, payload WSScanResultPayload) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 更新数据库中的 X 射线状态;若状态翻转则发 TG 通知(复用服务器上下线开关)
	prevRunning, err := h.repo.UpdateRemoteServerXrayStatus(ctx, serverID, payload.XrayRunning, payload.XrayVersion)
	if err != nil {
		log.Printf("[Remote Manage] Failed to update Xray status for server %d: %v", serverID, err)
	} else if prevRunning != payload.XrayRunning {
		if server, gErr := h.repo.GetRemoteServer(ctx, serverID); gErr == nil && server != nil {
			SendXrayStatusChangeNotification(ctx, server.Name, server.IPAddress, payload.XrayRunning)
		}
	}

	// Phase 3B: device kicks delta 触发设备超限通知。
	// payload.DeviceKicks 是累计量(自 agent 启动起单调递增),主控内存记录上次见到的值,算 delta。
	// 设备超限通知给 admin,文案带 email + delta。同一 email 5min 节流由 notifyAsync 兜底。
	if len(payload.DeviceKicks) > 0 {
		h.handleConnLimitKickDelta(ctx, serverID, payload.DeviceKicks)
	}

	if payload.XrayRunning {
		result := h.syncInboundsToNodesInternal(ctx, serverID)
		log.Printf("[Remote Manage] Auto-sync from scan_result for server %d: synced=%d (claimed=%d, created=%d), skipped=%d",
			serverID, result.SyncedCount, result.ClaimedCount, result.CreatedCount, result.SkippedCount)
	} else {
		// xray 未运行，自动下发配置
		server, err := h.repo.GetRemoteServer(ctx, serverID)
		if err == nil && server != nil {
			useStealSelf := server.Use443 && server.Domain != "" && h.stealSelfDeployer != nil
			go func() {
				deployCtx, deployCancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer deployCancel()
				// 已有用户内容就不覆盖:偷自己 server 重启瞬间 xray 未就绪也会上报 XrayRunning=false,
				// 之前只有 deployDefaultConfig 内部有 hasNonTemplateContent 保护、stealSelfDeployer 分支没有,
				// 导致已部署的偷自己 server 每次重启都被模板覆盖 nginx/config。这里统一拦一道,两分支都保护。
				if h.serverHasXrayContent(deployCtx, serverID) {
					log.Printf("[Remote Manage] server %d xray 未运行但配置已有用户内容,跳过自动下发(避免覆盖 nginx/config)", serverID)
					return
				}
				if useStealSelf {
					if err := h.stealSelfDeployer(deployCtx, serverID); err != nil {
						log.Printf("[Remote Manage] Auto-deploy steal-self config failed for server %d: %v", serverID, err)
					} else {
						log.Printf("[Remote Manage] Auto-deployed steal-self config for server %d", serverID)
					}
				} else {
					h.deployDefaultConfig(serverID)
				}
			}()
		}
	}
}

// RemoteWriteJSON 写入 JSON 响应
func remoteWriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// RemoteWriteError 写入错误响应
func remoteWriteError(w http.ResponseWriter, status int, message string) {
	// Cloudflare 等 CDN 会把源站 5xx 响应替换成自己的错误页(Error 502 Bad Gateway),
	// 导致真实错误信息(agent 转发失败 / xray·nginx 启动失败原因)丢失。
	// CF 默认透传 4xx,所以把 5xx 统一降为 4xx(语义上是"无法完成该远程操作"),
	// body 仍带真实 error/message,前端 onError 逻辑不变即可拿到真实原因。
	httpStatus := status
	if status >= 500 {
		httpStatus = http.StatusBadRequest
	}
	remoteWriteJSON(w, httpStatus, map[string]any{
		"success": false,
		"error":   message,
		"message": message,
		"status":  status,
	})
}

// 代理对远程服务器的服务状态请求
func (h *RemoteManageHandler) HandleServicesStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, "GET", "/api/child/services/status", nil)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

const minimumManagedNginxVersion = "1.25.1"

// forwardNginxSetupSSL 在下发新版 nginx 配置前检查远端版本。
// 老版发行版 nginx（如 Debian 12 的 1.22.1）不支持模板使用的 `http2 on;`，
// 与其覆盖配置后才在 reload 阶段报错，不如直接把可操作的提示返回给现有前端。
func (h *RemoteManageHandler) forwardNginxSetupSSL(ctx context.Context, serverID int64, payload []byte) ([]byte, error) {
	result, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/services/status", nil)
	if err != nil {
		return nil, fmt.Errorf("无法检查远端 Nginx 兼容性: %w", err)
	}

	var status ChildServicesStatusResponse
	if err := json.Unmarshal(result, &status); err != nil || status.Nginx == nil {
		return nil, fmt.Errorf("远端 Agent 未返回 Nginx 版本信息，请先升级 Agent 后重试")
	}
	if !status.Nginx.Installed {
		return nil, fmt.Errorf("未检测到 Nginx，请先在服务管理中安装 Nginx 后重试")
	}
	current := parseNginxVersion(status.Nginx.Version)
	if current == "" {
		return nil, fmt.Errorf("无法识别远端 Nginx 版本（%s），请通过服务管理重新安装 Nginx 后重试", status.Nginx.Version)
	}
	if compareSemver(current, minimumManagedNginxVersion) < 0 {
		return nil, fmt.Errorf(
			"检测到 Nginx %s，不兼容当前配置（要求 >= %s）；请先卸载系统自带 Nginx，再通过服务管理安装 Nginx 后重试",
			current,
			minimumManagedNginxVersion,
		)
	}

	return h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/nginx/setup-ssl", payload)
}

// deployNginxCertificateBeforeConfig 在写入引用证书的 nginx 配置前，同步等待 Agent
// 将证书落盘。不能依赖后台 auto-deploy：nginx -t 会在证书文件不存在时立即失败，
// 使配置流程提前返回，后续异步证书部署永远没有机会执行。
func (h *RemoteManageHandler) deployNginxCertificateBeforeConfig(ctx context.Context, server *storage.RemoteServer, domain string) (*storage.Certificate, error) {
	cert, err := h.repo.FindCertificateForDomain(ctx, strings.ToLower(strings.TrimSpace(domain)))
	if err != nil || cert == nil || cert.CertPEM == "" || cert.KeyPEM == "" {
		if h.certHandler != nil {
			go h.certHandler.DeployAutoDeployCertificates(server.ID)
		}
		return nil, fmt.Errorf("域名 %s 没有可用证书；已触发自动部署，请确认证书状态为有效后重试", domain)
	}

	certName := certDeployFilename(cert.Domain)
	payload, _ := json.Marshal(WSCertDeployPayload{
		Domain:   cert.Domain,
		CertPEM:  cert.CertPEM,
		KeyPEM:   cert.KeyPEM,
		CertPath: fmt.Sprintf("/usr/local/nginx/cert/%s.pem", certName),
		KeyPath:  fmt.Sprintf("/usr/local/nginx/cert/%s.key", certName),
		Reload:   "none",
	})
	if _, err := h.forwardToRemoteServer(ctx, server.ID, http.MethodPost, "/api/child/cert/deploy", payload); err != nil {
		return nil, fmt.Errorf("同步下发域名 %s 的 Nginx 证书失败: %w", domain, err)
	}
	return cert, nil
}

func parseNginxVersion(output string) string {
	const marker = "nginx/"
	start := strings.Index(output, marker)
	if start < 0 {
		return ""
	}
	start += len(marker)
	end := start
	for end < len(output) {
		c := output[end]
		if (c < '0' || c > '9') && c != '.' {
			break
		}
		end++
	}
	return strings.Trim(output[start:end], ".")
}

// 将服务控制请求代理到远程服务器
func (h *RemoteManageHandler) HandleServiceControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	// xray 启动/重启时使用带恢复的逻辑
	var req struct {
		Service string `json:"service"`
		Action  string `json:"action"`
	}
	if json.Unmarshal(body, &req) == nil && req.Service == "xray" && (req.Action == "start" || req.Action == "restart") {
		// 使用独立 context，避免同机 tunnel 模式下请求断开导致 context canceled
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := h.restartXrayWithRecovery(ctx, id, "ServiceControl"); err != nil {
			remoteWriteError(w, http.StatusBadGateway, err.Error())
			return
		}
		remoteWriteJSON(w, http.StatusOK, map[string]any{
			"success": true,
			"message": fmt.Sprintf("Service xray %sed successfully", req.Action),
		})
		return
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, "POST", "/api/child/services/control", body)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 代理 xray 安装请求到远程服务器
func (h *RemoteManageHandler) HandleXrayInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, "POST", "/api/child/xray/install", nil)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	// install 完成后异步自动触发"下发配置"动作 — 等价于用户手动点 UI 上的下发配置按钮。
	// 走同一份 DeployStealSelfConfig:按 server.StealMode dispatch 到 fallback / tunnel / default
	// 模板,与内置 xray 完全一致。否则装完 agent 跑的是"只有 api 入站"的默认配置,业务不通,
	// 用户必须手动再点一次"下发配置"才能用 — 这一步是冗余的。
	//
	// install 后 agent xray 启动 + RPC 就绪有几秒延迟,先等再 deploy。
	// 失败只 log,不影响 install 响应 — 用户仍可手动点"下发配置"重试。
	go func() {
		deployCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		select {
		case <-time.After(3 * time.Second):
		case <-deployCtx.Done():
			return
		}
		if err := h.DeployStealSelfConfig(deployCtx, id); err != nil {
			log.Printf("[Remote Manage] Post-install auto-deploy failed for server %d: %v (user can retry via UI 下发配置)", id, err)
			return
		}
		log.Printf("[Remote Manage] Post-install auto-deploy succeeded for server %d", id)
	}()

	// 成功安装 xray 后触发自动部署证书
	if h.certHandler != nil {
		go h.certHandler.DeployAutoDeployCertificates(id)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 代理对远程服务器的 xray 删除请求
func (h *RemoteManageHandler) HandleXrayRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, "POST", "/api/child/xray/remove", nil)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 将 xray 配置请求代理到远程服务器
func (h *RemoteManageHandler) HandleXrayConfig(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	var body []byte
	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to read body")
			return
		}
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/xray/config", body)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// HandleXrayTestConfig 把前端的 xray 配置预检请求转发到 agent。
// 前端在 dialog 点"保存"前先调一次本接口,失败则不下发,直接 toast 错误内容。
// agent 端不论 embedded/external 都会用 xray-core 库或 xray cli 验证 (见 ManageHandler.HandleXrayTestConfig)。
func (h *RemoteManageHandler) HandleXrayTestConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}
	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	result, err := h.forwardToRemoteServer(r.Context(), id, http.MethodPost, "/api/child/xray/test-config", body)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 代理 nginx 安装请求到远程服务器
func (h *RemoteManageHandler) HandleNginxInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	server, err := h.repo.GetRemoteServer(r.Context(), id)
	if err != nil {
		remoteWriteError(w, http.StatusNotFound, "server not found")
		return
	}

	var body []byte
	if server.Domain != "" {
		body, _ = json.Marshal(map[string]string{"domain": server.Domain})
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, "POST", "/api/child/nginx/install", body)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	// nginx 安装成功后触发自动部署证书
	if h.certHandler != nil {
		go h.certHandler.DeployAutoDeployCertificates(id)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 代理 nginx 删除对远程服务器的请求
func (h *RemoteManageHandler) HandleNginxRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, "POST", "/api/child/nginx/remove", nil)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// ================== SSE 流安装/删除 ==================

func remoteSSEError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	b, _ := json.Marshal(map[string]string{"type": "error", "message": msg})
	fmt.Fprintf(w, "data: %s\n\n", b)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (h *RemoteManageHandler) forwardStreamToRemote(w http.ResponseWriter, r *http.Request, serverID int64, agentPath string) {
	server, err := h.repo.GetRemoteServer(r.Context(), serverID)
	if err != nil {
		remoteSSEError(w, "server not found: "+err.Error())
		return
	}
	if server.Status != "connected" {
		remoteSSEError(w, "server not connected")
		return
	}

	// WS-first 流式 RPC:agent capabilities.stream=true 时直接走 WS,绕开反向 HTTP 的 IP 漂移痛点。
	// 写 SSE headers 必须在 try 之前 — 数据帧会立刻通过 out 写出,前端 EventSource 看到 headers
	// 才会开始解析事件。
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, _ := w.(http.Flusher)
	// 5 分钟硬超时跟 forwardUpgradeStream 对齐 — install/nginx 大部分场景几十秒内完成,够用。
	if ok, err := h.tryWSRPCStream(r.Context(), serverID, http.MethodPost, agentPath, nil, w, flusher, 5*time.Minute); ok {
		if err != nil {
			log.Printf("[Remote Manage] WS stream %s for server %s ended with error (no fallback): %v", agentPath, server.Name, err)
		}
		return
	}

	// IP 候选清单:v4 优先,v6 兜底。dial 失败才 fallback;一旦 200 OK 且开始读流就不再 fallback
	// (避免双重执行 install / upgrade 这类幂等性差的操作)。
	candidates := buildAgentURLCandidates(server, agentPath)
	if len(candidates) == 0 {
		remoteSSEError(w, "server IP address unknown")
		return
	}

	var resp *http.Response
	for i, childURL := range candidates {
		log.Printf("[Remote Manage] Forwarding stream %s to server %s (%s)", agentPath, server.Name, childURL)

		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, childURL, nil)
		if err != nil {
			if i+1 < len(candidates) {
				log.Printf("[Remote Manage] stream candidate %s req-build failed (%v), trying next", childURL, err)
				continue
			}
			remoteSSEError(w, "failed to create request: "+err.Error())
			return
		}
		req.Header.Set("Authorization", "Bearer "+server.Token)
		req.Header.Set("User-Agent", version.AgentUserAgent)

		client := &http.Client{} // SSE 没有超时
		r2, err := client.Do(req)
		if err != nil {
			if i+1 < len(candidates) {
				log.Printf("[Remote Manage] stream candidate %s dial failed (%v), trying next", childURL, err)
				continue
			}
			remoteSSEError(w, "agent unreachable: "+err.Error())
			return
		}
		// 4xx/5xx 也算"这个 candidate 失败",尝试下一个 — agent install/upgrade 类幂等性差,
		// 但 4xx 通常是 token/auth/path 错,fallback 也是同样 4xx,代价 = 1 次多发,可接受
		if r2.StatusCode >= 400 {
			body, _ := io.ReadAll(r2.Body)
			r2.Body.Close()
			if i+1 < len(candidates) {
				log.Printf("[Remote Manage] stream candidate %s returned %d, trying next", childURL, r2.StatusCode)
				continue
			}
			remoteSSEError(w, fmt.Sprintf("agent error %d: %s", r2.StatusCode, string(body)))
			return
		}
		resp = r2
		break
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		remoteSSEError(w, "streaming not supported")
		return
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Fprintf(w, "%s\n", line)
		flusher.Flush()
		select {
		case <-r.Context().Done():
			return
		default:
		}
	}
}

func (h *RemoteManageHandler) HandleXrayInstallStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil {
		remoteSSEError(w, "invalid server_id")
		return
	}
	h.forwardStreamToRemote(w, r, id, "/api/child/xray/install-stream")

	// 安装完成后自动扫描更新 xray 状态
	go h.refreshXrayStatus(id)
}

func (h *RemoteManageHandler) HandleXrayRemoveStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil {
		remoteSSEError(w, "invalid server_id")
		return
	}
	h.forwardStreamToRemote(w, r, id, "/api/child/xray/remove-stream")

	// 卸载完成后更新 xray 状态
	go h.refreshXrayStatus(id)
}

func (h *RemoteManageHandler) refreshXrayStatus(serverID int64) {
	time.Sleep(2 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := h.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/services/status", nil)
	if err != nil {
		log.Printf("[Remote Manage] refreshXrayStatus failed for server %d: %v", serverID, err)
		return
	}

	var status struct {
		Xray *struct {
			Running bool   `json:"running"`
			Version string `json:"version"`
		} `json:"xray"`
	}
	if err := json.Unmarshal(result, &status); err != nil || status.Xray == nil {
		return
	}

	version := ""
	if status.Xray.Version != "" {
		version = status.Xray.Version
	}
	prev, err := h.repo.UpdateRemoteServerXrayStatus(ctx, serverID, status.Xray.Running, version)
	if err != nil {
		log.Printf("[Remote Manage] refreshXrayStatus: failed to update DB for server %d: %v", serverID, err)
	} else {
		log.Printf("[Remote Manage] refreshXrayStatus: server %d xray_running=%v", serverID, status.Xray.Running)
		if prev != status.Xray.Running {
			if server, gErr := h.repo.GetRemoteServer(ctx, serverID); gErr == nil && server != nil {
				SendXrayStatusChangeNotification(ctx, server.Name, server.IPAddress, status.Xray.Running)
			}
		}
	}
}

func (h *RemoteManageHandler) HandleNginxInstallStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil {
		remoteSSEError(w, "invalid server_id")
		return
	}

	server, err := h.repo.GetRemoteServer(r.Context(), id)
	if err != nil {
		remoteSSEError(w, "server not found")
		return
	}

	agentPath := "/api/child/nginx/install-stream"
	if server.Domain != "" {
		agentPath += "?domain=" + server.Domain
	}
	h.forwardStreamToRemote(w, r, id, agentPath)

	// 流完成后触发自动部署证书
	if h.certHandler != nil {
		go h.certHandler.DeployAutoDeployCertificates(id)
	}
}

func (h *RemoteManageHandler) HandleNginxRemoveStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil {
		remoteSSEError(w, "invalid server_id")
		return
	}
	h.forwardStreamToRemote(w, r, id, "/api/child/nginx/remove-stream")
}

func (h *RemoteManageHandler) HandleAgentUpgradeStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil {
		remoteSSEError(w, "invalid server_id")
		return
	}
	h.forwardUpgradeStream(w, r, id)
}

// forwardUpgradeStream 是升级专用版本的 SSE 转发,在 forwardStreamToRemote 基础上加了:
//  1. 主控侧 60s 硬超时 — 老 agent 的 sseStreamCmd 会卡死,通用 forward 无 timeout 浏览器会一直转
//  2. 升级成功检测 — 用 system-info.agent_version 前后对比;无 agent_version 字段的老 agent 退化为
//     "ping 是否变化"(老 binary 没重启 → 旧 PID 还在响应原 conn;若新 binary 起来 → 短暂 502 然后恢复)
//  3. 失败时往 SSE 末尾追一条 {type:"result", success:false, hint:"..."} — 前端可据此提示
//     用户哪几台需要手工 ssh 上去跑 upgrade-agent.sh
func (h *RemoteManageHandler) forwardUpgradeStream(w http.ResponseWriter, r *http.Request, serverID int64) {
	const upgradeTimeout = 60 * time.Second

	server, err := h.repo.GetRemoteServer(r.Context(), serverID)
	if err != nil {
		remoteSSEError(w, "server not found: "+err.Error())
		return
	}
	if server.Status != "connected" {
		remoteSSEError(w, "server not connected")
		return
	}

	// 进入升级流程前先 mark — 升级期间 agent 必然要退出 + 重连一次,WS cleanup 和 handleAuth
	// 会跳过上下线通知,防止批量升级一台一对 → Telegram 风控爆。
	// 窗口 2min 兜底:GitHub CDN 慢 + agent 重启 + WS 重连,正常 <30s,留够冗余。
	MarkServerUpgrading(serverID, 2*time.Minute)

	// 拿升级前的 agent_version 做对比基线(老 agent 没这个字段就空,后面用其它信号)
	preVersion := h.probeAgentVersion(r.Context(), serverID)

	// WS-first:capabilities.stream=true 时走 WS,数据帧用 io.MultiWriter fork 一份给
	// markerWriter,继续扫 "Binary replaced" 关键字,verify 路径完全跟 HTTP 一致。
	// 升级末期 agent 必然重启 → WS 断 → CallAgentStream 返回 stream interrupted 错误,
	// 但 markerWriter 已经看到 Binary replaced(那是脚本最后一步,先于重启输出),正常进 verify。
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	if flusher, ok := w.(http.Flusher); ok {
		mw := &markerWriter{marker: []byte("Binary replaced")}
		out := io.MultiWriter(w, mw)
		ctx, cancel := context.WithTimeout(r.Context(), upgradeTimeout)
		wsOk, wsErr := h.tryWSRPCStream(ctx, serverID, http.MethodPost, "/api/child/agent/upgrade-stream", nil, out, flusher, upgradeTimeout)
		cancel()
		if wsOk {
			// 已走 WS 路径,直接 verify(agent 重启导致 wsErr 非 nil 是预期内的,不阻塞 verify)
			sawBinaryReplaced := mw.matched
			timeoutHit := wsErr != nil && (errors.Is(wsErr, context.DeadlineExceeded) ||
				strings.Contains(wsErr.Error(), "timed out"))
			h.upgradeVerify(w, flusher, server.Name, serverID, preVersion, sawBinaryReplaced, timeoutHit)
			return
		}
		// WS 不可用,继续走下面老 HTTP 路径(headers 已经写过,无副作用)
	}

	// v4-first → v6-fallback 候选清单
	candidates := buildAgentURLCandidates(server, "/api/child/agent/upgrade-stream")
	if len(candidates) == 0 {
		remoteSSEError(w, "server IP address unknown")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), upgradeTimeout)
	defer cancel()

	var resp *http.Response
	for i, childURL := range candidates {
		log.Printf("[Remote Manage] Forwarding upgrade stream to server %s (%s) preVersion=%q", server.Name, childURL, preVersion)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, childURL, nil)
		if err != nil {
			if i+1 < len(candidates) {
				log.Printf("[Remote Manage] upgrade-stream %s req-build failed (%v), trying next", childURL, err)
				continue
			}
			remoteSSEError(w, "failed to create request: "+err.Error())
			return
		}
		req.Header.Set("Authorization", "Bearer "+server.Token)
		req.Header.Set("User-Agent", version.AgentUserAgent)

		r2, err := http.DefaultClient.Do(req)
		if err != nil {
			if i+1 < len(candidates) {
				log.Printf("[Remote Manage] upgrade-stream %s dial failed (%v), trying next", childURL, err)
				continue
			}
			remoteSSEError(w, "agent unreachable: "+err.Error())
			return
		}
		if r2.StatusCode >= 400 {
			body, _ := io.ReadAll(r2.Body)
			r2.Body.Close()
			if i+1 < len(candidates) {
				log.Printf("[Remote Manage] upgrade-stream %s returned %d, trying next", childURL, r2.StatusCode)
				continue
			}
			remoteSSEError(w, fmt.Sprintf("agent error %d: %s", r2.StatusCode, string(body)))
			return
		}
		resp = r2
		break
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		remoteSSEError(w, "streaming not supported")
		return
	}

	// 透传 SSE,同时记录是否看到 "Binary replaced" 标记 — 那是 agent 脚本里最后一条 echo,
	// 看到代表脚本跑到了最后一步;没看到代表脚本中途卡死或失败。
	sawBinaryReplaced := false
	timeoutHit := false
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Binary replaced") {
			sawBinaryReplaced = true
		}
		fmt.Fprintf(w, "%s\n", line)
		flusher.Flush()
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				timeoutHit = true
			}
			goto verify
		default:
		}
	}
	if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		timeoutHit = true
	}

verify:
	h.upgradeVerify(w, flusher, server.Name, serverID, preVersion, sawBinaryReplaced, timeoutHit)
}

// upgradeVerify 抽出来供 WS 路径和 HTTP 路径共用 — 等 8 秒 agent 重启窗口,再 probe 一次
// 新版本号,把结果追到 SSE 末尾。
func (h *RemoteManageHandler) upgradeVerify(w io.Writer, flusher http.Flusher, serverName string, serverID int64, preVersion string, sawBinaryReplaced, timeoutHit bool) {
	time.Sleep(8 * time.Second)
	postVersion := h.probeAgentVersion(context.Background(), serverID)

	result := upgradeResult(preVersion, postVersion, sawBinaryReplaced, timeoutHit)
	resultJSON, _ := json.Marshal(result)
	fmt.Fprintf(w, "data: %s\n\n", resultJSON)
	if flusher != nil {
		flusher.Flush()
	}
	log.Printf("[Remote Manage] Upgrade verification for %s: pre=%q post=%q sawReplaced=%v timeout=%v → %+v",
		serverName, preVersion, postVersion, sawBinaryReplaced, timeoutHit, result)
}

// markerWriter 实现 io.Writer 但**不保存原文**,只跟踪给定 marker 字串是否出现过。
// 配合 io.MultiWriter 给 WS 路径用 — 让 master 既能透传字节给前端,又能扫到升级脚本的
// 最后一条 echo "Binary replaced",维持跟 HTTP 路径一致的 verify 判断口径。
//
// 跨写入边界的处理:保留上一次写入的最后 len(marker)-1 字节,与本次拼接后再扫,
// 避免单次 buf 切到 "Binary replac" + "ed" 时漏报。
type markerWriter struct {
	marker  []byte
	matched bool
	tail    []byte // 上次留下来的尾巴(长度 ≤ len(marker)-1)
}

func (m *markerWriter) Write(p []byte) (int, error) {
	if m.matched {
		return len(p), nil
	}
	combined := append(m.tail, p...)
	if bytes.Contains(combined, m.marker) {
		m.matched = true
		m.tail = nil
		return len(p), nil
	}
	overlap := len(m.marker) - 1
	if len(combined) > overlap {
		m.tail = append(m.tail[:0], combined[len(combined)-overlap:]...)
	} else {
		m.tail = combined
	}
	return len(p), nil
}

// probeAgentVersion GET 一次 system-info 取 agent_version,失败返回空字符串。
// 5s 超时 — 我们只想瞄一眼,不希望卡这条主流程。
func (h *RemoteManageHandler) probeAgentVersion(parent context.Context, serverID int64) string {
	// WS-first:auth 上报的版本优先(端口隐身后反向 HTTP 不可达)。
	// 升级后 agent 重连会带新版本覆盖 wsConn.AgentVersion,所以升级后再 probe 仍准。
	if h.wsHandler != nil {
		if conn, ok := h.wsHandler.GetConnectionByServerID(serverID); ok && conn.AgentVersion != "" {
			return conn.AgentVersion
		}
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	body, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/system/info", nil)
	if err != nil {
		return ""
	}
	var info struct {
		AgentVersion string `json:"agent_version"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return ""
	}
	return strings.TrimSpace(info.AgentVersion)
}

// upgradeResult 推导升级最终结果,根据前后版本号 + 脚本输出标记综合判断。
// 用于追加到 SSE 末尾告诉前端是否真的升级成功了 — 这是因为 agent 自身 SSE 在卡死/部分失败场景
// 不能保证有 type=complete/error 事件,主控这边再兜一道。
func upgradeResult(preVersion, postVersion string, sawBinaryReplaced, timeoutHit bool) map[string]any {
	r := map[string]any{
		"type":         "result",
		"pre_version":  preVersion,
		"post_version": postVersion,
	}

	switch {
	case postVersion != "" && preVersion != "" && postVersion != preVersion:
		// 新版本号 ≠ 旧版本号 → agent 重启 + 新 binary 装上了 → 真升上去了
		r["success"] = true
		r["message"] = fmt.Sprintf("升级成功:v%s → v%s", preVersion, postVersion)
	case postVersion != "" && preVersion == "" && sawBinaryReplaced:
		// 旧 agent 没上报版本,但脚本完整跑完且现在能查到版本号 → 大概率成功
		r["success"] = true
		r["message"] = fmt.Sprintf("升级成功:agent v%s(旧版本无法识别,以脚本完成 + 当前可查为准)", postVersion)
	case timeoutHit:
		r["success"] = false
		r["message"] = "升级超时(60s):agent 脚本可能卡死。请在服务器上手工跑 scripts/upgrade-agent.sh 救场"
		r["hint"] = "old_agent_stuck"
	case !sawBinaryReplaced:
		r["success"] = false
		r["message"] = "升级失败:agent 未跑到 'Binary replaced'(脚本中途出错)。请检查日志 journalctl -u mmw-agent / /var/log/mmw-agent.log,或手工 ssh 跑 upgrade-agent.sh"
		r["hint"] = "script_aborted"
	case preVersion != "" && postVersion == preVersion:
		r["success"] = false
		r["message"] = fmt.Sprintf("升级失败:版本号未变(v%s)。可能 agent 进程没真正重启,或 sseStreamCmd 卡死。请手工 ssh 跑 upgrade-agent.sh", preVersion)
		r["hint"] = "no_restart"
	case preVersion == "" && postVersion == "":
		r["success"] = false
		r["message"] = "升级状态未知:agent 老版本不上报 version,无法自动确认。建议手工 ssh 检查 /usr/local/bin/mmw-agent 时间戳"
		r["hint"] = "unknown_old_agent"
	default:
		// 兜底:脚本说看到 "Binary replaced" 但版本号没变 / 没拿到,认为"大概率成功",前端可正常 toast
		r["success"] = true
		r["message"] = "升级看似完成(脚本跑完最后一步)"
	}
	return r
}

func (h *RemoteManageHandler) HandleAgentUninstallStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil {
		remoteSSEError(w, "invalid server_id")
		return
	}
	h.forwardStreamToRemote(w, r, id, "/api/child/agent/uninstall-stream")
}

// 将 nginx 配置请求代理到远程服务器
func (h *RemoteManageHandler) HandleNginxConfig(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	var body []byte
	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to read body")
			return
		}
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/nginx/config", body)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 将系统信息请求代理到远程服务器
func (h *RemoteManageHandler) HandleSystemInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, "GET", "/api/child/system/info", nil)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 通过 HTTP 将请求转发到远程服务器
func (h *RemoteManageHandler) ForwardToServer(ctx context.Context, serverID int64, method, path string, body []byte) ([]byte, error) {
	return h.forwardToRemoteServer(ctx, serverID, method, path, body)
}

// syncMasterURLToAgent 校准单台 Agent 的回连地址。同机 Agent 必须保留
// 127.0.0.1:主控端口，联邦服务器则属于其它主控，两者都不能改写。
func (h *RemoteManageHandler) syncMasterURLToAgent(ctx context.Context, server *storage.RemoteServer, newMasterURL string) error {
	return h.syncMasterURLToAgentWithPolicy(ctx, server, newMasterURL, false)
}

func (h *RemoteManageHandler) syncMasterURLToAgentWithPolicy(ctx context.Context, server *storage.RemoteServer, newMasterURL string, allowSameHostOverride bool) error {
	if server == nil || server.IsFederated {
		return nil
	}
	if server.SameHostAsMaster && !allowSameHostOverride {
		log.Printf("[MasterURLSync] Server %d (%s): preserve same-host transport", server.ID, server.Name)
		return nil
	}
	// During automatic HTTPS recovery, agents whose existing transport still
	// works (notably Docker-network/loopback agents) must keep that address.
	// Agents that actually lost contact switch themselves through recovery_url.
	recovering, _ := h.repo.GetSystemSetting(ctx, settingForcePublicHTTP)
	if recovering == "1" && !strings.HasPrefix(strings.ToLower(newMasterURL), "https://") {
		log.Printf("[MasterURLSync] Server %d (%s): keep existing URL during HTTP recovery", server.ID, server.Name)
		return nil
	}
	payloadData := map[string]interface{}{"master_url": newMasterURL}
	// When HTTPS is restored, only agents that really switched to recovery_url
	// should switch back. Internal/loopback agents remained healthy and must not
	// have their transport address replaced by the public URL.
	if recovering == "1" {
		payloadData["only_if_recovery"] = true
	}
	payload, _ := json.Marshal(payloadData)
	resp, err := h.forwardToRemoteServer(ctx, server.ID, http.MethodPost, "/api/child/agent/update-master-url", payload)
	if err != nil {
		return err
	}
	log.Printf("[MasterURLSync] Server %d (%s): %s", server.ID, server.Name, string(resp))
	return nil
}

// SyncMasterURLOnReconnect 在 Agent 每次认证后补发最新地址。pending 首连的
// 偷自己配置由 handleAuth 中的安装就绪重试串行处理，避免两路覆盖同一配置。
func (h *RemoteManageHandler) SyncMasterURLOnReconnect(ctx context.Context, serverID int64, prevStatus string) {
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil || server.IsFederated {
		return
	}
	masterURL, _ := h.repo.GetSystemSetting(ctx, "master_url")
	masterURL = strings.TrimRight(strings.TrimSpace(masterURL), "/")
	// connected 表示只是 WS 短暂重连或主控自身重启。此时 Agent 已在使用可连接的地址，
	// 再调用旧版 Agent 的 update-master-url 会无条件退出进程，形成
	// “认证→退出→embedded Xray 停止→重启→再认证”的循环。
	// 真正离线期间错过地址广播的 Agent，其旧状态会是 offline，才需要在恢复时补发。
	if masterURL != "" && prevStatus == storage.RemoteServerStatusOffline {
		if err := h.syncMasterURLToAgent(ctx, server, masterURL); err != nil {
			log.Printf("[MasterURLSync] Server %d (%s) reconnect sync failed: %v", server.ID, server.Name, err)
		}
	}
}

// BroadcastMasterURLUpdate 向所有已连接的 agent 推送新的 master_url。
func (h *RemoteManageHandler) BroadcastMasterURLUpdate(ctx context.Context, newMasterURL string) {
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		log.Printf("[BroadcastMasterURL] Failed to list servers: %v", err)
		return
	}

	for _, s := range servers {
		if s.Status != "connected" || s.IsFederated {
			continue
		}
		server := s
		if err := h.syncMasterURLToAgent(ctx, &server, newMasterURL); err != nil {
			log.Printf("[BroadcastMasterURL] Server %d (%s): failed: %v", s.ID, s.Name, err)
		}
	}
	if recovering, _ := h.repo.GetSystemSetting(ctx, settingForcePublicHTTP); recovering == "1" && strings.HasPrefix(strings.ToLower(newMasterURL), "https://") {
		if err := h.repo.SetSystemSetting(ctx, settingForcePublicHTTP, "0"); err != nil {
			log.Printf("[BroadcastMasterURL] Failed to finish HTTP recovery state: %v", err)
		}
	}
}

// ForwardToAgent 导出包装,供联邦(分享服务器)转发使用。
func (h *RemoteManageHandler) ForwardToAgent(ctx context.Context, serverID int64, method, path string, body []byte) ([]byte, error) {
	return h.forwardToRemoteServer(ctx, serverID, method, path, body)
}

// isSessionInvalidErr 判断错误是否意味着 securechan 会话失效,需要重新协商密钥后重试。
// 覆盖三种信号:
//   - agent/拥有方"无会话"返回 412 "no session, re-negotiate"
//   - agent 解密我方请求失败返回 400 "decrypt failed"(我方持有的会话已过期/被新 KX 覆盖,与对端错位)
//   - 我方解密对端响应失败 "decrypt response/federation response"(同上,会话错位)
//
// 密钥轮换窗口(agent 会话 1h TTL 过期 / 同 token 并发请求触发重新 KX 覆盖旧会话)会出现后两种,
// 仅靠重协商一次即可自愈(doPullKeyExchange 是 KX+请求+明文响应一次往返,不涉及解密,必定成功)。
func isSessionInvalidErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "412") ||
		strings.Contains(s, "re-negotiate") ||
		strings.Contains(s, "decrypt")
}

type skipWSRPCContextKey struct{}

func withoutWSRPC(ctx context.Context) context.Context {
	return context.WithValue(ctx, skipWSRPCContextKey{}, true)
}

func (h *RemoteManageHandler) forwardToRemoteServer(ctx context.Context, serverID int64, method, path string, body []byte) (respBody []byte, err error) {
	// “整个节点作为出站”有多条入口（管理员路由、普通用户路由、出站管理）。
	// 前端提交的是节点当时的 Clash 地址；服务器锁定入口 IP 后，旧页面或历史配置仍可能
	// 携带心跳 IP/域名。所有下发路径在这里统一按节点归属服务器纠正，保证跨服务器出站
	// 也使用用户指定的锁定 IP。
	if method == http.MethodPost && path == "/api/child/outbounds" && len(body) > 0 {
		if rewritten, changed := h.rewriteLockedNodeOutbound(ctx, body); changed {
			body = rewritten
		}
	}

	// 写操作成功 + path 命中 xray 配置修改清单 → 异步 refresh snapshot
	// (用 defer + named return 统一处理所有 return 分支,无需在每个 return 点重复)
	defer func() {
		if err == nil && shouldRefreshXraySnapshotAfter(method, path) {
			go h.refreshXraySnapshot(serverID)
		}
	}()

	// 联邦(分享)服务器:不直连 agent,改走拥有方主控的 /api/federation/manage
	if fed, ferr := h.repo.GetFederatedServer(ctx, serverID); ferr == nil {
		return h.doFederationRequest(ctx, fed, method, path, body)
	}

	// WS-first:agent 上报 capabilities.rpc=true 且 WS 当前已连接 → 走反向 RPC,
	// 绕开 db.IPAddress 漂移 / agent 公网端口不可达 / 中间代理瞬时撕连 等 HTTP 反向请求痛点。
	// 只在以下情况 fallback 到 HTTP:
	//   - agent 老二进制不支持 RPC(Capabilities.RPC=false)→ tryWSRPC 直接 return nil,false
	//   - WS 临时断开 / RPC 调用超时 → tryWSRPC 返回 ErrWSRPCUnavailable
	//   - 业务级错误(handler 返回非 2xx)直接透传,**不** fallback(语义错就是错)
	if ctx.Value(skipWSRPCContextKey{}) == nil {
		if respBody, ok, err := h.tryWSRPC(ctx, serverID, method, path, body); ok {
			return respBody, err
		}
	}

	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return nil, fmt.Errorf("server not found: %v", err)
	}

	if server.Status != "connected" {
		return nil, fmt.Errorf("server not connected (status: %s)", server.Status)
	}

	// IP 候选清单:v4 优先,v6 兜底(空字段自动跳过)。用统一 helper 消灭旧 strings.LastIndex IPv6 截断 bug。
	candidates := buildAgentURLCandidates(server, path)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("server IP address unknown")
	}

	// 逐个 candidate 尝试:成功即返回;任何错误都 fallback 到下一个候选(代价 = 业务 4xx 多发一次,可接受)。
	// 单候选场景下退化为现状(只走一次,不重试)。
	for i, childURL := range candidates {
		log.Printf("[Remote Manage] Forwarding %s %s to server %s (%s)", method, path, server.Name, childURL)

		var attemptResp []byte
		var attemptErr error

		if h.crypto == nil || h.crypto.Identity == nil {
			attemptResp, attemptErr = h.doPlainPullRequest(ctx, method, childURL, server.Token, body)
		} else {
			sessionVal, ok := h.pullSessions.Load(serverID)
			if !ok {
				attemptResp, attemptErr = h.doPullKeyExchange(ctx, serverID, method, childURL, server.Token, body)
			} else {
				session := sessionVal.(*securechan.Session)
				attemptResp, attemptErr = h.doEncryptedPullRequest(ctx, method, childURL, server.Token, body, session)
				if isSessionInvalidErr(attemptErr) {
					h.pullSessions.Delete(serverID)
					log.Printf("[Remote Manage] Pull session invalid for server %d (%v), re-negotiating", serverID, attemptErr)
					attemptResp, attemptErr = h.doPullKeyExchange(ctx, serverID, method, childURL, server.Token, body)
				}
			}
		}

		if attemptErr == nil {
			return attemptResp, nil
		}
		if i+1 < len(candidates) {
			log.Printf("[Remote Manage] candidate %s failed (%v), trying next", childURL, attemptErr)
			continue
		}
		// 最后一个候选,直接把 err 透传给上层(同原行为)
		return attemptResp, attemptErr
	}
	return nil, fmt.Errorf("server %d: all IP candidates exhausted", serverID)
}

// doFederationRequest 把一条远程管理命令通过拥有方主控的 /api/federation/manage 转发(分享服务器)。
// 在 HTTPS 之上叠加"令牌揭示的 ECDH"端到端加密:已有会话则加密发送,无会话则先做密钥交换,
// 会话失效(412/re-negotiate)自动重新协商。
func (h *RemoteManageHandler) doFederationRequest(ctx context.Context, fed storage.FederatedServer, method, path string, body []byte) ([]byte, error) {
	payload, _ := json.Marshal(map[string]string{
		"method": method,
		"path":   path,
		"body":   base64.StdEncoding.EncodeToString(body),
	})

	if sessionVal, ok := h.fedSessions.Load(fed.ServerID); ok {
		session := sessionVal.(*securechan.Session)
		respBody, err := h.doEncryptedFederationRequest(ctx, fed, payload, session)
		if isSessionInvalidErr(err) {
			h.fedSessions.Delete(fed.ServerID)
			log.Printf("[Federation] session invalid for server %d (%v), re-negotiating", fed.ServerID, err)
			return h.doFederationKeyExchange(ctx, fed, payload)
		}
		return respBody, err
	}
	return h.doFederationKeyExchange(ctx, fed, payload)
}

// doFederationKeyExchange 发起密钥交换:明文发送 payload + 临时公钥,从响应头取拥有方临时公钥建会话。
func (h *RemoteManageHandler) doFederationKeyExchange(ctx context.Context, fed storage.FederatedServer, payload []byte) ([]byte, error) {
	consPriv, consPub, err := securechan.GenerateEphemeral()
	if err != nil {
		return h.doPlainFederationRequest(ctx, fed, payload)
	}
	url := strings.TrimRight(fed.OwnerURL, "/") + "/api/federation/manage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create federation request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Share-Token", fed.ShareToken)
	req.Header.Set("User-Agent", version.AgentUserAgent)
	req.Header.Set(fedKeyExchangeHeader, encodeKey(consPub))

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("federation request failed: %v", err)
	}
	defer resp.Body.Close()
	respBody, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		return nil, fmt.Errorf("read federation response: %v", rerr)
	}
	if resp.StatusCode >= 400 {
		return nil, federationErrorFromBody(resp.StatusCode, respBody)
	}

	// 拥有方支持加密时回带临时公钥,建会话供后续请求复用;不支持则保持明文(自动降级)。
	if kx := resp.Header.Get(fedKeyExchangeHeader); kx != "" {
		if ownerPub, ok := decodeKey(kx); ok {
			if session, derr := deriveFederationSession(consPriv, ownerPub, consPub, fed.ShareToken, true); derr == nil {
				h.fedSessions.Store(fed.ServerID, session)
				log.Printf("[Federation] key exchange completed for server %d", fed.ServerID)
			}
		}
	}
	return respBody, nil
}

// doEncryptedFederationRequest 用已建立的会话加密 payload 发送,并解密响应。
func (h *RemoteManageHandler) doEncryptedFederationRequest(ctx context.Context, fed storage.FederatedServer, payload []byte, session *securechan.Session) ([]byte, error) {
	encrypted, err := session.Encrypt(payload)
	if err != nil {
		return nil, fmt.Errorf("encrypt federation payload: %w", err)
	}
	url := strings.TrimRight(fed.OwnerURL, "/") + "/api/federation/manage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encrypted))
	if err != nil {
		return nil, fmt.Errorf("create federation request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Share-Token", fed.ShareToken)
	req.Header.Set("User-Agent", version.AgentUserAgent)
	req.Header.Set("X-Encrypted", "1")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("federation request failed: %v", err)
	}
	defer resp.Body.Close()
	respBody, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		return nil, fmt.Errorf("read federation response: %v", rerr)
	}
	// 拥有方对响应(含错误)加密,先解密再判状态码。
	if resp.Header.Get("X-Encrypted") == "1" {
		decrypted, derr := session.Decrypt(respBody)
		if derr != nil {
			return nil, fmt.Errorf("decrypt federation response: %w", derr)
		}
		respBody = decrypted
	}
	if resp.StatusCode >= 400 {
		return nil, federationErrorFromBody(resp.StatusCode, respBody)
	}
	return respBody, nil
}

func (h *RemoteManageHandler) doPlainFederationRequest(ctx context.Context, fed storage.FederatedServer, payload []byte) ([]byte, error) {
	url := strings.TrimRight(fed.OwnerURL, "/") + "/api/federation/manage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create federation request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Share-Token", fed.ShareToken)
	req.Header.Set("User-Agent", version.AgentUserAgent)
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("federation request failed: %v", err)
	}
	defer resp.Body.Close()
	respBody, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		return nil, fmt.Errorf("read federation response: %v", rerr)
	}
	if resp.StatusCode >= 400 {
		return nil, federationErrorFromBody(resp.StatusCode, respBody)
	}
	return respBody, nil
}

func federationErrorFromBody(status int, body []byte) error {
	var er map[string]any
	if json.Unmarshal(body, &er) == nil {
		if msg, ok := er["error"].(string); ok {
			return fmt.Errorf("%s", msg)
		}
	}
	return fmt.Errorf("federation returned status %d: %s", status, string(body))
}

func (h *RemoteManageHandler) doPlainPullRequest(ctx context.Context, method, childURL, token string, body []byte) ([]byte, error) {
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, childURL, bytes.NewReader(body))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, childURL, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", version.AgentUserAgent)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		if json.Unmarshal(respBody, &errResp) == nil {
			if msg, ok := errResp["error"].(string); ok {
				return nil, fmt.Errorf("%s", msg)
			}
		}
		return nil, fmt.Errorf("remote server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (h *RemoteManageHandler) doPullKeyExchange(ctx context.Context, serverID int64, method, childURL, token string, body []byte) ([]byte, error) {
	masterPriv, masterPub, err := securechan.GenerateEphemeral()
	if err != nil {
		return h.doPlainPullRequest(ctx, method, childURL, token, body)
	}

	sig := securechan.Sign(h.crypto.Identity.PrivateKey, masterPub)
	kxHeader := base64.StdEncoding.EncodeToString(masterPub) + "|" + base64.StdEncoding.EncodeToString(sig)

	var req *http.Request
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, childURL, bytes.NewReader(body))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, childURL, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", version.AgentUserAgent)
	req.Header.Set("X-Key-Exchange", kxHeader)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		if json.Unmarshal(respBody, &errResp) == nil {
			if msg, ok := errResp["error"].(string); ok {
				return nil, fmt.Errorf("%s", msg)
			}
		}
		return nil, fmt.Errorf("remote server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	if kxResp := resp.Header.Get("X-Key-Exchange"); kxResp != "" {
		agentEphPub, err := base64.StdEncoding.DecodeString(kxResp)
		if err == nil && len(agentEphPub) == 32 {
			sharedSecret, err := securechan.ComputeSharedSecret(masterPriv, agentEphPub)
			if err == nil {
				session, err := securechan.DeriveSession(sharedSecret, agentEphPub, masterPub, true)
				if err == nil {
					h.pullSessions.Store(serverID, session)
					log.Printf("[Remote Manage] Pull key exchange completed for server %d", serverID)
				}
			}
		}
	}

	return respBody, nil
}

func (h *RemoteManageHandler) doEncryptedPullRequest(ctx context.Context, method, childURL, token string, body []byte, session *securechan.Session) ([]byte, error) {
	var reqBody []byte
	if body != nil {
		encrypted, err := session.Encrypt(body)
		if err != nil {
			return nil, fmt.Errorf("encrypt: %w", err)
		}
		reqBody = encrypted
	}

	var req *http.Request
	var err error
	if reqBody != nil {
		req, err = http.NewRequestWithContext(ctx, method, childURL, bytes.NewReader(reqBody))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, childURL, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", version.AgentUserAgent)
	req.Header.Set("X-Encrypted", "1")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// agent 对所有响应都加密(含错误响应),必须先解密再判断状态码,
	// 否则错误响应体仍是密文,前端 toast 会显示乱码。
	if resp.Header.Get("X-Encrypted") == "1" {
		decrypted, derr := session.Decrypt(respBody)
		if derr != nil {
			return nil, fmt.Errorf("decrypt response: %w", derr)
		}
		respBody = decrypted
	}

	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		if json.Unmarshal(respBody, &errResp) == nil {
			if msg, ok := errResp["error"].(string); ok {
				return nil, fmt.Errorf("%s", msg)
			}
		}
		return nil, fmt.Errorf("remote server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// 处理远程服务器上的 xray 配置文件的列表和管理
func (h *RemoteManageHandler) HandleXrayConfigFiles(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	// 转发查询参数
	query := ""
	if file := r.URL.Query().Get("file"); file != "" {
		query = "?file=" + file
	}

	var body []byte
	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to read body")
			return
		}
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/xray/config/files"+query, body)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 处理远程服务器上的 nginx 配置文件的列表和管理
func (h *RemoteManageHandler) HandleNginxConfigFiles(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	// 转发查询参数
	query := ""
	if file := r.URL.Query().Get("file"); file != "" {
		query = "?file=" + file
	}

	var body []byte
	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to read body")
			return
		}
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/nginx/config/files"+query, body)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// HandleNginxServersList 转发到 agent 的 /api/child/nginx/servers-list,
// 让前端在新建 vless+wss 入站前能拿到目标服务器 nginx servers/ 目录里现有域名,
// 用于检测同域名旧 conf 被静默覆盖的风险(reality 或老 wss 配置)。
// 老 agent 没这个 endpoint 时返回 502 透传 — 前端兜底为"暂无冲突",保持向后兼容。
func (h *RemoteManageHandler) HandleNginxServersList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		remoteWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}
	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/nginx/servers-list", nil)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// HandleNginxWebsites exposes the agent-side website inventory and safe delete
// operation. The agent owns filesystem validation and nginx rollback; the
// master additionally protects the server's primary domain and cleans routing.
func (h *RemoteManageHandler) HandleNginxWebsites(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil || id <= 0 {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}
	server, err := h.repo.GetRemoteServer(r.Context(), id)
	if err != nil {
		remoteWriteError(w, http.StatusNotFound, "server not found")
		return
	}
	var body []byte
	if r.Method == http.MethodDelete {
		var req struct {
			Domain string `json:"domain"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			remoteWriteError(w, http.StatusBadRequest, "invalid body")
			return
		}
		domain := strings.ToLower(strings.TrimSpace(req.Domain))
		if domain == "" {
			remoteWriteError(w, http.StatusBadRequest, "domain required")
			return
		}
		if strings.EqualFold(domain, strings.TrimSpace(server.Domain)) {
			remoteWriteError(w, http.StatusConflict, "服务器主域名配置受保护，不能从网站管理删除")
			return
		}
		body, _ = json.Marshal(map[string]string{"domain": domain})
	} else if r.Method != http.MethodGet {
		remoteWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/nginx/websites", body)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if r.Method == http.MethodGet && strings.TrimSpace(server.Domain) != "" {
		var inventory map[string]any
		if json.Unmarshal(result, &inventory) == nil {
			if websites, ok := inventory["websites"].([]any); ok {
				for _, raw := range websites {
					website, _ := raw.(map[string]any)
					domain, _ := website["domain"].(string)
					if strings.EqualFold(domain, strings.TrimSpace(server.Domain)) {
						website["protected"] = true
						website["reason"] = "服务器主域名配置"
					}
				}
				if encoded, marshalErr := json.Marshal(inventory); marshalErr == nil {
					result = encoded
				}
			}
		}
	}
	if r.Method == http.MethodDelete {
		var req struct {
			Domain string `json:"domain"`
		}
		_ = json.Unmarshal(body, &req)
		h.cleanupWebsiteRouting(r.Context(), id, server.StealMode, req.Domain)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result)
}

func (h *RemoteManageHandler) cleanupWebsiteRouting(ctx context.Context, serverID int64, stealMode, domain string) {
	resp, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/xray/config", nil)
	if err != nil {
		log.Printf("[WebsiteDelete] read xray config failed for server %d: %v", serverID, err)
		return
	}
	var envelope struct {
		Config string `json:"config"`
	}
	if json.Unmarshal(resp, &envelope) != nil || envelope.Config == "" {
		return
	}
	var config map[string]any
	if json.Unmarshal([]byte(envelope.Config), &config) != nil {
		return
	}
	changed := false
	if stealMode == "fallback" {
		changed = removeWebsiteFallbackDomain(config, domain)
	} else {
		changed = h.removeDomainsFromTunnelNginxRoute(config, []string{domain})
	}
	if !changed {
		return
	}
	updated, _ := json.MarshalIndent(config, "", "    ")
	payload, _ := json.Marshal(map[string]string{"config": string(updated)})
	if _, err := h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/xray/config", payload); err != nil {
		log.Printf("[WebsiteDelete] write xray config failed for server %d: %v", serverID, err)
		return
	}
	if err := h.restartXrayWithRecovery(ctx, serverID, "DeleteWebsite"); err != nil {
		log.Printf("[WebsiteDelete] restart xray failed for server %d: %v", serverID, err)
	}
}

func removeWebsiteFallbackDomain(config map[string]any, domain string) bool {
	inbounds, _ := config["inbounds"].([]any)
	for _, raw := range inbounds {
		inbound, _ := raw.(map[string]any)
		settings, _ := inbound["settings"].(map[string]any)
		reality, _ := settings["realitySettings"].(map[string]any)
		names, _ := reality["serverNames"].([]any)
		if len(names) == 0 {
			continue
		}
		remaining := make([]any, 0, len(names))
		removed := false
		for _, rawName := range names {
			name, _ := rawName.(string)
			if strings.EqualFold(name, domain) {
				removed = true
				continue
			}
			remaining = append(remaining, rawName)
		}
		if removed {
			reality["serverNames"] = remaining
			return true
		}
	}
	return false
}

// getRemoteServerPort 提取或确定远程服务器的端口
// 现在，我们假设子服务器在配置中指定的同一端口上运行
func (h *RemoteManageHandler) getRemoteServerPort(server *storage.RemoteServer) string {
	// 默认端口
	port := "23889"

	// 如果服务器的名称或元数据中有特定端口，请将其提取
	// 目前，使用默认值
	if server.IPAddress != "" && strings.Contains(server.IPAddress, ":") {
		parts := strings.Split(server.IPAddress, ":")
		if len(parts) == 2 {
			port = parts[1]
		}
	}

	return port
}

// ================== X 射线入库管理 ==================

// 将入站管理请求代理到远程服务器
// validateInboundClientsSelfOnly 校验 add inbound 请求里的 clients/accounts 只包含当前登录账号自己。
// 返回空字符串表示通过,否则返回错误信息。
//
// 身份口径:xray 的 vless/vmess/trojan/shadowsocks 用 client.email 标识用户;socks/http 用 account.user。
// mmwx 约定 email/user == 用户名。校验要求每一条 client 的身份都等于当前登录用户名。
// 允许 0 条(空 clients,纯创建 inbound 不挂用户的场景)。
func validateInboundClientsSelfOnly(ctx context.Context, inboundReq map[string]interface{}) string {
	username := auth.UsernameFromContext(ctx)
	if username == "" {
		return "无法识别当前登录用户"
	}
	inbound, ok := inboundReq["inbound"].(map[string]interface{})
	if !ok {
		return "" // 没有 inbound 体(可能是别的 action),不拦
	}
	settings, _ := inbound["settings"].(map[string]interface{})
	if settings == nil {
		return ""
	}
	check := func(entries []interface{}, idField string) string {
		for _, e := range entries {
			m, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			// 优先 email,其次 idField(user)。两者都为空视为非法(无法归属)。
			identity, _ := m["email"].(string)
			if identity == "" {
				identity, _ = m[idField].(string)
			}
			if identity != username {
				return fmt.Sprintf("节点只能添加你自己(%s)的用户配置,检测到非法用户 %q", username, identity)
			}
		}
		return ""
	}
	if clients, ok := settings["clients"].([]interface{}); ok {
		if msg := check(clients, "id"); msg != "" {
			return msg
		}
	}
	if accounts, ok := settings["accounts"].([]interface{}); ok {
		if msg := check(accounts, "user"); msg != "" {
			return msg
		}
	}
	return ""
}

// validateInboundTLS 兜底校验入站 TLS 证书完整性。Hysteria2 / VLESS+TLS / Trojan+TLS 等
// 协议必 TLS,前端漏填证书时 xray-core 报 "both file and bytes are empty" 对用户不友好,
// 还容易让人误以为是后端 bug。这里在 forward 前明确拒绝并给出用户能看懂的提示。
//
// 调用时机:在 resolveInboundCert 之后,inboundReq 已经反映了"托管证书路径已注入"的最新形态。
// 兼容 action: "add" / "" 两种入站添加场景;remove/update 不校验。
func validateInboundTLS(inboundReq map[string]interface{}) string {
	inbound, _ := inboundReq["inbound"].(map[string]interface{})
	if inbound == nil {
		return ""
	}
	ss, _ := inbound["streamSettings"].(map[string]interface{})
	if ss == nil {
		return ""
	}
	sec, _ := ss["security"].(string)
	if sec != "tls" {
		return ""
	}
	protocol, _ := inbound["protocol"].(string)
	tls, _ := ss["tlsSettings"].(map[string]interface{})
	certs, _ := tls["certificates"].([]interface{})
	if len(certs) == 0 {
		return fmt.Sprintf("入站 %s 启用了 TLS,但未配置证书。请在「证书来源」选择主控托管证书,或手动填写 certificateFile + keyFile 路径", strings.ToLower(protocol))
	}
	for i, c := range certs {
		cm, ok := c.(map[string]interface{})
		if !ok {
			return fmt.Sprintf("入站 %s 的 tlsSettings.certificates[%d] 不是对象", strings.ToLower(protocol), i)
		}
		certFile, _ := cm["certificateFile"].(string)
		keyFile, _ := cm["keyFile"].(string)
		certBytes, _ := cm["certificate"].([]interface{})
		keyBytes, _ := cm["key"].([]interface{})
		if strings.TrimSpace(certFile) == "" && len(certBytes) == 0 {
			return fmt.Sprintf("入站 %s 的证书 #%d 没填证书文件路径(certificateFile),也没填证书内联内容(certificate)。请补全后重试", strings.ToLower(protocol), i)
		}
		if strings.TrimSpace(keyFile) == "" && len(keyBytes) == 0 {
			return fmt.Sprintf("入站 %s 的证书 #%d 没填私钥文件路径(keyFile),也没填私钥内联内容(key)。请补全后重试", strings.ToLower(protocol), i)
		}
	}
	return ""
}

// resolveInboundCert 处理「添加 tls 入站时选了主控托管证书」(前端通过带外字段 cert_id 指定):
// 同步把证书下发到该 agent 的 xray 证书目录,再把 tlsSettings.certificates 改写成 agent 上的真实路径,
// 并在 serverName 为空时补成证书域名。返回改写后的 body(未触发则返回 nil);失败返回错误,由调用方透传给前端。
func (h *RemoteManageHandler) resolveInboundCert(ctx context.Context, serverID int64, inboundReq map[string]interface{}) ([]byte, error) {
	inbound, _ := inboundReq["inbound"].(map[string]interface{})
	if inbound == nil {
		return nil, nil
	}
	// cert_id 是前端塞进 inbound 的带外字段(选了主控托管证书时);处理后剥离,不传给 agent。
	certIDf, _ := inbound["cert_id"].(float64)
	certID := int64(certIDf)
	if certID <= 0 {
		return nil, nil // 未选托管证书:用户手填路径或非 tls,不处理
	}
	ss, _ := inbound["streamSettings"].(map[string]interface{})
	if ss == nil {
		return nil, fmt.Errorf("入站缺少 streamSettings,无法应用证书")
	}
	if sec, _ := ss["security"].(string); sec != "tls" {
		return nil, nil // 非 tls 不处理
	}
	if h.certHandler == nil {
		return nil, fmt.Errorf("证书功能未初始化")
	}
	cert, err := h.repo.GetCertificate(ctx, certID)
	if err != nil || cert == nil {
		return nil, fmt.Errorf("所选证书不存在(id=%d)", certID)
	}
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return nil, err
	}
	certPath, keyPath, derr := h.certHandler.DeployCertToServerSync(ctx, server, cert)
	if derr != nil {
		return nil, fmt.Errorf("下发证书到服务器失败: %v", derr)
	}
	tls, _ := ss["tlsSettings"].(map[string]interface{})
	if tls == nil {
		tls = map[string]interface{}{}
		ss["tlsSettings"] = tls
	}
	tls["certificates"] = []interface{}{
		map[string]interface{}{"certificateFile": certPath, "keyFile": keyPath},
	}
	if sn, _ := tls["serverName"].(string); sn == "" {
		tls["serverName"] = cert.Domain
	}
	delete(inbound, "cert_id") // 剥离带外字段,xray 不认识它
	return json.Marshal(inboundReq)
}

// inboundCredentialKey 返回某协议在 inbound.settings 里存放客户端凭据的数组字段名。
func inboundCredentialKey(protocol string) string {
	switch strings.ToLower(protocol) {
	case "socks", "socks5", "http":
		return "accounts"
	case "anytls", "snell", "mieru":
		return "users"
	default: // vless/vmess/trojan/shadowsocks/hysteria/hysteria2...
		return "clients"
	}
}

// preserveInboundCredentials 把 current 入站的客户端凭据(clients/users/accounts + SS2022 服务端 password)
// 原样拷回 newInbound,覆盖前端传来的任何凭据 —— 保证「修改节点」不能改 xray 用户(uuid/password)。
func preserveInboundCredentials(newInbound, current map[string]any, protocol string) {
	curSettings, _ := current["settings"].(map[string]any)
	if curSettings == nil {
		return
	}
	newSettings, _ := newInbound["settings"].(map[string]any)
	if newSettings == nil {
		newSettings = map[string]any{}
		newInbound["settings"] = newSettings
	}
	key := inboundCredentialKey(protocol)
	if cred, ok := curSettings[key]; ok {
		newSettings[key] = cred
	}
	// SS2022 服务端密码也属凭据
	if pw, ok := curSettings["password"]; ok {
		newSettings["password"] = pw
	}
}

func regenerateInboundCredentials(inbound, current map[string]interface{}) (map[string]string, error) {
	protocol := strings.ToLower(strings.TrimSpace(fmt.Sprint(inbound["protocol"])))
	settings, _ := inbound["settings"].(map[string]interface{})
	if settings == nil {
		settings = map[string]interface{}{}
		inbound["settings"] = settings
	}
	currentSettings, _ := current["settings"].(map[string]interface{})
	oldKey := inboundCredentialKey(strings.ToLower(strings.TrimSpace(fmt.Sprint(current["protocol"]))))
	newKey := inboundCredentialKey(protocol)
	oldItems, _ := currentSettings[oldKey].([]interface{})
	method := strings.TrimSpace(fmt.Sprint(settings["method"]))
	generated := make([]interface{}, 0, len(oldItems))
	byIdentity := make(map[string]string, len(oldItems))
	for _, item := range oldItems {
		old, _ := item.(map[string]interface{})
		if old == nil {
			continue
		}
		email := strings.TrimSpace(fmt.Sprint(old["email"]))
		identity := email
		if identity == "" || identity == "<nil>" {
			identity = strings.TrimSpace(fmt.Sprint(old["user"]))
		}
		if identity == "" || identity == "<nil>" {
			identity = strings.TrimSpace(fmt.Sprint(old["username"]))
		}
		if identity == "" || identity == "<nil>" {
			return nil, errors.New("入站存在无法识别归属的账户，不能安全重新生成凭据")
		}
		cred, credJSON, err := generateRoutedClientCred(protocol, method, email)
		if err != nil {
			return nil, err
		}
		if newKey == "accounts" {
			cred["user"] = identity
			delete(cred, "email")
			if b, err := json.Marshal(cred); err == nil {
				credJSON = string(b)
			}
		}
		if protocol == "vless" {
			if flow := firstInboundFlow(settings); flow != "" {
				cred["flow"] = flow
				if b, err := json.Marshal(cred); err == nil {
					credJSON = string(b)
				}
			}
		}
		generated = append(generated, cred)
		byIdentity[identity] = credJSON
	}
	delete(settings, "clients")
	delete(settings, "users")
	delete(settings, "accounts")
	settings[newKey] = generated
	if protocol == "shadowsocks" {
		keyLen := shadowsocksKeyLength(method)
		key := make([]byte, keyLen)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		settings["password"] = base64.StdEncoding.EncodeToString(key)
	}
	return byIdentity, nil
}

func firstInboundFlow(settings map[string]interface{}) string {
	for _, key := range []string{"clients", "users", "accounts"} {
		if items, _ := settings[key].([]interface{}); len(items) > 0 {
			if first, _ := items[0].(map[string]interface{}); first != nil {
				flow, _ := first["flow"].(string)
				return strings.TrimSpace(flow)
			}
		}
	}
	return ""
}

// applyShadowsocksTCPFastOpen 让目标 Agent 检测内核服务端 TFO 能力，再决定是否下发。
// 老 Agent 没有该字段时按不支持处理，避免 xray 配置看似开启、实际内核未启用。
func (h *RemoteManageHandler) applyShadowsocksTCPFastOpen(ctx context.Context, serverID int64, inboundReq map[string]interface{}) {
	inbound, _ := inboundReq["inbound"].(map[string]interface{})
	protocol, _ := inbound["protocol"].(string)
	if !strings.EqualFold(protocol, "shadowsocks") {
		return
	}
	supported := false
	if raw, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/system/info", nil); err == nil {
		var info struct {
			TCPFastOpenServer bool `json:"tcp_fast_open_server"`
		}
		if json.Unmarshal(raw, &info) == nil {
			supported = info.TCPFastOpenServer
		}
	} else {
		log.Printf("[HandleInbounds] detect TCP Fast Open on server %d failed: %v", serverID, err)
	}

	stream, _ := inbound["streamSettings"].(map[string]interface{})
	if supported {
		if stream == nil {
			stream = map[string]interface{}{"network": "tcp"}
			inbound["streamSettings"] = stream
		}
		sockopt, _ := stream["sockopt"].(map[string]interface{})
		if sockopt == nil {
			sockopt = map[string]interface{}{}
			stream["sockopt"] = sockopt
		}
		sockopt["tcpFastOpen"] = true
		return
	}
	if stream == nil {
		return
	}
	if sockopt, _ := stream["sockopt"].(map[string]interface{}); sockopt != nil {
		delete(sockopt, "tcpFastOpen")
		if len(sockopt) == 0 {
			delete(stream, "sockopt")
		}
	}
	if len(stream) == 1 && strings.EqualFold(fmt.Sprint(stream["network"]), "tcp") {
		delete(inbound, "streamSettings")
	}
}

// applyConfiguredInboundPortRange 是随机端口范围的后端最终兜底。前端可能在服务器
// 详情尚未加载完成时先按默认范围生成端口，因此不能只依赖浏览器端约束。
func (h *RemoteManageHandler) applyConfiguredInboundPortRange(ctx context.Context, serverID int64, inboundReq map[string]interface{}) error {
	inbound, _ := inboundReq["inbound"].(map[string]interface{})
	if inbound == nil || isRealityInbound(inbound) || isVlessWSInboundReq(inboundReq) {
		return nil
	}
	protocol := strings.ToLower(strings.TrimSpace(fmt.Sprint(inbound["protocol"])))
	if protocol == "tunnel" || protocol == "dokodemo-door" {
		return nil
	}
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return err
	}
	minPort, maxPort := server.PortRangeMin, server.PortRangeMax
	if minPort <= 0 || maxPort <= 0 || minPort > maxPort {
		return nil
	}
	oldPort := toInt(inbound["port"])
	if oldPort >= minPort && oldPort <= maxPort {
		return nil
	}

	raw, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/inbounds", nil)
	if err != nil {
		return fmt.Errorf("读取已用端口失败: %w", err)
	}
	var current struct {
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &current); err != nil {
		return fmt.Errorf("解析已用端口失败: %w", err)
	}
	used := make(map[int]bool, len(current.Inbounds))
	for _, item := range current.Inbounds {
		used[toInt(item["port"])] = true
	}
	size := maxPort - minPort + 1
	start := mathrand.IntN(size)
	newPort := 0
	for offset := 0; offset < size; offset++ {
		candidate := minPort + (start+offset)%size
		if !used[candidate] {
			newPort = candidate
			break
		}
	}
	if newPort == 0 {
		return fmt.Errorf("服务器随机端口范围 %d-%d 已全部占用", minPort, maxPort)
	}
	inbound["port"] = newPort
	if tag, _ := inbound["tag"].(string); tag != "" && oldPort > 0 {
		oldSuffix := "-" + strconv.Itoa(oldPort)
		if strings.HasSuffix(tag, oldSuffix) {
			inbound["tag"] = strings.TrimSuffix(tag, oldSuffix) + "-" + strconv.Itoa(newPort)
		}
	}
	log.Printf("[HandleInbounds] remapped out-of-range port %d to %d (range=%d-%d server=%d)", oldPort, newPort, minPort, maxPort, serverID)
	return nil
}

// fetchRemoteInboundByTag 从 agent 拉当前全部入站,按 tag 返回一条完整配置(含 settings/streamSettings)。
// 无匹配返回 (nil, nil)。给「修改入站」保留原协议/凭据用。
func (h *RemoteManageHandler) fetchRemoteInboundByTag(ctx context.Context, serverID int64, tag string) (map[string]any, error) {
	raw, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/inbounds", nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	for _, ib := range resp.Inbounds {
		if t, _ := ib["tag"].(string); t == tag {
			return ib, nil
		}
	}
	return nil, nil
}

func (h *RemoteManageHandler) HandleInbounds(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	var body []byte
	var inboundReq map[string]interface{}
	var selectedWSSDomain string
	var selectedWSSCertID int64
	var realityGuardRequested *bool
	if r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to read body")
			return
		}
		// 解析请求体以获取入站配置
		if err := json.Unmarshal(body, &inboundReq); err != nil {
			remoteWriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}

	// reality_guard 是主控专用的带外开关，不能原样交给 Xray。辅助 tunnel 使用保留 tag，
	// 在主入站成功写入后由完整配置同步函数一次性加入/更新/移除。
	if r.Method == http.MethodPost && inboundReq != nil {
		if inbound, _ := inboundReq["inbound"].(map[string]interface{}); inbound != nil {
			if value, ok := inbound["reality_guard"].(bool); ok {
				realityGuardRequested = new(bool)
				*realityGuardRequested = value
				delete(inbound, "reality_guard")
				body, _ = json.Marshal(inboundReq)
			}
		}
	}
	// Reality 防偷会把主入站 dest 改为本地 helper tunnel；偷自己同样依赖 tunnel/fallback
	// 拓扑改写，两套编排不能叠加。必须在任何 Agent 写入前拒绝，避免绕过前端造成半套配置。
	if realityGuardRequested != nil && *realityGuardRequested {
		server, getErr := h.repo.GetRemoteServer(r.Context(), id)
		if getErr != nil || server == nil {
			remoteWriteError(w, http.StatusInternalServerError, "读取服务器配置失败，无法校验 Reality 防偷")
			return
		}
		if guardErr := validateRealityGuardStealMode(server.StealMode, realityGuardRequested); guardErr != nil {
			remoteWriteError(w, http.StatusBadRequest, guardErr.Error())
			return
		}
	}

	// update = 修改节点对应的入站:服务端强制保留原协议 + 原凭据(不信任前端),先删旧入站,
	// 再改写成 add 走后续预处理/下发,最后发 EventInboundUpdated(原地更新 v4/v6 节点,不重建)。
	origAction := ""
	if inboundReq != nil {
		origAction, _ = inboundReq["action"].(string)
	}
	isUpdate := r.Method == http.MethodPost && strings.EqualFold(origAction, "update")
	updateTag := ""
	var updateOldInbound map[string]interface{}
	if isUpdate {
		tag, _ := inboundReq["tag"].(string)
		updateTag = strings.TrimSpace(tag)
		inbound, _ := inboundReq["inbound"].(map[string]interface{})
		if strings.TrimSpace(tag) == "" || inbound == nil {
			remoteWriteError(w, http.StatusBadRequest, "update 需要 tag 与 inbound")
			return
		}
		current, cerr := h.fetchRemoteInboundByTag(r.Context(), id, tag)
		if cerr != nil {
			remoteWriteError(w, http.StatusBadGateway, "获取当前入站失败: "+cerr.Error())
			return
		}
		if current == nil {
			remoteWriteError(w, http.StatusBadRequest, "未找到要修改的入站: "+tag)
			return
		}
		updateOldInbound = current
		// TAG 是路由与节点关联的稳定主键；其它配置（含协议）均允许修改。
		inbound["tag"] = tag
		credentials, regenErr := regenerateInboundCredentials(inbound, current)
		if regenErr != nil {
			remoteWriteError(w, http.StatusBadRequest, "重新生成账户凭据失败: "+regenErr.Error())
			return
		}
		protocol := strings.ToLower(strings.TrimSpace(fmt.Sprint(inbound["protocol"])))
		settings, _ := inbound["settings"].(map[string]interface{})
		method := strings.TrimSpace(fmt.Sprint(settings["method"]))
		// Agent 上只有当前活跃账户；数据库还可能保存禁用/超限用户的凭据。
		// 这些账户也预生成新协议凭据，但不塞回 Agent，恢复权限时直接复用新值。
		if configs, err := h.repo.GetUserInboundConfigsByServer(r.Context(), id); err == nil {
			for _, cfg := range configs {
				if cfg.InboundTag != tag {
					continue
				}
				var old map[string]interface{}
				_ = json.Unmarshal([]byte(cfg.CredentialJSON), &old)
				identity := strings.TrimSpace(fmt.Sprint(old["email"]))
				if identity == "" || identity == "<nil>" {
					identity = strings.TrimSpace(fmt.Sprint(old["user"]))
				}
				if identity == "" || identity == "<nil>" || credentials[identity] != "" {
					continue
				}
				cred, credJSON, err := generateRoutedClientCred(protocol, method, identity)
				if err != nil {
					remoteWriteError(w, http.StatusBadRequest, "生成非活跃账户凭据失败: "+err.Error())
					return
				}
				if inboundCredentialKey(protocol) == "accounts" {
					cred["user"] = identity
					delete(cred, "email")
					if b, err := json.Marshal(cred); err == nil {
						credJSON = string(b)
					}
				}
				credentials[identity] = credJSON
			}
		}
		if emails, err := h.repo.ListInboundSubaccountEmails(r.Context(), id, tag); err == nil {
			for _, email := range emails {
				if credentials[email] != "" {
					continue
				}
				_, credJSON, err := generateRoutedClientCred(protocol, method, email)
				if err != nil {
					remoteWriteError(w, http.StatusBadRequest, "生成路由子账户凭据失败: "+err.Error())
					return
				}
				credentials[email] = credJSON
			}
		}
		inboundReq["regenerated_credentials"] = credentials
		// 内部继续按 add 做证书/端口/TFO 预处理；真正转发时改成 Agent 原子 replace。
		inboundReq["action"] = "add"
		if nb, mErr := json.Marshal(inboundReq); mErr == nil {
			body = nb
		}
	}

	// 添加节点(add inbound)时校验:inbound.settings.clients/accounts 只能包含"当前登录账号自己"。
	// 用户卡片在前端已锁死,但后端必须独立校验,防止普通用户绕过前端直接构造请求把别人的 uuid/email 塞进节点。
	// 管理员是节点管理者,可添加任意 client(任意 uuid/email),不受此限制。
	// 注:套餐分配用户走的是 addUserToInbound → forwardToRemoteServer,不经过本 HTTP handler,不受影响。
	// update 已在上面强制保留 current 凭据(前端改不了),故跳过此自身校验(current 可能合法含多 client)。
	if r.Method == http.MethodPost && inboundReq != nil && !isUpdate {
		action, _ := inboundReq["action"].(string)
		if al := strings.ToLower(action); al == "" || al == "add" {
			uname := auth.UsernameFromContext(r.Context())
			if !userIsAdmin(r.Context(), h.repo, uname) {
				if msg := validateInboundClientsSelfOnly(r.Context(), inboundReq); msg != "" {
					remoteWriteError(w, http.StatusForbidden, msg)
					return
				}
			}
		}
	}

	// 删除 reality 入站前，先保存其 serverNames 以便后续恢复路由
	var preDeleteRealityDomains []string
	var preDeleteRealityGuard bool
	var preDeleteInbound map[string]interface{}
	if r.Method == http.MethodPost && inboundReq != nil {
		action, _ := inboundReq["action"].(string)
		if strings.ToLower(action) == "remove" {
			if tag, _ := inboundReq["tag"].(string); tag != "" {
				preDeleteInbound, _ = h.fetchRemoteInboundByTag(r.Context(), id, tag)
				preDeleteRealityDomains = h.getRealityServerNames(r.Context(), id, tag)
				if helper, _ := h.fetchRemoteInboundByTag(r.Context(), id, realityGuardTag(tag)); helper != nil {
					preDeleteRealityGuard = true
				}
			}
		}
	}

	// 添加 tls 入站若选了主控托管证书(cert_id),先同步下发证书到 agent 并把路径注入到入站配置,
	// 避免「agent 上没有该证书 → xray 加载失败 → 502」。失败明确报错(已透传,不被 CF 吞)。
	if r.Method == http.MethodPost && inboundReq != nil {
		if action, _ := inboundReq["action"].(string); action == "" || strings.ToLower(action) == "add" {
			// WSS 的 cert_id 是带外字段，resolveInboundCert 会在转发前删除它。
			// 提前保留用户在专家模式选的证书和 SNI，供 nginx 同步精确使用。
			if inbound, ok := inboundReq["inbound"].(map[string]interface{}); ok && isVlessWSInboundReq(inboundReq) {
				if certID, ok := inbound["cert_id"].(float64); ok {
					selectedWSSCertID = int64(certID)
				}
				if ss, _ := inbound["streamSettings"].(map[string]interface{}); ss != nil {
					if tls, _ := ss["tlsSettings"].(map[string]interface{}); tls != nil {
						if domain, _ := tls["serverName"].(string); strings.TrimSpace(domain) != "" {
							selectedWSSDomain = strings.TrimSpace(domain)
						}
					}
				}
			}
			if newBody, certErr := h.resolveInboundCert(r.Context(), id, inboundReq); certErr != nil {
				remoteWriteError(w, http.StatusBadGateway, "证书处理失败: "+certErr.Error())
				return
			} else if newBody != nil {
				body = newBody
				// 重新 unmarshal 一下,后续 TLS 兜底校验要看到最新的 certificates 值
				_ = json.Unmarshal(body, &inboundReq)
			}
		}
	}

	// VLESS + WSS 入站添加:强制 listen=127.0.0.1、自动分配本地端口、自动随机 path、security=none
	// (TLS 由 nginx 在 443 处理,xray 只接 ws upgrade)。后续 forward 成功再调 syncWSSNginx 聚合渲染。
	// per-server 锁:防止并发添加抢到同一端口。
	if r.Method == http.MethodPost && inboundReq != nil {
		if action, _ := inboundReq["action"].(string); (action == "" || strings.ToLower(action) == "add") && isVlessWSInboundReq(inboundReq) {
			lock := wssServerLock(id)
			lock.Lock()
			defer lock.Unlock()
			newBody, perr := h.preprocessWSSInbound(r.Context(), id, body, inboundReq)
			if perr != nil {
				remoteWriteError(w, http.StatusBadGateway, perr.Error())
				return
			}
			body = newBody
			_ = json.Unmarshal(body, &inboundReq)
		}
	}

	// tunnel 偷自己时 443 已由 tunnel-in 对外监听。首次创建 Reality 若前端仍提交 443，
	// 必须在转发给 Agent 前改成 tunnel-in.settings.port；否则 Agent 会先因端口占用拒绝，
	// 后面的 cleanupTunnelRouteForReality 根本没有机会更新转发目标。
	if r.Method == http.MethodPost && inboundReq != nil {
		if action, _ := inboundReq["action"].(string); action == "" || strings.EqualFold(action, "add") {
			if inbound, ok := inboundReq["inbound"].(map[string]interface{}); ok && isRealityInbound(inbound) {
				server, serr := h.repo.GetRemoteServer(r.Context(), id)
				if serr == nil && server != nil && server.StealMode == "tunnel" && toInt(inbound["port"]) == 443 {
					if internalPort := h.getTunnelInSettingsPort(r.Context(), id); internalPort > 0 {
						inbound["port"] = internalPort
						body, _ = json.Marshal(inboundReq)
						log.Printf("[HandleInbounds] Remapped tunnel Reality inbound port 443 to tunnel-in settings.port %d on server %d", internalPort, id)
					}
				}
			}
		}
	}

	// TLS 入站兜底校验:hysteria2 / vless+tls / trojan 等必须 TLS 的协议,前端漏填证书时
	// xray-core 的错是 "both file and bytes are empty",对用户不友好且让人怀疑后端 bug。
	// 这里在 forward 前明确拒绝并给出用户能看懂的提示。
	if r.Method == http.MethodPost && inboundReq != nil {
		if action, _ := inboundReq["action"].(string); action == "" || strings.ToLower(action) == "add" {
			if !isUpdate {
				if portErr := h.applyConfiguredInboundPortRange(r.Context(), id, inboundReq); portErr != nil {
					remoteWriteError(w, http.StatusConflict, portErr.Error())
					return
				}
			}
			h.applyShadowsocksTCPFastOpen(r.Context(), id, inboundReq)
			body, _ = json.Marshal(inboundReq)
			if msg := validateInboundTLS(inboundReq); msg != "" {
				remoteWriteError(w, http.StatusBadRequest, msg)
				return
			}
		}
	}

	// anytls/snell/mieru 入站只有内嵌 xray(fork)支持,官方外置 xray 无此协议 → 会以 "unknown config id: xxx" 启动失败。
	// 外置模式直接拒绝(前端也会禁用该选项,这里是绕过前端直连 API 的兜底)。
	if r.Method == http.MethodPost && inboundReq != nil {
		if action, _ := inboundReq["action"].(string); action == "" || strings.ToLower(action) == "add" {
			if inbound, ok := inboundReq["inbound"].(map[string]interface{}); ok {
				if proto, _ := inbound["protocol"].(string); strings.ToLower(proto) == "anytls" || strings.ToLower(proto) == "snell" || strings.ToLower(proto) == "mieru" {
					if server, err := h.repo.GetRemoteServer(r.Context(), id); err == nil && server != nil && server.XrayMode == "external" {
						remoteWriteError(w, http.StatusBadRequest, strings.ToLower(proto)+" 协议需要内嵌 xray,请先将该服务器切换为内嵌模式")
						return
					}
				}
			}
		}
	}

	// 中转(relay):relay_server/relay_port 是前端 wizard 挂在 inbound 上的带外字段,agent/xray 不需要 ——
	// 转发前从 body 里剥掉,仅用于建节点时把 clash server/port 换成中转地址(经 InboundEvent 传给 NodeSyncListener)。
	var relayServer string
	var relayPort int
	if r.Method == http.MethodPost && inboundReq != nil {
		if inbound, ok := inboundReq["inbound"].(map[string]interface{}); ok {
			if rs, _ := inbound["relay_server"].(string); strings.TrimSpace(rs) != "" {
				relayServer = strings.TrimSpace(rs)
				if rp, ok := inbound["relay_port"].(float64); ok {
					relayPort = int(rp)
				}
				delete(inbound, "relay_server")
				delete(inbound, "relay_port")
				if nb, mErr := json.Marshal(inboundReq); mErr == nil {
					body = nb
				}
			}
		}
	}

	// 不安全(自签证书):insecure 是前端挂在 inbound 上的带外字段,agent/xray 不需要 —— 转发前剥掉,
	// 仅用于建节点时给 HY2 clash 节点配 skip-cert-verify(自签证书客户端需跳过校验才能连)。
	var inboundInsecure bool
	if r.Method == http.MethodPost && inboundReq != nil {
		if inbound, ok := inboundReq["inbound"].(map[string]interface{}); ok {
			if iv, _ := inbound["insecure"].(bool); iv {
				inboundInsecure = true
				delete(inbound, "insecure")
				if nb, mErr := json.Marshal(inboundReq); mErr == nil {
					body = nb
				}
			}
		}
	}

	var regeneratedCredentials map[string]string
	updatedProtocol := ""
	if isUpdate {
		if inbound, _ := inboundReq["inbound"].(map[string]interface{}); inbound != nil {
			updatedProtocol = strings.ToLower(strings.TrimSpace(fmt.Sprint(inbound["protocol"])))
		}
		regeneratedCredentials, _ = inboundReq["regenerated_credentials"].(map[string]string)
		// JSON round trips decode this map as map[string]interface{}.
		if regeneratedCredentials == nil {
			if rawMap, ok := inboundReq["regenerated_credentials"].(map[string]interface{}); ok {
				regeneratedCredentials = make(map[string]string, len(rawMap))
				for key, value := range rawMap {
					regeneratedCredentials[key] = fmt.Sprint(value)
				}
			}
		}
		delete(inboundReq, "regenerated_credentials")
		inboundReq["action"] = "replace"
		inboundReq["tag"] = updateTag
		body, _ = json.Marshal(inboundReq)
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/inbounds", body)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	// 对于 GET 请求，过滤掉空 tag 和 tag="api" 的入站
	if r.Method == http.MethodGet {
		result = h.filterInboundsResponse(result)
	}

	// 对于 POST 请求，处理添加和删除操作
	if r.Method == http.MethodPost {
		action, _ := inboundReq["action"].(string)
		actionLower := strings.ToLower(action)
		if isUpdate {
			actionLower = "add"
		}

		// 检查远程服务器响应是否成功
		var resp map[string]interface{}
		if err := json.Unmarshal(result, &resp); err == nil {
			if success, ok := resp["success"].(bool); ok && success {
				// Reality 防盗与主入站生命周期绑定。添加/修改按显式开关同步；删除始终清理专用辅助项。
				guardTag := ""
				guardEnable := false
				guardSync := false
				if actionLower == "remove" && preDeleteRealityGuard {
					guardTag, _ = inboundReq["tag"].(string)
					guardSync = strings.TrimSpace(guardTag) != ""
				} else if (actionLower == "" || actionLower == "add") && realityGuardRequested != nil {
					if inbound, _ := inboundReq["inbound"].(map[string]interface{}); inbound != nil && isRealityInbound(inbound) {
						guardTag, _ = inbound["tag"].(string)
						guardEnable = *realityGuardRequested
						guardSync = strings.TrimSpace(guardTag) != ""
					}
				}
				if guardSync {
					if guardErr := h.syncRealityGuardConfig(r.Context(), id, guardTag, guardEnable); guardErr != nil {
						// 新增/修改失败时恢复主入站；完整配置同步自身也会恢复辅助配置。
						if isUpdate && updateOldInbound != nil {
							rollbackBody, _ := json.Marshal(map[string]interface{}{"action": "replace", "tag": updateTag, "inbound": updateOldInbound})
							_, _ = h.forwardToRemoteServer(context.Background(), id, http.MethodPost, "/api/child/inbounds", rollbackBody)
						} else if actionLower == "remove" && preDeleteInbound != nil {
							rollbackBody, _ := json.Marshal(map[string]interface{}{"action": "add", "inbound": preDeleteInbound})
							_, _ = h.forwardToRemoteServer(context.Background(), id, http.MethodPost, "/api/child/inbounds", rollbackBody)
						} else if actionLower == "" || actionLower == "add" {
							rollbackBody, _ := json.Marshal(map[string]interface{}{"action": "remove", "tag": guardTag})
							_, _ = h.forwardToRemoteServer(context.Background(), id, http.MethodPost, "/api/child/inbounds", rollbackBody)
						}
						remoteWriteError(w, http.StatusBadGateway, "Reality 防盗配置下发失败，已回滚: "+guardErr.Error())
						return
					}
				}
				if isUpdate {
					if syncErr := h.repo.UpdateInboundCredentialReferences(r.Context(), id, updateTag, updatedProtocol, regeneratedCredentials); syncErr != nil {
						rollbackBody, _ := json.Marshal(map[string]interface{}{"action": "replace", "tag": updateTag, "inbound": updateOldInbound})
						if _, rollbackErr := h.forwardToRemoteServer(context.Background(), id, http.MethodPost, "/api/child/inbounds", rollbackBody); rollbackErr != nil {
							log.Printf("[HandleInbounds] credential DB sync and Agent rollback both failed server=%d tag=%s: sync=%v rollback=%v", id, updateTag, syncErr, rollbackErr)
							remoteWriteError(w, http.StatusInternalServerError, "凭据数据库同步失败，且旧入站回滚失败，请立即检查 Agent: "+syncErr.Error())
							return
						}
						remoteWriteError(w, http.StatusInternalServerError, "凭据数据库同步失败，已恢复旧入站: "+syncErr.Error())
						return
					}
				}
				if actionLower == "" || actionLower == "add" {
					// WSS 必须把证书 + nginx 配置下发作为创建事务的一部分。
					// 旧逻辑放到 goroutine 后立即返回成功，导致下发失败只写日志，界面却创建出不通的节点。
					if isVlessWSInboundReq(inboundReq) {
						if syncErr := h.syncWSSNginx(r.Context(), id, selectedWSSDomain, selectedWSSCertID); syncErr != nil {
							// 回滚刚创建的入站，避免用户重试时产生重复 tag / 残留节点。
							if inbound, ok := inboundReq["inbound"].(map[string]interface{}); ok {
								if tag, _ := inbound["tag"].(string); tag != "" {
									rollbackBody, _ := json.Marshal(map[string]interface{}{
										"action": "remove",
										"tag":    tag,
									})
									if _, rollbackErr := h.forwardToRemoteServer(context.Background(), id, http.MethodPost, "/api/child/inbounds", rollbackBody); rollbackErr != nil {
										log.Printf("[WSS-Nginx] rollback inbound server=%d tag=%s failed: %v", id, tag, rollbackErr)
									}
								}
							}
							remoteWriteError(w, http.StatusBadGateway, "WSS Nginx 配置下发失败，已回滚入站: "+syncErr.Error())
							return
						}
					}

					// 添加入站：先处理 reality 相关配置（更新 tunnel-in port + 清理域名路由）
					if inbound, ok := inboundReq["inbound"].(map[string]interface{}); ok {
						tag, _ := inbound["tag"].(string)
						protocol, _ := inbound["protocol"].(string)
						port, _ := inbound["port"].(float64)
						// WSS 对外由 Nginx 443 接入，inbound.port 只是本机 proxy_pass 目标。
						// 把实际 SNI 留给节点转换，并统一事件的客户端端口为 443。
						if isVlessWSInboundReq(inboundReq) {
							port = 443
							if selectedWSSDomain != "" {
								inbound["wss_domain"] = selectedWSSDomain
							}
						}
						customNodeName, _ := inboundReq["node_name"].(string)
						forwardNodeID, _ := inboundReq["forward_node_id"].(float64) // tunnel「转发已有节点」时携带源节点 ID
						// ip_version: ""/v4(默认) | v6 | both —— 决定生成节点 clash server 用 v4/v6/双节点
						ipVersion, _ := inboundReq["ip_version"].(string)
						switch ipVersion {
						case "v4", "v6", "both":
						default:
							ipVersion = "" // 非法值降级为默认 v4
						}

						h.cleanupTunnelRouteForReality(r.Context(), id, inbound)

						// 转换为 map[string]any
						inboundAny := make(map[string]any)
						for k, v := range inbound {
							inboundAny[k] = v
						}
						// update:发 EventInboundUpdated → handleUpdated 原地更新该 tag 下 v4/v6 节点(不重建、保留 ID/ip_family)。
						evtType := event.EventInboundAdded
						if isUpdate {
							evtType = event.EventInboundUpdated
						}
						event.GetBus().PublishAsync(event.InboundEvent{
							Type:          evtType,
							ServerID:      id,
							Tag:           tag,
							Protocol:      protocol,
							Port:          int(port),
							Inbound:       inboundAny,
							NodeName:      customNodeName,
							ForwardNodeID: int64(forwardNodeID),
							IPVersion:     ipVersion,
							RelayServer:   relayServer,
							RelayPort:     relayPort,
							Insecure:      inboundInsecure,
						})
					}
				} else if actionLower == "remove" {
					// 删除入站：发布事件
					if tag, ok := inboundReq["tag"].(string); ok && tag != "" {
						event.GetBus().PublishAsync(event.InboundEvent{
							Type:     event.EventInboundRemoved,
							ServerID: id,
							Tag:      tag,
						})
					}
					// 恢复被 reality 接管的域名到 tunnel-in→nginx 路由
					if len(preDeleteRealityDomains) > 0 {
						go h.restoreTunnelRouteForReality(context.Background(), id, preDeleteRealityDomains)
					}
					// 不知道被删的入站是否 vless+ws,稳妥起见每次 remove 都触发 sync(代价是一次 GET inbounds + 渲染)
					go func() {
						if err := h.SyncWSSNginx(context.Background(), id); err != nil {
							log.Printf("[WSS-Nginx] sync after remove server=%d failed: %v", id, err)
						}
					}()
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 过滤入站响应，移除空 tag 和 tag="api" 的入站
func (h *RemoteManageHandler) filterInboundsResponse(result []byte) []byte {
	var resp struct {
		Success  bool                     `json:"success"`
		Inbounds []map[string]interface{} `json:"inbounds"`
		Message  string                   `json:"message,omitempty"`
	}

	if err := json.Unmarshal(result, &resp); err != nil {
		return result
	}

	// 编辑 Reality 入站时把辅助 tunnel 隐藏成一个布尔开关，并将实际伪装目标还原到 dest。
	// 否则界面会看到 127.0.0.1:本地端口，保存后也无法正确判断功能是否开启。
	for _, ib := range resp.Inbounds {
		tag := strings.TrimSpace(fmt.Sprint(ib["tag"]))
		reality := realitySettingsOf(ib)
		if tag == "" || reality == nil {
			continue
		}
		ib["reality_guard"] = false
		guardTag := realityGuardTag(tag)
		for _, candidate := range resp.Inbounds {
			if strings.TrimSpace(fmt.Sprint(candidate["tag"])) != guardTag {
				continue
			}
			settings, _ := candidate["settings"].(map[string]interface{})
			host := strings.TrimSpace(fmt.Sprint(settings["address"]))
			port := toInt(settings["port"])
			if host != "" && port > 0 {
				reality["dest"] = joinRealityDest(host, port)
				ib["reality_guard"] = true
			}
			break
		}
	}

	// 过滤入站列表
	filtered := make([]map[string]interface{}, 0, len(resp.Inbounds))
	for _, ib := range resp.Inbounds {
		tag, _ := ib["tag"].(string)
		source, _ := ib["_source"].(string)

		// 跳过 tag="api" 的入站
		if tag == "api" || isRealityGuardTag(tag) {
			continue
		}
		// 跳过空 tag 的 runtime_only 入站
		if tag == "" && source == "runtime_only" {
			continue
		}
		// 对于空 tag 的配置入站，生成名称
		if tag == "" && source == "config" {
			protocol, _ := ib["protocol"].(string)
			port := 0
			if p, ok := ib["port"].(float64); ok {
				port = int(p)
			}
			if protocol != "" && port > 0 {
				ib["tag"] = fmt.Sprintf("%s-%d", protocol, port)
				ib["_generated_tag"] = true
			}
		}
		filtered = append(filtered, ib)
	}

	resp.Inbounds = filtered
	newResult, err := json.Marshal(resp)
	if err != nil {
		return result
	}
	return newResult
}

// 自动将入站同步到节点表
func (h *RemoteManageHandler) autoSyncInboundToNodes(ctx context.Context, serverID int64, inbound map[string]interface{}) {
	// 获取远程服务器信息
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		log.Printf("[Remote Manage] Failed to get remote server %d: %v", serverID, err)
		return
	}

	// Domain → 非私有的 PullAddress → IPAddress 优先序
	serverHost := chooseClashServerHost(server)
	if serverHost == "" {
		log.Printf("[Remote Manage] No server address available for server %d", serverID)
		return
	}

	// tunnel 模式：仅当入站端口 == tunnel-in 的 settings.port 时，使用 443 端口（但 server 保持用 IP，域名可能走 CDN）
	tunnelPort := 0
	if server.Domain != "" && (server.StealMode == "tunnel" || server.StealMode == "") {
		inboundPort := 0
		if p, ok := inbound["port"].(float64); ok {
			inboundPort = int(p)
		} else if p, ok := inbound["port"].(int); ok {
			inboundPort = p
		}
		if inboundPort > 0 {
			tunnelInSettingsPort := h.getTunnelInSettingsPort(ctx, serverID)
			if tunnelInSettingsPort > 0 && inboundPort == tunnelInSettingsPort {
				tunnelPort = 443
			}
		}
	}
	// WSS 入站 → 客户端视角 (port 443, sni, Host header)。覆盖上面 tunnel 端口判断,因为
	// listen=127.0.0.1 的 WSS 入站本来就跟 tunnel 互斥。
	if effPort, effHost := applyWSSClientRewrite(inbound, server); effPort > 0 {
		tunnelPort = effPort
		serverHost = effHost
	}
	clashProxy, err := h.inboundToClashProxy(inbound, serverHost, server.Name, tunnelPort)
	if err != nil {
		log.Printf("[Remote Manage] Failed to convert inbound to Clash proxy: %v", err)
		return
	}

	// 序列化为 JSON（与 HandleSyncInboundsToNodes 保持一致）
	clashJSON, err := json.Marshal(clashProxy)
	if err != nil {
		log.Printf("[Remote Manage] Failed to marshal Clash proxy to JSON: %v", err)
		return
	}

	// 获取入站标签
	inboundTag, _ := inbound["tag"].(string)
	protocol, _ := inbound["protocol"].(string)
	nodeName, _ := clashProxy["name"].(string)

	// 创建节点
	node := storage.Node{
		Username:       "admin", // 默认为管理员
		NodeName:       nodeName,
		Protocol:       protocol,
		ClashConfig:    string(clashJSON),
		ParsedConfig:   string(clashJSON),
		Enabled:        true,
		Tag:            fmt.Sprintf("远程:%s", server.Name),
		OriginalServer: server.Name,
		InboundTag:     inboundTag,
	}

	_, err = h.repo.CreateNode(ctx, node)
	if err != nil {
		log.Printf("[Remote Manage] Failed to create node for inbound %s: %v", inboundTag, err)
		return
	}

	log.Printf("[Remote Manage] Auto-synced inbound %s to nodes table for server %s", inboundTag, server.Name)
}

// 自动删除入站对应的节点
func (h *RemoteManageHandler) autoDeleteInboundNodes(ctx context.Context, serverID int64, inboundTag string) {
	// 获取远程服务器信息
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		log.Printf("[Remote Manage] Failed to get remote server %d for node deletion: %v", serverID, err)
		return
	}

	// 删除对应的节点
	deleted, err := h.repo.DeleteNodesByInboundTag(ctx, server.Name, inboundTag)
	if err != nil {
		log.Printf("[Remote Manage] Failed to delete nodes for inbound %s: %v", inboundTag, err)
		return
	}

	if deleted > 0 {
		log.Printf("[Remote Manage] Auto-deleted %d node(s) for inbound %s on server %s", deleted, inboundTag, server.Name)
	}
}

// ================== X 射线出库管理 ==================

// 将出站管理请求代理到远程服务器
func (h *RemoteManageHandler) HandleOutbounds(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	var body []byte
	if r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to read body")
			return
		}
		// Hook: action=add 且 outbound 是 TLS 且 pinnedPeerCertSha256 缺失 → TLS dial 拿对端证书 sha256 自动注入
		// 失败直接 400 返给前端,提示用户手动填(替代已废弃的 allowInsecure)
		if newBody, hookErr := autoInjectPinnedCertSha256(r.Context(), body); hookErr != nil {
			remoteWriteError(w, http.StatusBadRequest, hookErr.Error())
			return
		} else if newBody != nil {
			body = newBody
		}
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/outbounds", body)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// autoInjectPinnedCertSha256 解析 outbound add 请求体,若 TLS outbound 缺 pinnedPeerCertSha256
// 则 TLS dial 抓 peer cert sha256 注入。非 add 动作 / 非 TLS / 已填 sha256 → 返回 (nil, nil) 不动 body。
// 失败返回错误(前端会展开 sha256 输入框让用户手动填)。
func autoInjectPinnedCertSha256(ctx context.Context, body []byte) ([]byte, error) {
	if len(body) == 0 {
		return nil, nil
	}
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, nil // 不是 JSON 就不动,让 forward 把原 body 透传
	}
	action, _ := req["action"].(string)
	if strings.ToLower(strings.TrimSpace(action)) != "add" {
		return nil, nil
	}
	ob, _ := req["outbound"].(map[string]any)
	if ob == nil {
		return nil, nil
	}
	ss, _ := ob["streamSettings"].(map[string]any)
	if ss == nil {
		return nil, nil
	}
	if sec, _ := ss["security"].(string); strings.ToLower(strings.TrimSpace(sec)) != "tls" {
		return nil, nil
	}
	// Hysteria2 走 QUIC/UDP,证书经 QUIC 握手协商 —— TCP 版的 fetchPeerCertSha256 连不上其 UDP 端口。
	// 跳过 pin 注入(不 dial 也不报错),让 config 原样下发。真证书 HY2 客户端按 serverName 正常验证即可;
	// 自签证书 HY2 是 fork 禁用 allowInsecure 后的固有限制,另议。
	if net, _ := ss["network"].(string); strings.ToLower(strings.TrimSpace(net)) == "hysteria" {
		return nil, nil
	}
	if _, hasHy := ss["hysteriaSettings"]; hasHy {
		return nil, nil
	}
	tlsObj, _ := ss["tlsSettings"].(map[string]any)
	if tlsObj == nil {
		tlsObj = map[string]any{}
		ss["tlsSettings"] = tlsObj
	}
	// 已填 sha256 → 跳过
	if existing, _ := tlsObj["pinnedPeerCertSha256"].(string); strings.TrimSpace(existing) != "" {
		return nil, nil
	}

	// 提取 address/port:支持 vnext[0] (VLESS/VMess) 或 servers[0] (Trojan/Shadowsocks)
	addr, port := extractOutboundTarget(ob)
	if addr == "" || port == 0 {
		return nil, fmt.Errorf("无法识别 outbound 目标地址,请在 tlsSettings.pinnedPeerCertSha256 手动填写证书 SHA256")
	}

	sni, _ := tlsObj["serverName"].(string)
	alpn := ""
	if alpnArr, ok := tlsObj["alpn"].([]any); ok && len(alpnArr) > 0 {
		parts := make([]string, 0, len(alpnArr))
		for _, a := range alpnArr {
			if s, ok := a.(string); ok {
				parts = append(parts, s)
			}
		}
		alpn = strings.Join(parts, ",")
	}

	dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	sha, err := fetchPeerCertSha256(dialCtx, addr, port, sni, alpn)
	if err != nil {
		return nil, fmt.Errorf("自动获取对端证书 SHA256 失败 (%s:%d): %v;请在 tlsSettings.pinnedPeerCertSha256 手动填写", addr, port, err)
	}
	tlsObj["pinnedPeerCertSha256"] = sha
	// 顺手清掉 allowInsecure(xray 已废弃,留着没意义)
	delete(tlsObj, "allowInsecure")
	return json.Marshal(req)
}

// extractOutboundTarget 从 xray outbound JSON 中提取目标 address/port。
// 支持 settings.vnext[0] (VLESS/VMess) 和 settings.servers[0] (Trojan/Shadowsocks/Socks/HTTP)。
func extractOutboundTarget(ob map[string]any) (string, int) {
	settings, _ := ob["settings"].(map[string]any)
	if settings == nil {
		return "", 0
	}
	pickAddrPort := func(m map[string]any) (string, int) {
		addr, _ := m["address"].(string)
		var port int
		switch v := m["port"].(type) {
		case float64:
			port = int(v)
		case int:
			port = v
		case int64:
			port = int(v)
		case string:
			if p, err := strconv.Atoi(v); err == nil {
				port = p
			}
		}
		return strings.TrimSpace(addr), port
	}
	if vnext, ok := settings["vnext"].([]any); ok && len(vnext) > 0 {
		if first, ok := vnext[0].(map[string]any); ok {
			if a, p := pickAddrPort(first); a != "" && p > 0 {
				return a, p
			}
		}
	}
	if servers, ok := settings["servers"].([]any); ok && len(servers) > 0 {
		if first, ok := servers[0].(map[string]any); ok {
			if a, p := pickAddrPort(first); a != "" && p > 0 {
				return a, p
			}
		}
	}
	return "", 0
}

// ================== X 射线路由管理 ==================

// 代理将管理请求路由到远程服务器
func (h *RemoteManageHandler) HandleRouting(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	var body []byte
	if r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to read body")
			return
		}
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/routing", body)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// ==================扫描==================

// 将扫描请求代理到远程服务器并将入站同步到节点
func (h *RemoteManageHandler) HandleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, "POST", "/api/child/scan", nil)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	// 解析扫描结果以更新数据库中的 X 射线状态
	var scanResult struct {
		Success     bool   `json:"success"`
		XrayRunning bool   `json:"xray_running"`
		XrayVersion string `json:"xray_version"`
	}
	if err := json.Unmarshal(result, &scanResult); err == nil && scanResult.Success {
		// 更新数据库中的 X 射线状态;状态翻转时发 TG 通知
		prev, updateErr := h.repo.UpdateRemoteServerXrayStatus(r.Context(), id, scanResult.XrayRunning, scanResult.XrayVersion)
		if updateErr != nil {
			log.Printf("[Remote Manage] Failed to update Xray status for server %d: %v", id, updateErr)
		} else if prev != scanResult.XrayRunning {
			if server, gErr := h.repo.GetRemoteServer(r.Context(), id); gErr == nil && server != nil {
				SendXrayStatusChangeNotification(r.Context(), server.Name, server.IPAddress, scanResult.XrayRunning)
			}
		}

		// 如果 Xray 正在运行，则将入站同步到节点表
		if scanResult.XrayRunning {
			syncResult := h.syncInboundsToNodesInternal(r.Context(), id)
			log.Printf("[Remote Manage] Sync inbounds result for server %d: synced=%d (claimed=%d, created=%d), skipped=%d, tags=%v",
				id, syncResult.SyncedCount, syncResult.ClaimedCount, syncResult.CreatedCount, syncResult.SkippedCount, syncResult.SyncedTags)

			// 将同步结果合并到响应中
			var response map[string]interface{}
			if err := json.Unmarshal(result, &response); err == nil {
				response["synced_count"] = syncResult.SyncedCount
				response["claimed_count"] = syncResult.ClaimedCount
				response["created_count"] = syncResult.CreatedCount
				response["skipped_count"] = syncResult.SkippedCount
				response["synced_tags"] = syncResult.SyncedTags
				if len(syncResult.Errors) > 0 {
					response["sync_errors"] = syncResult.Errors
				}
				result, _ = json.Marshal(response)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 将远程服务器的入站同步到节点表（内部使用）
func (h *RemoteManageHandler) syncInboundsToNodesInternal(ctx context.Context, serverID int64) SyncInboundsToNodesResponse {
	return h.syncInboundsToNodes(ctx, serverID, "", false)
}

// syncInboundsToNodes 是真正的实现:auto-sync(WS scan_result)与手动同步(HandleSyncInboundsToNodes)
// 共用一份逻辑,避免两边漂移(历史上手动同步分支没有 claim 逻辑,导致"回落+路由出站"场景下同一 inbound
// 对应的多个外部节点无法被认领,见 issue: hk-n.2ha.me 节点只有 1 个被匹配的反馈)。
//
// serverHostOverride: 写入 clash proxy 配置的 server 字段;空时回退到 server.IPAddress。
// forceOverride: true 时,遇到同名节点先删除再新建(手动同步对话框的"强制覆盖"开关)。
func (h *RemoteManageHandler) syncInboundsToNodes(ctx context.Context, serverID int64, serverHostOverride string, forceOverride bool) SyncInboundsToNodesResponse {
	response := SyncInboundsToNodesResponse{
		Success:    true,
		SyncedTags: []string{},
		Errors:     []string{},
	}

	// 获取远程服务器信息
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		response.Success = false
		response.Errors = append(response.Errors, fmt.Sprintf("获取服务器信息失败: %v", err))
		return response
	}

	// 计算本次同步允许新建 routed 节点的余额 — 防止用户绕过 RoutedOutbound.create() 走"同步入站"
	// 路径无限新建 routed 节点。budget < 0 表示禁用限制(开发场景 / 无 license)。
	routedBudget := -1
	if h.licenseManager != nil {
		status := h.licenseManager.GetStatus()
		maxNodes := 20
		if status.Plan != nil {
			maxNodes = status.Plan.MaxNodes
		}
		if cur, cerr := h.repo.CountLicensedNodes(ctx); cerr == nil {
			routedBudget = maxNodes - int(cur)
			if routedBudget < 0 {
				routedBudget = 0
			}
		}
	}

	// 调用方显式 override > Domain > 非私有 PullAddress > IPAddress
	serverHost := strings.TrimSpace(serverHostOverride)
	if serverHost == "" {
		serverHost = chooseClashServerHost(server)
	}
	if serverHost == "" {
		response.Success = false
		response.Errors = append(response.Errors, "服务器 IP/域名 均为空")
		return response
	}

	// 从远程服务器获取入站
	result, err := h.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/inbounds", nil)
	if err != nil {
		response.Success = false
		response.Errors = append(response.Errors, fmt.Sprintf("获取入站失败: %v", err))
		return response
	}

	var inboundsResp struct {
		Success  bool                     `json:"success"`
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if err := json.Unmarshal(result, &inboundsResp); err != nil {
		response.Success = false
		response.Errors = append(response.Errors, fmt.Sprintf("解析入站失败: %v", err))
		return response
	}

	if !inboundsResp.Success {
		response.Success = false
		response.Errors = append(response.Errors, "远程服务器返回错误")
		return response
	}

	// 拉一次全量 xray config,提取 routing.rules 用于构造 email → outboundTag 映射。
	// 这是判定"路由出站节点"的依据 —— 客户端 email 命中 user[] 且规则有具体 outboundTag,即视为该客户端绑定到那条出站。
	// 注意:agent 返回的 config 字段是 JSON 字符串(原文),需要二次 unmarshal,不能直接当 map 读。
	// 拉取失败不算 sync 失败,仅放弃路由识别。
	emailToOutbound := map[string]string{}
	if rawCfg, err := h.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/xray/config", nil); err == nil {
		var cfgResp struct {
			Success bool   `json:"success"`
			Config  string `json:"config"`
		}
		if err := json.Unmarshal(rawCfg, &cfgResp); err == nil && cfgResp.Success && cfgResp.Config != "" {
			var xrayCfg map[string]interface{}
			if err := json.Unmarshal([]byte(cfgResp.Config), &xrayCfg); err == nil {
				if routing, _ := xrayCfg["routing"].(map[string]interface{}); routing != nil {
					if rules, _ := routing["rules"].([]interface{}); rules != nil {
						for _, r := range rules {
							rm, _ := r.(map[string]interface{})
							if rm == nil {
								continue
							}
							outTag, _ := rm["outboundTag"].(string)
							if outTag == "" || outTag == "block" || outTag == "direct" || outTag == "api" {
								continue
							}
							users, _ := rm["user"].([]interface{})
							for _, u := range users {
								if s, ok := u.(string); ok && s != "" {
									emailToOutbound[s] = outTag
								}
							}
						}
					}
				}
			}
		}
	}
	log.Printf("[Remote Manage] Sync server=%q: parsed %d routing user→outbound mappings", server.Name, len(emailToOutbound))

	// 提取 tunnel-in 的 settings.port
	tunnelInSettingsPort := 0
	if server.Domain != "" && (server.StealMode == "tunnel" || server.StealMode == "") {
		for _, ib := range inboundsResp.Inbounds {
			if tag, _ := ib["tag"].(string); tag == "tunnel-in" {
				if s, _ := ib["settings"].(map[string]interface{}); s != nil {
					if p, ok := s["port"].(float64); ok && p > 0 {
						tunnelInSettingsPort = int(p)
					}
				}
				break
			}
		}
	}

	username := h.repo.GetSystemNodeOwner(ctx)

	// 先确保 admin email 已经在 vless/vmess/trojan inbound 的 clients[] 里。
	// 历史 inbound(从 mmw 迁过来 / 老 agent 手动加的)往往只有用户原始 client,没有 admin 的 — 流量统计会算到别人头上、
	// admin 也无法以"自己的身份"连。这里给缺失的 inbound 自动补一个 admin client,凭据现场生成,后续同步幂等不重复。
	for _, inbound := range inboundsResp.Inbounds {
		protocol, _ := inbound["protocol"].(string)
		// 只对带 clients[] 的协议补 admin client;ss 类协议是入站全局密码,没有 per-client 身份
		if protocol != "vless" && protocol != "vmess" && protocol != "trojan" {
			continue
		}
		tag, _ := inbound["tag"].(string)
		if tag == "" || tag == "api" {
			continue
		}
		settings, _ := inbound["settings"].(map[string]interface{})
		if settings == nil {
			continue
		}
		clients, _ := settings["clients"].([]interface{})
		var refClient map[string]interface{}
		hasAdmin := false
		for _, c := range clients {
			cm, _ := c.(map[string]interface{})
			if cm == nil {
				continue
			}
			if e, _ := cm["email"].(string); e == username {
				hasAdmin = true
				break
			}
			if refClient == nil {
				refClient = cm
			}
		}
		if hasAdmin {
			continue
		}
		// 生成新 client。flow 复用现有 client 的(reality/vision 必须一致);其它字段 agent 端自行补默认
		newClient := map[string]interface{}{"email": username}
		switch protocol {
		case "vless", "vmess":
			newClient["id"] = uuid.New().String()
			if refClient != nil {
				if flow, ok := refClient["flow"].(string); ok && flow != "" {
					newClient["flow"] = flow
				}
			}
		case "trojan":
			newClient["password"] = uuid.New().String()
		}
		if err := addClientToInbound(ctx, h, server.ID, tag, newClient); err != nil {
			log.Printf("[Remote Manage] inject admin client failed (server=%s tag=%s): %v", server.Name, tag, err)
			continue
		}
		log.Printf("[Remote Manage] Injected admin client into inbound (server=%s tag=%s email=%s protocol=%s)", server.Name, tag, username, protocol)
		// 更新本次循环的 in-memory inbound 视图,后续 routed 检测 / 节点 dedup 才能正确看到 admin client
		settings["clients"] = append(clients, newClient)
		inbound["settings"] = settings
	}

	// 在循环之前获取现有节点一次。dedup 两步走:
	//   1. inbound_tag 精确匹配 → 直接 skip(命中后续 tag 维护逻辑无需触发)
	//   2. clash 配置指纹(server + 归一化 protocol + port)→ skip,并把库里该节点的 inbound_tag 校正成本次同步扫到的 tag,
	//      下次再同步就能走第 1 步快速通道(tag 用户改名 / 老 agent 改命名规则,都是通过这一步收敛)。
	// 端口与协议用 clash_config 字段(已应用过 tunnel 端口映射等规则,与本次同步生成的 clashProxy 同坐标系)。
	existingNodes, _ := h.repo.ListNodes(ctx, username)
	existingNodeNames := make(map[string]bool)
	existingByTag := make(map[string]bool)                  // 键: server.Name + ":" + inbound_tag
	existingByFingerprint := make(map[string]*storage.Node) // 键: server.Name + ":" + 归一化协议 + ":" + 端口

	serverAddrSet := map[string]bool{}
	for _, a := range []string{server.IPAddress, server.Domain, server.PullAddress, serverHost} {
		a = strings.TrimSpace(a)
		if a != "" {
			serverAddrSet[a] = true
		}
	}

	for i := range existingNodes {
		n := &existingNodes[i]
		existingNodeNames[n.NodeName] = true
		var config map[string]interface{}
		if err := json.Unmarshal([]byte(n.ClashConfig), &config); err != nil {
			continue
		}
		proto, _ := config["type"].(string)
		port, _ := config["port"].(float64)
		if proto == "" || port == 0 {
			continue
		}
		cfgServer, _ := config["server"].(string)
		// 节点归属本服务器的判定:已绑 original_server,或老的未绑节点但 clash_config.server 落在本服务器地址集内
		belongs := n.OriginalServer == server.Name || (n.OriginalServer == "" && serverAddrSet[cfgServer])
		if !belongs {
			continue
		}
		if n.InboundTag != "" {
			existingByTag[server.Name+":"+n.InboundTag] = true
		}
		fp := fmt.Sprintf("%s:%s:%d", server.Name, normalizeProtocol(proto), int(port))
		// 多个节点共享同一 fingerprint(回落+路由出站)时,这里只挂第一个 —— 它代表「这条 inbound 连接坐标已被消耗」,
		// 真正需要按 credential 区分的多节点 claim 走 tryClaimExternalNodeForSync 那条独立路径。
		if _, ok := existingByFingerprint[fp]; !ok {
			existingByFingerprint[fp] = n
		}
	}

	// 处理每个入站并创建节点
	for _, inbound := range inboundsResp.Inbounds {
		tag, _ := inbound["tag"].(string)
		protocol, _ := inbound["protocol"].(string)
		port, _ := inbound["port"].(float64)

		// 跳过 api 入站
		if tag == "api" || protocol == "tunnel" {
			response.SkippedCount++
			continue
		}

		// 将入站转换为 Clash 代理配置(server 保持用 IP,域名可能走 CDN)
		// 即便该 inbound 会被 dedupe skip,我们仍需 clash_config 来 claim 同 server:port:proto 的其它外部节点
		tunnelPort := 0
		if tunnelInSettingsPort > 0 && int(port) == tunnelInSettingsPort {
			tunnelPort = 443
		}
		effectiveServerHost := serverHost
		if effPort, effHost := applyWSSClientRewrite(inbound, server); effPort > 0 {
			tunnelPort = effPort
			effectiveServerHost = effHost
		}
		clashProxy, err := h.inboundToClashProxy(inbound, effectiveServerHost, server.Name, tunnelPort)
		if err != nil {
			// "no settings found" — agent listInbounds 返回的"孤儿入站"(只有 tag/protocol/port,缺 settings),
			// 既无法生成节点配置也对用户毫无价值。后台静默调 agent remove RPC 清理掉,
			// 不污染前端 SkippedCount/Errors,用户感知不到。
			if err.Error() == "no settings found" {
				go h.silentlyRemoveOrphanInbound(serverID, tag)
				continue
			}
			response.Errors = append(response.Errors, fmt.Sprintf("tag=%s: %v", tag, err))
			response.SkippedCount++
			continue
		}
		if clashProxy == nil {
			response.Errors = append(response.Errors, fmt.Sprintf("tag=%s: 无法生成节点配置", tag))
			response.SkippedCount++
			continue
		}
		clashConfigJSON, err := json.Marshal(clashProxy)
		if err != nil {
			response.Errors = append(response.Errors, fmt.Sprintf("tag=%s: 序列化配置失败", tag))
			response.SkippedCount++
			continue
		}

		// dedup key 取 clashProxy 内的 type/port —— 与存量节点 clash_config 字段同源,确保 tunnel 端口映射等规则两边一致
		proxyType, _ := clashProxy["type"].(string)
		proxyPort := 0
		switch p := clashProxy["port"].(type) {
		case float64:
			proxyPort = int(p)
		case int:
			proxyPort = p
		}
		dedupeKey := fmt.Sprintf("%s:%s:%d", server.Name, normalizeProtocol(proxyType), proxyPort)

		// 先尝试 claim 所有匹配的未认领外部节点 — 这一步必须在 dedupe 之前,
		// 因为「回落+路由出站」场景下 1 个 inbound 可能对应 N 个客户端节点(uuid/email 不同),
		// 即使其中 1 个节点已经认领了这个 inbound(导致 dedupe 命中),其余的也仍需要 claim。
		claimedThis := h.tryClaimExternalNodeForSync(ctx, server, protocol, int(port), string(clashConfigJSON), tag)
		if claimedThis {
			response.ClaimedCount++
			if tag != "" {
				response.SyncedTags = append(response.SyncedTags, fmt.Sprintf("%s (port:%d) [claimed]", tag, int(port)))
			}
		}

		// Step 1: inbound_tag 精确匹配 → 直接 skip。最便宜的快速通道
		if tag != "" && existingByTag[server.Name+":"+tag] {
			response.SkippedCount++
			continue
		}

		// Step 2: clash 配置指纹(server+协议+端口)匹配 → skip 创建,但若 agent 这次扫到的 tag 与库里不一致,
		//          把库里 tag 校正成最新值;这样下次同步就能走 Step 1 快速通道。
		if existingNode, ok := existingByFingerprint[dedupeKey]; ok {
			if tag != "" && existingNode.InboundTag != tag {
				if err := h.repo.UpdateNodeInboundTag(ctx, existingNode.ID, tag); err != nil {
					log.Printf("[Remote Manage] UpdateNodeInboundTag id=%d %q → %q failed: %v", existingNode.ID, existingNode.InboundTag, tag, err)
				} else {
					log.Printf("[Remote Manage] Reconciled inbound_tag id=%d: %q → %q (matched by config fingerprint)", existingNode.ID, existingNode.InboundTag, tag)
					existingNode.InboundTag = tag
					existingByTag[server.Name+":"+tag] = true
				}
			}
			response.SkippedCount++
			continue
		}

		// 创建节点名称:如果没有标签,则使用协议:端口
		var nodeName string
		if tag != "" {
			nodeName = fmt.Sprintf("[%s] %s", server.Name, tag)
		} else {
			nodeName = fmt.Sprintf("[%s] %s:%d", server.Name, protocol, int(port))
		}

		// 走到这里已过 Step 1(tag)+ Step 2(fingerprint)两道真重复闸门,撞名一定是"不同物理节点碰巧同名"。
		if existingNodeNames[nodeName] {
			if forceOverride {
				// 强制覆盖:删除同名节点,后面走"创建"路径覆盖
				for _, n := range existingNodes {
					if n.NodeName == nodeName {
						if err := h.repo.DeleteNode(ctx, n.ID, username); err != nil {
							response.Errors = append(response.Errors, fmt.Sprintf("tag=%s: 删除旧节点失败: %v", tag, err))
							response.SkippedCount++
							continue
						}
						break
					}
				}
				delete(existingNodeNames, nodeName)
			} else {
				// 撞名 → 加协议后缀保证唯一(否则订阅侧会出现重复 proxy name),而不是 skip 丢节点
				nodeName = storage.UniqueNodeName(nodeName, protocol, existingNodeNames)
			}
		}

		// 如果上一步 claim 命中,本次循环已经处理完,不再走"创建新节点"分支
		if claimedThis {
			response.SyncedCount++
			// claim 后该节点已落库,占用当前 fingerprint/tag,后续同步循环里别再生成重复
			existingByFingerprint[dedupeKey] = &storage.Node{InboundTag: tag}
			if tag != "" {
				existingByTag[server.Name+":"+tag] = true
			}
			continue
		}

		// 把 clash 配置的 name 同步成最终 nodeName(撞名改名后必须一致,订阅用的是 clash 配置里的 name)
		clashProxy["name"] = nodeName
		if b, mErr := json.Marshal(clashProxy); mErr == nil {
			clashConfigJSON = b
		}

		// 创建节点
		node := storage.Node{
			Username:       username,
			NodeName:       nodeName,
			Protocol:       protocol,
			ClashConfig:    string(clashConfigJSON),
			ParsedConfig:   string(clashConfigJSON),
			Enabled:        true,
			Tag:            fmt.Sprintf("远程:%s", server.Name),
			OriginalServer: server.Name,
			InboundTag:     tag,
		}

		if _, err := h.repo.CreateNode(ctx, node); err != nil {
			response.Errors = append(response.Errors, fmt.Sprintf("tag=%s: 创建节点失败: %v", tag, err))
			continue
		}

		response.SyncedCount++
		response.CreatedCount++
		if tag != "" {
			response.SyncedTags = append(response.SyncedTags, fmt.Sprintf("%s (port:%d)", tag, int(port)))
		} else {
			response.SyncedTags = append(response.SyncedTags, fmt.Sprintf("%s:%d", protocol, int(port)))
		}

		// 更新 dedup 索引,防止同一批次同 fingerprint 的入站再次落到这里(理论上 inbound 列表不会重复,纯防御)
		existingByFingerprint[dedupeKey] = &storage.Node{InboundTag: tag}
		if tag != "" {
			existingByTag[server.Name+":"+tag] = true
		}
		existingNodeNames[nodeName] = true
	}

	// 同步末尾顺手把该服务器下已存在节点的 clash_config.server 字段刷成当前 serverHost。
	// 主要处理"服务器配过域名后 / IP 漂移后,老节点的 server 字段还停在旧 IP"的场景 — 用户每次同步就自动校正。
	if refreshed, err := h.repo.RefreshNodesServerAddress(ctx, server.Name, serverHost); err != nil {
		log.Printf("[Remote Manage] Refresh node server address failed for %s: %v", server.Name, err)
	} else if refreshed > 0 {
		log.Printf("[Remote Manage] Refreshed %d node(s) server address → %s for %s", refreshed, serverHost, server.Name)
	}
	// v6 节点单独校正(RefreshNodesServerAddress 只动 v4/域名节点)。
	// 锁定入口 IP 时用手填地址(v6RefreshTarget),避免动态出口 IPv6 覆盖锁定值。
	if v6 := v6RefreshTarget(server); v6 != "" {
		if refreshed, err := h.repo.RefreshNodesServerAddressV6(ctx, server.Name, v6); err != nil {
			log.Printf("[Remote Manage] Refresh v6 node server address failed for %s: %v", server.Name, err)
		} else if refreshed > 0 {
			log.Printf("[Remote Manage] Refreshed %d v6 node(s) server address → %s for %s", refreshed, v6, server.Name)
		}
	}

	// 路由出站节点识别:扫所有 inbound 的 clients[],建立 凭据值 → email 映射;
	// 已存在节点的 clash_config 凭据(uuid / password)能在这里反查到 email,且 email 命中 emailToOutbound 时,
	// 把节点升级为 routed_outbound 类型,parent 指向同 inbound 下"非路由"节点(master)。识别失败不阻断 sync。
	if len(emailToOutbound) > 0 {
		// per-inbound 视角:protocol:port → (credToEmail / clients)
		type inboundClientMap struct {
			credToEmail map[string]string                 // uuid|password → email
			emailToCred map[string]map[string]interface{} // email → 完整 client(用来自动建节点)
			rawInbound  map[string]interface{}            // 原始 inbound 引用,后续可调 inboundToClashProxy
		}
		perInbound := map[string]*inboundClientMap{}
		for _, inbound := range inboundsResp.Inbounds {
			protocol, _ := inbound["protocol"].(string)
			port, _ := inbound["port"].(float64)
			if protocol == "" || port == 0 || protocol == "tunnel" {
				continue
			}
			settings, _ := inbound["settings"].(map[string]interface{})
			if settings == nil {
				continue
			}
			clients, _ := settings["clients"].([]interface{})
			if len(clients) == 0 {
				continue
			}
			tunnelPortForKey := 0
			if tunnelInSettingsPort > 0 && int(port) == tunnelInSettingsPort {
				tunnelPortForKey = 443
			}
			effectivePort := int(port)
			if tunnelPortForKey > 0 {
				effectivePort = tunnelPortForKey
			}
			key := fmt.Sprintf("%s:%s:%d", server.Name, normalizeProtocol(protocol), effectivePort)
			m := &inboundClientMap{
				credToEmail: map[string]string{},
				emailToCred: map[string]map[string]interface{}{},
				rawInbound:  inbound,
			}
			for _, c := range clients {
				cm, _ := c.(map[string]interface{})
				if cm == nil {
					continue
				}
				email, _ := cm["email"].(string)
				if email == "" {
					continue
				}
				m.emailToCred[email] = cm
				if id, ok := cm["id"].(string); ok && id != "" {
					m.credToEmail[id] = email
				}
				if pw, ok := cm["password"].(string); ok && pw != "" {
					m.credToEmail[pw] = email
				}
			}
			perInbound[key] = m
		}

		// 第一遍:按 fingerprint 找该 inbound 下的「master」物理节点 —— 凭据 email 不在 emailToOutbound 里的那个(默认/未路由用户)。
		// 找不到 master 也允许其它路由节点处理,只是 parent 留空。
		masterByFingerprint := map[string]int64{}
		for i := range existingNodes {
			n := &existingNodes[i]
			if n.OriginalServer != server.Name || n.NodeType == "routed" {
				continue
			}
			var cfg map[string]interface{}
			if err := json.Unmarshal([]byte(n.ClashConfig), &cfg); err != nil {
				continue
			}
			proto, _ := cfg["type"].(string)
			port, _ := cfg["port"].(float64)
			if proto == "" || port == 0 {
				continue
			}
			fp := fmt.Sprintf("%s:%s:%d", server.Name, normalizeProtocol(proto), int(port))
			ib := perInbound[fp]
			if ib == nil {
				continue
			}
			var cred string
			for _, k := range []string{"uuid", "password"} {
				if v, _ := cfg[k].(string); v != "" {
					cred = v
					break
				}
			}
			if cred == "" {
				continue
			}
			email := ib.credToEmail[cred]
			if _, isRouted := emailToOutbound[email]; !isRouted {
				// 该节点凭据对应的 email 不在路由规则里 → 视为 master(默认用户)
				if _, exists := masterByFingerprint[fp]; !exists {
					masterByFingerprint[fp] = n.ID
				}
			}
		}

		// 第二遍:已存在的节点凭据对应 email 命中路由规则 → 升级为 routed,parent 指 master
		matchedEmails := map[string]bool{} // 用于第三遍判断"哪些 email 还没节点"
		for i := range existingNodes {
			n := &existingNodes[i]
			if n.OriginalServer != server.Name {
				continue
			}
			var cfg map[string]interface{}
			if err := json.Unmarshal([]byte(n.ClashConfig), &cfg); err != nil {
				continue
			}
			proto, _ := cfg["type"].(string)
			port, _ := cfg["port"].(float64)
			if proto == "" || port == 0 {
				continue
			}
			fp := fmt.Sprintf("%s:%s:%d", server.Name, normalizeProtocol(proto), int(port))
			ib := perInbound[fp]
			if ib == nil {
				continue
			}
			var cred string
			for _, k := range []string{"uuid", "password"} {
				if v, _ := cfg[k].(string); v != "" {
					cred = v
					break
				}
			}
			if cred == "" {
				continue
			}
			email := ib.credToEmail[cred]
			outTag, ok := emailToOutbound[email]
			if !ok {
				continue
			}
			matchedEmails[fp+":"+email] = true
			parentID := masterByFingerprint[fp]
			if err := h.repo.MarkNodeAsRouted(ctx, n.ID, outTag, parentID); err != nil {
				log.Printf("[Remote Manage] MarkNodeAsRouted id=%d email=%q → %s failed: %v", n.ID, email, outTag, err)
				continue
			}
			log.Printf("[Remote Manage] Detected routed node id=%d %q: email=%q → outboundTag=%q parent=%d", n.ID, n.NodeName, email, outTag, parentID)
			// 把这个 routed client 写进 admin 的 user_subaccounts(已存在则刷新凭据/激活状态)。
			// 不写的话:每日流量通知合并子账号失败、套餐分配也找不到这个 routed 节点对应的 admin 子账号。
			if client := ib.emailToCred[email]; client != nil {
				if credJSON, err := json.Marshal(client); err == nil {
					if _, err := h.repo.UpsertUserSubaccount(ctx, storage.UserSubaccount{
						Username: username, RoutedNodeID: n.ID, Email: email, CredentialJSON: string(credJSON), IsActive: true,
					}); err != nil {
						log.Printf("[Remote Manage] UpsertUserSubaccount routed_node=%d email=%q failed: %v", n.ID, email, err)
					}
				}
			}
		}

		// 次级 dedup:扫已有节点,记录已经存在的 (server, inbound_tag, outbound_tag) 三元组,
		// 防止上一次因为凭据映射错(uuid 取了 master 的)留下来的脏数据继续被当成"还没节点"再造一份。
		existingRoutedTriple := map[string]bool{}
		for _, n := range existingNodes {
			if n.OriginalServer != server.Name {
				continue
			}
			if n.NodeType != "routed" || n.RoutedOutboundTag == "" {
				continue
			}
			existingRoutedTriple[n.InboundTag+":"+n.RoutedOutboundTag] = true
		}

		// 第三遍:为没有节点的 routed email 自动建一个 routed 节点
		for fp, ib := range perInbound {
			master, hasMaster := masterByFingerprint[fp]
			if !hasMaster {
				continue // 没找到 master,无法挂 parent,这一轮跳过(等用户先 sync 出 master 物理节点)
			}
			inboundTagStr, _ := ib.rawInbound["tag"].(string)
			for email, client := range ib.emailToCred {
				outTag, isRouted := emailToOutbound[email]
				if !isRouted {
					continue
				}
				if matchedEmails[fp+":"+email] {
					continue // 已有节点的凭据对应该 email
				}
				if existingRoutedTriple[inboundTagStr+":"+outTag] {
					continue // 已经有一个 routed 节点占据这条 outbound,即便凭据值错了也不再追加
				}
				// 用 inboundToClashProxy 构造 clash 配置,然后把凭据字段替换为本 client 的
				tunnelPortForKey := 0
				port, _ := ib.rawInbound["port"].(float64)
				if tunnelInSettingsPort > 0 && int(port) == tunnelInSettingsPort {
					tunnelPortForKey = 443
				}
				effectiveServerHostForKey := serverHost
				if effPort, effHost := applyWSSClientRewrite(ib.rawInbound, server); effPort > 0 {
					tunnelPortForKey = effPort
					effectiveServerHostForKey = effHost
				}
				proxy, err := h.inboundToClashProxy(ib.rawInbound, effectiveServerHostForKey, server.Name, tunnelPortForKey)
				if err != nil || proxy == nil {
					log.Printf("[Remote Manage] auto-create routed node for email=%q skip: build clash failed: %v", email, err)
					continue
				}
				// xray 客户端的字段 ↔ clash 字段映射(vless/vmess/trojan):
				//   client.id ↔ proxy.uuid (vless/vmess)
				//   client.password ↔ proxy.password (trojan/ss)
				//   client.email 透传方便后续反查
				if id, ok := client["id"].(string); ok && id != "" {
					proxy["uuid"] = id
				}
				if pw, ok := client["password"].(string); ok && pw != "" {
					proxy["password"] = pw
				}
				if flow, ok := client["flow"].(string); ok && flow != "" {
					proxy["flow"] = flow
				}
				if aid, ok := client["alterId"]; ok {
					proxy["alterId"] = aid
				}
				if cipher, ok := client["cipher"].(string); ok && cipher != "" {
					proxy["cipher"] = cipher
				}
				nodeName := fmt.Sprintf("[%s] %s · %s", server.Name, inboundTagStr, email)
				// license 余额检查 — budget < 0 表示禁用限制,>= 0 时为本次同步还能新建的 routed 节点数
				if routedBudget == 0 {
					response.SkippedCount++
					response.Errors = append(response.Errors, fmt.Sprintf("已达 license 节点上限,跳过新建 routed: %s", nodeName))
					log.Printf("[Remote Manage] license budget exhausted, skip auto-create routed: %s", nodeName)
					continue
				}
				proxy["name"] = nodeName
				cfgJSON, err := json.Marshal(proxy)
				if err != nil {
					continue
				}
				protocolStr, _ := ib.rawInbound["protocol"].(string)
				node := storage.Node{
					Username:       username,
					NodeName:       nodeName,
					Protocol:       protocolStr,
					ClashConfig:    string(cfgJSON),
					ParsedConfig:   string(cfgJSON),
					Enabled:        true,
					Tag:            fmt.Sprintf("远程:%s", server.Name),
					OriginalServer: server.Name,
					InboundTag:     inboundTagStr,
				}
				created, err := h.repo.CreateNode(ctx, node)
				if err != nil {
					log.Printf("[Remote Manage] auto-create routed node for email=%q failed: %v", email, err)
					continue
				}
				// 同步给 admin 注册子账号 — 同 Pass 2 的理由
				if credJSON, err := json.Marshal(client); err == nil {
					if _, err := h.repo.UpsertUserSubaccount(ctx, storage.UserSubaccount{
						Username: username, RoutedNodeID: created.ID, Email: email, CredentialJSON: string(credJSON), IsActive: true,
					}); err != nil {
						log.Printf("[Remote Manage] UpsertUserSubaccount routed_node=%d email=%q failed: %v", created.ID, email, err)
					}
				}
				// CreateNode 没有写 node_type/parent/routed_outbound_tag,补一刀
				if err := h.repo.MarkNodeAsRouted(ctx, created.ID, outTag, master); err != nil {
					log.Printf("[Remote Manage] auto-create: MarkNodeAsRouted id=%d failed: %v", created.ID, err)
				}
				if routedBudget > 0 {
					routedBudget--
				}
				existingRoutedTriple[inboundTagStr+":"+outTag] = true
				response.SyncedCount++
				response.CreatedCount++
				log.Printf("[Remote Manage] Auto-created routed node id=%d email=%q → outboundTag=%q parent=%d", created.ID, email, outTag, master)
			}
		}
	}

	response.Message = fmt.Sprintf("已同步 %d 个节点(绑定 %d 个，新增 %d 个)，跳过 %d 个",
		response.SyncedCount, response.ClaimedCount, response.CreatedCount, response.SkippedCount)
	return response
}

// protocolEquivalent 判断 clash type 和 xray protocol 是否等价。
// clash 用 `type: ss/vless/vmess/trojan`,xray 用 `protocol: shadowsocks/vless/vmess/trojan`,
// 这里把 ss <-> shadowsocks 同等化(其他名字一致)。
func protocolEquivalent(clashType, xrayProtocol string) bool {
	return normalizeProtocol(clashType) == normalizeProtocol(xrayProtocol)
}

// normalizeProtocol 把 clash type 和 xray protocol 统一成同一个规范形式,
// 便于参与 dedup key 拼装(参与字符串匹配 而不只是相等判断)。
func normalizeProtocol(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "ss" {
		return "shadowsocks"
	}
	return s
}

// 同样的等价判断,也给 NodeSyncListener / 别处用。在 event 包里也有 tryClaim,
// 那边自己也保留一份语义一致的判断;此处不导出避免跨包耦合。

// MatchRemoteServerByNodeHost 给定一个 clash 配置(JSON),如果它的 server 字段命中
// 任一已注册 remote_server 的 IPAddress/Domain/PullAddress,返回那台 server。
// 用于"导入节点时识别它是否指向 mmwx 已管理的 server",从而走 license 配额检查 + 自动 claim。
// overrideHost 非空时用它替代 clash.server 匹配 —— 中转节点 clash.server 是中转地址,必须用
// 原始源站地址(relay_orig_server)才能匹配到真实 server。找不到返回 (nil, nil)。
func (h *RemoteManageHandler) MatchRemoteServerByNodeHost(ctx context.Context, clashConfigJSON string, overrideHost string) (*storage.RemoteServer, error) {
	srv := strings.TrimSpace(overrideHost)
	if srv == "" {
		if strings.TrimSpace(clashConfigJSON) == "" {
			return nil, nil
		}
		var cfg map[string]any
		if err := json.Unmarshal([]byte(clashConfigJSON), &cfg); err != nil {
			return nil, nil
		}
		s, _ := cfg["server"].(string)
		srv = strings.TrimSpace(s)
	}
	if srv == "" {
		return nil, nil
	}
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return nil, err
	}
	for i := range servers {
		s := &servers[i]
		for _, host := range []string{s.IPAddress, s.IPAddressV6, s.Domain, s.DomainV6, s.PullAddress} {
			if strings.TrimSpace(host) == "" {
				continue
			}
			if strings.EqualFold(host, srv) {
				return s, nil
			}
		}
	}
	return nil, nil
}

// tryClaimExternalNodeForSync 在 sync inbounds → nodes 流程里,扫"外部节点"
// (original_server=” AND inbound_tag=”),按 server 地址(IP/Domain/PullAddress 任一)+ port + protocol
// 匹配,把命中的节点全部升级为受管节点(填上 original_server + inbound_tag),返回是否至少 claim 了一个。
//
// 全部 claim 而非 claim 第一个:同一台服务器使用「回落+路由出站」时,订阅里会出现多条
// server+port+protocol 完全相同、只是用户凭据 / email 不同的客户端节点(各自走不同上游路径),
// 都应该匹配到这台服务器,见 Issue: hk-n.2ha.me 多个节点只匹配到 1 个的反馈。
func (h *RemoteManageHandler) tryClaimExternalNodeForSync(ctx context.Context, server *storage.RemoteServer, protocol string, port int, clashConfigJSON, inboundTag string) bool {
	candidates := map[string]bool{}
	for _, a := range []string{server.IPAddress, server.IPAddressV6, server.Domain, server.DomainV6, server.PullAddress} {
		a = strings.TrimSpace(a)
		if a != "" {
			candidates[a] = true
		}
	}
	if len(candidates) == 0 {
		return false
	}
	allNodes, err := h.repo.ListAllNodes(ctx)
	if err != nil {
		return false
	}
	claimedAny := false
	for _, n := range allNodes {
		if strings.TrimSpace(n.OriginalServer) != "" || strings.TrimSpace(n.InboundTag) != "" {
			continue
		}
		if n.NodeType == "routed" {
			continue
		}
		var cfg map[string]any
		if err := json.Unmarshal([]byte(n.ClashConfig), &cfg); err != nil {
			continue
		}
		srv, _ := cfg["server"].(string)
		if !candidates[srv] {
			continue
		}
		var cfgPort int
		switch p := cfg["port"].(type) {
		case float64:
			cfgPort = int(p)
		case int:
			cfgPort = p
		}
		if cfgPort != port {
			continue
		}
		proto, _ := cfg["type"].(string)
		if !protocolEquivalent(proto, protocol) {
			continue
		}
		// 命中:用 agent 转出来的 clash_config 作为「连接配置」基础,但保留原节点名(用户改过的中文名)
		// 以及原 clash_config 里区分各节点的凭据字段(uuid/password/email,因为这是回落+路由出站下区分 route 的关键)
		mergedConfig := clashConfigJSON
		var newCfg map[string]any
		if err := json.Unmarshal([]byte(clashConfigJSON), &newCfg); err == nil {
			if name, _ := cfg["name"].(string); name != "" {
				newCfg["name"] = name
			}
			// 凭据字段 — 多节点共用同一 inbound 时,这些字段是区分路由的关键,必须保留原值
			for _, k := range []string{"uuid", "password", "email", "alterId", "cipher"} {
				if v, ok := cfg[k]; ok {
					newCfg[k] = v
				}
			}
			if updated, err := json.Marshal(newCfg); err == nil {
				mergedConfig = string(updated)
			}
		}
		if err := h.repo.ClaimExternalNode(ctx, n.ID, server.Name, inboundTag, fmt.Sprintf("远程:%s", server.Name), mergedConfig); err != nil {
			log.Printf("[Remote Manage] tryClaim node %d failed: %v", n.ID, err)
			continue
		}
		log.Printf("[Remote Manage] Claimed external node id=%d name=%q for %s/%s:%d", n.ID, n.NodeName, server.Name, protocol, port)
		claimedAny = true
	}
	return claimedAny
}

// ================== X射线系统配置==================

// 将 xray 系统配置请求代理到远程服务器
func (h *RemoteManageHandler) HandleXraySystemConfig(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	var body []byte
	if r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to read body")
			return
		}
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/xray/system-config", body)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// ================== 将入站同步到节点 ==================

// SyncInboundsToNodesRequest 表示将入站同步到节点的请求
type SyncInboundsToNodesRequest struct {
	ServerHost    string `json:"server_host"`    // 远程服务器的对外访问地址
	ForceOverride bool   `json:"force_override"` // 是否强制覆盖已存在的节点
}

// SyncInboundsToNodesResponse 表示同步入站的响应
type SyncInboundsToNodesResponse struct {
	Success      bool     `json:"success"`
	Message      string   `json:"message"`
	SyncedCount  int      `json:"synced_count"`
	ClaimedCount int      `json:"claimed_count"` // 自动绑定已有外部节点的数量
	CreatedCount int      `json:"created_count"` // 新建节点的数量
	SkippedCount int      `json:"skipped_count"`
	SyncedTags   []string `json:"synced_tags,omitempty"`
	Errors       []string `json:"errors,omitempty"`
}

// 将远程服务器的入站同步到节点表(手动触发)。
// 与 WS scan_result 自动同步共用 syncInboundsToNodes 实现 — 不再单独写一份循环逻辑,
// 防止 claim/dedupe/规则跨入口漂移。
func (h *RemoteManageHandler) HandleSyncInboundsToNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	// 解析请求体(server_host + force_override 都是可选)
	var req SyncInboundsToNodesRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			remoteWriteError(w, http.StatusBadRequest, "invalid request body")
			return
		}
	}

	response := h.syncInboundsToNodes(r.Context(), id, req.ServerHost, req.ForceOverride)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// chooseClashServerHost 给一台 remote server 选合适的 clash_config.server 值。
// 优先级:Domain → PullAddress (仅当不是 IP) → IPAddress → DomainV6 → IPAddressV6。
//
// 关键规则:PullAddress 是 IP 字符串(v4/v6)→ 跳过,fall to IPAddress。
// 因为 IPAddress 由 agent 心跳实时上报,IP 漂移自动跟随;而 PullAddress 是用户表单写入的静态字符串,
// 漂了不会自己更新,如果用作 clash.server 会让节点指向旧 IP。
// 反过来 PullAddress 是域名/反代地址时保留 — 域名是稳定的,用户特意填的就是要走它。
//
// IPv6 放在 IPv4 之后作为兜底:双栈服务器保持既有的 IPv4 默认行为;纯 IPv6 服务器也能生成节点,
// 不会因为 serverHost 为空而在入站事件/手动同步路径提前退出。
func chooseClashServerHost(server *storage.RemoteServer) string {
	if server == nil {
		return ""
	}
	// 锁定入口 IP:忽略域名/DDNS/v6,只用「服务器地址」(PullAddress 优先,否则 IPAddress)里填的 IP。
	// NAT 机:域名/DDNS 指向动态出口 IP,只有用户填的静态入口 IP 能连。
	if server.LockEntryIP {
		if p := strings.TrimSpace(server.PullAddress); p != "" {
			return p
		}
		return strings.TrimSpace(server.IPAddress)
	}
	if d := strings.TrimSpace(server.Domain); d != "" {
		return d
	}
	if p := strings.TrimSpace(server.PullAddress); p != "" && net.ParseIP(p) == nil {
		return p
	}
	// 跳过 127.0.0.1 / localhost:NAT 机没配入口 IP 时 agent 会上报回环地址,
	// 直接拿它当 clash server 生成的节点根本连不上,不如往后退到 v6 / 留空提示用户配入口 IP。
	if ip := strings.TrimSpace(server.IPAddress); ip != "" && !isLoopbackHost(ip) {
		return ip
	}
	if d := strings.TrimSpace(server.DomainV6); d != "" {
		return d
	}
	return strings.TrimSpace(server.IPAddressV6)
}

// v6RefreshTarget 返回该服务器 v6 节点(ip_family='v6')的 clash server 应刷成的地址。
// 锁定入口 IP 时:v6 节点同样只用手填的「服务器地址」(PullAddress→IPAddress),与 chooseClashServerHost
// 的锁定分支保持一致 —— NAT 机的动态出口 IPv6 连不上,只有手填的静态入口 IP 能连。
// 未锁定时:沿用 agent 心跳上报的动态 IPAddressV6(现状行为)。
func v6RefreshTarget(server *storage.RemoteServer) string {
	if server == nil {
		return ""
	}
	if server.LockEntryIP {
		if p := strings.TrimSpace(server.PullAddress); p != "" {
			return p
		}
		return strings.TrimSpace(server.IPAddress)
	}
	return strings.TrimSpace(server.IPAddressV6)
}

// isLoopbackHost 判断 host 是否为回环地址(127.0.0.1 / ::1 / localhost)。
func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// silentlyRemoveOrphanInbound 在后台静默删除 agent 上的"孤儿入站"(listInbounds 返回但 settings 缺失)。
// 触发场景:agent 的 xray runtime 里残留只有 tag/protocol/port 没 settings 的入站,通常来自:
//   - 手动 SSH 操作时半截写入的入站
//   - 历史 bug 留下的损坏入站
//   - confdir 下 *.json 文件丢失但 runtime 还在跑
//
// 这类入站既无法生成节点配置,留着只会每次扫描污染 SkippedCount/Errors,用户也看不懂。
// 直接调 agent 的 inbounds remove RPC 清掉,跟 deleteRemoteInbound 同款路径。
// 失败只 log,不阻塞 sync 流程;成功也只 log,前端无感。
func (h *RemoteManageHandler) silentlyRemoveOrphanInbound(serverID int64, tag string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]string{"action": "remove", "tag": tag})
	if _, err := h.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/inbounds", body); err != nil {
		log.Printf("[SyncInbounds] silent cleanup of orphan inbound %s on server=%d failed: %v", tag, serverID, err)
		return
	}
	log.Printf("[SyncInbounds] silently removed orphan inbound %s on server=%d (no settings found)", tag, serverID)
}

// inboundToClashProxy 将 Xray 入站配置转换为 Clash 代理配置。
// tunnelPort > 0 表示服务器使用隧道模式；将其用作节点的外部端口。
func (h *RemoteManageHandler) inboundToClashProxy(inbound map[string]interface{}, serverHost, serverName string, tunnelPort int) (map[string]interface{}, error) {
	protocol, _ := inbound["protocol"].(string)
	tag, _ := inbound["tag"].(string)
	port, _ := inbound["port"].(float64)
	settings, _ := inbound["settings"].(map[string]interface{})
	streamSettings, _ := inbound["streamSettings"].(map[string]interface{})

	if settings == nil {
		return nil, fmt.Errorf("no settings found")
	}

	// 获取第一个客户/帐户(anytls 用 users[],其他主流协议用 clients[],socks/http 用 accounts[])
	var client map[string]interface{}
	if clients, ok := settings["clients"].([]interface{}); ok && len(clients) > 0 {
		client, _ = clients[0].(map[string]interface{})
	} else if users, ok := settings["users"].([]interface{}); ok && len(users) > 0 {
		client, _ = users[0].(map[string]interface{})
	} else if accounts, ok := settings["accounts"].([]interface{}); ok && len(accounts) > 0 {
		client, _ = accounts[0].(map[string]interface{})
	}

	// shadowsocks server 端 password 在 settings 顶层不在 clients[];socks / http 无认证模式 accounts 可空;
	// dokodemo-door 是端口转发,本来就没 clients/users/accounts。这几个协议允许 client == nil 继续走下游 case 分支。
	// 历史 bug:只放过 shadowsocks → 无认证 SOCKS5 入站扫描时这里报 "no client/account found",
	// syncInboundsToNodes SkippedCount++ → 节点不进 DB → UI 节点列表看不到 + 无法删除。
	noClientProtocols := map[string]bool{"shadowsocks": true, "socks": true, "http": true, "dokodemo-door": true}
	if client == nil && !noClientProtocols[protocol] {
		return nil, fmt.Errorf("no client/account found")
	}

	// 节点名称
	nodeName := fmt.Sprintf("[%s] %s", serverName, tag)

	nodePort := int(port)
	if tunnelPort > 0 {
		nodePort = tunnelPort
	}

	proxy := map[string]interface{}{
		"name":   nodeName,
		"server": serverHost,
		"port":   nodePort,
		// 默认开启 UDP 转发(clash/mihomo 里 udp:true 表示该代理支持 UDP relay)。
		"udp": true,
	}

	switch protocol {
	case "vless":
		proxy["type"] = "vless"
		if id, ok := client["id"].(string); ok {
			proxy["uuid"] = id
		}
		// 检查流量
		if flow, ok := client["flow"].(string); ok && flow != "" {
			proxy["flow"] = flow
		}
		// VLESS Reality V2 encryption(mihomo 已支持):服务端的 settings.encryption 客户端配置必须带,
		// 否则握手失败。注意是 settings.encryption(对外下发的密钥),不是 decryption(服务端自己解密)。
		if enc, ok := settings["encryption"].(string); ok && enc != "" && enc != "none" {
			proxy["encryption"] = enc
		}
		// 添加流设置
		h.addStreamSettings(proxy, streamSettings)

	case "vmess":
		proxy["type"] = "vmess"
		if id, ok := client["id"].(string); ok {
			proxy["uuid"] = id
		}
		proxy["alterId"] = 0
		if aid, ok := client["alterId"].(float64); ok {
			proxy["alterId"] = int(aid)
		}
		proxy["cipher"] = "auto"
		// 添加流设置
		h.addStreamSettings(proxy, streamSettings)

	case "trojan":
		proxy["type"] = "trojan"
		if password, ok := client["password"].(string); ok {
			proxy["password"] = password
		}
		// 检查流量
		if flow, ok := client["flow"].(string); ok && flow != "" {
			proxy["flow"] = flow
		}
		// 添加流设置
		h.addStreamSettings(proxy, streamSettings)
		// mihomo trojan 使用 sni 而非 servername
		if sn, ok := proxy["servername"]; ok {
			proxy["sni"] = sn
			delete(proxy, "servername")
		}

	case "shadowsocks":
		proxy["type"] = "ss"
		method, _ := settings["method"].(string)
		if method != "" {
			proxy["cipher"] = method
		}
		// SS2022(method 以 "2022-" 开头)需要 `master:userPass` 双段密码。
		// 节点 clash_config 是 admin 视角(也用作直接订阅 / routed 出站模板):
		//   - 有 client → 拼 `master:firstClient.password`(jimlee 等 admin 自用此节点能直接订阅)
		//   - 无 client → 只放 master(空 inbound,后续 user override 时再拼)
		// 订阅生成时 appendUserCredentialOverride 会兜底剥掉冒号后段重拼当前用户密码,所以多用户场景不会三段叠加。
		// 老 SS(非 2022)单段密码,直接 master 就够,client password 跟 master 必须相同 → 不拼。
		nodePass, _ := settings["password"].(string)
		if strings.HasPrefix(method, "2022-") {
			if clients, ok := settings["clients"].([]interface{}); ok && len(clients) > 0 {
				if first, ok := clients[0].(map[string]interface{}); ok {
					if clientPass, ok := first["password"].(string); ok && clientPass != "" {
						nodePass = nodePass + ":" + clientPass
					}
				}
			}
		}
		if nodePass != "" {
			proxy["password"] = nodePass
		}

	case "hysteria":
		proxy["type"] = "hysteria2"
		if auth, ok := client["auth"].(string); ok {
			proxy["password"] = auth
		}
		if streamSettings != nil {
			if tlsSettings, ok := streamSettings["tlsSettings"].(map[string]interface{}); ok {
				if sni, ok := tlsSettings["serverName"].(string); ok && sni != "" {
					proxy["sni"] = sni
				}
			}
			if hySettings, ok := streamSettings["hysteriaSettings"].(map[string]interface{}); ok {
				if obfsPwd, ok := hySettings["password"].(string); ok && obfsPwd != "" {
					proxy["obfs"] = "salamander"
					proxy["obfs-password"] = obfsPwd
				}
			}
		}

	case "anytls":
		// mihomo anytls(https://wiki.metacubex.one/en/config/proxies/anytls/):password + sni,跟 trojan 几乎一致。
		proxy["type"] = "anytls"
		// anytls 天然支持 UDP(UDP-over-TCP,服务端自动无需配置),默认开启;不依赖 streamSettings
		// 是否为 nil(addStreamSettings 在 streamSettings==nil 时会提前返回、漏设 udp)。
		proxy["udp"] = true
		if password, ok := client["password"].(string); ok {
			proxy["password"] = password
		}
		h.addStreamSettings(proxy, streamSettings)
		if sn, ok := proxy["servername"]; ok {
			proxy["sni"] = sn
			delete(proxy, "servername")
		}

	case "socks", "http":
		// proxyparser/mihomo 生态统一用 "socks5"(xray 协议名是 "socks")—— 存 "socks" 会被 substore
		// 各生成器(clash 白名单、uri.go case)漏掉:订阅里丢节点、复制 URI 产出空串。这里归一。
		if protocol == "socks" {
			proxy["type"] = "socks5"
		} else {
			proxy["type"] = protocol
		}
		// client 为 nil 时(无认证模式),clash 配置不带 username/password,客户端按无认证直连。
		if client != nil {
			if user, ok := client["user"].(string); ok {
				proxy["username"] = user
			}
			if pass, ok := client["pass"].(string); ok {
				proxy["password"] = pass
			}
		}

	case "snell":
		// mihomo/clash snell:type:snell, server, port, psk, version, obfs-opts:{mode,host}(v4/v5);
		// v6:mode(default/unshaped/unsafe-raw)。字段来自 settings.users[] 条目(generateInboundConfig 下发)。
		proxy["type"] = "snell"
		if psk, ok := client["psk"].(string); ok {
			proxy["psk"] = psk
		}
		version := 4
		if v, ok := client["version"].(float64); ok {
			version = int(v)
		} else if v, ok := client["version"].(int); ok {
			version = v
		}
		proxy["version"] = version
		if version == 6 {
			if mode, ok := client["v6Mode"].(string); ok && mode != "" {
				proxy["mode"] = mode
			}
		} else if obfsMode, ok := client["obfsMode"].(string); ok && obfsMode != "" && obfsMode != "none" {
			obfsOpts := map[string]interface{}{"mode": obfsMode}
			if obfsHost, ok := client["obfsHost"].(string); ok && obfsHost != "" {
				obfsOpts["host"] = obfsHost
			}
			proxy["obfs-opts"] = obfsOpts
		}
		// 新增 Snell 节点默认开启 UDP relay（proxy 基础字段 udp=true）和端口复用。
		// TFO 不设默认值；只有节点配置显式包含该字段时，订阅生成器才应输出。
		proxy["reuse"] = true

	case "mieru":
		// mihomo/clash mieru:type:mieru, server, port, transport(TCP/UDP), username, password。
		// 字段来自 settings.users[] 条目(username/password)。仅 mihomo(Clash.Meta)/官方 mieru 客户端支持,
		// 其余订阅格式(surge/loon/qx/sing-box/裸 clash)不支持 → 由 clash_snell_filter 范式过滤,producer 跳过。
		// 服务端 TCP+UDP 都监听;transport 由 inbound.settings.transport 决定订阅下发给客户端用哪个(默认 TCP)。
		proxy["type"] = "mieru"
		transport := "TCP"
		if t, ok := settings["transport"].(string); ok && strings.ToUpper(t) == "UDP" {
			transport = "UDP"
		}
		proxy["transport"] = transport
		if username, ok := client["username"].(string); ok {
			proxy["username"] = username
		}
		if password, ok := client["password"].(string); ok {
			proxy["password"] = password
		}

	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	return proxy, nil
}

// 将流设置添加到 Clash 代理配置
func (h *RemoteManageHandler) addStreamSettings(proxy map[string]interface{}, streamSettings map[string]interface{}) {
	if streamSettings == nil {
		return
	}

	network, _ := streamSettings["network"].(string)
	security, _ := streamSettings["security"].(string)

	// 设置网络类型（始终包含，即使对于 tcp）
	if network != "" {
		proxy["network"] = network
	}

	// UDP支持
	proxy["udp"] = true

	// 处理 TLS
	if security == "tls" {
		proxy["tls"] = true
		if tlsSettings, ok := streamSettings["tlsSettings"].(map[string]interface{}); ok {
			if sni, ok := tlsSettings["serverName"].(string); ok && sni != "" {
				proxy["servername"] = sni
			}
			if alpn, ok := tlsSettings["alpn"].([]interface{}); ok && len(alpn) > 0 {
				alpnStrs := make([]string, 0, len(alpn))
				for _, a := range alpn {
					if s, ok := a.(string); ok {
						alpnStrs = append(alpnStrs, s)
					}
				}
				proxy["alpn"] = alpnStrs
			}
			if fp, ok := tlsSettings["fingerprint"].(string); ok && fp != "" {
				proxy["client-fingerprint"] = fp
			}
			// 反查 xray → clash:保留证书 SHA-256，后续 URI producer 会输出 pcs/pinSHA256。
			// 老 allowInsecure 数据仍映射为 skip-cert-verify，等待补全任务取得真实指纹。
			pinned, _ := tlsSettings["pinnedPeerCertSha256"].(string)
			allowInsecure, _ := tlsSettings["allowInsecure"].(bool)
			if pinned = strings.TrimSpace(pinned); pinned != "" {
				proxy["tls-fingerprint"] = pinned
				proxy["skip-cert-verify"] = true
			} else if allowInsecure {
				proxy["skip-cert-verify"] = true
			} else {
				proxy["skip-cert-verify"] = false
			}
		}
	}

	// 处理现实
	if security == "reality" {
		proxy["tls"] = true
		// reality 靠 X25519 公钥验证、不走 CA 校验,skip-cert-verify 对 reality 是 no-op;
		// 输出 false 避免"默认跳过证书校验"的误导(mihomo 对 reality 忽略此字段,连通性不变)。
		proxy["skip-cert-verify"] = false
		if realitySettings, ok := streamSettings["realitySettings"].(map[string]interface{}); ok {
			realityOpts := map[string]interface{}{}
			if publicKey, ok := realitySettings["publicKey"].(string); ok {
				realityOpts["public-key"] = toURLSafeBase64(publicKey)
			}
			// ShortIds 是 Xray 配置中的一个数组
			if shortIds, ok := realitySettings["shortIds"].([]interface{}); ok && len(shortIds) > 0 {
				if sid, ok := shortIds[0].(string); ok {
					realityOpts["short-id"] = sid
				}
			}
			// 后备：单个 ShortId 字段
			if _, exists := realityOpts["short-id"]; !exists {
				if shortId, ok := realitySettings["shortId"].(string); ok {
					realityOpts["short-id"] = shortId
				}
			}
			if spiderX, ok := realitySettings["spiderX"].(string); ok {
				realityOpts["spider-x"] = spiderX
			}
			if len(realityOpts) > 0 {
				proxy["reality-opts"] = realityOpts
			}
			// serverNames 是 Xray 配置中的一个数组
			if serverNames, ok := realitySettings["serverNames"].([]interface{}); ok && len(serverNames) > 0 {
				if sn, ok := serverNames[0].(string); ok && sn != "" {
					proxy["servername"] = sn
				}
			}
			// 后备：单个 serverName 字段
			if _, exists := proxy["servername"]; !exists {
				if sni, ok := realitySettings["serverName"].(string); ok && sni != "" {
					proxy["servername"] = sni
				}
			}
			if fp, ok := realitySettings["fingerprint"].(string); ok && fp != "" {
				proxy["client-fingerprint"] = fp
			}
		}
		// 如果未设置，则为 REALITY 默认客户端指纹
		if _, exists := proxy["client-fingerprint"]; !exists {
			proxy["client-fingerprint"] = "chrome"
		}
	}

	// 处理WebSocket
	if network == "ws" {
		if wsSettings, ok := streamSettings["wsSettings"].(map[string]interface{}); ok {
			wsOpts := map[string]interface{}{}
			if path, ok := wsSettings["path"].(string); ok {
				wsOpts["path"] = path
			}
			if headers, ok := wsSettings["headers"].(map[string]interface{}); ok {
				wsOpts["headers"] = headers
			}
			if len(wsOpts) > 0 {
				proxy["ws-opts"] = wsOpts
			}
		}
	}

	// 处理 gRPC
	if network == "grpc" {
		if grpcSettings, ok := streamSettings["grpcSettings"].(map[string]interface{}); ok {
			grpcOpts := map[string]interface{}{}
			if serviceName, ok := grpcSettings["serviceName"].(string); ok {
				grpcOpts["grpc-service-name"] = serviceName
			}
			if len(grpcOpts) > 0 {
				proxy["grpc-opts"] = grpcOpts
			}
		}
	}

	// 处理 HTTP/2
	if network == "h2" || network == "http" {
		if httpSettings, ok := streamSettings["httpSettings"].(map[string]interface{}); ok {
			h2Opts := map[string]interface{}{}
			if path, ok := httpSettings["path"].(string); ok {
				h2Opts["path"] = path
			}
			if host, ok := httpSettings["host"].([]interface{}); ok && len(host) > 0 {
				h2Opts["host"] = host
			}
			if len(h2Opts) > 0 {
				proxy["h2-opts"] = h2Opts
			}
		}
	}

	// 处理 XHTTP
	if network == "xhttp" {
		if xhttpSettings, ok := streamSettings["xhttpSettings"].(map[string]interface{}); ok {
			xhttpOpts := map[string]interface{}{
				"headers": map[string]interface{}{},
			}
			if path, ok := xhttpSettings["path"].(string); ok {
				xhttpOpts["path"] = path
			}
			proxy["xhttp-opts"] = xhttpOpts
			if mode, ok := xhttpSettings["mode"].(string); ok && mode != "" {
				proxy["mode"] = mode
			}
		}
	}
}

func (h *RemoteManageHandler) getTunnelInSettingsPort(ctx context.Context, serverID int64) int {
	result, err := h.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/inbounds", nil)
	if err != nil {
		return 0
	}
	var resp struct {
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if json.Unmarshal(result, &resp) != nil {
		return 0
	}
	for _, ib := range resp.Inbounds {
		tag, _ := ib["tag"].(string)
		if tag != "tunnel-in" {
			continue
		}
		settings, _ := ib["settings"].(map[string]interface{})
		if settings == nil {
			return 0
		}
		if p, ok := settings["port"].(float64); ok && p > 0 {
			return int(p)
		}
		return 0
	}
	return 0
}

func isRealityInbound(inbound map[string]interface{}) bool {
	streamSettings, _ := inbound["streamSettings"].(map[string]interface{})
	security, _ := streamSettings["security"].(string)
	return strings.EqualFold(strings.TrimSpace(security), "reality")
}

// InboundToClashProxyByServerID 将 Xray 入站配置转换为 Clash 代理 JSON 字符串。
// 这是供事件侦听器使用的导出方法。
func (h *RemoteManageHandler) InboundToClashProxyByServerID(serverID int64, inbound map[string]any) (string, error) {
	ctx := context.Background()
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return "", fmt.Errorf("get server: %w", err)
	}

	serverHost := chooseClashServerHost(server)
	tunnelPort := 0

	// tunnel 模式:新入站端口正好等于 tunnel-in 的 settings.port,意味着这条入站会被 tunnel 暴露在 443
	if server.Domain != "" && (server.StealMode == "tunnel" || server.StealMode == "") {
		inboundPort := 0
		if p, ok := inbound["port"].(float64); ok {
			inboundPort = int(p)
		} else if p, ok := inbound["port"].(int); ok {
			inboundPort = p
		}

		if inboundPort > 0 {
			tunnelInSettingsPort := h.getTunnelInSettingsPort(ctx, serverID)
			if tunnelInSettingsPort > 0 && inboundPort == tunnelInSettingsPort {
				tunnelPort = 443
			}
		}
	}

	if serverHost == "" {
		return "", fmt.Errorf("server has no IP or domain")
	}

	inboundMap := make(map[string]interface{})
	for k, v := range inbound {
		inboundMap[k] = v
	}

	if effPort, effHost := applyWSSClientRewrite(inboundMap, server); effPort > 0 {
		tunnelPort = effPort
		serverHost = effHost
	}

	proxy, err := h.inboundToClashProxy(inboundMap, serverHost, server.Name, tunnelPort)
	if err != nil {
		return "", err
	}

	clashJSON, err := json.Marshal(proxy)
	if err != nil {
		return "", fmt.Errorf("marshal clash config: %w", err)
	}

	return string(clashJSON), nil
}

// applyWSSClientRewrite 若 inbound 是 VLESS WSS 入站(network=ws + security=none + listen 127.0.0.1),
// 把 inboundMap 原地改写为"客户端视角"(security=tls, tlsSettings.serverName=domain, wsSettings.headers.Host=domain),
// 并返回客户端连接用的端口(443) + serverHost(域名)。
//
// 否则不修改 inboundMap,返回 (0, "")。调用方据此判断是否覆盖默认 tunnelPort/serverHost。
//
// 域名优先取创建时已解析的 wss_domain，其次取 tlsSettings.serverName，最后才回退 server.Domain。
// 这样服务器只配 DDNS 域名或专家模式手动选 SNI 时，节点仍使用正确的对外地址。
func applyWSSClientRewrite(inboundMap map[string]interface{}, server *storage.RemoteServer) (port int, host string) {
	if server == nil {
		return 0, ""
	}
	if proto, _ := inboundMap["protocol"].(string); !strings.EqualFold(proto, "vless") {
		return 0, ""
	}
	ss, _ := inboundMap["streamSettings"].(map[string]interface{})
	if ss == nil {
		return 0, ""
	}
	network, _ := ss["network"].(string)
	security, _ := ss["security"].(string)
	listen, _ := inboundMap["listen"].(string)
	if network != "ws" || !(security == "" || security == "none") || !(listen == "127.0.0.1" || listen == "localhost") {
		return 0, ""
	}
	domain, _ := inboundMap["wss_domain"].(string)
	domain = normalizeWSSDomain(domain)
	if domain == "" {
		if tls, _ := ss["tlsSettings"].(map[string]interface{}); tls != nil {
			domain, _ = tls["serverName"].(string)
			domain = normalizeWSSDomain(domain)
		}
	}
	if domain == "" {
		domain = normalizeWSSDomain(server.Domain)
	}
	if domain == "" {
		return 0, ""
	}

	// 不污染外面持有的 streamSettings,做浅拷贝
	ssCopy := make(map[string]interface{}, len(ss)+1)
	for k, v := range ss {
		ssCopy[k] = v
	}
	ssCopy["security"] = "tls"
	ssCopy["tlsSettings"] = map[string]interface{}{"serverName": domain}

	ws, _ := ssCopy["wsSettings"].(map[string]interface{})
	wsCopy := make(map[string]interface{}, len(ws)+1)
	for k, v := range ws {
		wsCopy[k] = v
	}
	headers, _ := wsCopy["headers"].(map[string]interface{})
	if headers == nil {
		headers = map[string]interface{}{}
	}
	if _, ok := headers["Host"]; !ok {
		headers["Host"] = domain
	}
	wsCopy["headers"] = headers
	ssCopy["wsSettings"] = wsCopy
	inboundMap["streamSettings"] = ssCopy
	delete(inboundMap, "wss_domain")
	return 443, domain
}

// 重置服务器令牌（代理用于推送到服务器）
func (h *RemoteManageHandler) HandleResetServerToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	ctx := r.Context()

	// 获取当前服务器信息以查找旧令牌
	server, err := h.repo.GetRemoteServer(ctx, id)
	if err != nil {
		remoteWriteError(w, http.StatusNotFound, "server not found")
		return
	}
	oldToken := server.Token

	// 重置令牌
	newToken, expiresAt, err := h.repo.ResetServerToken(ctx, id)
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 尝试通过 WebSocket 将新令牌推送到连接的代理
	pushSuccess := false
	if h.wsHandler != nil && h.wsHandler.IsConnected(oldToken) {
		if err := h.wsHandler.SendTokenUpdate(oldToken, newToken, *expiresAt); err != nil {
			log.Printf("[Token Reset] Failed to push token update to agent: %v", err)
		} else {
			pushSuccess = true
			log.Printf("[Token Reset] Successfully pushed new token to server %s", server.Name)
		}
	}

	remoteWriteJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"server_token": newToken,
		"expires_at":   expiresAt.Format(time.RFC3339),
		"pushed":       pushSuccess,
		"message":      "Server token reset successfully",
	})
}

// 重置代理令牌（服务器使用它从代理中拉取）
func (h *RemoteManageHandler) HandleResetAgentToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	ctx := r.Context()

	// 重置代理令牌
	newToken, expiresAt, err := h.repo.ResetAgentToken(ctx, id)
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	remoteWriteJSON(w, http.StatusOK, map[string]any{
		"success":     true,
		"agent_token": newToken,
		"expires_at":  expiresAt.Format(time.RFC3339),
		"message":     "Agent token reset successfully",
	})
}

// 重置服务器令牌和代理令牌
func (h *RemoteManageHandler) HandleResetAllTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	ctx := r.Context()

	// 获取当前服务器信息以查找旧令牌
	server, err := h.repo.GetRemoteServer(ctx, id)
	if err != nil {
		remoteWriteError(w, http.StatusNotFound, "server not found")
		return
	}
	oldToken := server.Token

	// 重置所有令牌
	serverToken, serverExpiresAt, agentToken, agentExpiresAt, err := h.repo.ResetAllTokens(ctx, id)
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 尝试通过 WebSocket 将新的服务器令牌推送到连接的代理
	pushSuccess := false
	if h.wsHandler != nil && h.wsHandler.IsConnected(oldToken) {
		if err := h.wsHandler.SendTokenUpdate(oldToken, serverToken, *serverExpiresAt); err != nil {
			log.Printf("[Token Reset] Failed to push token update to agent: %v", err)
		} else {
			pushSuccess = true
			log.Printf("[Token Reset] Successfully pushed new token to server %s", server.Name)
		}
	}

	remoteWriteJSON(w, http.StatusOK, map[string]any{
		"success":                 true,
		"server_token":            serverToken,
		"server_token_expires_at": serverExpiresAt.Format(time.RFC3339),
		"agent_token":             agentToken,
		"agent_token_expires_at":  agentExpiresAt.Format(time.RFC3339),
		"pushed":                  pushSuccess,
		"message":                 "All tokens reset successfully",
	})
}

// isXrayConfigError 判断 xray 重启失败是否源于「配置本身」(JSON 解析 / config 构建失败)。
// 这类错误重启多少次、清 nginx stream、停 nginx 都救不了 —— config 不改就永远起不来。
// 内嵌模式下,主控对坏配置反复升级重启会挤占 / 阻塞 agent 的 WS 心跳,把它误判成「断联」
// (见:负载均衡 burstObservatory 缺 pingConfig 导致整机假性掉线的事故)。命中则跳过后续升级重试。
func isXrayConfigError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, kw := range []string{
		"failed to parse json config",
		"infra/conf",
		"requires a valid",
		"failed to build",
		"unknown config id",
		"failed to load",
	} {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}

func (h *RemoteManageHandler) restartXrayWithRecovery(ctx context.Context, serverID int64, logPrefix string) error {
	// restartAndVerify 改成 polling — 之前固定 sleep N 秒固然简单但显著拖慢套餐绑定/批量操作:
	// 主控对每条 server restart 都等满 sleep 时长,套餐里多 routed 节点跨多台 server 时
	// total wait ≈ 最慢 server 的 sleep 时长。xray 实际重启通常 < 500ms,polling 能把
	// 多数情况从 sleep 2s 砍到 ~200ms,batch 绑定/解绑直接感知"立刻完成"。
	restartAndVerify := func(maxWait time.Duration) error {
		if _, err := h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/services/control", []byte(`{"service":"xray","action":"restart"}`)); err != nil {
			return err
		}
		// 先给 100ms 让 service 退出再 polling,避免恰好 catch 到老进程残留 running 状态。
		time.Sleep(100 * time.Millisecond)
		deadline := time.Now().Add(maxWait)
		var lastErr error
		for {
			statusResult, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/services/status", nil)
			if err == nil {
				var statusResp struct {
					Xray *struct {
						Running bool `json:"running"`
					} `json:"xray"`
				}
				if jerr := json.Unmarshal(statusResult, &statusResp); jerr == nil && statusResp.Xray != nil && statusResp.Xray.Running {
					return nil
				}
				lastErr = fmt.Errorf("xray not yet running")
			} else {
				lastErr = fmt.Errorf("failed to check xray status: %v", err)
			}
			if time.Now().After(deadline) {
				if lastErr == nil {
					return fmt.Errorf("xray process exited after restart (likely port conflict)")
				}
				return lastErr
			}
			time.Sleep(150 * time.Millisecond)
		}
	}

	// 第一轮:polling 最多 2 秒 — 正常 xray 启动通常 < 500ms
	if err := restartAndVerify(2 * time.Second); err == nil {
		return nil
	} else {
		log.Printf("[%s] Xray restart attempt 1 failed on server %d: %v", logPrefix, serverID, err)
		// config 本身错误(如 burstObservatory 缺 pingConfig / anytls 未知协议 / JSON 解析失败):
		// 后面的升级重试(等更久、清 nginx stream、停 nginx 重启)全都无济于事,只会反复折腾、
		// 拖垮 agent。直接返回,让用户去修配置 —— 不进入升级重启风暴。
		if isXrayConfigError(err) {
			log.Printf("[%s] server %d: xray 配置错误,跳过升级重启(需改配置才能恢复): %v", logPrefix, serverID, err)
			return err
		}
	}

	// 第二轮:可能只是启动慢,polling 久一点
	if err := restartAndVerify(5 * time.Second); err == nil {
		log.Printf("[%s] Xray restarted on server %d after longer wait", logPrefix, serverID)
		return nil
	} else {
		log.Printf("[%s] Xray restart attempt 2 failed on server %d: %v, trying stream cleanup", logPrefix, serverID, err)
	}

	// 第三轮：清理 nginx stream 端口冲突后重试
	clearPayload, _ := json.Marshal(map[string]int{"port": 443})
	clearResult, clearErr := h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/nginx/clear-stream-port", clearPayload)
	if clearErr == nil {
		var clearResp struct {
			Removed int `json:"removed"`
		}
		json.Unmarshal(clearResult, &clearResp)
		if clearResp.Removed > 0 {
			log.Printf("[%s] Removed %d stream config(s) on server %d, retrying", logPrefix, clearResp.Removed, serverID)
			if err := restartAndVerify(3 * time.Second); err == nil {
				log.Printf("[%s] Xray restarted after stream cleanup on server %d", logPrefix, serverID)
				return nil
			}
		}
	} else {
		log.Printf("[%s] Stream cleanup failed on server %d: %v", logPrefix, serverID, clearErr)
	}

	// 第四轮兜底：先停 nginx 释放端口 → 重启 xray → 再启 nginx
	log.Printf("[%s] All normal attempts failed on server %d, trying nginx stop → xray restart → nginx start", logPrefix, serverID)
	h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/services/control", []byte(`{"service":"nginx","action":"stop"}`))
	time.Sleep(1 * time.Second)

	if err := restartAndVerify(3 * time.Second); err != nil {
		// xray 还是起不来，把 nginx 恢复
		h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/services/control", []byte(`{"service":"nginx","action":"start"}`))
		log.Printf("[%s] Xray restart failed even after stopping nginx on server %d: %v", logPrefix, serverID, err)
		return fmt.Errorf("xray restart failed after all recovery attempts: %v", err)
	}

	// xray 起来了，恢复 nginx
	h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/services/control", []byte(`{"service":"nginx","action":"start"}`))
	log.Printf("[%s] Xray restarted via nginx stop/start fallback on server %d", logPrefix, serverID)
	return nil
}

func (h *RemoteManageHandler) HandleValidateSite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ServerID  int64  `json:"server_id"`
		SiteType  string `json:"site_type"`
		SiteValue string `json:"site_value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ServerID == 0 || req.SiteValue == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id and site_value are required")
		return
	}

	if err := validateSiteValue(req.SiteType, req.SiteValue); err != nil {
		remoteWriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	payload, _ := json.Marshal(map[string]string{
		"site_type":  req.SiteType,
		"site_value": req.SiteValue,
	})
	resp, err := h.forwardToRemoteServer(r.Context(), req.ServerID, http.MethodPost, "/api/child/validate-site", payload)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, fmt.Sprintf("验证失败: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

func (h *RemoteManageHandler) HandleAddWebsite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ServerID  int64  `json:"server_id"`
		Domain    string `json:"domain"`
		SiteType  string `json:"site_type"`
		SiteValue string `json:"site_value"`
		EntryMode string `json:"entry_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ServerID == 0 || req.Domain == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id and domain are required")
		return
	}

	if err := validateSiteValue(req.SiteType, req.SiteValue); err != nil {
		remoteWriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx := r.Context()
	server, err := h.repo.GetRemoteServer(ctx, req.ServerID)
	if err != nil {
		remoteWriteError(w, http.StatusNotFound, "server not found")
		return
	}

	domain := strings.ToLower(strings.TrimSpace(req.Domain))

	var environment struct {
		Nginx struct {
			Installed bool   `json:"installed"`
			CanManage bool   `json:"can_manage"`
			Reason    string `json:"reason"`
		} `json:"nginx"`
		Ports map[string]string `json:"ports"`
	}
	if raw, envErr := h.forwardToRemoteServer(ctx, req.ServerID, http.MethodGet, "/api/child/nginx/websites", nil); envErr != nil || json.Unmarshal(raw, &environment) != nil {
		remoteWriteError(w, http.StatusBadGateway, "无法检查 Agent Nginx 环境，请先升级 Agent")
		return
	}
	if !environment.Nginx.Installed {
		remoteWriteError(w, http.StatusConflict, "Agent 尚未安装 Nginx，请先在网站管理中安装")
		return
	}
	if !environment.Nginx.CanManage {
		reason := environment.Nginx.Reason
		if reason == "" {
			reason = "现有 Nginx 配置不支持 MMWX websites 目录"
		}
		remoteWriteError(w, http.StatusConflict, reason)
		return
	}

	effectiveMode := strings.ToLower(strings.TrimSpace(req.EntryMode))
	if effectiveMode == "" || effectiveMode == "auto" {
		if server.StealMode == "tunnel" || server.StealMode == "fallback" {
			effectiveMode = server.StealMode
		} else {
			switch environment.Ports["443"] {
			case "", "nginx":
				effectiveMode = "direct"
			case "xray":
				remoteWriteError(w, http.StatusConflict, "443 已被 Xray 占用，请选择 Xray fallback 或 tunnel 网站入口")
				return
			case "unknown":
				remoteWriteError(w, http.StatusConflict, "Agent 缺少 ss/netstat，无法安全确认 443 端口占用")
				return
			default:
				remoteWriteError(w, http.StatusConflict, fmt.Sprintf("443 已被其他程序占用: %s", environment.Ports["443"]))
				return
			}
		}
	}
	if effectiveMode != "direct" && effectiveMode != "tunnel" && effectiveMode != "fallback" {
		remoteWriteError(w, http.StatusBadRequest, "entry_mode must be auto, direct, tunnel or fallback")
		return
	}
	if (effectiveMode == "tunnel" || effectiveMode == "fallback") && server.StealMode != effectiveMode {
		remoteWriteError(w, http.StatusConflict, fmt.Sprintf("服务器尚未建立 %s 入口；为避免覆盖现有 Xray 配置，请先在隧道/偷自己配置中创建该入口", effectiveMode))
		return
	}
	if effectiveMode == "direct" && environment.Ports["443"] != "" && environment.Ports["443"] != "nginx" {
		remoteWriteError(w, http.StatusConflict, "直接 Nginx 模式要求 443 空闲或已由 Nginx 使用")
		return
	}

	if h.certHandler == nil {
		remoteWriteError(w, http.StatusInternalServerError, "证书服务不可用")
		return
	}
	cert, certErr := h.repo.FindDeployableCertByDomain(ctx, domain, req.ServerID)
	if certErr != nil || cert == nil || cert.CertPEM == "" || cert.KeyPEM == "" {
		remoteWriteError(w, http.StatusConflict, fmt.Sprintf("未找到覆盖 %s 的有效证书，请先申请或部署证书", domain))
		return
	}
	certName := certDeployFilename(cert.Domain)
	certPayload, _ := json.Marshal(WSCertDeployPayload{
		Domain: cert.Domain, CertPEM: cert.CertPEM, KeyPEM: cert.KeyPEM,
		CertPath: "/usr/local/nginx/cert/" + certName + ".pem",
		KeyPath:  "/usr/local/nginx/cert/" + certName + ".key", Reload: "none",
	})
	if _, err := h.forwardToRemoteServer(ctx, req.ServerID, http.MethodPost, "/api/child/cert/deploy", certPayload); err != nil {
		remoteWriteError(w, http.StatusBadGateway, fmt.Sprintf("证书下发失败: %v", err))
		return
	}
	// 1. 生成 nginx domain config(统一渲染:伪装站 location / + ws location)。
	// ws 入站走主域名 fallback,故仅当添加的正是 server 主域名时才聚合 ws location;额外网站域名不带 ws。
	var wssForDomain []wssInboundInfo
	if strings.EqualFold(domain, strings.ToLower(strings.TrimSpace(server.Domain))) {
		wssForDomain = h.fetchWSSInbounds(ctx, req.ServerID)
	}
	var domainConf string
	if effectiveMode == "direct" {
		domainConf, err = renderDirectWebsiteConf(req.SiteType, req.SiteValue, domain, certName)
	} else {
		domainConf, err = renderStealSelfDomainConf(effectiveMode, req.SiteType, req.SiteValue, domain, certName, wssForDomain)
	}
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, fmt.Sprintf("渲染 domain.conf 失败: %v", err))
		return
	}
	domainConf = fmt.Sprintf("# MMWX-WEBSITE v1\n# mmwx-site-type: %s\n# mmwx-site-value-b64: %s\n%s", req.SiteType, base64.StdEncoding.EncodeToString([]byte(req.SiteValue)), domainConf)

	// 2. 部署 nginx domain config（不覆盖 nginx.conf）
	sslPayload, _ := json.Marshal(map[string]any{
		"domain":        domain,
		"domain_config": domainConf,
	})
	if _, err := h.forwardNginxSetupSSL(ctx, req.ServerID, sslPayload); err != nil {
		remoteWriteError(w, http.StatusBadGateway, fmt.Sprintf("部署 nginx 配置失败: %v", err))
		return
	}
	if effectiveMode == "direct" {
		remoteWriteJSON(w, http.StatusOK, map[string]any{"success": true, "message": fmt.Sprintf("网站 %s 添加成功", domain), "entry_mode": effectiveMode})
		return
	}

	// 3. 读取当前 xray 配置
	xrayResp, err := h.forwardToRemoteServer(ctx, req.ServerID, http.MethodGet, "/api/child/xray/config", nil)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, fmt.Sprintf("读取 xray 配置失败: %v", err))
		return
	}
	var xrayConfigResp struct {
		Config string `json:"config"`
	}
	json.Unmarshal(xrayResp, &xrayConfigResp)

	var xrayConfig map[string]any
	if err := json.Unmarshal([]byte(xrayConfigResp.Config), &xrayConfig); err != nil {
		remoteWriteError(w, http.StatusInternalServerError, fmt.Sprintf("解析 xray 配置失败: %v", err))
		return
	}

	// 4. 修改 xray 配置
	if effectiveMode == "fallback" {
		h.addWebsiteFallbackConfig(xrayConfig, domain)
	} else {
		h.addWebsiteTunnelConfig(xrayConfig, domain)
	}

	updatedConfig, _ := json.MarshalIndent(xrayConfig, "", "    ")
	configPayload, _ := json.Marshal(map[string]string{
		"config": string(updatedConfig),
	})
	if _, err := h.forwardToRemoteServer(ctx, req.ServerID, http.MethodPost, "/api/child/xray/config", configPayload); err != nil {
		remoteWriteError(w, http.StatusBadGateway, fmt.Sprintf("写入 xray 配置失败: %v", err))
		return
	}

	// 5. 重启 xray
	if err := h.restartXrayWithRecovery(ctx, req.ServerID, "AddWebsite"); err != nil {
		log.Printf("[AddWebsite] %v", err)
	}

	remoteWriteJSON(w, http.StatusOK, map[string]any{
		"success":    true,
		"message":    fmt.Sprintf("网站 %s 添加成功", domain),
		"entry_mode": effectiveMode,
	})
}

func renderDirectWebsiteConf(siteType, siteValue, domain, certName string) (string, error) {
	name := "website/direct_static.conf"
	placeholder := "{static_root_path}"
	if siteType == "proxy" {
		name = "website/direct_proxy.conf"
		placeholder = "{proxy_pass_server}"
	}
	tpl, err := templates.ReadFile(name)
	if err != nil {
		return "", err
	}
	result := strings.ReplaceAll(string(tpl), "{domain}", domain)
	result = strings.ReplaceAll(result, "{cert_name}", certName)
	result = strings.ReplaceAll(result, placeholder, siteValue)
	return result, nil
}

func (h *RemoteManageHandler) addWebsiteTunnelConfig(config map[string]any, domain string) {
	routing, _ := config["routing"].(map[string]any)
	if routing == nil {
		return
	}
	rules, _ := routing["rules"].([]any)

	for i, rule := range rules {
		r, _ := rule.(map[string]any)
		if r == nil {
			continue
		}
		outTag, _ := r["outboundTag"].(string)
		if outTag != "nginx" {
			continue
		}
		inTags, _ := r["inboundTag"].([]any)
		hasTunnelIn := false
		for _, t := range inTags {
			if s, _ := t.(string); s == "tunnel-in" {
				hasTunnelIn = true
				break
			}
		}
		if !hasTunnelIn {
			continue
		}
		domains, _ := r["domain"].([]any)
		found := false
		for _, d := range domains {
			if s, _ := d.(string); s == domain {
				found = true
				break
			}
		}
		if !found {
			r["domain"] = append(domains, domain)
		}
		// tunnel-in → nginx 必须始终拥有最高优先级。已有规则即使来自手动编辑且
		// 位于末尾，同步配置时也要移动到 rules[0]，避免先命中 tunnel-in → direct。
		if i > 0 {
			reordered := make([]any, 0, len(rules))
			reordered = append(reordered, rule)
			reordered = append(reordered, rules[:i]...)
			reordered = append(reordered, rules[i+1:]...)
			routing["rules"] = reordered
		}
		return
	}

	newRule := map[string]any{
		"inboundTag":  []any{"tunnel-in"},
		"domain":      []any{domain},
		"outboundTag": "nginx",
	}
	rules = append([]any{newRule}, rules...)
	routing["rules"] = rules
}

func (h *RemoteManageHandler) removeDomainsFromTunnelNginxRoute(config map[string]any, domainsToRemove []string) bool {
	routing, _ := config["routing"].(map[string]any)
	if routing == nil {
		return false
	}
	rules, _ := routing["rules"].([]any)

	removeSet := make(map[string]struct{})
	for _, d := range domainsToRemove {
		removeSet[strings.ToLower(d)] = struct{}{}
	}

	for i, rule := range rules {
		r, _ := rule.(map[string]any)
		if r == nil {
			continue
		}
		outTag, _ := r["outboundTag"].(string)
		if outTag != "nginx" {
			continue
		}
		inTags, _ := r["inboundTag"].([]any)
		hasTunnelIn := false
		for _, t := range inTags {
			if s, _ := t.(string); s == "tunnel-in" {
				hasTunnelIn = true
				break
			}
		}
		if !hasTunnelIn {
			continue
		}

		domains, _ := r["domain"].([]any)
		var remaining []any
		for _, d := range domains {
			if s, _ := d.(string); s != "" {
				if _, found := removeSet[strings.ToLower(s)]; !found {
					remaining = append(remaining, d)
				}
			}
		}

		if len(remaining) == 0 {
			routing["rules"] = append(rules[:i], rules[i+1:]...)
		} else {
			r["domain"] = remaining
		}
		return true
	}
	return false
}

func (h *RemoteManageHandler) cleanupTunnelRouteForReality(ctx context.Context, serverID int64, inbound map[string]interface{}) {
	streamSettings, _ := inbound["streamSettings"].(map[string]interface{})
	if streamSettings == nil {
		return
	}
	security, _ := streamSettings["security"].(string)
	if security != "reality" {
		return
	}
	realitySettings, _ := streamSettings["realitySettings"].(map[string]interface{})
	if realitySettings == nil {
		return
	}
	serverNames, _ := realitySettings["serverNames"].([]interface{})
	if len(serverNames) == 0 {
		return
	}

	var domains []string
	for _, sn := range serverNames {
		if s, _ := sn.(string); s != "" {
			domains = append(domains, s)
		}
	}
	if len(domains) == 0 {
		return
	}

	inboundPort := 0
	if p, ok := inbound["port"].(float64); ok {
		inboundPort = int(p)
	}
	inboundTag, _ := inbound["tag"].(string)

	xrayResp, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/xray/config", nil)
	if err != nil {
		return
	}
	var configResp struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal(xrayResp, &configResp); err != nil {
		return
	}
	var xrayConfig map[string]any
	if err := json.Unmarshal([]byte(configResp.Config), &xrayConfig); err != nil {
		return
	}

	configChanged := false

	// 如果是第一个 reality 入站，更新 tunnel-in 的 settings.port
	if inboundPort > 0 && h.isFirstRealityInbound(xrayConfig, inboundTag) {
		if h.updateTunnelInPortInConfig(xrayConfig, inboundPort) {
			configChanged = true
			log.Printf("[HandleInbounds] Updated tunnel-in settings.port to %d for first reality inbound on server %d", inboundPort, serverID)
		}
	}

	// 从 tunnel-in→nginx 路由中移除 reality serverNames
	if h.removeDomainsFromTunnelNginxRoute(xrayConfig, domains) {
		configChanged = true
	}

	if !configChanged {
		return
	}

	updatedConfig, _ := json.MarshalIndent(xrayConfig, "", "    ")
	configPayload, _ := json.Marshal(map[string]string{"config": string(updatedConfig)})
	if _, err := h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/xray/config", configPayload); err != nil {
		log.Printf("[HandleInbounds] Failed to update xray config for reality cleanup: %v", err)
		return
	}
	if err := h.restartXrayWithRecovery(ctx, serverID, "RealityRouteUpdate"); err != nil {
		log.Printf("[HandleInbounds] %v", err)
	}
	log.Printf("[HandleInbounds] Reality cleanup done on server %d: domains=%v", serverID, domains)
}

// isFirstRealityInbound 检查当前配置中是否已有其他 reality 入站（排除 currentTag）
func (h *RemoteManageHandler) isFirstRealityInbound(xrayConfig map[string]any, currentTag string) bool {
	inbounds, _ := xrayConfig["inbounds"].([]any)
	for _, ib := range inbounds {
		ibMap, _ := ib.(map[string]any)
		if ibMap == nil {
			continue
		}
		tag, _ := ibMap["tag"].(string)
		if tag == currentTag || tag == "" {
			continue
		}
		ss, _ := ibMap["streamSettings"].(map[string]any)
		if ss == nil {
			continue
		}
		if sec, _ := ss["security"].(string); sec == "reality" {
			return false
		}
	}
	return true
}

// updateTunnelInPortInConfig 修改 xray 配置中 tunnel-in 的 settings.port
func (h *RemoteManageHandler) updateTunnelInPortInConfig(xrayConfig map[string]any, port int) bool {
	inbounds, _ := xrayConfig["inbounds"].([]any)
	for _, ib := range inbounds {
		ibMap, _ := ib.(map[string]any)
		if ibMap == nil {
			continue
		}
		tag, _ := ibMap["tag"].(string)
		if tag != "tunnel-in" {
			continue
		}
		settings, _ := ibMap["settings"].(map[string]any)
		if settings == nil {
			settings = map[string]any{}
			ibMap["settings"] = settings
		}
		settings["port"] = port
		return true
	}
	return false
}

// getRealityServerNames 获取指定 inbound 的 reality serverNames（删除前调用）。
func (h *RemoteManageHandler) getRealityServerNames(ctx context.Context, serverID int64, tag string) []string {
	resp, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/inbounds", nil)
	if err != nil {
		return nil
	}
	var inboundsResp struct {
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if json.Unmarshal(resp, &inboundsResp) != nil {
		return nil
	}
	for _, inb := range inboundsResp.Inbounds {
		inbTag, _ := inb["tag"].(string)
		if inbTag != tag {
			continue
		}
		ss, _ := inb["streamSettings"].(map[string]interface{})
		if ss == nil {
			return nil
		}
		if sec, _ := ss["security"].(string); sec != "reality" {
			return nil
		}
		rs, _ := ss["realitySettings"].(map[string]interface{})
		if rs == nil {
			return nil
		}
		sns, _ := rs["serverNames"].([]interface{})
		var domains []string
		for _, sn := range sns {
			if s, _ := sn.(string); s != "" {
				domains = append(domains, s)
			}
		}
		return domains
	}
	return nil
}

// restoreTunnelRouteForReality 删除 reality 入站后，将其 serverNames 恢复到 tunnel-in→nginx 路由。
func (h *RemoteManageHandler) restoreTunnelRouteForReality(ctx context.Context, serverID int64, domains []string) {
	xrayResp, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/xray/config", nil)
	if err != nil {
		return
	}
	var configResp struct {
		Config string `json:"config"`
	}
	if json.Unmarshal(xrayResp, &configResp) != nil {
		return
	}
	var xrayConfig map[string]any
	if json.Unmarshal([]byte(configResp.Config), &xrayConfig) != nil {
		return
	}

	for _, domain := range domains {
		h.addWebsiteTunnelConfig(xrayConfig, domain)
	}

	updatedConfig, _ := json.MarshalIndent(xrayConfig, "", "    ")
	configPayload, _ := json.Marshal(map[string]string{"config": string(updatedConfig)})
	if _, err := h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/xray/config", configPayload); err != nil {
		log.Printf("[HandleInbounds] Failed to restore domains %v to tunnel route: %v", domains, err)
		return
	}
	if err := h.restartXrayWithRecovery(ctx, serverID, "RealityRouteRestore"); err != nil {
		log.Printf("[HandleInbounds] %v", err)
	}
	log.Printf("[HandleInbounds] Restored reality serverNames %v to tunnel-in→nginx route on server %d", domains, serverID)
}

func (h *RemoteManageHandler) addWebsiteFallbackConfig(config map[string]any, domain string) {
	inbounds, _ := config["inbounds"].([]any)
	for _, inb := range inbounds {
		ib, _ := inb.(map[string]any)
		if ib == nil {
			continue
		}
		settings, _ := ib["settings"].(map[string]any)
		if settings == nil {
			continue
		}
		realitySettings, _ := settings["realitySettings"].(map[string]any)
		if realitySettings == nil {
			continue
		}
		serverNames, _ := realitySettings["serverNames"].([]any)
		for _, sn := range serverNames {
			if s, _ := sn.(string); s == domain {
				return
			}
		}
		realitySettings["serverNames"] = append(serverNames, domain)
		return
	}
}

func (h *RemoteManageHandler) HandleUserSpeeds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	serverID, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil || serverID <= 0 {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid server_id"})
		return
	}

	speeds := h.wsHandler.GetUserSpeeds(serverID)
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "user_speeds": speeds})
}

func toURLSafeBase64(s string) string {
	replacer := strings.NewReplacer("+", "-", "/", "_")
	return strings.TrimRight(replacer.Replace(s), "=")
}
