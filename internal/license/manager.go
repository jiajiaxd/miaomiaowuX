package license

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"miaomiaowux/internal/version"
	"net/http"
	"strings"
	"sync"
	"time"
)

type PlanInfo struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Description string   `json:"description,omitempty"`
	MaxServers  int      `json:"max_servers"`
	MaxNodes    int      `json:"max_nodes"`
	MaxUsers    int      `json:"max_users"`
	Features    []string `json:"features"`
	// FeatureTokens 每个 feature 单独的 ed25519 签名 token,由 license server 签发。
	// Manager.HasFeature 用对应 token + VerifyFeatureToken 校验,fork 主控的人改 Features 数组也无效。
	// 老 license server 不返回此字段时 → 所有 PRO feature 都不可用(强制升级 license server)。
	FeatureTokens map[string]string `json:"feature_tokens,omitempty"`
}

type Status struct {
	Valid      bool      `json:"valid"`
	Error      string    `json:"error,omitempty"`
	MaxServers int       `json:"max_servers"`
	ExpiresAt  string    `json:"expires_at,omitempty"`
	Plan       *PlanInfo `json:"plan,omitempty"`
	LastCheck  time.Time `json:"last_check"`

	// HardRevoked 为 true 表示 license 服务器明确返回了"无效"(unbind / revoked / expired / wrong machine_id),
	// 跟"网络故障导致没拿到响应"区分开。IsValid() 在 HardRevoked=true 时直接 return false,
	// 不再走 24h grace period;反之网络故障下保留 grace,容忍短暂中断。
	HardRevoked bool `json:"hard_revoked,omitempty"`
}

// Status.HasFeature 已废弃 — Status 没有 license key / machine_id,无法验签。
// 调用方应使用 Manager.HasFeature(name)。本函数保留只为不破坏外部依赖,**永远返回 false**。
// 这是有意为之:fork 主控的人如果只看 Status.Features 数组绕过 Manager.HasFeature,得到的是 false。
func (s *Status) HasFeature(_ string) bool {
	return false
}

var defaultStatus = Status{
	Valid:      true,
	MaxServers: 1,
	Plan: &PlanInfo{
		Name:        "TRIAL",
		DisplayName: "试用版",
		MaxServers:  1,
		MaxNodes:    5,
		MaxUsers:    3,
		Features:    nil,
	},
}

// SettingsGetter is kept for backward compatibility.
type SettingsGetter interface {
	GetSystemSetting(ctx context.Context, key string) (string, error)
}

// SettingsStore extends SettingsGetter with write capability.
type SettingsStore interface {
	GetSystemSetting(ctx context.Context, key string) (string, error)
	SetSystemSetting(ctx context.Context, key, value string) error
}

// UsageReporter 让 manager 在心跳时取本机当前 license 占用数。
// 通常用 *storage.TrafficRepository 实现(已在 storage.LicenseUsage 提供)。
// 实现可以返回 err 表示采集失败,heartbeat 会跳过 usage 字段不影响验签。
type UsageReporter interface {
	LicenseUsage(ctx context.Context) (servers, nodes, users int, err error)
}

type Manager struct {
	mu                sync.RWMutex
	status            Status
	serverURL         string
	key               string
	machineID         string
	settings          SettingsStore
	usage             UsageReporter
	client            *http.Client
	cancel            context.CancelFunc
	exchangeMu        sync.RWMutex
	exchangeRates     map[string]float64
	exchangeFetchedAt time.Time
	// onRecover 在 license 从 invalid→valid 恢复时异步触发(如重推 limiter — 失效期被 gate 漏下发的补上)。
	onRecover func()
	// onQuotaChange 在「有效服务器配额」变化(valid 翻转或 Plan.MaxServers 变化)时异步触发,
	// 由 handler 注册为「重算 per-server 授权并下发给在线 agent」。
	onQuotaChange func()
	// onFeatureLost 在某个 PRO 特性由「有」变「无」时异步触发,参数是丢失的特性名。
	//
	// 与 onRecover 成对存在,补的是**降级方向**:此前只有「失效→恢复时补推」,
	// 没有「有效→失效时撤销」。而 agent 侧的限速是纯内存态,主控不推新配置 ≠ 限速消失 ——
	// 降级后 agent 上那份 PRO 时期的限速配置会一直生效到进程重启。
	onFeatureLost func(feature string)
	// onStatusChecked 在许可证服务器返回并通过协议校验后触发。它与状态是否发生变化无关，
	// 用于周期性纠正直接修改数据库绕过许可证门控的本地配置。
	onStatusChecked func()
}

// watchedFeatures 是需要在丢失时通知 handler 主动撤销已下发配置的特性。
//
// 只列「已经推到 agent、且 agent 会一直沿用」的能力。像 speed_test 这种每次都由主控
// 现场发起的,不推就没有,不需要撤销。
var watchedFeatures = []string{"limiter"}

// SetOnRecover 注册 license 从失效恢复为有效时的回调(例如重推 limiter 配置)。启动前调一次。
func (m *Manager) SetOnRecover(cb func()) {
	m.mu.Lock()
	m.onRecover = cb
	m.mu.Unlock()
}

// SetOnQuotaChange 注册「有效服务器配额变化」时的回调(重算并下发 per-server xray 授权)。启动前调一次。
func (m *Manager) SetOnQuotaChange(cb func()) {
	m.mu.Lock()
	m.onQuotaChange = cb
	m.mu.Unlock()
}

// SetOnFeatureLost 注册「PRO 特性丢失」回调(例如降级后撤销已下发到 agent 的限速)。启动前调一次。
func (m *Manager) SetOnFeatureLost(cb func(feature string)) {
	m.mu.Lock()
	m.onFeatureLost = cb
	m.mu.Unlock()
}

// SetOnStatusChecked 注册每次有效许可证响应处理完成后的回调。
func (m *Manager) SetOnStatusChecked(cb func()) {
	m.mu.Lock()
	m.onStatusChecked = cb
	m.mu.Unlock()
}

// snapshotWatchedFeatures 记录当前 watchedFeatures 的持有状态,用于前后比对。
// 必须在持锁之外调用 —— HasFeature 内部会取读锁。
func (m *Manager) snapshotWatchedFeatures() map[string]bool {
	out := make(map[string]bool, len(watchedFeatures))
	for _, f := range watchedFeatures {
		out[f] = m.HasFeature(f)
	}
	return out
}

// SetUsageReporter 注入 usage 来源,启动前调一次。nil 时 heartbeat payload 不带 used_* 字段。
func (m *Manager) SetUsageReporter(r UsageReporter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.usage = r
}

const DefaultServerURL = "https://license.miaomiaowux.com"

func NewManager(settings SettingsStore, machineID string) *Manager {
	return &Manager{
		status:    defaultStatus,
		serverURL: DefaultServerURL,
		machineID: machineID,
		settings:  settings,
		client:    &http.Client{Timeout: 15 * time.Second},
	}
}

func (m *Manager) Start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)

	m.loadSettings(ctx)
	m.loadPersistedStatus(ctx)

	if m.key != "" && m.serverURL != "" {
		m.activate(ctx)
	}

	go m.heartbeatLoop(ctx)
}

func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
}

func (m *Manager) GetStatus() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *Manager) IsValid() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isValidLocked()
}

// FeaturePremiumTheme 只由许可证服务为真实付费许可证签发。
const FeaturePremiumTheme = "premium_theme"

// CanUsePremiumTheme 使用 per-feature Ed25519 token 判断 Premium 主题资格。
// 不能退化成套餐名判断：免费许可证同样可能拥有非 TRIAL 套餐。
func (m *Manager) CanUsePremiumTheme() bool {
	return m.HasFeature(FeaturePremiumTheme)
}

// isValidLocked 是 IsValid 的无锁版,调用方须持有 m.mu(R 或 W)。
func (m *Manager) isValidLocked() bool {
	if m.status.HardRevoked {
		// 服务器明确否决 → 立即失效,不进 grace。
		return false
	}
	if !m.status.Valid {
		// valid=false 但不是 HardRevoked → 通常是网络故障 / 启动期未 activate,允许 grace。
		return m.withinGracePeriod()
	}
	return true
}

// QuotaEnforced 仅在「配置了 license key」时为 true。
// 无 key 的开源自建主控走 defaultStatus(MaxServers=1),不能拿它当配额执行——否则会把自建砍到只剩 1 台。
func (m *Manager) QuotaEnforced() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.key != ""
}

// EffectiveServerQuota 返回当前生效的服务器配额:有效且有 Plan → Plan.MaxServers,否则 0。
// 走 isValidLocked(含 24h grace / HardRevoked),天然继承 429/网络故障容错——临时拿不到 license 不会误判配额变少。
func (m *Manager) EffectiveServerQuota() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.isValidLocked() || m.status.Plan == nil {
		return 0
	}
	return m.status.Plan.MaxServers
}

// HasFeature 校验当前 license 是否启用某 PRO feature。
// 不仅看名称在 Features 列表(可被 fork 主控伪造),还要用 license server 签发的
// per-feature ed25519 token 验签 → 没私钥就签不出有效 token。
// IsValid 失败 / 没 FeatureTokens / token 验签失败 → 一律 false (fail-closed)。
func (m *Manager) HasFeature(name string) bool {
	if !m.IsValid() {
		return false
	}
	m.mu.RLock()
	plan := m.status.Plan
	expiresAt := m.status.ExpiresAt
	licenseKey := m.key
	machineID := m.machineID
	m.mu.RUnlock()

	if plan == nil || plan.FeatureTokens == nil {
		return false
	}
	tokenB64, ok := plan.FeatureTokens[name]
	if !ok || tokenB64 == "" {
		return false
	}
	return VerifyFeatureToken(licenseKey, machineID, name, expiresAt, tokenB64)
}

func (m *Manager) Refresh(ctx context.Context) {
	m.loadSettings(ctx)
	if m.key != "" && m.serverURL != "" {
		m.activate(ctx)
	}
}

func (m *Manager) withinGracePeriod() bool {
	if m.status.LastCheck.IsZero() {
		return true
	}
	return time.Since(m.status.LastCheck) < 24*time.Hour
}

func (m *Manager) loadSettings(ctx context.Context) {
	if m.settings == nil {
		return
	}
	if key, err := m.settings.GetSystemSetting(ctx, "license_key"); err == nil && key != "" {
		m.key = key
	}
	// 可选 override:不写则用 DefaultServerURL。
	// 测试环境用:在 system_settings 表写 license_server_url=https://iloli.vip:2233
	if url, err := m.settings.GetSystemSetting(ctx, "license_server_url"); err == nil && url != "" {
		m.serverURL = url
	}
}

func (m *Manager) loadPersistedStatus(ctx context.Context) {
	if m.settings == nil {
		return
	}
	raw, err := m.settings.GetSystemSetting(ctx, "license_status")
	if err != nil || raw == "" {
		return
	}
	var status Status
	if err := json.Unmarshal([]byte(raw), &status); err != nil {
		log.Printf("[license] failed to load persisted status: %v", err)
		return
	}
	// 不信任持久化的 HardRevoked:硬吊销是「服务端明确否决」的实时状态,重启后必须
	// 重新向服务端确认,而不是拿旧值当真 —— 否则历史上因机器码变化 / 服务端抖动误置的
	// HardRevoked 会跨重启一直停服,永远无法自愈。清成 false 后先走 grace(LastCheck 保留),
	// 由启动后的 activate/heartbeat 重新判定:真吊销会秒级重新置位,可恢复的则自动重绑。
	status.HardRevoked = false
	m.mu.Lock()
	m.status = status
	m.mu.Unlock()
	log.Printf("[license] restored status from database: valid=%v plan=%s", status.Valid, status.Plan.Name)
}

func (m *Manager) persistStatus(ctx context.Context) {
	if m.settings == nil {
		return
	}
	m.mu.RLock()
	data, err := json.Marshal(m.status)
	m.mu.RUnlock()
	if err != nil {
		return
	}
	if err := m.settings.SetSystemSetting(ctx, "license_status", string(data)); err != nil {
		log.Printf("[license] failed to persist status: %v", err)
	}
}

func (m *Manager) activate(ctx context.Context) {
	nonce := genNonce()
	body, _ := json.Marshal(map[string]string{
		"key":         m.key,
		"machine_id":  m.machineID,
		"nonce":       nonce,
		"app_version": version.Version,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.serverURL+"/api/v1/activate", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		log.Printf("[license] activate failed: %v", err)
		return
	}
	defer resp.Body.Close()

	m.parseResponse(ctx, resp, nonce)
}

func (m *Manager) heartbeat(ctx context.Context) {
	if m.key == "" || m.serverURL == "" {
		return
	}

	// 带上本机当前 usage,license server 用来在面板上展示 + 兜底比对配额。
	// 采集失败(repo 错)不影响心跳本身,只是这次不传 used_* 字段。
	nonce := genNonce()
	payload := map[string]any{
		"key":         m.key,
		"machine_id":  m.machineID,
		"nonce":       nonce,
		"app_version": version.Version,
		"client_fp":   collectFingerprint(),
	}
	m.mu.RLock()
	usage := m.usage
	m.mu.RUnlock()
	if usage != nil {
		if s, n, u, err := usage.LicenseUsage(ctx); err == nil {
			payload["used_servers"] = s
			payload["used_nodes"] = n
			payload["used_users"] = u
		} else {
			log.Printf("[license] usage report skipped: %v", err)
		}
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.serverURL+"/api/v1/heartbeat", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		// 网络故障 → 静默,IsValid 走 grace 容忍。LastCheck 不更新避免 grace 永远续命。
		log.Printf("[license] heartbeat network error: %v (grace period in effect)", err)
		return
	}
	defer resp.Body.Close()

	if m.parseResponse(ctx, resp, nonce) {
		// 机器码变化 / 解绑后未重绑 → 心跳循环本身不会重绑,主动发起一次 activate 自愈。
		// activate 内部同样走 parseResponse,但不理会其 needReactivate 返回值,故无递归风暴。
		go m.activate(ctx)
	}
}

func (m *Manager) parseResponse(ctx context.Context, resp *http.Response, nonce string) (needReactivate bool) {
	// 非 2xx(尤其 429 限流 / 5xx / 502 等)是"临时故障",不是"服务器明确否决"。
	// 直接 return:不更新 status、不 HardRevoked,交给 IsValid 的 24h grace 容忍。
	// 否则 license 服务器一抖动(限流/重启/网关波动)就会把本机 PRO 功能全灭。
	// 真正的"许可证无效"(unbind/revoked/wrong machine_id)license 服务器一律用 200 + valid:false 返回,
	// 会正常走到下面的 HardRevoked 分支,不受此拦截影响。
	if resp.StatusCode != http.StatusOK {
		log.Printf("[license] non-200 from server: %d (treated as transient, grace in effect)", resp.StatusCode)
		return
	}
	var result struct {
		Valid      bool            `json:"valid"`
		Error      string          `json:"error,omitempty"`
		MaxServers int             `json:"max_servers"`
		ExpiresAt  string          `json:"expires_at,omitempty"`
		Plan       json.RawMessage `json:"plan,omitempty"`
		Sig        string          `json:"sig,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("[license] parse response error: %v", err)
		return
	}

	// 解析 plan + features(同时用于验签和写入 status)。
	var plan PlanInfo
	var hasPlan bool
	if result.Valid && result.Plan != nil {
		if err := json.Unmarshal(result.Plan, &plan); err == nil {
			if plan.Features == nil {
				var raw struct {
					Features json.RawMessage `json:"features"`
				}
				_ = json.Unmarshal(result.Plan, &raw)
				if raw.Features != nil {
					_ = json.Unmarshal(raw.Features, &plan.Features)
				}
			}
			hasPlan = true
		}
	}

	// valid=true 的响应必须通过 ed25519 签名校验,否则视为"未拿到有效响应":
	// 不更新 status(保留上一次的合法状态 + 走 grace),从而假许可证服务/MITM 无法把 TRIAL 提权成 PRO。
	if result.Valid {
		if !verifyLicenseSig(nonce, m.machineID, true, result.MaxServers, result.ExpiresAt, plan.Features, result.Sig) {
			log.Printf("[license] response signature verification FAILED — ignoring response (possible forged license server / MITM)")
			return
		}
	}

	// 记录变更前是否有效,用于 invalid→valid 恢复回调(重推 limiter 等)。
	wasValid := m.IsValid()
	// 记录变更前的有效配额,用于「配额变化 → 重算下发 per-server 授权」回调。
	oldQuota := m.EffectiveServerQuota()
	oldFeatures := m.snapshotWatchedFeatures()

	m.mu.Lock()

	m.status.Valid = result.Valid
	m.status.Error = result.Error

	if result.Valid {
		// 服务器明确"有效"且验签通过 → 清除 HardRevoked(用于解绑后续绑生效场景),
		// 并刷新 grace 基准时间 LastCheck(只有"确认有效"才续 grace)。
		m.status.HardRevoked = false
		m.status.LastCheck = time.Now()
		m.status.MaxServers = result.MaxServers
		m.status.ExpiresAt = result.ExpiresAt
		if hasPlan {
			m.status.Plan = &plan
		}
	} else if isRebindableError(result.Error) {
		// 「绑定层面」可恢复失效:机器码变化(machine mismatch)或解绑后未重绑
		// (license not activated)。不同于过期/吊销 —— 重新 activate 一次即可恢复
		// (覆盖激活开时服务端自动换绑)。因此不置 HardRevoked、保留 24h grace 不立即停服,
		// 并置 needReactivate 让心跳侧异步发起一次 activate 自愈重绑。
		//
		// 关键:这里**不刷新 LastCheck**。grace 自最后一次 valid=true 起真实倒计时,
		// 24h 内仍重绑不上(如覆盖激活关且机器码永久变了)→ grace 到期自然停服,
		// 覆盖激活关时的防盗用边界得以保留,不会因每 5 分钟心跳把 grace 无限续命。
		m.status.HardRevoked = false
		needReactivate = true
		log.Printf("[license] rebindable invalid (%s) — keeping grace, will re-activate", result.Error)
	} else {
		// 真正失效:过期 / 吊销 / 无效 key → 立即硬吊销,不走 24h grace。
		m.status.HardRevoked = true
		log.Printf("[license] HARD REVOKED by server: %s", result.Error)
	}

	cb := m.onRecover
	quotaCb := m.onQuotaChange
	lostCb := m.onFeatureLost
	checkedCb := m.onStatusChecked
	m.mu.Unlock()

	m.persistStatus(ctx)

	// invalid→valid 恢复:主动触发回调(重推 limiter 等 — 失效期被 license gate 漏下发的配置补上,
	// 否则限速要等 agent 下次重连/用户改配置才恢复)。
	if result.Valid && !wasValid && cb != nil {
		go cb()
	}

	// 有效配额变化(valid 翻转或 Plan.MaxServers 变化)→ 重算并下发 per-server xray 授权。
	if quotaCb != nil && m.EffectiveServerQuota() != oldQuota {
		go quotaCb()
	}

	// PRO 特性由「有」变「无」(降级 / 到期 / 解绑)→ 通知 handler 撤销已下发到 agent 的配置。
	// 光靠"不再推新配置"是不够的:agent 侧限速是内存态,不撤销就会一直沿用旧值。
	if lostCb != nil {
		for _, f := range watchedFeatures {
			if oldFeatures[f] && !m.HasFeature(f) {
				log.Printf("[license] feature %q lost, revoking pushed config", f)
				go lostCb(f)
			}
		}
	}
	if checkedCb != nil {
		go checkedCb()
	}
	return needReactivate
}

// isRebindableError 判断服务端 valid=false 的 error 是否属于「重新激活即可恢复的绑定问题」:
//   - "machine mismatch"      机器码变了(Docker 卷/迁移/重装),覆盖激活开时 activate 会自动换绑
//   - "license not activated" 被解绑后尚未重绑,activate 会重新占用该 key
//
// 这两类不该按硬吊销立即停服,而应保留 grace 并自动重激活。其余(过期/吊销/无效 key)返回 false,
// 仍走硬吊销。字符串与 license 服务端 validate.go 的返回值一一对应。
func isRebindableError(msg string) bool {
	switch strings.ToLower(strings.TrimSpace(msg)) {
	case "machine mismatch", "license not activated":
		return true
	default:
		return false
	}
}

func (m *Manager) heartbeatLoop(ctx context.Context) {
	m.loadSettings(ctx)

	// 启动后立即先跑一次心跳,把 used_* 数据 + 当前激活状态推上去,
	// 避免之前 "first heartbeat 要等 30 分钟" 的尴尬。
	m.heartbeat(ctx)

	// 之前 30 分钟太长,解绑生效慢。5 分钟兼顾"unbind 快速生效"和"心跳负担"。
	// 进一步缩到 1 分钟需要 license server 加版本号协议(见 B 方案),当前 5 分钟够用。
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.loadSettings(ctx)
			m.heartbeat(ctx)
		}
	}
}

func (m *Manager) StatusForAgent() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := map[string]any{
		"valid":       m.status.Valid || m.withinGracePeriod(),
		"max_servers": m.status.MaxServers,
	}
	if m.status.ExpiresAt != "" {
		result["expires_at"] = m.status.ExpiresAt
	}
	if m.status.Plan != nil {
		result["plan"] = map[string]any{
			"name":         m.status.Plan.Name,
			"display_name": m.status.Plan.DisplayName,
			"description":  m.status.Plan.Description,
			"max_servers":  m.status.Plan.MaxServers,
			"max_nodes":    m.status.Plan.MaxNodes,
			"max_users":    m.status.Plan.MaxUsers,
			"features":     m.status.Plan.Features,
		}
	}
	return result
}

func GetMachineID() string {
	return persistentMachineID()
}
