package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"miaomiaowux/internal/license"
	"miaomiaowux/internal/storage"
)

type LicenseHandler struct {
	repo    *storage.TrafficRepository
	manager *license.Manager
}

func NewLicenseHandler(repo *storage.TrafficRepository, mgr *license.Manager) *LicenseHandler {
	return &LicenseHandler{repo: repo, manager: mgr}
}

func (h *LicenseHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	status := h.manager.GetStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"license": status,
	})
}

func (h *LicenseHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	key, _ := h.repo.GetSystemSetting(r.Context(), "license_key")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":     true,
		"license_key": key,
	})
}

func (h *LicenseHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LicenseKey string `json:"license_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}

	ctx := r.Context()
	if req.LicenseKey != "" {
		_ = h.repo.SetSystemSetting(ctx, "license_key", req.LicenseKey)
	}

	h.manager.Refresh(ctx)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (h *LicenseHandler) UserGetStatus(w http.ResponseWriter, r *http.Request) {
	status := h.manager.GetStatus()
	resp := map[string]any{
		"success":       true,
		"valid":         status.Valid,
		"premium_theme": h.manager.CanUsePremiumTheme(),
	}
	if status.Plan != nil {
		resp["plan"] = map[string]any{
			"name":         status.Plan.Name,
			"display_name": status.Plan.DisplayName,
			"description":  status.Plan.Description,
			"max_servers":  status.Plan.MaxServers,
			"max_nodes":    status.Plan.MaxNodes,
			"max_users":    status.Plan.MaxUsers,
			"features":     status.Plan.Features,
		}
	}
	if status.ExpiresAt != "" {
		resp["expires_at"] = status.ExpiresAt
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// licenseUserQuotaExceeded 判断「再建一个用户」是否会超出许可证的用户数配额。
// 返回面向用户的提示语和是否超限;lm 为 nil(未接许可证)时一律放行。
//
// **每一条创建普通用户的路径都必须先过这里** —— 目前是管理员建号(users.go)和
// Telegram 邀请码注册(tgbot_admin.go)。TG 注册曾经完全绕过配额检查,
// 因为它是另一条 handler 链路,加限额时漏掉了;抽成函数就是为了下次新增入口时不再漏。
//
// 口径与面板展示、上报 license 服务器一致:CountLicensedUsers = 启用中的非管理员。
func licenseUserQuotaExceeded(ctx context.Context, repo *storage.TrafficRepository, lm *license.Manager) (string, bool) {
	if lm == nil || repo == nil {
		return "", false
	}
	maxUsers := 10
	if status := lm.GetStatus(); status.Plan != nil {
		maxUsers = status.Plan.MaxUsers
	}
	count, err := repo.CountLicensedUsers(ctx)
	if err != nil {
		// 统计失败不阻断创建 —— 宁可漏挡一次,也不因为一次 DB 抖动把注册整个卡死。
		return "", false
	}
	if count >= maxUsers {
		return fmt.Sprintf("已达到用户数量上限 (%d/%d)，请升级许可证", count, maxUsers), true
	}
	return "", false
}

func (h *LicenseHandler) GetUsage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	status := h.manager.GetStatus()

	serverCount, _ := h.repo.CountRemoteServers(ctx)
	// 跟实际限制点(routed_outbound.go)一致 — 只计 admin 平台创建的 routed 出站节点。
	// 用户手动导入 / 外部订阅 / 用户私有路由出站都不计 license 配额。
	nodeCount, _ := h.repo.CountLicensedNodes(ctx)
	// 与上报 license 服务器、创建用户限额同一口径(启用中的非管理员),
	// 否则面板显示的 current 会比许可证后台大,且和实际能创建的数量对不上。
	userCount, _ := h.repo.CountLicensedUsers(ctx)

	maxServers, maxNodes, maxUsers := 5, 20, 10
	if status.Plan != nil {
		maxServers = status.Plan.MaxServers
		maxNodes = status.Plan.MaxNodes
		maxUsers = status.Plan.MaxUsers
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"usage": map[string]any{
			"servers": map[string]any{"current": serverCount, "max": maxServers},
			"nodes":   map[string]any{"current": nodeCount, "max": maxNodes},
			"users":   map[string]any{"current": userCount, "max": maxUsers},
		},
	})
}

// 许可证称号的展示位开关。每个位置独立,默认值见 defaultLicenseBadgeDisplay。
//
// 探针页两个位置默认**关闭**:那是对外的伪装页面,挂上「妙妙屋X 许可证称号」
// 等于自曝身份,伪装就白做了 —— 要开由管理员自己权衡。
const LicenseBadgeDisplayKey = "license_badge_display"

// 合法位置。前端传 pos 时必须命中其一,否则一律不返回名字。
var licenseBadgePositions = []string{"login", "about", "probe_login", "probe_footer", "probe_header"}

func defaultLicenseBadgeDisplay() map[string]bool {
	return map[string]bool{
		"login":        true,
		"about":        true,
		"probe_login":  false, // 伪装页,默认不暴露
		"probe_footer": false, // 同上
		"probe_header": false, // 探针页标题后方,同为伪装页,默认关闭
	}
}

// loadLicenseBadgeDisplay 读开关,缺失的位置用默认值补齐(新增位置时老配置不会漏键)。
func loadLicenseBadgeDisplay(ctx context.Context, repo *storage.TrafficRepository) map[string]bool {
	out := defaultLicenseBadgeDisplay()
	if repo == nil {
		return out
	}
	raw, _ := repo.GetSystemSetting(ctx, LicenseBadgeDisplayKey)
	if strings.TrimSpace(raw) == "" {
		return out
	}
	var stored map[string]bool
	if json.Unmarshal([]byte(raw), &stored) != nil {
		return out
	}
	for _, p := range licenseBadgePositions {
		if v, ok := stored[p]; ok {
			out[p] = v
		}
	}
	return out
}

// NewLicenseBadgePublicHandler GET /api/public/license-badge[?pos=login]
//
// **免鉴权**,所以只暴露 name / display_name / valid —— 刻意不含配额、features、
// 到期时间、许可证 key:登录页和伪装探针页是任何人都能打开的,多一个字段就多一分暴露面。
//
// 两种用法:
//   - 带 pos:该位置开关**打开**时才返回名字,关闭则只回 valid:false —— 把授权判断放在
//     服务端,而不是"先发下去再让前端决定显不显示"(那样关了开关也能从网络面板看到)。
//   - 不带 pos:只返回各位置开关状态,不含任何名字。供已登录页面(关于弹窗)取开关用。
func NewLicenseBadgePublicHandler(repo *storage.TrafficRepository, mgr *license.Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		show := loadLicenseBadgeDisplay(r.Context(), repo)
		w.Header().Set("Content-Type", "application/json")

		pos := strings.TrimSpace(r.URL.Query().Get("pos"))
		if pos == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"show": show})
			return
		}
		resp := map[string]any{"valid": false}
		if show[pos] && mgr != nil {
			st := mgr.GetStatus()
			if st.Plan != nil {
				resp["name"] = st.Plan.Name
				resp["display_name"] = st.Plan.DisplayName
			}
			resp["valid"] = st.Valid
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// NewLicenseBadgeDisplayHandler GET/PUT /api/admin/system-settings/license-badge —— 读写展示位开关。
func NewLicenseBadgeDisplayHandler(repo *storage.TrafficRepository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			respondJSON(w, http.StatusOK, map[string]any{"success": true, "show": loadLicenseBadgeDisplay(r.Context(), repo)})
		case http.MethodPut:
			var req struct {
				Show map[string]bool `json:"show"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeBadRequest(w, "请求格式不正确")
				return
			}
			cur := loadLicenseBadgeDisplay(r.Context(), repo)
			// 只认已知位置,忽略请求里的任何多余键
			for _, p := range licenseBadgePositions {
				if v, ok := req.Show[p]; ok {
					cur[p] = v
				}
			}
			b, _ := json.Marshal(cur)
			if err := repo.SetSystemSetting(r.Context(), LicenseBadgeDisplayKey, string(b)); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			respondJSON(w, http.StatusOK, map[string]any{"success": true, "show": cur})
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodPut)
		}
	})
}
