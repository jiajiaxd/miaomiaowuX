package handler

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/license"
	"miaomiaowux/internal/storage"
)

type userEntry struct {
	Username            string   `json:"username"`
	Email               string   `json:"email"`
	Nickname            string   `json:"nickname"`
	Avatar              string   `json:"avatar_url"`
	Role                string   `json:"role"`
	IsActive            bool     `json:"is_active"`
	Remark              string   `json:"remark"`
	PackageID           *int64   `json:"package_id"`
	PackageName         string   `json:"package_name,omitempty"`
	TrafficLimitGB      float64  `json:"traffic_limit_gb,omitempty"`
	TrafficUsed         int64    `json:"traffic_used,omitempty"`
	TrafficLimit        int64    `json:"traffic_limit,omitempty"`
	TrafficMultiplier   int64    `json:"traffic_multiplier,omitempty"` // 套餐流量倍率(oneway=1/twoway=2),供首页按用户流量列表换算计费流量
	IsOverLimit         bool     `json:"is_over_limit"`
	IsReset             bool     `json:"is_reset"`
	ResetDay            int      `json:"reset_day"`
	PackageEndDate      *string  `json:"package_end_date,omitempty"`
	SpeedLimitMbps      float64  `json:"speed_limit_mbps"`
	DeviceLimit         int      `json:"device_limit"`
	SpeedLimitOverride  *float64 `json:"speed_limit_override"`
	DeviceLimitOverride *int     `json:"device_limit_override"`
	// 用户级流量上限覆写(GB)。指针必需:0(显式不限流量)与 null(继承套餐)语义不同。
	// 注意 TrafficLimitGB/TrafficLimit 给的是**有效值**(已含覆写),这个字段只供弹窗回填 + 标记"已覆写"。
	TrafficLimitOverrideGB   *float64          `json:"traffic_limit_override_gb"`
	NodeSpeedLimitOverrides  map[int64]float64 `json:"node_speed_limit_overrides,omitempty"`
	NodeDeviceLimitOverrides map[int64]int     `json:"node_device_limit_overrides,omitempty"`
	// 短码:user_short_code 是系统自动生成的;custom_user_short_code 非空时优先生效。
	// 前端用 user_short_code 显示"当前生效",custom_user_short_code 作为编辑输入框的回填值。
	UserShortCode       string `json:"user_short_code"`
	CustomUserShortCode string `json:"custom_user_short_code"`
	// TG 绑定信息:让直接添加、事后绑 TG 的用户也能在用户管理里看出对应哪个 Telegram 账号。
	// 0 / 空 = 未绑定。
	TelegramID       int64  `json:"telegram_id,omitempty"`
	TelegramUsername string `json:"telegram_username,omitempty"`
}

type userStatusRequest struct {
	Username string `json:"username"`
	IsActive bool   `json:"is_active"`
}

type userResetRequest struct {
	Username    string `json:"username"`
	NewPassword string `json:"new_password"`
}

type userResetResponse struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type userCreateRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Nickname string `json:"nickname"`
	Password string `json:"password"`
	Remark   string `json:"remark"`
}

type userCreateResponse struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Nickname string `json:"nickname"`
	Role     string `json:"role"`
	Password string `json:"password"`
}

func NewUserListHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("user list handler requires repository")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		users, err := repo.ListUsers(r.Context(), 1000)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		pkgMap := make(map[int64]storage.Package)
		packages, _ := repo.ListPackages(r.Context())
		for _, p := range packages {
			pkgMap[p.ID] = p
		}

		// 计费流量:倍率已由 collector 在采集时折算,拿到即最终值。批量版避免 N+1。
		trafficMap, _ := repo.GetAllUserBillableTraffic(r.Context())

		// 一次性查所有用户短码,避免列表循环里逐个 query(N+1)。
		shortCodeMap, _ := repo.ListUserShortCodeInfo(r.Context())

		// 一次性查所有用户的 TG 绑定,供列表展示(避免 N+1)。
		tgMap, _ := repo.ListUserTelegramBindings(r.Context())

		entries := make([]userEntry, 0, len(users))
		for _, user := range users {
			scInfo := shortCodeMap[user.Username]
			entry := userEntry{
				Username:            user.Username,
				Email:               user.Email,
				Nickname:            user.Nickname,
				Avatar:              user.AvatarURL,
				Role:                user.Role,
				IsActive:            user.IsActive,
				Remark:              user.Remark,
				UserShortCode:       scInfo.UserShortCode,
				CustomUserShortCode: scInfo.CustomUserShortCode,
			}
			if tg, ok := tgMap[user.Username]; ok {
				entry.TelegramID = tg.TelegramID
				entry.TelegramUsername = tg.TelegramUsername
			}
			entry.SpeedLimitOverride = user.SpeedLimitOverride
			entry.DeviceLimitOverride = user.DeviceLimitOverride
			entry.NodeSpeedLimitOverrides = user.NodeSpeedLimitOverrides
			entry.NodeDeviceLimitOverrides = user.NodeDeviceLimitOverrides
			if user.PackageID > 0 {
				pid := user.PackageID
				entry.PackageID = &pid
				var pkgPtr *storage.Package
				if pkg, ok := pkgMap[pid]; ok {
					pkgPtr = &pkg
					entry.PackageName = pkg.Name
					entry.SpeedLimitMbps = pkg.SpeedLimitMbps
					entry.DeviceLimit = pkg.DeviceLimit
				}
				// TrafficLimit/TrafficLimitGB 给的是**有效值**(用户覆写 ?? 套餐),前端流量条直接用,
				// 全量视图与套餐视图两处进度条因此无需各自解析优先级。
				limitBytes := resolveTrafficLimitBytes(&user, pkgPtr)
				entry.TrafficLimit = limitBytes
				entry.TrafficLimitGB = float64(limitBytes) / (1024 * 1024 * 1024)
				// 原始覆写值单独给出:供弹窗回填 + 前端标记"已覆写"。
				if user.TrafficLimitOverride != nil {
					gb := float64(*user.TrafficLimitOverride) / (1024 * 1024 * 1024)
					entry.TrafficLimitOverrideGB = &gb
				}
				// TrafficUsed 已是计费流量(采集时折算),不再乘倍率。
				// traffic_multiplier 仍吐给前端,但只作展示标注(首页按用户流量列表用它标"×2")。
				if pkg, ok := pkgMap[pid]; ok {
					entry.TrafficMultiplier = pkg.TrafficMultiplier()
				}
				entry.TrafficUsed = trafficMap[user.Username]
				if entry.TrafficLimit > 0 && entry.TrafficUsed >= entry.TrafficLimit {
					entry.IsOverLimit = true
				}
				entry.IsReset = user.IsReset
				entry.ResetDay = user.ResetDay
				if user.PackageEndDate != nil {
					s := user.PackageEndDate.Format("2006-01-02")
					entry.PackageEndDate = &s
				}
			}
			entries = append(entries, entry)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"users": entries})
	})
}

// NewUserStatusHandler 切换 user.is_active。
//
// 禁用 (is_active=false):
//   - 把 users.is_active 设为 0
//   - 遍历 user_inbound_configs,从每个节点的 xray inbound 移除该用户的 client (uuid/password 还在 DB 里)
//   - 推 limiter 给 agent,让 agent limiter UserInfo 里也移除
//
// 启用 (is_active=true):
//   - 把 users.is_active 设为 1
//   - 遍历 user_inbound_configs,用 saved credential_json 调 addUserToInbound 把 client 加回 xray
//     (addUserToInbound 已实现"复用已保存凭据",见 packages.go:775)
//   - 推 limiter
//
// 跟 user delete 路径区别:本接口 **保留** user_inbound_configs 行 (credential 留着),
// 启用时能精确还原原 uuid/password,客户端订阅无需重新生成。
func NewUserStatusHandler(repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher, tokens *auth.TokenStore) http.Handler {
	if repo == nil {
		panic("user status handler requires repository")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}

		var payload userStatusRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		username := strings.TrimSpace(payload.Username)
		if username == "" {
			writeError(w, http.StatusBadRequest, errors.New("username is required"))
			return
		}

		ctx := r.Context()

		// 检查目标用户是否是admin
		targetUser, err := repo.GetUser(ctx, username)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				writeError(w, http.StatusNotFound, errors.New("user not found"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		if targetUser.Role == storage.RoleAdmin {
			writeError(w, http.StatusBadRequest, errors.New("不能修改管理员状态"))
			return
		}

		// 先准备并提交所有服务器的完整目标配置，全部成功后才切换用户状态。
		// 启用账号不等于绕过套餐状态：超限或套餐过期时只恢复面板登录。
		shouldSyncAccess := !payload.IsActive
		if payload.IsActive {
			overLimit, _ := repo.IsUserOverLimit(ctx, username)
			packageValid := targetUser.PackageID > 0 &&
				(targetUser.PackageEndDate == nil || targetUser.PackageEndDate.After(time.Now()))
			shouldSyncAccess = !overLimit && packageValid
		}
		if shouldSyncAccess && remoteManage != nil {
			if err := syncUserAccessTransactionally(ctx, repo, remoteManage, targetUser, payload.IsActive, false); err != nil {
				writeError(w, http.StatusBadGateway, fmt.Errorf("用户状态未修改，Xray 配置事务失败: %w", err))
				return
			}
		}

		if err := repo.UpdateUserStatus(ctx, username, payload.IsActive); err != nil {
			// 数据库提交失败时，把刚切换的 Agent 配置补偿回原状态。
			if shouldSyncAccess && remoteManage != nil {
				_ = syncUserAccessTransactionally(context.WithoutCancel(ctx), repo, remoteManage, targetUser, !payload.IsActive, false)
			}
			if errors.Is(err, storage.ErrUserNotFound) {
				writeError(w, http.StatusNotFound, errors.New("user not found"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// 禁用 → 立即踢出该用户当前登录会话。RequireToken 命中内存 token 即放行、不重查
		// is_active,不踢的话被禁用户的面板会话到期(最长 30 天)前一直有效。
		// 内存 + DB 双清(DB 会话主控重启会 LoadSessions 重新加载,只清内存不彻底)。
		if !payload.IsActive {
			if tokens != nil {
				tokens.RevokeUser(username)
			}
			if err := repo.DeleteUserSessions(ctx, username); err != nil {
				log.Printf("[UserStatus] disable: delete persisted sessions for %s failed: %v", username, err)
			}
		}

		if !payload.IsActive && shouldSyncAccess {
			_ = repo.UpdateUserDisabledAccessEnforced(ctx, username, true)
		}

		// 推 limiter 配置,让 agent 内存 limiter UserInfo 跟 DB 状态对齐
		// (push 路径会重新从 DB 读 is_active,disabled 用户不会被推送。)
		if pusher != nil {
			go pusher.PushToAllServersForUser(context.Background(), username)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
	})
}

func NewUserResetPasswordHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("user reset handler requires repository")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}

		var payload userResetRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		username := strings.TrimSpace(payload.Username)
		if username == "" {
			writeError(w, http.StatusBadRequest, errors.New("username is required"))
			return
		}

		// 检查目标用户是否是admin
		targetUser, err := repo.GetUser(r.Context(), username)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				writeError(w, http.StatusNotFound, errors.New("user not found"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		if targetUser.Role == storage.RoleAdmin {
			writeError(w, http.StatusBadRequest, errors.New("不能重置管理员密码"))
			return
		}

		newPassword := strings.TrimSpace(payload.NewPassword)
		if newPassword == "" {
			generated, err := generateRandomPassword(12)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			newPassword = generated
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		if err := repo.UpdateUserPassword(r.Context(), username, string(hash)); err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				writeError(w, http.StatusNotFound, errors.New("user not found"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(userResetResponse{Username: username, Password: newPassword})
	})
}

type userCreateHandler struct {
	repo           *storage.TrafficRepository
	licenseManager *license.Manager
}

func NewUserCreateHandler(repo *storage.TrafficRepository) *userCreateHandler {
	if repo == nil {
		panic("user create handler requires repository")
	}
	return &userCreateHandler{repo: repo}
}

func (h *userCreateHandler) SetLicenseManager(mgr *license.Manager) {
	h.licenseManager = mgr
}

func (h *userCreateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
		return
	}

	if msg, exceeded := licenseUserQuotaExceeded(r.Context(), h.repo, h.licenseManager); exceeded {
		writeJSONError(w, http.StatusForbidden, msg)
		return
	}

	var payload userCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	username := strings.TrimSpace(payload.Username)
	email := strings.TrimSpace(payload.Email)
	nickname := strings.TrimSpace(payload.Nickname)
	password := strings.TrimSpace(payload.Password)
	remark := strings.TrimSpace(payload.Remark)

	if username == "" {
		writeError(w, http.StatusBadRequest, errors.New("username is required"))
		return
	}
	if err := validateUsername(username); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if password == "" {
		random, err := generateRandomPassword(12)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		password = random
	}
	if nickname == "" {
		nickname = username
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	role := storage.RoleUser

	if err := h.repo.CreateUser(r.Context(), username, email, nickname, string(hash), role, remark); err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			writeError(w, http.StatusConflict, errors.New("用户已存在"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 立即为新用户生成 user_tokens(含 user_short_code),使订阅链接创建后即可用。
	// 否则短码是懒生成(首次登录 / 访问订阅才建行),管理员新建用户、绑套餐后在用户管理看不到订阅链接。
	if _, err := h.repo.GetOrCreateUserToken(r.Context(), username); err != nil {
		log.Printf("[CreateUser] 生成 user token/short_code 失败 user=%s: %v", username, err)
	}

	SendUserRegisteredNotification(r.Context(), username, email, "管理员添加")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(userCreateResponse{
		Username: username,
		Email:    email,
		Nickname: nickname,
		Role:     role,
		Password: password,
	})
}

type userDeleteRequest struct {
	Username string `json:"username"`
}

func NewUserDeleteHandler(repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher) http.Handler {
	if repo == nil {
		panic("user delete handler requires repository")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}

		var payload userDeleteRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		username := strings.TrimSpace(payload.Username)
		if username == "" {
			writeError(w, http.StatusBadRequest, errors.New("username is required"))
			return
		}

		ctx := r.Context()

		// 检查目标用户是否是admin
		targetUser, err := repo.GetUser(ctx, username)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				writeError(w, http.StatusNotFound, errors.New("user not found"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		if targetUser.Role == storage.RoleAdmin {
			writeError(w, http.StatusBadRequest, errors.New("不能删除管理员账号"))
			return
		}

		// 物理入站、共享 routed、用户私有 routed 的 rule/client/outbound 必须
		// 作为一份完整配置统一切换。任一 Agent 失败则用户和数据库均不删除。
		if remoteManage != nil {
			if err := syncUserAccessTransactionally(ctx, repo, remoteManage, targetUser, false, true); err != nil {
				writeError(w, http.StatusBadGateway, fmt.Errorf("用户未删除，Xray 配置事务失败: %w", err))
				return
			}
		}

		if err := repo.DeleteUser(ctx, username); err != nil {
			if remoteManage != nil {
				_ = syncUserAccessTransactionally(context.WithoutCancel(ctx), repo, remoteManage, targetUser, true, false)
			}
			if errors.Is(err, storage.ErrUserNotFound) {
				writeError(w, http.StatusNotFound, errors.New("user not found"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// 通知 agent limiter 移除该用户
		if pusher != nil {
			go pusher.PushToAllServersForUser(context.Background(), username)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	})
}

func generateRandomPassword(length int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if length <= 0 {
		length = 12
	}
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(bytes), nil
}

type userRemarkRequest struct {
	Username string `json:"username"`
	Remark   string `json:"remark"`
}

// shortCodeRe 跟前端 SHORT_CODE_RE 保持一致 — 留空表示清除自定义,系统回退到 user_short_code。
var shortCodeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{2,16}$`)

// reservedShortCodes 不允许普通用户把自己短码设成这些字符串,防止订阅短链路由被误用 / 钓鱼。
// 大小写不敏感比较。
var reservedShortCodes = map[string]bool{
	"admin":  true,
	"root":   true,
	"system": true,
	"api":    true,
	"share":  true,
	"test":   true,
	"user":   true,
	"guest":  true,
	"null":   true,
	"www":    true,
	"mmw":    true,
	"mmwx":   true,
}

// validateCustomUserShortCode 在所有"设置用户自定义短码"路径(admin 改任意用户 + user 改自己)前调用。
//   - code = ""             → 通过(清除自定义,系统回退自动 user_short_code)
//   - 格式不匹配 shortCodeRe → 400
//   - 命中保留字            → 400(防 /x/admin 之类的钓鱼)
//   - 撞其他用户的 username  → 409
//   - 撞其他用户的有效短码    → 409(custom_user_short_code 列的 UNIQUE 索引只防"custom 撞 custom",
//     并不阻止"custom 撞别人的自动 user_short_code")
//
// targetUsername 是被设置短码的"目标用户";同名跳过(允许重置成自己当前的值)。
func validateCustomUserShortCode(ctx context.Context, repo *storage.TrafficRepository, code, targetUsername string) error {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil
	}
	if !shortCodeRe.MatchString(code) {
		return errors.New("短码只能含字母 / 数字 / 下划线 / 横杠,长度 2-16")
	}
	if reservedShortCodes[strings.ToLower(code)] {
		return errors.New("该短码为系统保留字,请更换")
	}
	// 撞其他用户的 username(无论该用户角色)。同名跳过。
	if u, err := repo.GetUser(ctx, code); err == nil && u.Username != "" && !strings.EqualFold(u.Username, targetUsername) {
		return errors.New("该短码与已存在用户名冲突,请更换")
	}
	// 撞其他用户的有效短码 / 自定义短码。
	if infos, err := repo.ListUserShortCodeInfo(ctx); err == nil {
		for username, info := range infos {
			if strings.EqualFold(username, targetUsername) {
				continue
			}
			if strings.EqualFold(info.UserShortCode, code) || strings.EqualFold(info.CustomUserShortCode, code) {
				return errors.New("该短码已被其他用户占用,请更换")
			}
		}
	}
	return nil
}

type userShortCodeRequest struct {
	Username  string `json:"username"`
	ShortCode string `json:"short_code"`
}

// 管理员改任意用户的自定义短码。前端在用户管理表的气泡编辑里用。
//   - 留空 = 清除 custom_user_short_code,系统继续用自动生成的 user_short_code
//   - 非空 = 必须匹配 shortCodeRe;UNIQUE 冲突由 DB 索引兜底
func NewUserShortCodeHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("user short code handler requires repository")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}
		var payload userShortCodeRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		username := strings.TrimSpace(payload.Username)
		if username == "" {
			writeError(w, http.StatusBadRequest, errors.New("username is required"))
			return
		}
		code := strings.TrimSpace(payload.ShortCode)
		// 格式 / 保留字 / 撞别人 username / 撞别人 effective short code 一并校验。
		if err := validateCustomUserShortCode(r.Context(), repo, code, username); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := repo.UpdateUserCustomShortCode(r.Context(), username, code); err != nil {
			// UpdateUserCustomShortCode 返回的"该短码已被占用..."字符串作为 409 抛上去
			if strings.Contains(err.Error(), "已被占用") {
				writeError(w, http.StatusConflict, err)
				return
			}
			if errors.Is(err, storage.ErrUserNotFound) {
				writeError(w, http.StatusNotFound, err)
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusOK, map[string]any{"status": "updated"})
	})
}

func NewUserRemarkHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("user remark handler requires repository")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}

		var payload userRemarkRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		username := strings.TrimSpace(payload.Username)
		if username == "" {
			writeError(w, http.StatusBadRequest, errors.New("username is required"))
			return
		}

		if err := repo.UpdateUserRemark(r.Context(), username, payload.Remark); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
	})
}

// 创建用于更新用户电子邮件的处理程序
func NewUserUpdateEmailHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("user update email handler requires repository")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}

		var req struct {
			Username string `json:"username"`
			Email    string `json:"email"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		if req.Username == "" {
			writeError(w, http.StatusBadRequest, errors.New("username is required"))
			return
		}

		ctx := r.Context()
		if err := repo.UpdateUserEmail(ctx, req.Username, req.Email); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Email updated successfully",
		})
	})
}

func NewUserLimitsHandler(repo *storage.TrafficRepository, pusher *LimiterConfigPusher, licenseManager *license.Manager) http.Handler {
	type req struct {
		Username            string   `json:"username"`
		SpeedLimitOverride  *float64 `json:"speed_limit_override"`
		DeviceLimitOverride *int     `json:"device_limit_override"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var body req
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
			return
		}

		if strings.TrimSpace(body.Username) == "" {
			writeError(w, http.StatusBadRequest, errors.New("username is required"))
			return
		}

		// limiter 是 PRO feature — 设置非空 SpeedLimitOverride 才走 gate。
		// DeviceLimit 不算 limiter 范围(那是 socket 数限制,跟限速逻辑不同)。
		if body.SpeedLimitOverride != nil && *body.SpeedLimitOverride > 0 && licenseManager != nil && !licenseManager.HasFeature("limiter") {
			http.Error(w, "限速器是 PRO 功能,需要许可证", http.StatusForbidden)
			return
		}

		if err := repo.UpdateUserLimitOverrides(r.Context(), body.Username, body.SpeedLimitOverride, body.DeviceLimitOverride); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		if pusher != nil {
			// 必须用 Background:goroutine 异步执行,handler 一返回 r.Context() 就被 net/http cancel,
			// 会让下发里的 DB 查询 context canceled → 限速静默不下发(用户管理限速失效的根因)。
			go pusher.PushToAllServersForUser(context.Background(), body.Username)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"message": "User limits updated",
		})
	})
}
