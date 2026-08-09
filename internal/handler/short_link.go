package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/storage"
)

type shortLinkHandler struct {
	repo                *storage.TrafficRepository
	subscriptionHandler *SubscriptionHandler
	packageHandler      http.Handler
}

func NewShortLinkHandler(repo *storage.TrafficRepository, subscriptionHandler *SubscriptionHandler, packageHandler http.Handler) *shortLinkHandler {
	if repo == nil {
		panic("short link handler requires repository")
	}
	if subscriptionHandler == nil {
		panic("short link handler requires subscription handler")
	}

	return &shortLinkHandler{
		repo:                repo,
		subscriptionHandler: subscriptionHandler,
		packageHandler:      packageHandler,
	}
}

// TryServe attempts to serve the request as a short link.
// Returns true if the request was handled, false if not matched (caller should fall through).
func (h *shortLinkHandler) TryServe(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	// 订阅短码是可轮换凭据，任何中间缓存都会让已经更换或删除的旧地址
	// 在数据库不再命中的情况下继续返回历史订阅。显式禁止浏览器、反代和
	// CDN 缓存；内容缓存由订阅生成器内部负责，不能缓存鉴权入口响应。
	setSubscriptionNoCacheHeaders(w)

	code := strings.Trim(r.URL.Path, "/")
	code = strings.TrimPrefix(code, "x/")
	if len(code) < 2 {
		return false
	}

	ctx := r.Context()

	// 新逻辑：直接用 code 查 subscribe_files 表（custom_short_code 或 file_short_code）
	if sf, err := h.repo.GetSubscribeFileByShortCode(ctx, code); err == nil {
		username := sf.CreatedBy
		if username == "" {
			return false
		}

		if sf.Type == "package" && h.packageHandler != nil {
			newCtx := auth.ContextWithUsername(ctx, username)
			h.packageHandler.ServeHTTP(w, r.Clone(newCtx))
			return true
		}

		newURL := *r.URL
		q := newURL.Query()
		q.Set("filename", sf.Filename)
		if clientType := r.URL.Query().Get("t"); clientType != "" {
			q.Set("t", clientType)
		}
		newURL.RawQuery = q.Encode()

		newCtx := auth.ContextWithUsername(ctx, username)
		newRequest := r.Clone(newCtx)
		newRequest.URL = &newURL
		h.subscriptionHandler.ServeHTTP(w, newRequest)
		return true
	}

	// Fallback: 旧复合码逻辑（FileShortCode + UserShortCode）
	fileCodes, err := h.repo.GetAllFileShortCodes(ctx)
	if err != nil {
		fileCodes = nil
	}
	userCodes, err := h.repo.GetAllUserShortCodes(ctx)
	if err != nil || len(userCodes) == 0 {
		return false
	}
	packageCodes, _ := h.repo.GetAllPackageShortCodes(ctx)

	if len(fileCodes) == 0 && len(packageCodes) == 0 {
		return false
	}

	var filename, username string
	var isPackage bool
	matched := false
	for i := len(code) - 1; i >= 1; i-- {
		leftCode := code[:i]
		rightCode := code[i:]
		un, uOk := userCodes[rightCode]
		if !uOk {
			continue
		}
		if fn, fOk := fileCodes[leftCode]; fOk {
			filename = fn
			username = un
			matched = true
			break
		}
		if _, pOk := packageCodes[leftCode]; pOk {
			username = un
			isPackage = true
			matched = true
			break
		}
	}

	if !matched {
		return false
	}

	if isPackage && h.packageHandler != nil {
		newCtx := auth.ContextWithUsername(ctx, username)
		newRequest := r.Clone(newCtx)
		h.packageHandler.ServeHTTP(w, newRequest)
		return true
	}

	newURL := *r.URL
	q := newURL.Query()
	q.Set("filename", filename)
	if clientType := r.URL.Query().Get("t"); clientType != "" {
		q.Set("t", clientType)
	}
	newURL.RawQuery = q.Encode()

	newCtx := auth.ContextWithUsername(ctx, username)
	newRequest := r.Clone(newCtx)
	newRequest.URL = &newURL
	h.subscriptionHandler.ServeHTTP(w, newRequest)
	return true
}

func (h *shortLinkHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.TryServe(w, r) {
		http.NotFound(w, r)
	}
}

type shortLinkResetHandler struct {
	repo *storage.TrafficRepository
}

func NewShortLinkResetHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("short link reset handler requires repository")
	}

	return &shortLinkResetHandler{repo: repo}
}

func (h *shortLinkResetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
		return
	}

	if err := h.repo.ResetAllSubscriptionShortURLs(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"message":"所有订阅的短链接已重置"}`)
}

// NewUserCustomShortCodeSelfHandler 用户自行设置自定义短链接
func NewUserCustomShortCodeSelfHandler(repo *storage.TrafficRepository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := auth.UsernameFromContext(r.Context())
		if username == "" {
			writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}

		// 不向普通用户开放:用户短码现为系统随机生成(3-10 位)不可自定义,
		// 仅管理员保留设置入口,避免普通用户自定义引发的短码冲突可用性预言机。
		if !userIsAdmin(r.Context(), repo, username) {
			writeError(w, http.StatusForbidden, errors.New("该功能未开放"))
			return
		}

		switch r.Method {
		case http.MethodGet:
			code, err := repo.GetUserCustomShortCode(r.Context(), username)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			// effective = 自定义短码优先,否则系统自动短码(供前端预填当前短码)
			effective, eerr := repo.GetEffectiveUserShortCode(r.Context(), username)
			if eerr != nil {
				effective = code
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"custom_short_code": code, "effective_short_code": effective})

		case http.MethodPost:
			var payload struct {
				CustomShortCode string `json:"custom_short_code"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}

			code := strings.TrimSpace(payload.CustomShortCode)
			for _, c := range code {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
					writeError(w, http.StatusBadRequest, errors.New("自定义连接只能包含字母和数字"))
					return
				}
			}

			if code != "" {
				userCodes, err := repo.GetAllUserShortCodes(r.Context())
				if err == nil {
					if un, exists := userCodes[code]; exists && un != username {
						// 不透露被谁占用,避免泄露其他用户的短码(可用性预言机)。
						writeError(w, http.StatusConflict, errors.New("该短码已被占用，请更换一个"))
						return
					}
				}
			}

			if err := repo.UpdateUserCustomShortCode(r.Context(), username, code); err != nil {
				writeError(w, http.StatusConflict, errors.New("该短码已被占用，请更换一个"))
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "updated"})

		default:
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		}
	})
}
