package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"miaomiaowux/internal/license"
	"miaomiaowux/internal/storage"
)

// 自定义品牌(PRO):站点标题 / 左上角标题 / logo。
//
// 配置随便存(管理员可改),但**是否生效**由 license.FeatureCustomBranding 门控 —— 公开读取接口
// PublicGet 只在有 PRO 时才返回自定义值,否则返回空(前端回落内置默认)。这样即使用户直接改数据库,
// 没有 license 服务签发的 ed25519 签名 token 也不会生效;且 license Manager 每 5min refresh 一次,
// 满足「定期与许可证服务同步、防自行改库生效」。

const (
	brandingSiteTitleKey  = "branding_site_title"  // 浏览器标签页标题
	brandingBrandTitleKey = "branding_brand_title" // 左上角标题文字
	brandingLogoURLKey    = "branding_logo_url"    // logo:外部 URL 或内部 /api/branding/logo?v=<ts>
	brandingLogoExtKey    = "branding_logo_ext"    // 上传 logo 的扩展名(serve 时据此定 content-type)

	brandingLogoMaxSize = 2 << 20 // 2MB
)

var brandingDir = filepath.Join("data", "branding")

// 允许的 logo 扩展名 → content-type
var brandingLogoTypes = map[string]string{
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".webp": "image/webp",
	".gif":  "image/gif",
	".svg":  "image/svg+xml",
	".ico":  "image/x-icon",
}

// BrandingHandler 提供自定义品牌的读写与 logo 上传/服务。
type BrandingHandler struct {
	repo               *storage.TrafficRepository
	license            *license.Manager
	onSiteTitleChanged func(string)
}

func NewBrandingHandler(repo *storage.TrafficRepository, lic *license.Manager) *BrandingHandler {
	return &BrandingHandler{repo: repo, license: lic}
}

// SetOnSiteTitleChanged 注册运行时标题同步回调。用于让静态 HTML 首屏和公开品牌接口保持一致。
func (h *BrandingHandler) SetOnSiteTitleChanged(fn func(string)) {
	h.onSiteTitleChanged = fn
}

func (h *BrandingHandler) featureOn() bool {
	return h.license != nil && h.license.HasFeature(license.FeatureCustomBranding)
}

type brandingConfig struct {
	SiteTitle  string `json:"site_title"`
	BrandTitle string `json:"brand_title"`
	LogoURL    string `json:"logo_url"`
}

func (h *BrandingHandler) load(ctx context.Context) brandingConfig {
	get := func(k string) string { v, _ := h.repo.GetSystemSetting(ctx, k); return strings.TrimSpace(v) }
	return brandingConfig{
		SiteTitle:  get(brandingSiteTitleKey),
		BrandTitle: get(brandingBrandTitleKey),
		LogoURL:    get(brandingLogoURLKey),
	}
}

// EffectiveSiteTitle 返回经过许可证门控后的标题。空字符串表示使用内置标题。
func (h *BrandingHandler) EffectiveSiteTitle(ctx context.Context) string {
	if !h.featureOn() {
		return ""
	}
	return h.load(ctx).SiteTitle
}

// Admin 按方法分发 /api/admin/system-settings/branding:GET 读、POST 写。
func (h *BrandingHandler) Admin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.AdminGet(w, r)
	case http.MethodPost:
		h.AdminSet(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}
}

// AdminGet GET /api/admin/system-settings/branding — 管理员看当前配置 + 是否已启用(PRO)。
func (h *BrandingHandler) AdminGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"success": true, "branding": h.load(r.Context()), "feature_enabled": h.featureOn(),
	})
}

// AdminSet POST /api/admin/system-settings/branding — 设置标题 / logo URL。无论有没有 PRO 都能存;
// 生效与否由 PublicGet 按 feature 门控。
func (h *BrandingHandler) AdminSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	var req brandingConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}
	ctx := r.Context()
	_ = h.repo.SetSystemSetting(ctx, brandingSiteTitleKey, strings.TrimSpace(req.SiteTitle))
	_ = h.repo.SetSystemSetting(ctx, brandingBrandTitleKey, strings.TrimSpace(req.BrandTitle))
	// LogoURL:允许清空或填外部 URL(上传走单独接口,会覆盖成内部路径;此处原样保留前端传的值)。
	_ = h.repo.SetSystemSetting(ctx, brandingLogoURLKey, strings.TrimSpace(req.LogoURL))
	if h.onSiteTitleChanged != nil {
		h.onSiteTitleChanged(h.EffectiveSiteTitle(ctx))
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "feature_enabled": h.featureOn()})
}

// UploadLogo POST /api/admin/system-settings/branding/logo — 上传 logo 文件,存盘并把 logo_url 指到内部路径。
func (h *BrandingHandler) UploadLogo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	if err := r.ParseMultipartForm(brandingLogoMaxSize + (1 << 20)); err != nil {
		writeBadRequest(w, "解析上传失败")
		return
	}
	file, header, err := r.FormFile("logo")
	if err != nil {
		writeBadRequest(w, "缺少 logo 文件")
		return
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	if _, ok := brandingLogoTypes[ext]; !ok {
		writeBadRequest(w, "只支持 png/jpg/webp/gif/svg/ico 图片")
		return
	}
	if header.Size > brandingLogoMaxSize {
		writeBadRequest(w, fmt.Sprintf("logo 文件过大,不能超过 %dMB", brandingLogoMaxSize>>20))
		return
	}

	if err := os.MkdirAll(brandingDir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("创建目录失败: %w", err))
		return
	}
	// 清掉旧的其它扩展名文件,避免残留(serve 按当前 ext 定位)。
	for e := range brandingLogoTypes {
		_ = os.Remove(filepath.Join(brandingDir, "logo"+e))
	}
	dstPath := filepath.Join(brandingDir, "logo"+ext)
	dst, err := os.Create(dstPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("保存失败: %w", err))
		return
	}
	written, cerr := io.Copy(dst, io.LimitReader(file, brandingLogoMaxSize+1))
	_ = dst.Close()
	if cerr != nil || written > brandingLogoMaxSize {
		_ = os.Remove(dstPath)
		writeBadRequest(w, "保存失败或文件过大")
		return
	}
	ctx := r.Context()
	_ = h.repo.SetSystemSetting(ctx, brandingLogoExtKey, ext)
	url := fmt.Sprintf("/api/branding/logo?v=%d", time.Now().Unix()) // 时间戳 cache-bust
	_ = h.repo.SetSystemSetting(ctx, brandingLogoURLKey, url)
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "logo_url": url})
}

// ServeLogo GET /api/branding/logo — 公开服务上传的 logo 文件(无 PRO 时 404,防 PRO 失效后仍露出自定义 logo)。
func (h *BrandingHandler) ServeLogo(w http.ResponseWriter, r *http.Request) {
	if !h.featureOn() {
		http.NotFound(w, r)
		return
	}
	ext := strings.ToLower(strings.TrimSpace(func() string { v, _ := h.repo.GetSystemSetting(r.Context(), brandingLogoExtKey); return v }()))
	ctype, ok := brandingLogoTypes[ext]
	if !ok {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(brandingDir, "logo"+ext))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = io.Copy(w, f)
}

// PublicGet GET /api/branding — 公开返回【生效】的品牌(有 PRO 才返回自定义值,否则空)。
// 无 auth:登录页也要能拿到品牌。门控在此 —— 改数据库但没 PRO,一律返回空,前端回落内置默认。
func (h *BrandingHandler) PublicGet(w http.ResponseWriter, r *http.Request) {
	out := brandingConfig{}
	if h.featureOn() {
		out = h.load(r.Context())
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "branding": out})
}
