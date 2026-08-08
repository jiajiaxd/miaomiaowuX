package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"

	"miaomiaowux/internal/storage"
)

const probeExternalTokenHeader = "X-MMwx-Probe-Token"

// RequireProbeExternalAccess 在探针接口保护开启时允许两条访问通道：
//   - 内置探针：浏览器发起的同源请求，不需要把长期密钥暴露到前端；
//   - 独立探针：Cloudflare Worker 携带专用密钥访问。
//
// 其他请求统一返回 404，避免普通盗链、跨站浏览器调用和无来源扫描。公开页面的数据
// 无法从协议层绝对阻止能够伪造 Origin/Referer 的服务端抓取，因此仍需配合限流。
func RequireProbeExternalAccess(repo *storage.TrafficRepository, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		internalOn, externalOn := probeChannelEnabled(repo, r)
		// A valid Worker token always selects the external channel. Check it
		// before Origin because a reverse proxy may add an Origin header.
		if externalOn && validProbeExternalToken(repo, r) {
			next.ServeHTTP(w, r)
			return
		}
		// Same-origin browser traffic is the built-in panel channel. Do not let
		// the legacy public-external fallback below turn on the master homepage
		// when only the external probe switch is enabled.
		if probeSameOriginRequest(repo, r) {
			if internalOn {
				next.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
			return
		}
		// 未开启接口保护时，外置探针可按原有公开接口方式访问；内置开关不会
		// 顺带公开接口。开启保护后，外置请求必须携带专用密钥。
		only, _ := repo.GetSystemSetting(r.Context(), probeExternalOnlyKey)
		if externalOn && only != "1" {
			next.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

func probeChannelEnabled(repo *storage.TrafficRepository, r *http.Request) (internal, external bool) {
	internalRaw, _ := repo.GetSystemSetting(r.Context(), probeInternalEnabledKey)
	externalRaw, _ := repo.GetSystemSetting(r.Context(), probeExternalEnabledKey)
	if internalRaw == "" && externalRaw == "" {
		legacy, _ := repo.GetSystemSetting(r.Context(), probeDisguiseEnabledKey)
		return legacy == "1", legacy == "1"
	}
	return internalRaw == "1", externalRaw == "1"
}

func validProbeExternalToken(repo *storage.TrafficRepository, r *http.Request) bool {
	storedHex, _ := repo.GetSystemSetting(r.Context(), probeExternalTokenHashKey)
	stored, err := hex.DecodeString(strings.TrimSpace(storedHex))
	provided := sha256.Sum256([]byte(r.Header.Get(probeExternalTokenHeader)))
	return err == nil && len(stored) == sha256.Size && subtle.ConstantTimeCompare(stored, provided[:]) == 1
}

func probeSameOriginRequest(repo *storage.TrafficRepository, r *http.Request) bool {
	allowedHosts := map[string]struct{}{}
	addHost := func(raw string) {
		if host := strings.ToLower(strings.TrimSpace(raw)); host != "" {
			allowedHosts[host] = struct{}{}
		}
	}
	addHost(r.Host)
	if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); forwarded != "" {
		addHost(forwarded)
	}
	if masterURL, _ := repo.GetSystemSetting(r.Context(), "master_url"); masterURL != "" {
		if parsed, err := url.Parse(strings.TrimSpace(masterURL)); err == nil {
			addHost(parsed.Host)
		}
	}
	if len(allowedHosts) == 0 {
		return false
	}

	matches := func(raw string) bool {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || !u.IsAbs() {
			return false
		}
		_, ok := allowedHosts[strings.ToLower(u.Host)]
		return ok
	}
	// WebSocket 握手始终带 Origin；普通同源 GET 通常只有 Referer。
	if origin := r.Header.Get("Origin"); origin != "" {
		return matches(origin)
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "same-origin") && matches(r.Header.Get("Referer"))
}
