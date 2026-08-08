package handler

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/MMWOrg/mmwX-plugins/proxyparser"
)

// parseCompatibleURIList parses a plain or base64 URI list. SOCKS/SOCKS5 is
// handled locally because proxyparser v0.1.7 silently turns malformed ports
// into zero and treats URI schemes case-sensitively.
func parseCompatibleURIList(content string) ([]map[string]any, bool) {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return nil, false
	}
	if decoded, ok := decodeURIListBase64(trimmed); ok {
		trimmed = decoded
	}

	lines := strings.Split(strings.ReplaceAll(trimmed, "\r\n", "\n"), "\n")
	proxies := make([]map[string]any, 0, len(lines))
	sawURI := false
	sawSocks := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !strings.Contains(line, "://") {
			return nil, false
		}
		sawURI = true
		var (
			proxy map[string]any
			err   error
		)
		if isSocksURI(line) {
			sawSocks = true
			proxy, err = parseSocksURICompat(line)
		} else {
			proxy, err = proxyparser.Parse(line)
		}
		if err != nil || proxy == nil {
			if sawSocks {
				// Recognized SOCKS input must not fall through to proxyparser v0.1.7,
				// which would silently turn this exact error into port:0.
				return []map[string]any{}, true
			}
			// A URI list must not silently accept a broken entry. Returning false
			// lets the existing parser/error path handle unsupported formats.
			return nil, false
		}
		proxies = append(proxies, proxy)
	}
	return proxies, sawURI && len(proxies) > 0
}

func isSocksURI(raw string) bool {
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd < 0 {
		return false
	}
	scheme := strings.ToLower(strings.TrimSpace(raw[:schemeEnd]))
	return scheme == "socks" || scheme == "socks5"
}

func parseSocksURICompat(raw string) (map[string]any, error) {
	raw = strings.TrimSpace(raw)
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd < 0 || !isSocksURI(raw) {
		return nil, fmt.Errorf("unsupported SOCKS URI")
	}
	rest := strings.TrimSpace(raw[schemeEnd+3:])
	if rest == "" {
		return nil, fmt.Errorf("SOCKS URI 缺少地址")
	}

	// Only delimiters after the last @ belong to host/query/fragment. This also
	// tolerates legacy links containing an unescaped # or ? in the password.
	hostStart := 0
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		hostStart = at + 1
	}
	name := ""
	if rel := strings.Index(rest[hostStart:], "#"); rel >= 0 {
		idx := hostStart + rel
		name = safeURIUnescape(rest[idx+1:])
		rest = rest[:idx]
	}
	if rel := strings.Index(rest[hostStart:], "?"); rel >= 0 {
		rest = rest[:hostStart+rel]
	}
	rest = strings.TrimSpace(strings.TrimSuffix(rest, "/"))

	userinfo, hostport := "", rest
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		userinfo, hostport = rest[:at], rest[at+1:]
	}
	hostport = strings.TrimSpace(hostport)
	host, portText, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, fmt.Errorf("SOCKS URI 地址或端口无效: %w", err)
	}
	port, err := strconv.Atoi(strings.TrimSpace(portText))
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("SOCKS URI 端口无效: %q", portText)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("SOCKS URI 缺少服务器地址")
	}

	username, password := "", ""
	if userinfo != "" {
		if colon := strings.Index(userinfo, ":"); colon >= 0 {
			username = safeURIUnescape(userinfo[:colon])
			password = safeURIUnescape(userinfo[colon+1:])
		} else {
			username = safeURIUnescape(userinfo)
		}
	}
	if name == "" {
		name = net.JoinHostPort(host, strconv.Itoa(port))
	}
	proxy := map[string]any{
		"name": name, "type": "socks5", "server": host, "port": port, "udp": true,
	}
	if username != "" {
		proxy["username"] = username
	}
	if password != "" {
		proxy["password"] = password
	}
	return proxy, nil
}

func safeURIUnescape(value string) string {
	if decoded, err := url.QueryUnescape(value); err == nil {
		return decoded
	}
	return value
}

func decodeURIListBase64(content string) (string, bool) {
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		decoded, err := encoding.DecodeString(content)
		if err == nil && strings.Contains(string(decoded), "://") {
			return strings.TrimSpace(string(decoded)), true
		}
	}
	return "", false
}
