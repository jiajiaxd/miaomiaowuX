package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"miaomiaowux/internal/storage"
	"miaomiaowux/internal/version"
)

// 消费方:接入一台"分享服务器"。探测拥有方联邦接口校验令牌,然后建一条 remote_servers 行 + federated_servers 标记。
type AddSharedServerHandler struct {
	repo   *storage.TrafficRepository
	client *http.Client
}

func NewAddSharedServerHandler(repo *storage.TrafficRepository) *AddSharedServerHandler {
	return &AddSharedServerHandler{repo: repo, client: &http.Client{Timeout: 15 * time.Second}}
}

func (h *AddSharedServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	var req struct {
		OwnerURL   string `json:"owner_url"`
		ShareToken string `json:"share_token"`
		Name       string `json:"name"`
		Prefix     string `json:"prefix"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("请求格式不正确"))
		return
	}
	ownerURL := strings.TrimRight(strings.TrimSpace(req.OwnerURL), "/")
	shareToken := strings.TrimSpace(req.ShareToken)
	if ownerURL == "" || shareToken == "" {
		writeError(w, http.StatusBadRequest, errors.New("拥有方地址和分享令牌必填"))
		return
	}
	if !strings.HasPrefix(ownerURL, "http://") && !strings.HasPrefix(ownerURL, "https://") {
		ownerURL = "https://" + ownerURL
	}

	// 探测拥有方联邦接口,校验令牌并取服务器信息
	info, err := h.probe(r, ownerURL, shareToken)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		if n, _ := info["name"].(string); n != "" {
			name = n
		} else {
			name = "共享服务器"
		}
	}
	ip, _ := info["ip_address"].(string)
	// v6 网络信息透传:分享服务器也能建 IPv6 节点(联邦轮询里也会持续同步)。
	ipv6, _ := info["ip_address_v6"].(string)
	domain, _ := info["domain"].(string)
	domainV6, _ := info["domain_v6"].(string)
	ipv6Enabled, _ := info["ipv6_enabled"].(bool)
	// 拥有方 xray 模式透传,避免消费方按默认 'external' 显示与拥有方不一致(联邦轮询里也会持续同步)
	xrayMode, _ := info["xray_mode"].(string)
	if xrayMode != "embedded" && xrayMode != "external" {
		xrayMode = ""
	}

	token, err := generateSecureToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	server := &storage.RemoteServer{
		Name:        name,
		Token:       token, // 占位:联邦服务器不直连 agent,不使用此 token
		Status:      "connected",
		IPAddress:   ip,
		IPAddressV6: ipv6,
		IPv6Enabled: ipv6Enabled,
		Domain:      domain,
		DomainV6:    domainV6,
		XrayMode:    xrayMode,
	}
	if err := h.repo.CreateRemoteServer(r.Context(), server); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := h.repo.SetFederatedServer(r.Context(), server.ID, ownerURL, shareToken, strings.TrimSpace(req.Prefix)); err != nil {
		// 回滚:删除刚建的服务器行
		_ = h.repo.DeleteRemoteServer(r.Context(), server.ID, false)
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": server.ID, "name": name, "status": "connected"})
}

func (h *AddSharedServerHandler) probe(r *http.Request, ownerURL, shareToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, ownerURL+"/api/federation/server-info", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Share-Token", shareToken)
	req.Header.Set("User-Agent", version.AgentUserAgent)
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, errors.New("无法连接到拥有方主控")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errors.New("分享令牌无效或已被吊销")
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, errors.New("拥有方未开启分享(PRO)功能")
	}
	if resp.StatusCode >= 400 {
		return nil, errors.New("拥有方联邦接口返回错误")
	}
	var info map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, errors.New("拥有方返回数据异常")
	}
	return info, nil
}
