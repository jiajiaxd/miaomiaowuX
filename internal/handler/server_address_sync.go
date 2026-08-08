package handler

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"miaomiaowux/internal/storage"
)

// SyncServerAddressChange propagates an Agent address change to nodes,
// persisted subscriptions, outbound metadata and live Xray instances.
func (h *RemoteManageHandler) SyncServerAddressChange(ctx context.Context, before, after *storage.RemoteServer) {
	if h == nil || h.repo == nil || before == nil || after == nil {
		return
	}
	replacements := serverAddressReplacements(before, after)
	if len(replacements) == 0 && before.Name == after.Name {
		return
	}
	h.serverAddressSyncMu.Lock()
	defer h.serverAddressSyncMu.Unlock()

	beforeNodes, err := h.repo.ListAllNodes(ctx)
	if err != nil {
		log.Printf("[ServerAddressSync] list nodes before refresh failed: %v", err)
	}
	newHost := chooseClashServerHost(after)
	if newHost != "" {
		if n, refreshErr := h.repo.RefreshNodesServerAddress(ctx, after.Name, newHost); refreshErr != nil {
			log.Printf("[ServerAddressSync] refresh nodes for %s failed: %v", after.Name, refreshErr)
		} else if n > 0 {
			log.Printf("[ServerAddressSync] refreshed %d node address(es) for %s", n, after.Name)
		}
	}
	if v6 := v6RefreshTarget(after); v6 != "" {
		if _, refreshErr := h.repo.RefreshNodesServerAddressV6(ctx, after.Name, v6); refreshErr != nil {
			log.Printf("[ServerAddressSync] refresh IPv6 nodes for %s failed: %v", after.Name, refreshErr)
		}
	}
	h.syncChangedNodesToSubscriptions(ctx, beforeNodes)

	if len(replacements) == 0 {
		return
	}
	h.persistPendingOutboundAddressReplacements(ctx, replacements)
	if n, rewriteErr := h.repo.RewriteStoredOutboundAddresses(ctx, replacements); rewriteErr != nil {
		log.Printf("[ServerAddressSync] rewrite stored outbound metadata failed: %v", rewriteErr)
	} else if n > 0 {
		log.Printf("[ServerAddressSync] rewrote %d stored outbound record(s)", n)
	}
	h.rewriteLiveOutboundAddresses(ctx, replacements)
}

func serverAddressReplacements(before, after *storage.RemoteServer) map[string]string {
	replacements := make(map[string]string)
	// 开启“锁定节点入口 IP”时是一次显式的地址策略切换，不只是普通 IP 漂移。
	// 已下发到其它 Agent 的出站可能仍指向旧域名、DDNS、IPv4 或 IPv6；它们都必须
	// 收敛到用户指定的 PullAddress（chooseClashServerHost 的锁定结果）。TLS 的 SNI
	// 位于 streamSettings，不经过 rewriteOutboundAddress，因此不会被这里误改。
	if after.LockEntryIP {
		locked := strings.TrimSpace(chooseClashServerHost(after))
		if locked != "" {
			for _, oldAddr := range []string{
				before.IPAddress, before.IPAddressV6, before.Domain, before.DomainV6,
				before.PullAddress, before.PullAddressV6,
			} {
				oldAddr = strings.TrimSpace(oldAddr)
				if oldAddr != "" && oldAddr != locked {
					replacements[oldAddr] = locked
				}
			}
			return replacements
		}
	}
	add := func(oldAddr, newAddr string) {
		oldAddr, newAddr = strings.TrimSpace(oldAddr), strings.TrimSpace(newAddr)
		// Only replace known literal IPs. Domains, SNI and user-provided hosts are preserved.
		if oldAddr != "" && newAddr != "" && oldAddr != newAddr && net.ParseIP(oldAddr) != nil {
			replacements[oldAddr] = newAddr
		}
	}
	add(before.IPAddress, chooseClashServerHost(after))
	add(before.IPAddressV6, v6RefreshTarget(after))
	return replacements
}

func (h *RemoteManageHandler) syncChangedNodesToSubscriptions(ctx context.Context, before []storage.Node) {
	if h.yamlSyncManager == nil || len(before) == 0 {
		return
	}
	after, err := h.repo.ListAllNodes(ctx)
	if err != nil {
		log.Printf("[ServerAddressSync] list nodes after refresh failed: %v", err)
		return
	}
	oldByID := make(map[int64]storage.Node, len(before))
	for _, node := range before {
		oldByID[node.ID] = node
	}
	updates := make([]NodeUpdate, 0)
	for _, node := range after {
		old, ok := oldByID[node.ID]
		if ok && old.ClashConfig != node.ClashConfig {
			updates = append(updates, NodeUpdate{OldName: old.NodeName, NewName: node.NodeName, ClashConfigJSON: node.ClashConfig})
		}
	}
	if err := h.yamlSyncManager.BatchSyncNodes(updates); err != nil {
		log.Printf("[ServerAddressSync] sync %d node(s) to subscriptions failed: %v", len(updates), err)
	}
}

func rewriteOutboundAddress(outbound map[string]any, replacements map[string]string) bool {
	settings, _ := outbound["settings"].(map[string]any)
	if settings == nil {
		return false
	}
	changed := false
	for _, key := range []string{"vnext", "servers"} {
		entries, _ := settings[key].([]interface{})
		for _, entry := range entries {
			item, _ := entry.(map[string]any)
			if item == nil {
				continue
			}
			old, _ := item["address"].(string)
			if replacement, ok := replacements[strings.TrimSpace(old)]; ok {
				item["address"] = replacement
				changed = true
			}
		}
	}
	return changed
}

func (h *RemoteManageHandler) rewriteLiveOutboundAddresses(ctx context.Context, replacements map[string]string) {
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		log.Printf("[ServerAddressSync] list servers for outbound refresh failed: %v", err)
		return
	}
	for i := range servers {
		server := &servers[i]
		if server.IsFederated || server.Status != storage.RemoteServerStatusConnected {
			continue
		}
		h.rewriteServerOutboundAddresses(ctx, server, replacements)
	}
}

func (h *RemoteManageHandler) rewriteServerOutboundAddresses(ctx context.Context, server *storage.RemoteServer, replacements map[string]string) {
	if server == nil || len(replacements) == 0 {
		return
	}
	sctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	raw, fetchErr := h.forwardToRemoteServer(sctx, server.ID, http.MethodGet, "/api/child/outbounds", nil)
	cancel()
	if fetchErr != nil {
		log.Printf("[ServerAddressSync] list outbounds on %s failed: %v", server.Name, fetchErr)
		return
	}
	var response struct {
		Success   bool             `json:"success"`
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		log.Printf("[ServerAddressSync] decode outbounds on %s failed: %v", server.Name, err)
		return
	}
	for _, outbound := range response.Outbounds {
		if !rewriteOutboundAddress(outbound, replacements) {
			continue
		}
		tag, _ := outbound["tag"].(string)
		if strings.TrimSpace(tag) == "" {
			continue
		}
		payload, _ := json.Marshal(map[string]any{"action": "update", "tag": tag, "outbound": outbound})
		uctx, ucancel := context.WithTimeout(ctx, 12*time.Second)
		_, updateErr := h.forwardToRemoteServer(uctx, server.ID, http.MethodPost, "/api/child/outbounds", payload)
		ucancel()
		if updateErr != nil {
			log.Printf("[ServerAddressSync] update outbound %s on %s failed: %v", tag, server.Name, updateErr)
		} else {
			log.Printf("[ServerAddressSync] updated outbound %s on %s", tag, server.Name)
		}
	}
}

const pendingOutboundAddressReplacementsKey = "pending_outbound_address_replacements"

func (h *RemoteManageHandler) persistPendingOutboundAddressReplacements(ctx context.Context, replacements map[string]string) {
	merged := make(map[string]string)
	if raw, _ := h.repo.GetSystemSetting(ctx, pendingOutboundAddressReplacementsKey); raw != "" {
		_ = json.Unmarshal([]byte(raw), &merged)
	}
	for oldAddr, newAddr := range replacements {
		// Collapse chains (A→B followed by B→C becomes A→C) so long-offline Agents
		// can jump directly to the current address.
		for old, current := range merged {
			if current == oldAddr {
				merged[old] = newAddr
			}
		}
		merged[oldAddr] = newAddr
	}
	encoded, _ := json.Marshal(merged)
	if err := h.repo.SetSystemSetting(ctx, pendingOutboundAddressReplacementsKey, string(encoded)); err != nil {
		log.Printf("[ServerAddressSync] persist pending outbound replacements failed: %v", err)
	}
}

// SyncPendingOutboundAddressChanges repairs an Agent that was offline during an
// address change. It is called after its actual Xray config snapshot is synced.
func (h *RemoteManageHandler) SyncPendingOutboundAddressChanges(ctx context.Context, serverID int64) {
	raw, _ := h.repo.GetSystemSetting(ctx, pendingOutboundAddressReplacementsKey)
	var replacements map[string]string
	if raw == "" || json.Unmarshal([]byte(raw), &replacements) != nil || len(replacements) == 0 {
		return
	}
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil || server.IsFederated {
		return
	}
	h.rewriteServerOutboundAddresses(ctx, server, replacements)
}
