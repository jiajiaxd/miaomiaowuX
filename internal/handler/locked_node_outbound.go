package handler

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	"miaomiaowux/internal/storage"
)

// rewriteLockedNodeOutbound rewrites an outbound add/update request to the
// effective address of a locked managed server. It deliberately matches both
// node address+port and all known addresses of that node's owning server: an
// already-open browser may submit the pre-lock Clash address after the DB node
// has been refreshed.
func (h *RemoteManageHandler) rewriteLockedNodeOutbound(ctx context.Context, body []byte) ([]byte, bool) {
	var req map[string]any
	if json.Unmarshal(body, &req) != nil {
		return body, false
	}
	action := strings.ToLower(strings.TrimSpace(lockedOutboundString(req["action"])))
	if action != "add" && action != "update" {
		return body, false
	}
	outbound, _ := req["outbound"].(map[string]any)
	if outbound == nil {
		return body, false
	}
	address, port := extractOutboundTarget(outbound)
	if address == "" || port <= 0 {
		return body, false
	}

	nodes, err := h.repo.ListAllNodes(ctx)
	if err != nil {
		log.Printf("[LockedNodeOutbound] list nodes failed: %v", err)
		return body, false
	}
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		log.Printf("[LockedNodeOutbound] list servers failed: %v", err)
		return body, false
	}
	serverByName := make(map[string]*storage.RemoteServer, len(servers))
	for i := range servers {
		serverByName[servers[i].Name] = &servers[i]
	}

	// More than one locked server may share an address/port (NAT). Only rewrite
	// when all matching managed nodes agree on the same locked destination.
	replacement := ""
	for i := range nodes {
		node := &nodes[i]
		server := serverByName[node.OriginalServer]
		if server == nil || !server.LockEntryIP || node.NodeType == "routed" {
			continue
		}
		var clash map[string]any
		if json.Unmarshal([]byte(node.ClashConfig), &clash) != nil || toInt(clash["port"]) != port {
			continue
		}
		if !lockedServerAddressMatches(address, clash, server) {
			continue
		}
		effective := chooseClashServerHost(server)
		if effective == "" || effective == address {
			continue
		}
		if replacement != "" && replacement != effective {
			log.Printf("[LockedNodeOutbound] ambiguous target %s:%d; keep original address", address, port)
			return body, false
		}
		replacement = effective
	}
	if replacement == "" || !setOutboundTargetAddress(outbound, replacement) {
		return body, false
	}
	rewritten, err := json.Marshal(req)
	if err != nil {
		return body, false
	}
	log.Printf("[LockedNodeOutbound] rewrote target %s:%d -> %s:%d", address, port, replacement, port)
	return rewritten, true
}

func lockedServerAddressMatches(address string, clash map[string]any, server *storage.RemoteServer) bool {
	address = strings.TrimSpace(address)
	if address == "" || server == nil {
		return false
	}
	known := []string{
		lockedOutboundString(clash["server"]), server.IPAddress, server.IPAddressV6,
		server.Domain, server.DomainV6, server.PullAddress, server.PullAddressV6,
	}
	for _, candidate := range known {
		if strings.EqualFold(address, strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func setOutboundTargetAddress(outbound map[string]any, address string) bool {
	settings, _ := outbound["settings"].(map[string]any)
	if settings == nil {
		return false
	}
	for _, key := range []string{"vnext", "servers"} {
		entries, _ := settings[key].([]any)
		if len(entries) == 0 {
			continue
		}
		first, _ := entries[0].(map[string]any)
		if first != nil {
			first["address"] = address
			return true
		}
	}
	return false
}

func lockedOutboundString(v any) string {
	s, _ := v.(string)
	return s
}
