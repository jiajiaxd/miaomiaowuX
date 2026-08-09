package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/storage"
)

// NewAdminXrayCredentialResetHandler rotates only the currently authenticated
// administrator's Xray credentials. Client emails stay unchanged so traffic
// attribution and routed rules remain valid.
func NewAdminXrayCredentialResetHandler(repo *storage.TrafficRepository, rm *RemoteManageHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}
		username := strings.TrimSpace(auth.UsernameFromContext(r.Context()))
		user, err := repo.GetUser(r.Context(), username)
		if err != nil || user.Role != storage.RoleAdmin {
			writeError(w, http.StatusForbidden, errors.New("administrator account required"))
			return
		}
		if rm == nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("remote management is unavailable"))
			return
		}

		updated, err := resetAdminXrayCredentials(r.Context(), repo, rm, user)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "updated", "credentials_updated": updated})
	})
}

// NewAdminNodeCredentialRepairHandler repairs subscription-facing credentials
// in nodes from the administrator credential records already stored by the
// master. It deliberately does not mutate Xray or generate new credentials.
func NewAdminNodeCredentialRepairHandler(repo *storage.TrafficRepository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}
		username := strings.TrimSpace(auth.UsernameFromContext(r.Context()))
		admin, err := repo.GetUser(r.Context(), username)
		if err != nil || admin.Role != storage.RoleAdmin {
			writeError(w, http.StatusForbidden, errors.New("administrator account required"))
			return
		}

		result, err := repairAdminNodeCredentials(r.Context(), repo, admin)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusOK, map[string]any{
			"status":            "repaired",
			"nodes_repaired":    result.repaired,
			"nodes_unchanged":   result.unchanged,
			"records_unmatched": result.unmatched,
		})
	})
}

type adminNodeCredentialRepairResult struct {
	repaired  int
	unchanged int
	unmatched int
}

func repairAdminNodeCredentials(ctx context.Context, repo *storage.TrafficRepository, admin storage.User) (adminNodeCredentialRepairResult, error) {
	var result adminNodeCredentialRepairResult
	nodes, err := repo.ListAllNodes(ctx)
	if err != nil {
		return result, fmt.Errorf("list nodes: %w", err)
	}
	servers, err := repo.ListRemoteServers(ctx)
	if err != nil {
		return result, fmt.Errorf("list servers: %w", err)
	}
	serverNames := make(map[int64]string, len(servers))
	for _, server := range servers {
		serverNames[server.ID] = server.Name
	}

	configs, err := repo.GetUserInboundConfigs(ctx, admin.Username)
	if err != nil {
		return result, fmt.Errorf("list administrator inbound credentials: %w", err)
	}
	for _, cfg := range configs {
		credential := map[string]interface{}{}
		if err := json.Unmarshal([]byte(cfg.CredentialJSON), &credential); err != nil {
			return result, fmt.Errorf("decode credential for server %d inbound %s: %w", cfg.ServerID, cfg.InboundTag, err)
		}
		serverName := serverNames[cfg.ServerID]
		if serverName == "" {
			result.unmatched++
			continue
		}
		matched := false
		for _, node := range nodes {
			// Early releases left username empty on some administrator-created
			// physical nodes. They are still safe to repair because server+inbound
			// is tied to this administrator credential record.
			if node.NodeType == "routed" || (node.Username != "" && node.Username != admin.Username) ||
				node.OriginalServer != serverName || node.InboundTag != cfg.InboundTag {
				continue
			}
			matched = true
			if !json.Valid([]byte(node.ClashConfig)) {
				return result, fmt.Errorf("physical node %d has invalid clash config", node.ID)
			}
			repaired := cloneClashWithCredential(node.ClashConfig, cfg.Protocol, credential, node.NodeName)
			if repaired == node.ClashConfig {
				result.unchanged++
				continue
			}
			if err := repo.UpdateNodeClashCredential(ctx, node.ID, repaired); err != nil {
				return result, fmt.Errorf("repair physical node %d: %w", node.ID, err)
			}
			result.repaired++
		}
		if !matched {
			result.unmatched++
		}
	}

	subaccounts, err := repo.ListUserSubaccounts(ctx, admin.Username)
	if err != nil {
		return result, fmt.Errorf("list administrator routed subaccounts: %w", err)
	}
	for _, sa := range subaccounts {
		routed, err := repo.GetRoutedNodeDetail(ctx, sa.RoutedNodeID)
		if err != nil {
			result.unmatched++
			continue
		}
		// A routed node can retain more than one administrator-related record.
		// Only its designated administrator email is allowed to overwrite the
		// subscription-facing credential.
		if routed.RoutedAdminEmail != "" && routed.RoutedAdminEmail != sa.Email {
			result.unmatched++
			continue
		}
		protocol := routed.Protocol
		if routed.ParentNodeID != nil {
			if parent, perr := repo.GetNodeByID(ctx, *routed.ParentNodeID); perr == nil && parent.Protocol != "" {
				protocol = parent.Protocol
			}
		}
		credential := map[string]interface{}{}
		if err := json.Unmarshal([]byte(sa.CredentialJSON), &credential); err != nil {
			return result, fmt.Errorf("decode routed credential %d: %w", sa.ID, err)
		}
		if !json.Valid([]byte(routed.ClashConfig)) {
			return result, fmt.Errorf("routed node %d has invalid clash config", routed.ID)
		}
		repaired := cloneClashWithCredential(routed.ClashConfig, protocol, credential, routed.NodeName)
		credentialChanged := strings.TrimSpace(routed.RoutedAdminCredential) != strings.TrimSpace(sa.CredentialJSON)
		if repaired == routed.ClashConfig && !credentialChanged {
			result.unchanged++
			continue
		}
		if err := repo.UpdateRoutedAdminCredential(ctx, routed.ID, sa.CredentialJSON, repaired); err != nil {
			return result, fmt.Errorf("repair routed node %d: %w", routed.ID, err)
		}
		result.repaired++
	}
	return result, nil
}

func resetAdminXrayCredentials(ctx context.Context, repo *storage.TrafficRepository, rm *RemoteManageHandler, admin storage.User) (int, error) {
	configs, err := repo.GetUserInboundConfigs(ctx, admin.Username)
	if err != nil {
		return 0, fmt.Errorf("list administrator inbound credentials: %w", err)
	}
	nodes, err := repo.ListAllNodes(ctx)
	if err != nil {
		return 0, fmt.Errorf("list nodes: %w", err)
	}

	updated := 0
	// Migration data may register the same routed administrator client in both
	// tables. Rotate each remote client only once, then reuse the generated value
	// for every database reference to it.
	rotatedRemote := make(map[string]map[string]interface{})
	for _, cfg := range configs {
		oldCred := map[string]interface{}{}
		if err := json.Unmarshal([]byte(cfg.CredentialJSON), &oldCred); err != nil {
			return updated, fmt.Errorf("decode credential for server %d inbound %s: %w", cfg.ServerID, cfg.InboundTag, err)
		}
		remoteKey := xrayCredentialRemoteKey(cfg.ServerID, cfg.InboundTag, cfg.Protocol, oldCred)
		newCred := rotatedRemote[remoteKey]
		didRemoteRotate := false
		if newCred == nil {
			newCred, err = rotateXrayCredential(cfg.Protocol, oldCred)
			if err != nil {
				return updated, fmt.Errorf("rotate credential for server %d inbound %s: %w", cfg.ServerID, cfg.InboundTag, err)
			}
			if err := replaceInboundClientCredential(ctx, rm, cfg.ServerID, cfg.InboundTag, oldCred, newCred); err != nil {
				return updated, fmt.Errorf("update Xray client on server %d inbound %s: %w", cfg.ServerID, cfg.InboundTag, err)
			}
			rotatedRemote[remoteKey] = newCred
			didRemoteRotate = true
		}
		newJSONBytes, _ := json.Marshal(newCred)
		newJSON := string(newJSONBytes)
		if err := repo.UpdateUserInboundCredentialJSONByID(ctx, cfg.ID, newJSON); err != nil {
			if didRemoteRotate {
				_ = replaceInboundClientCredential(ctx, rm, cfg.ServerID, cfg.InboundTag, newCred, oldCred)
			}
			return updated, fmt.Errorf("save administrator inbound credential: %w", err)
		}

		for _, node := range nodes {
			if node.NodeType == "routed" || node.Username != admin.Username || node.InboundTag != cfg.InboundTag {
				continue
			}
			server, serr := repo.GetRemoteServerByName(ctx, node.OriginalServer)
			if serr != nil || server.ID != cfg.ServerID || !clashUsesCredential(node.ClashConfig, cfg.Protocol, oldCred) {
				continue
			}
			clash := cloneClashWithCredential(node.ClashConfig, cfg.Protocol, newCred, node.NodeName)
			if err := repo.UpdateNodeClashCredential(ctx, node.ID, clash); err != nil {
				return updated, fmt.Errorf("update node %d credential: %w", node.ID, err)
			}
		}
		updated++
	}

	subaccounts, err := repo.ListUserSubaccounts(ctx, admin.Username)
	if err != nil {
		return updated, fmt.Errorf("list administrator routed subaccounts: %w", err)
	}
	for _, sa := range subaccounts {
		routed, err := repo.GetRoutedNodeDetail(ctx, sa.RoutedNodeID)
		if err != nil || routed.ParentNodeID == nil {
			return updated, fmt.Errorf("load routed node %d: %w", sa.RoutedNodeID, err)
		}
		parent, err := repo.GetNodeByID(ctx, *routed.ParentNodeID)
		if err != nil {
			return updated, fmt.Errorf("load parent node for routed node %d: %w", sa.RoutedNodeID, err)
		}
		server, err := repo.GetRemoteServerByName(ctx, parent.OriginalServer)
		if err != nil {
			return updated, fmt.Errorf("resolve server for routed node %d: %w", sa.RoutedNodeID, err)
		}
		oldCred := map[string]interface{}{}
		if err := json.Unmarshal([]byte(sa.CredentialJSON), &oldCred); err != nil {
			return updated, fmt.Errorf("decode routed credential %d: %w", sa.ID, err)
		}
		remoteKey := xrayCredentialRemoteKey(server.ID, parent.InboundTag, parent.Protocol, oldCred)
		newCred := rotatedRemote[remoteKey]
		didRemoteRotate := false
		if newCred == nil {
			newCred, err = rotateXrayCredential(parent.Protocol, oldCred)
			if err != nil {
				return updated, fmt.Errorf("rotate routed credential %d: %w", sa.ID, err)
			}
		}
		if sa.IsActive && rotatedRemote[remoteKey] == nil {
			if err := replaceInboundClientCredential(ctx, rm, server.ID, parent.InboundTag, oldCred, newCred); err != nil {
				return updated, fmt.Errorf("update routed Xray client %d: %w", sa.ID, err)
			}
			rotatedRemote[remoteKey] = newCred
			didRemoteRotate = true
		}
		newJSONBytes, _ := json.Marshal(newCred)
		newJSON := string(newJSONBytes)
		sa.CredentialJSON = newJSON
		if _, err := repo.UpsertUserSubaccount(ctx, sa); err != nil {
			if didRemoteRotate {
				_ = replaceInboundClientCredential(ctx, rm, server.ID, parent.InboundTag, newCred, oldCred)
			}
			return updated, fmt.Errorf("save routed credential %d: %w", sa.ID, err)
		}
		clash := cloneClashWithCredential(routed.ClashConfig, parent.Protocol, newCred, routed.NodeName)
		if routed.RoutedAdminEmail == sa.Email {
			if err := repo.UpdateRoutedAdminCredential(ctx, routed.ID, newJSON, clash); err != nil {
				return updated, fmt.Errorf("update routed node %d: %w", routed.ID, err)
			}
		} else if err := repo.UpdateNodeClashCredential(ctx, routed.ID, clash); err != nil {
			return updated, fmt.Errorf("update routed node %d: %w", routed.ID, err)
		}
		updated++
	}
	return updated, nil
}

func xrayCredentialRemoteKey(serverID int64, inboundTag, protocol string, credential map[string]interface{}) string {
	// Email is metadata in Xray and legacy imports may contain several clients
	// with the same administrator email. Use the protocol's actual client key so
	// each distinct credential is rotated, while duplicate DB references to the
	// same client still collapse into one remote operation.
	var identity interface{}
	switch strings.ToLower(protocol) {
	case "vless", "vmess":
		identity = credential["id"]
	case "trojan", "anytls", "shadowsocks", "ss":
		identity = credential["password"]
	case "snell":
		identity = credential["psk"]
	case "hysteria", "hysteria2", "hy2":
		identity = credential["auth"]
	case "socks", "http":
		identity = credential["user"]
	case "mieru":
		identity = credential["username"]
	default:
		identity = credential["email"]
	}
	return fmt.Sprintf("%d\x00%s\x00%s\x00%v", serverID, inboundTag, strings.ToLower(protocol), identity)
}

func replaceInboundClientCredential(ctx context.Context, rm *RemoteManageHandler, serverID int64, inboundTag string, oldCred, newCred map[string]interface{}) error {
	if err := mutateInboundClient(ctx, rm, serverID, inboundTag, "remove-client", oldCred); err != nil {
		return fmt.Errorf("remove old client: %w", err)
	}
	if err := mutateInboundClient(ctx, rm, serverID, inboundTag, "add-client", newCred); err != nil {
		_ = mutateInboundClient(ctx, rm, serverID, inboundTag, "add-client", oldCred)
		return fmt.Errorf("add new client: %w", err)
	}
	return nil
}

func rotateXrayCredential(protocol string, old map[string]interface{}) (map[string]interface{}, error) {
	credential := cloneMap(old)
	switch strings.ToLower(protocol) {
	case "vless", "vmess":
		credential["id"] = uuid.NewString()
	case "trojan", "anytls", "mieru":
		credential["password"] = uuid.NewString()
	case "snell":
		credential["psk"] = uuid.NewString()
	case "hysteria", "hysteria2", "hy2":
		credential["auth"] = uuid.NewString()
	case "shadowsocks", "ss":
		length := 16
		if decoded, err := base64.StdEncoding.DecodeString(fmt.Sprint(old["password"])); err == nil && len(decoded) > 0 {
			length = len(decoded)
		}
		key := make([]byte, length)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		credential["password"] = base64.StdEncoding.EncodeToString(key)
	case "socks", "http":
		credential["pass"] = strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	default:
		return nil, fmt.Errorf("unsupported protocol %q", protocol)
	}
	return credential, nil
}

func clashUsesCredential(clashJSON, protocol string, credential map[string]interface{}) bool {
	var clash map[string]interface{}
	if json.Unmarshal([]byte(clashJSON), &clash) != nil {
		return false
	}
	switch strings.ToLower(protocol) {
	case "vless", "vmess":
		return fmt.Sprint(clash["uuid"]) == fmt.Sprint(credential["id"])
	case "trojan", "anytls":
		return fmt.Sprint(clash["password"]) == fmt.Sprint(credential["password"])
	case "snell":
		return fmt.Sprint(clash["psk"]) == fmt.Sprint(credential["psk"])
	case "hysteria", "hysteria2", "hy2":
		return fmt.Sprint(clash["password"]) == fmt.Sprint(credential["auth"])
	case "shadowsocks", "ss":
		return strings.HasSuffix(fmt.Sprint(clash["password"]), ":"+fmt.Sprint(credential["password"])) || fmt.Sprint(clash["password"]) == fmt.Sprint(credential["password"])
	}
	return false
}
