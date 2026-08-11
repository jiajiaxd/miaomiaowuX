package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"miaomiaowux/internal/storage"

	"github.com/google/uuid"
)

type packageConfigState struct {
	serverID int64
	config   map[string]interface{}
}

type routedActiveBefore struct {
	id     int64
	active bool
}

type packageConfigDBDelta struct {
	newPhysical     []storage.UserInboundConfig
	removedPhysical []storage.UserInboundConfig
	routedBefore    map[string]routedActiveBefore
}

func loadPackageServerConfig(ctx context.Context, rm *RemoteManageHandler, states map[int64]*packageConfigState, serverID int64) (*packageConfigState, error) {
	if state := states[serverID]; state != nil {
		return state, nil
	}
	raw, err := rm.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/xray/config", nil)
	if err != nil {
		return nil, fmt.Errorf("读取服务器 %d Xray 配置: %w", serverID, err)
	}
	var resp struct {
		Success bool   `json:"success"`
		Config  string `json:"config"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || !resp.Success || strings.TrimSpace(resp.Config) == "" {
		return nil, fmt.Errorf("服务器 %d 返回了无效的 Xray 配置", serverID)
	}
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Config), &config); err != nil {
		return nil, fmt.Errorf("解析服务器 %d Xray 配置: %w", serverID, err)
	}
	state := &packageConfigState{serverID: serverID, config: config}
	states[serverID] = state
	return state, nil
}

func managedInbound(config map[string]interface{}, tag string) (map[string]interface{}, map[string]interface{}, string, error) {
	inbounds, _ := config["inbounds"].([]interface{})
	for _, raw := range inbounds {
		inbound, _ := raw.(map[string]interface{})
		if inbound == nil || fmt.Sprint(inbound["tag"]) != tag {
			continue
		}
		settings, _ := inbound["settings"].(map[string]interface{})
		if settings == nil {
			settings = map[string]interface{}{}
			inbound["settings"] = settings
		}
		return inbound, settings, strings.ToLower(fmt.Sprint(inbound["protocol"])), nil
	}
	return nil, nil, "", fmt.Errorf("inbound %s 不存在", tag)
}

func managedClientArrayKey(protocol string) (string, error) {
	switch strings.ToLower(protocol) {
	case "vless", "vmess", "trojan", "shadowsocks", "hysteria":
		return "clients", nil
	case "anytls", "snell", "mieru":
		return "users", nil
	case "socks", "http":
		return "accounts", nil
	default:
		return "", fmt.Errorf("不支持为协议 %s 管理用户", protocol)
	}
}

func managedCredentialEmail(credential map[string]interface{}, fallback string) string {
	if email, _ := credential["email"].(string); strings.TrimSpace(email) != "" {
		return email
	}
	return fallback
}

func upsertManagedClient(config map[string]interface{}, inboundTag string, credential map[string]interface{}) error {
	_, settings, protocol, err := managedInbound(config, inboundTag)
	if err != nil {
		return err
	}
	key, err := managedClientArrayKey(protocol)
	if err != nil {
		return err
	}
	entries, _ := settings[key].([]interface{})
	email := strings.TrimSpace(fmt.Sprint(credential["email"]))
	for i, raw := range entries {
		entry, _ := raw.(map[string]interface{})
		sameEmail := entry != nil && email != "" && email != "<nil>" && strings.TrimSpace(fmt.Sprint(entry["email"])) == email
		// SOCKS/HTTP accounts do not carry an email. Their stable identity is the
		// username; replacing by protocol identity keeps repair/rebind idempotent.
		sameCredential := entry != nil && matchCredential(entry, credential, protocol)
		if sameEmail || sameCredential {
			entries[i] = credential
			settings[key] = entries
			return nil
		}
	}
	settings[key] = append(entries, credential)
	return nil
}

func removeManagedClient(config map[string]interface{}, inboundTag, email string, credentials ...map[string]interface{}) error {
	_, settings, protocol, err := managedInbound(config, inboundTag)
	if err != nil {
		return err
	}
	key, err := managedClientArrayKey(protocol)
	if err != nil {
		return err
	}
	entries, _ := settings[key].([]interface{})
	kept := make([]interface{}, 0, len(entries))
	for _, raw := range entries {
		entry, _ := raw.(map[string]interface{})
		matches := entry != nil && email != "" && strings.TrimSpace(fmt.Sprint(entry["email"])) == email
		if !matches && entry != nil && len(credentials) > 0 && credentials[0] != nil {
			matches = matchCredential(entry, credentials[0], protocol)
		}
		if matches {
			continue
		}
		kept = append(kept, raw)
	}
	settings[key] = kept
	return nil
}

func mutateManagedRouteUser(config map[string]interface{}, marktag, outboundTag, email string, add bool) error {
	routing, _ := config["routing"].(map[string]interface{})
	if routing == nil {
		return errors.New("routing 配置不存在")
	}
	rules, _ := routing["rules"].([]interface{})
	for _, raw := range rules {
		rule, _ := raw.(map[string]interface{})
		if rule == nil {
			continue
		}
		matched := marktag != "" && fmt.Sprint(rule["marktag"]) == marktag
		if !matched && marktag == "" && outboundTag != "" {
			matched = fmt.Sprint(rule["outboundTag"]) == outboundTag
		}
		if !matched {
			continue
		}
		users, _ := rule["user"].([]interface{})
		kept := make([]interface{}, 0, len(users)+1)
		exists := false
		for _, rawUser := range users {
			if fmt.Sprint(rawUser) == email {
				exists = true
				if !add {
					continue
				}
			}
			kept = append(kept, rawUser)
		}
		if add && !exists {
			kept = append(kept, email)
		}
		rule["user"] = kept
		return nil
	}
	return fmt.Errorf("未找到 routed rule(marktag=%q outboundTag=%q)", marktag, outboundTag)
}

func validateManagedConfig(config map[string]interface{}) error {
	inbounds, _ := config["inbounds"].([]interface{})
	for _, raw := range inbounds {
		inbound, _ := raw.(map[string]interface{})
		if inbound == nil {
			continue
		}
		tag := fmt.Sprint(inbound["tag"])
		settings, _ := inbound["settings"].(map[string]interface{})
		seenEmail := map[string]bool{}
		for _, key := range []string{"clients", "users", "accounts"} {
			entries, _ := settings[key].([]interface{})
			for _, rawEntry := range entries {
				entry, _ := rawEntry.(map[string]interface{})
				email := strings.TrimSpace(fmt.Sprint(entry["email"]))
				if email == "" || email == "<nil>" {
					continue
				}
				if seenEmail[email] {
					return fmt.Errorf("inbound %s 出现重复 Xray email %s", tag, email)
				}
				seenEmail[email] = true
			}
		}
	}
	return nil
}

func packageNodeDiff(oldNodes, newNodes []int64) (added, removed []int64) {
	oldSet, newSet := map[int64]bool{}, map[int64]bool{}
	for _, id := range oldNodes {
		oldSet[id] = true
	}
	for _, id := range newNodes {
		newSet[id] = true
	}
	for _, id := range newNodes {
		if !oldSet[id] {
			added = append(added, id)
		}
	}
	for _, id := range oldNodes {
		if !newSet[id] {
			removed = append(removed, id)
		}
	}
	return
}

// packageNodeSkipsInboundSync reports whether a package node is subscription-only.
// External/imported nodes intentionally have no inbound_tag: they belong in the
// generated subscription, but there is no managed Xray inbound to mutate for them.
func packageNodeSkipsInboundSync(node storage.Node) bool {
	return node.NodeType != "routed" && strings.TrimSpace(node.InboundTag) == ""
}

func (h *PackageUpdateHandler) syncPackageNodesTransactionally(ctx context.Context, packageID int64, oldNodes, newNodes []int64) error {
	addedNodes, removedNodes := packageNodeDiff(oldNodes, newNodes)
	if len(addedNodes) == 0 && len(removedNodes) == 0 {
		return nil
	}
	users, err := h.repo.ListUsersWithPackage(ctx)
	if err != nil {
		return fmt.Errorf("读取套餐用户: %w", err)
	}
	targetUsers := make([]storage.User, 0)
	for _, user := range users {
		if user.PackageID == packageID {
			targetUsers = append(targetUsers, user)
		}
	}
	if len(targetUsers) == 0 {
		return nil
	}
	return h.syncPackageUserNodesTransactionally(ctx, targetUsers, oldNodes, newNodes)
}

func (h *PackageUpdateHandler) syncPackageUserNodesTransactionally(ctx context.Context, targetUsers []storage.User, oldNodes, newNodes []int64) error {
	addedNodes, removedNodes := packageNodeDiff(oldNodes, newNodes)
	if len(addedNodes) == 0 && len(removedNodes) == 0 {
		return nil
	}

	stillUsed := map[string]bool{}
	for _, nodeID := range newNodes {
		node, err := h.repo.GetNodeByID(ctx, nodeID)
		if err != nil || node.NodeType == "routed" || packageNodeSkipsInboundSync(node) {
			continue
		}
		server, _ := resolveNodeServer(ctx, h.repo, h.remoteManage, node)
		if server != nil {
			stillUsed[fmt.Sprintf("%d|%s", server.ID, node.InboundTag)] = true
		}
	}

	states := map[int64]*packageConfigState{}
	delta := packageConfigDBDelta{routedBefore: map[string]routedActiveBefore{}}
	rollbackReservations := func() {
		for _, cfg := range delta.newPhysical {
			_ = h.repo.DeleteUserInboundConfig(context.WithoutCancel(ctx), cfg.Username, cfg.ServerID, cfg.InboundTag)
		}
		for _, before := range delta.routedBefore {
			_ = h.repo.SetSubaccountActive(context.WithoutCancel(ctx), before.id, before.active)
		}
	}

	for _, user := range targetUsers {
		for _, nodeID := range addedNodes {
			node, err := h.repo.GetNodeByID(ctx, nodeID)
			if err != nil {
				rollbackReservations()
				return fmt.Errorf("读取新增节点 %d: %w", nodeID, err)
			}
			if node.NodeType == "routed" {
				before, _ := h.repo.GetUserSubaccount(ctx, node.ID, user.Username)
				info, err := computeRoutedNodeUserCred(ctx, h.remoteManage, h.repo, user, node.ID)
				if err != nil {
					rollbackReservations()
					return fmt.Errorf("准备用户 %s 的路由节点 %s: %w", user.Username, node.NodeName, err)
				}
				if before != nil {
					delta.routedBefore[fmt.Sprintf("%s|%d", user.Username, node.ID)] = routedActiveBefore{id: before.ID, active: before.IsActive}
				} else if claimed, _ := h.repo.GetUserSubaccount(ctx, node.ID, user.Username); claimed != nil {
					delta.routedBefore[fmt.Sprintf("%s|%d", user.Username, node.ID)] = routedActiveBefore{id: claimed.ID, active: false}
				}
				state, err := loadPackageServerConfig(ctx, h.remoteManage, states, info.ServerID)
				if err == nil {
					err = upsertManagedClient(state.config, info.InboundTag, info.Credential)
				}
				if err == nil {
					err = mutateManagedRouteUser(state.config, info.Marktag, info.OutboundTag, info.UserEmail, true)
				}
				if err != nil {
					rollbackReservations()
					return fmt.Errorf("添加用户 %s 到路由节点 %s: %w", user.Username, node.NodeName, err)
				}
				continue
			}
			if packageNodeSkipsInboundSync(node) {
				continue
			}

			server, reason := resolveNodeServer(ctx, h.repo, h.remoteManage, node)
			if server == nil {
				rollbackReservations()
				return fmt.Errorf("节点 %s 无法确定服务器: %s", node.NodeName, reason)
			}
			state, err := loadPackageServerConfig(ctx, h.remoteManage, states, server.ID)
			if err != nil {
				rollbackReservations()
				return fmt.Errorf("添加用户 %s 到节点 %s: %w", user.Username, node.NodeName, err)
			}
			_, settings, protocol, err := managedInbound(state.config, node.InboundTag)
			if err != nil {
				rollbackReservations()
				return fmt.Errorf("读取节点 %s 的入站 %s: %w", node.NodeName, node.InboundTag, err)
			}
			existing, _ := h.repo.GetUserInboundConfig(ctx, user.Username, server.ID, node.InboundTag)
			credential, credentialJSON, _, err := getOrCreateInboundCredential(ctx, h.repo, user, server.ID, node.InboundTag, protocol, settings)
			if err != nil {
				rollbackReservations()
				return fmt.Errorf("生成用户 %s 在节点 %s 的凭据: %w", user.Username, node.NodeName, err)
			}
			// getOrCreate historically tolerated a failed reservation write. A
			// coordinated operation cannot do that: the Agent config and the
			// credential used to generate subscriptions must be byte-for-byte the
			// same before prepare begins.
			reserved, reserveErr := h.repo.GetUserInboundConfig(ctx, user.Username, server.ID, node.InboundTag)
			if reserveErr != nil || reserved == nil || reserved.CredentialJSON != credentialJSON || !strings.EqualFold(reserved.Protocol, protocol) {
				rollbackReservations()
				if reserveErr == nil {
					reserveErr = errors.New("凭据未持久化或与候选配置不一致")
				}
				return fmt.Errorf("保存用户 %s 节点 %s 凭据: %w", user.Username, node.NodeName, reserveErr)
			}
			if existing == nil {
				delta.newPhysical = append(delta.newPhysical, storage.UserInboundConfig{Username: user.Username, ServerID: server.ID, InboundTag: node.InboundTag, Protocol: protocol, CredentialJSON: credentialJSON})
			}
			if err := upsertManagedClient(state.config, node.InboundTag, credential); err != nil {
				rollbackReservations()
				return fmt.Errorf("写入用户 %s 到节点 %s 的 Xray 配置: %w", user.Username, node.NodeName, err)
			}
		}

		for _, nodeID := range removedNodes {
			node, err := h.repo.GetNodeByID(ctx, nodeID)
			if err != nil {
				rollbackReservations()
				return fmt.Errorf("读取移除节点 %d: %w", nodeID, err)
			}
			if node.NodeType == "routed" {
				subaccount, err := h.repo.GetUserSubaccount(ctx, node.ID, user.Username)
				if err != nil || subaccount == nil || !subaccount.IsActive {
					continue
				}
				detail, err := h.repo.GetRoutedNodeDetail(ctx, node.ID)
				if err != nil {
					rollbackReservations()
					return fmt.Errorf("读取路由节点 %s 配置: %w", node.NodeName, err)
				}
				server, err := h.repo.GetRemoteServerByName(ctx, detail.OriginalServer)
				if err != nil {
					rollbackReservations()
					return fmt.Errorf("查找路由节点 %s 所在服务器: %w", node.NodeName, err)
				}
				state, err := loadPackageServerConfig(ctx, h.remoteManage, states, server.ID)
				if err == nil {
					err = removeManagedClient(state.config, detail.InboundTag, subaccount.Email)
				}
				if err == nil {
					err = mutateManagedRouteUser(state.config, detail.RoutedRuleMarktag, detail.RoutedOutboundTag, subaccount.Email, false)
				}
				if err != nil {
					rollbackReservations()
					return fmt.Errorf("从路由节点 %s 移除用户 %s: %w", node.NodeName, user.Username, err)
				}
				delta.routedBefore[fmt.Sprintf("%s|%d", user.Username, node.ID)] = routedActiveBefore{id: subaccount.ID, active: true}
				continue
			}
			if packageNodeSkipsInboundSync(node) {
				continue
			}

			server, reason := resolveNodeServer(ctx, h.repo, h.remoteManage, node)
			if server == nil {
				rollbackReservations()
				return fmt.Errorf("节点 %s 无法确定服务器: %s", node.NodeName, reason)
			}
			if stillUsed[fmt.Sprintf("%d|%s", server.ID, node.InboundTag)] {
				continue
			}
			state, err := loadPackageServerConfig(ctx, h.remoteManage, states, server.ID)
			if err != nil {
				rollbackReservations()
				return fmt.Errorf("从节点 %s 移除用户 %s: %w", node.NodeName, user.Username, err)
			}
			cfg, _ := h.repo.GetUserInboundConfig(ctx, user.Username, server.ID, node.InboundTag)
			email := user.Username + "__" + node.InboundTag
			if cfg != nil {
				var credential map[string]interface{}
				_ = json.Unmarshal([]byte(cfg.CredentialJSON), &credential)
				email = managedCredentialEmail(credential, email)
				delta.removedPhysical = append(delta.removedPhysical, *cfg)
			}
			var savedCredential map[string]interface{}
			if cfg != nil {
				_ = json.Unmarshal([]byte(cfg.CredentialJSON), &savedCredential)
			}
			if err := removeManagedClient(state.config, node.InboundTag, email, savedCredential); err != nil {
				rollbackReservations()
				return fmt.Errorf("从节点 %s 的 Xray 配置移除用户 %s: %w", node.NodeName, user.Username, err)
			}
		}
	}

	targets := make([]xrayConfigTransactionTarget, 0, len(states))
	for serverID, state := range states {
		if err := validateManagedConfig(state.config); err != nil {
			rollbackReservations()
			return fmt.Errorf("校验服务器 %d Xray 配置: %w", serverID, err)
		}
		configJSON, err := json.MarshalIndent(state.config, "", "  ")
		if err != nil {
			rollbackReservations()
			return fmt.Errorf("序列化服务器 %d Xray 配置: %w", serverID, err)
		}
		targets = append(targets, xrayConfigTransactionTarget{ServerID: serverID, Config: string(configJSON)})
	}

	operationID := "pkg-" + uuid.NewString()
	if err := applyXrayConfigTransaction(ctx, h.remoteManage, operationID, targets); err != nil {
		rollbackReservations()
		return err
	}

	var finalizeErrs []error
	for _, cfg := range delta.removedPhysical {
		if err := h.repo.DeleteUserInboundConfig(ctx, cfg.Username, cfg.ServerID, cfg.InboundTag); err != nil {
			finalizeErrs = append(finalizeErrs, err)
		}
	}
	for key, before := range delta.routedBefore {
		parts := strings.Split(key, "|")
		shouldActive := true
		if len(parts) == 2 {
			for _, removedID := range removedNodes {
				if fmt.Sprint(removedID) == parts[1] {
					shouldActive = false
					break
				}
			}
		}
		if err := h.repo.SetSubaccountActive(ctx, before.id, shouldActive); err != nil {
			finalizeErrs = append(finalizeErrs, err)
		}
	}
	if len(finalizeErrs) > 0 {
		_ = finishXrayConfigTransaction(context.WithoutCancel(ctx), h.remoteManage, operationID, targets, false)
		for _, cfg := range delta.removedPhysical {
			_ = h.repo.SaveUserInboundConfig(context.WithoutCancel(ctx), cfg)
		}
		rollbackReservations()
		return fmt.Errorf("提交套餐凭据数据库状态失败: %w", errors.Join(finalizeErrs...))
	}
	if err := finishXrayConfigTransaction(context.WithoutCancel(ctx), h.remoteManage, operationID, targets, true); err != nil {
		log.Printf("[PackageConfigTxn] operation %s committed but agent cleanup incomplete: %v", operationID, err)
	}
	for _, target := range targets {
		go h.remoteManage.refreshXraySnapshot(target.ServerID)
	}
	return nil
}
