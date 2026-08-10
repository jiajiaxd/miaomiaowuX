package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// scanNodeTags deserializes JSON tags and syncs Tag field.
func scanNodeTags(node *Node, tagsJSON string) {
	if tagsJSON != "" && tagsJSON != "[]" {
		if err := json.Unmarshal([]byte(tagsJSON), &node.Tags); err != nil {
			node.Tags = nil
		}
	}
	if len(node.Tags) > 0 && node.Tag == "" {
		node.Tag = node.Tags[0]
	}
	if node.Tag != "" && len(node.Tags) == 0 {
		node.Tags = []string{node.Tag}
	}
}

// serializeNodeTags returns JSON string for tags and syncs Tag/Tags fields.
func serializeNodeTags(node *Node) string {
	if len(node.Tags) == 0 && node.Tag != "" {
		node.Tags = []string{node.Tag}
	}
	if len(node.Tags) > 0 {
		node.Tag = node.Tags[0]
	}
	if len(node.Tags) == 0 {
		return "[]"
	}
	b, err := json.Marshal(node.Tags)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// scanRelayGroupNodeIDs 反序列化中转组成员 ID 列表(存的是 JSON 数组)。
func scanRelayGroupNodeIDs(node *Node, idsJSON string) {
	if idsJSON != "" && idsJSON != "[]" {
		_ = json.Unmarshal([]byte(idsJSON), &node.RelayGroupNodeIDs)
	}
}

// serializeRelayGroupNodeIDs 把中转组成员 ID 列表序列化为 JSON(空列表存 "[]")。
func serializeRelayGroupNodeIDs(ids []int64) string {
	if len(ids) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ids)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// pruneRelayGroupMember 在删除节点后,从同一用户其他节点的中转组成员列表中移除该节点 ID。
// 若移除后某节点的中转组成员为空,则清除其整个中转组配置(relay_group_name + relay_group_node_ids),
// 使该节点在生成订阅时回退为普通节点,避免悬空的中转组引用。
func (r *TrafficRepository) pruneRelayGroupMember(ctx context.Context, deletedID int64, username string) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, relay_group_node_ids FROM nodes WHERE username = ? AND relay_group_node_ids != '' AND relay_group_node_ids != '[]'`, username)
	if err != nil {
		return
	}
	type pending struct {
		id  int64
		ids []int64
	}
	var updates []pending
	for rows.Next() {
		var nid int64
		var idsJSON string
		if err := rows.Scan(&nid, &idsJSON); err != nil {
			continue
		}
		var ids []int64
		if err := json.Unmarshal([]byte(idsJSON), &ids); err != nil {
			continue
		}
		var filtered []int64
		removed := false
		for _, x := range ids {
			if x == deletedID {
				removed = true
				continue
			}
			filtered = append(filtered, x)
		}
		if removed {
			updates = append(updates, pending{id: nid, ids: filtered})
		}
	}
	rows.Close()

	for _, u := range updates {
		if len(u.ids) == 0 {
			_, _ = r.db.ExecContext(ctx, `UPDATE nodes SET relay_group_name = '', relay_group_node_ids = '[]', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND username = ?`, u.id, username)
		} else {
			_, _ = r.db.ExecContext(ctx, `UPDATE nodes SET relay_group_node_ids = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND username = ?`, serializeRelayGroupNodeIDs(u.ids), u.id, username)
		}
	}
}

func (n Node) HasAnyTag(tags map[string]bool) bool {
	for _, t := range n.Tags {
		if tags[t] {
			return true
		}
	}
	return false
}

// 检查用户的节点名称是否已存在（如果提供，则排除特定节点 ID）。
func (r *TrafficRepository) CheckNodeNameExists(ctx context.Context, nodeName, username string, excludeID int64) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("traffic repository not initialized")
	}

	nodeName = strings.TrimSpace(nodeName)
	username = strings.TrimSpace(username)
	if nodeName == "" || username == "" {
		return false, errors.New("node name and username are required")
	}

	var count int
	query := `SELECT COUNT(*) FROM nodes WHERE node_name = ? AND username = ?`
	args := []interface{}{nodeName, username}

	if excludeID > 0 {
		query += ` AND id != ?`
		args = append(args, excludeID)
	}

	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check node name exists: %w", err)
	}

	return count > 0, nil
}

// UniqueNodeName 在 base 撞名时追加协议/序号后缀,保证在 taken 集合里唯一。
// taken 为调用方已加载的现有节点名集合(值 true=已占用),本函数不修改它。
func UniqueNodeName(base, protocol string, taken map[string]bool) string {
	if !taken[base] {
		return base
	}
	if p := strings.TrimSpace(protocol); p != "" {
		withProto := base + " " + p // 例:"A hysteria2"
		if !taken[withProto] {
			return withProto
		}
		for i := 2; ; i++ {
			c := fmt.Sprintf("%s %s %d", base, p, i)
			if !taken[c] {
				return c
			}
		}
	}
	for i := 2; ; i++ {
		c := fmt.Sprintf("%s (%d)", base, i)
		if !taken[c] {
			return c
		}
	}
}

// 返回特定用户名的所有节点。
func (r *TrafficRepository) ListNodes(ctx context.Context, username string) ([]Node, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("username is required")
	}

	rows, err := r.db.QueryContext(ctx, `SELECT id, username, raw_url, node_name, protocol, parsed_config, clash_config, enabled, COALESCE(tag, 'personal'), COALESCE(tags, '[]'), COALESCE(original_server, ''), COALESCE(original_domain, ''), COALESCE(inbound_tag, ''), chain_proxy_node_id, COALESCE(relay_group_name, ''), COALESCE(relay_group_node_ids, '[]'), COALESCE(node_type, 'physical'), parent_node_id, COALESCE(routed_outbound_tag, ''), COALESCE(routed_owner, 'shared'), COALESCE(relay_orig_server, ''), COALESCE(relay_orig_port, 0), created_at, updated_at FROM nodes WHERE username = ? ORDER BY created_at DESC`, username)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	defer rows.Close()

	var nodes []Node
	for rows.Next() {
		var node Node
		var enabled int
		var tagsJSON string
		var relayGroupIDsJSON string
		if err := rows.Scan(&node.ID, &node.Username, &node.RawURL, &node.NodeName, &node.Protocol, &node.ParsedConfig, &node.ClashConfig, &enabled, &node.Tag, &tagsJSON, &node.OriginalServer, &node.OriginalDomain, &node.InboundTag, &node.ChainProxyNodeID, &node.RelayGroupName, &relayGroupIDsJSON, &node.NodeType, &node.ParentNodeID, &node.RoutedOutboundTag, &node.RoutedOwner, &node.RelayOrigServer, &node.RelayOrigPort, &node.CreatedAt, &node.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan node: %w", err)
		}
		node.Enabled = enabled != 0
		scanNodeTags(&node, tagsJSON)
		scanRelayGroupNodeIDs(&node, relayGroupIDsJSON)
		nodes = append(nodes, node)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate nodes: %w", err)
	}

	return nodes, nil
}

// UpdateNodeProxyConfigs 原子更新节点的解析配置与 Clash 配置。
// 供证书指纹等后台修复任务使用，避免调用 UpdateNode 时用扫描到的旧 Node 覆盖用户并发修改的
// 名称、标签、中转等无关字段。
func (r *TrafficRepository) UpdateNodeProxyConfigs(ctx context.Context, id int64, parsedConfig, clashConfig string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return errors.New("node id is required")
	}
	res, err := r.db.ExecContext(ctx, `UPDATE nodes
		SET parsed_config = ?, clash_config = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`, parsedConfig, clashConfig, id)
	if err != nil {
		return fmt.Errorf("update node proxy configs: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("node proxy configs rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNodeNotFound
	}
	return nil
}

// UpdateNodeClashCredential updates only the subscription-facing Clash config.
// Credential rotation must not overwrite parsed_config because it describes the
// shared inbound rather than one Xray client.
func (r *TrafficRepository) UpdateNodeClashCredential(ctx context.Context, id int64, clashConfig string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	res, err := r.db.ExecContext(ctx, `UPDATE nodes SET clash_config = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, clashConfig, id)
	if err != nil {
		return fmt.Errorf("update node clash credential: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("node clash credential rows affected: %w", err)
	}
	if n == 0 {
		return ErrNodeNotFound
	}
	return nil
}

// UpdateRoutedNodeProxyConfigs refreshes a routed child's inherited transport
// settings after its physical inbound is replaced, while preserving the child
// identity and outbound/rule metadata.
func (r *TrafficRepository) UpdateRoutedNodeProxyConfigs(ctx context.Context, id int64, parsedConfig, clashConfig, protocol string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	res, err := r.db.ExecContext(ctx, `UPDATE nodes SET protocol=?, parsed_config=?, clash_config=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND COALESCE(node_type,'physical')='routed'`,
		protocol, parsedConfig, clashConfig, id)
	if err != nil {
		return fmt.Errorf("update routed node proxy configs: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update routed node proxy configs rows affected: %w", err)
	}
	if n == 0 {
		return ErrNodeNotFound
	}
	return nil
}

// UpdateRoutedAdminCredential keeps the routed node's stored admin credential
// and its subscription-facing Clash config in sync.
func (r *TrafficRepository) UpdateRoutedAdminCredential(ctx context.Context, id int64, credentialJSON, clashConfig string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	res, err := r.db.ExecContext(ctx, `UPDATE nodes
		SET routed_admin_credential = ?, clash_config = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND node_type = 'routed'`, credentialJSON, clashConfig, id)
	if err != nil {
		return fmt.Errorf("update routed admin credential: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("routed admin credential rows affected: %w", err)
	}
	if n == 0 {
		return ErrNodeNotFound
	}
	return nil
}

func (r *TrafficRepository) CountNodes(ctx context.Context) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	var count int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM nodes`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count nodes: %w", err)
	}
	return count, nil
}

// CountLicensedNodes 统计"占用 license 配额"的节点 — 任何指向 mmwx 已管理 server 的节点。
//
// 计入:
//   - routed + routed_owner='shared'(admin 在出站管理里创建 + 同步入站自动识别)— 占用 server 上实际 xray 资源
//   - physical + original_server != ”(节点已 claim 到某台已注册 server)— 用户手动导入或外部订阅
//     指向 mmwx 管理的 server 时,handleCreate 会自动 claim 并把 original_server 填上,等于"伪装的 routed"
//
// 不计入:
//   - physical + original_server = ”(指向真外部 vps,跟 mmwx 资源无关)
//   - routed + routed_owner='user'(普通用户私有路由出站,有 user_permissions quota)
//
// 这套语义堵了"用户通过手动导入 vless:// 绕过 license"的口子 — 只要节点 server 指向已注册 server,
// 创建时就被 claim,后续计数自动覆盖。
func (r *TrafficRepository) CountLicensedNodes(ctx context.Context) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	var count int64
	// 许可证节点计数:所有路由出站节点都计入 —— routed_owner='shared'(admin 分配)和 'user'(普通用户自建)
	// 都消耗 server 出站资源,都该受 max_nodes 限制(之前漏算了 'user',普通用户的路由出站不受限,已修正)。
	// 再加已注册到 remote_server 的物理节点(original_server 非空)。
	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(1) FROM nodes
		WHERE node_type = 'routed'
		   OR (node_type = 'physical' AND COALESCE(original_server, '') != '')
	`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count licensed nodes: %w", err)
	}
	return count, nil
}

// ListSharedRoutedByParentIDs 按父节点 ID 列举所有 routed_owner='shared' 的子节点。
// 用于普通用户节点列表:套餐里只放父物理节点 ID,但 admin 派生的 shared routed 子节点
// (落地+路由出站功能)也应该在套餐内自动可见。无父 ID → 返回空,无 panic。
func (r *TrafficRepository) ListSharedRoutedByParentIDs(ctx context.Context, parentIDs []int64) ([]Node, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if len(parentIDs) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(parentIDs))
	args := make([]interface{}, len(parentIDs))
	for i, id := range parentIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	query := `SELECT id, username, raw_url, node_name, protocol, parsed_config, clash_config, enabled, COALESCE(tag, 'personal'), COALESCE(tags, '[]'), COALESCE(original_server, ''), COALESCE(original_domain, ''), COALESCE(inbound_tag, ''), chain_proxy_node_id, COALESCE(relay_group_name, ''), COALESCE(relay_group_node_ids, '[]'), COALESCE(node_type, 'physical'), parent_node_id, COALESCE(routed_outbound_tag, ''), COALESCE(routed_owner, 'shared'), COALESCE(relay_orig_server, ''), COALESCE(relay_orig_port, 0), created_at, updated_at FROM nodes WHERE node_type = 'routed' AND COALESCE(routed_owner, 'shared') = 'shared' AND parent_node_id IN (` + strings.Join(placeholders, ",") + `) ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list shared routed by parents: %w", err)
	}
	defer rows.Close()
	var nodes []Node
	for rows.Next() {
		var node Node
		var enabled int
		var tagsJSON string
		var relayGroupIDsJSON string
		if err := rows.Scan(&node.ID, &node.Username, &node.RawURL, &node.NodeName, &node.Protocol, &node.ParsedConfig, &node.ClashConfig, &enabled, &node.Tag, &tagsJSON, &node.OriginalServer, &node.OriginalDomain, &node.InboundTag, &node.ChainProxyNodeID, &node.RelayGroupName, &relayGroupIDsJSON, &node.NodeType, &node.ParentNodeID, &node.RoutedOutboundTag, &node.RoutedOwner, &node.RelayOrigServer, &node.RelayOrigPort, &node.CreatedAt, &node.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan node: %w", err)
		}
		node.Enabled = enabled != 0
		scanNodeTags(&node, tagsJSON)
		scanRelayGroupNodeIDs(&node, relayGroupIDsJSON)
		nodes = append(nodes, node)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate nodes: %w", err)
	}
	return nodes, nil
}

// 返回管理员用户的所有节点。
func (r *TrafficRepository) ListAllNodes(ctx context.Context) ([]Node, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	rows, err := r.db.QueryContext(ctx, `SELECT id, username, raw_url, node_name, protocol, parsed_config, clash_config, enabled, COALESCE(tag, 'personal'), COALESCE(tags, '[]'), COALESCE(original_server, ''), COALESCE(original_domain, ''), COALESCE(inbound_tag, ''), chain_proxy_node_id, COALESCE(relay_group_name, ''), COALESCE(relay_group_node_ids, '[]'), COALESCE(node_type, 'physical'), parent_node_id, COALESCE(routed_outbound_tag, ''), COALESCE(routed_owner, 'shared'), COALESCE(relay_orig_server, ''), COALESCE(relay_orig_port, 0), created_at, updated_at FROM nodes ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list all nodes: %w", err)
	}
	defer rows.Close()

	var nodes []Node
	for rows.Next() {
		var node Node
		var enabled int
		var tagsJSON string
		var relayGroupIDsJSON string
		if err := rows.Scan(&node.ID, &node.Username, &node.RawURL, &node.NodeName, &node.Protocol, &node.ParsedConfig, &node.ClashConfig, &enabled, &node.Tag, &tagsJSON, &node.OriginalServer, &node.OriginalDomain, &node.InboundTag, &node.ChainProxyNodeID, &node.RelayGroupName, &relayGroupIDsJSON, &node.NodeType, &node.ParentNodeID, &node.RoutedOutboundTag, &node.RoutedOwner, &node.RelayOrigServer, &node.RelayOrigPort, &node.CreatedAt, &node.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan node: %w", err)
		}
		node.Enabled = enabled != 0
		scanNodeTags(&node, tagsJSON)
		scanRelayGroupNodeIDs(&node, relayGroupIDsJSON)
		nodes = append(nodes, node)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate nodes: %w", err)
	}

	return nodes, nil
}

// 通过 ID 和用户名检索单个节点。
func (r *TrafficRepository) GetNode(ctx context.Context, id int64, username string) (Node, error) {
	var node Node
	if r == nil || r.db == nil {
		return node, errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return node, errors.New("node id is required")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return node, errors.New("username is required")
	}

	var enabled int
	var tagsJSON string
	var relayGroupIDsJSON string
	row := r.db.QueryRowContext(ctx, `SELECT id, username, raw_url, node_name, protocol, parsed_config, clash_config, enabled, COALESCE(tag, 'personal'), COALESCE(tags, '[]'), COALESCE(original_server, ''), COALESCE(original_domain, ''), COALESCE(inbound_tag, ''), chain_proxy_node_id, COALESCE(relay_group_name, ''), COALESCE(relay_group_node_ids, '[]'), COALESCE(node_type, 'physical'), parent_node_id, COALESCE(routed_outbound_tag, ''), COALESCE(routed_owner, 'shared'), COALESCE(relay_orig_server, ''), COALESCE(relay_orig_port, 0), created_at, updated_at FROM nodes WHERE id = ? AND username = ? LIMIT 1`, id, username)
	if err := row.Scan(&node.ID, &node.Username, &node.RawURL, &node.NodeName, &node.Protocol, &node.ParsedConfig, &node.ClashConfig, &enabled, &node.Tag, &tagsJSON, &node.OriginalServer, &node.OriginalDomain, &node.InboundTag, &node.ChainProxyNodeID, &node.RelayGroupName, &relayGroupIDsJSON, &node.NodeType, &node.ParentNodeID, &node.RoutedOutboundTag, &node.RoutedOwner, &node.RelayOrigServer, &node.RelayOrigPort, &node.CreatedAt, &node.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return node, ErrNodeNotFound
		}
		return node, fmt.Errorf("get node: %w", err)
	}
	node.Enabled = enabled != 0
	scanNodeTags(&node, tagsJSON)
	scanRelayGroupNodeIDs(&node, relayGroupIDsJSON)

	return node, nil
}

// GetNodeByID 仅通过 ID 检索节点（供管理员使用）。
// 该函数不检查用户名。
func (r *TrafficRepository) GetNodeByID(ctx context.Context, id int64) (Node, error) {
	var node Node
	if r == nil || r.db == nil {
		return node, errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return node, errors.New("node id is required")
	}

	var enabled int
	var tagsJSON string
	var relayGroupIDsJSON string
	row := r.db.QueryRowContext(ctx, `SELECT id, username, raw_url, node_name, protocol, parsed_config, clash_config, enabled, COALESCE(tag, 'personal'), COALESCE(tags, '[]'), COALESCE(original_server, ''), COALESCE(original_domain, ''), COALESCE(inbound_tag, ''), chain_proxy_node_id, COALESCE(relay_group_name, ''), COALESCE(relay_group_node_ids, '[]'), COALESCE(node_type, 'physical'), parent_node_id, COALESCE(routed_outbound_tag, ''), COALESCE(routed_owner, 'shared'), COALESCE(relay_orig_server, ''), COALESCE(relay_orig_port, 0), created_at, updated_at FROM nodes WHERE id = ? LIMIT 1`, id)
	if err := row.Scan(&node.ID, &node.Username, &node.RawURL, &node.NodeName, &node.Protocol, &node.ParsedConfig, &node.ClashConfig, &enabled, &node.Tag, &tagsJSON, &node.OriginalServer, &node.OriginalDomain, &node.InboundTag, &node.ChainProxyNodeID, &node.RelayGroupName, &relayGroupIDsJSON, &node.NodeType, &node.ParentNodeID, &node.RoutedOutboundTag, &node.RoutedOwner, &node.RelayOrigServer, &node.RelayOrigPort, &node.CreatedAt, &node.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return node, ErrNodeNotFound
		}
		return node, fmt.Errorf("get node by id: %w", err)
	}
	node.Enabled = enabled != 0
	scanNodeTags(&node, tagsJSON)
	scanRelayGroupNodeIDs(&node, relayGroupIDsJSON)

	return node, nil
}

// 插入一个新的代理节点。
func (r *TrafficRepository) CreateNode(ctx context.Context, node Node) (Node, error) {
	if r == nil || r.db == nil {
		return Node{}, errors.New("traffic repository not initialized")
	}

	node.Username = strings.TrimSpace(node.Username)
	node.RawURL = strings.TrimSpace(node.RawURL)
	node.NodeName = strings.TrimSpace(node.NodeName)
	node.Protocol = strings.ToLower(strings.TrimSpace(node.Protocol))
	node.Tag = strings.TrimSpace(node.Tag)
	node.InboundTag = strings.TrimSpace(node.InboundTag)

	if node.Username == "" {
		return Node{}, errors.New("username is required")
	}
	// RawURL 可以为空（Clash 订阅节点），但 ClashConfig 必须存在
	if node.RawURL == "" && node.ClashConfig == "" {
		return Node{}, errors.New("raw URL or clash config is required")
	}
	if node.NodeName == "" {
		return Node{}, errors.New("node name is required")
	}
	if node.Protocol == "" {
		return Node{}, errors.New("protocol is required")
	}
	// 默认标签策略:新节点 tag 为空 / 是历史默认"手动输入" 且 OriginalServer 非空 → 用所属服务器名,
	// 让标签下拉天然按服务器分类筛选。用户显式设过 tag 的不改。
	if (node.Tag == "" || node.Tag == "手动输入") && node.OriginalServer != "" {
		node.Tag = node.OriginalServer
	}
	if node.Tag == "" {
		node.Tag = "手动输入"
	}
	tagsJSON := serializeNodeTags(&node)

	enabled := 0
	if node.Enabled {
		enabled = 1
	}

	// 互斥:中转组与单链式代理不能同时存在
	if len(node.RelayGroupNodeIDs) > 0 {
		node.ChainProxyNodeID = nil
	}
	if node.ChainProxyNodeID != nil {
		node.RelayGroupName = ""
		node.RelayGroupNodeIDs = nil
	}
	relayGroupIDsJSON := serializeRelayGroupNodeIDs(node.RelayGroupNodeIDs)

	res, err := r.db.ExecContext(ctx, `INSERT INTO nodes (username, raw_url, node_name, protocol, parsed_config, clash_config, enabled, tag, tags, original_server, original_domain, inbound_tag, chain_proxy_node_id, relay_group_name, relay_group_node_ids, relay_orig_server, relay_orig_port, ip_family) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, node.Username, node.RawURL, node.NodeName, node.Protocol, node.ParsedConfig, node.ClashConfig, enabled, node.Tag, tagsJSON, node.OriginalServer, node.OriginalDomain, node.InboundTag, node.ChainProxyNodeID, node.RelayGroupName, relayGroupIDsJSON, node.RelayOrigServer, node.RelayOrigPort, strings.TrimSpace(node.IPFamily))
	if err != nil {
		return Node{}, fmt.Errorf("create node: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return Node{}, fmt.Errorf("fetch node id: %w", err)
	}

	return r.GetNode(ctx, id, node.Username)
}

// 更新现有的代理节点。
func (r *TrafficRepository) UpdateNode(ctx context.Context, node Node) (Node, error) {
	if r == nil || r.db == nil {
		return Node{}, errors.New("traffic repository not initialized")
	}

	if node.ID <= 0 {
		return Node{}, errors.New("node id is required")
	}

	node.Username = strings.TrimSpace(node.Username)
	node.RawURL = strings.TrimSpace(node.RawURL)
	node.NodeName = strings.TrimSpace(node.NodeName)
	node.Protocol = strings.ToLower(strings.TrimSpace(node.Protocol))
	node.Tag = strings.TrimSpace(node.Tag)
	node.InboundTag = strings.TrimSpace(node.InboundTag)

	if node.Username == "" {
		return Node{}, errors.New("username is required")
	}
	// RawURL 可以为空（Clash 订阅节点），但 ClashConfig 必须存在
	if node.RawURL == "" && node.ClashConfig == "" {
		return Node{}, errors.New("raw URL or clash config is required")
	}
	if node.NodeName == "" {
		return Node{}, errors.New("node name is required")
	}
	if node.Protocol == "" {
		return Node{}, errors.New("protocol is required")
	}
	if node.Tag == "" {
		node.Tag = "手动输入"
	}
	tagsJSON := serializeNodeTags(&node)

	enabled := 0
	if node.Enabled {
		enabled = 1
	}

	// 互斥:中转组与单链式代理不能同时存在
	if len(node.RelayGroupNodeIDs) > 0 {
		node.ChainProxyNodeID = nil
	}
	if node.ChainProxyNodeID != nil {
		node.RelayGroupName = ""
		node.RelayGroupNodeIDs = nil
	}
	relayGroupIDsJSON := serializeRelayGroupNodeIDs(node.RelayGroupNodeIDs)

	res, err := r.db.ExecContext(ctx, `UPDATE nodes SET raw_url = ?, node_name = ?, protocol = ?, parsed_config = ?, clash_config = ?, enabled = ?, tag = ?, tags = ?, original_server = ?, original_domain = ?, inbound_tag = ?, chain_proxy_node_id = ?, relay_group_name = ?, relay_group_node_ids = ?, relay_orig_server = ?, relay_orig_port = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND username = ?`, node.RawURL, node.NodeName, node.Protocol, node.ParsedConfig, node.ClashConfig, enabled, node.Tag, tagsJSON, node.OriginalServer, node.OriginalDomain, node.InboundTag, node.ChainProxyNodeID, node.RelayGroupName, relayGroupIDsJSON, node.RelayOrigServer, node.RelayOrigPort, node.ID, node.Username)
	if err != nil {
		return Node{}, fmt.Errorf("update node: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return Node{}, fmt.Errorf("node update rows affected: %w", err)
	}
	if affected == 0 {
		return Node{}, ErrNodeNotFound
	}

	return r.GetNode(ctx, node.ID, node.Username)
}

// 删除代理节点。
func (r *TrafficRepository) DeleteNode(ctx context.Context, id int64, username string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return errors.New("node id is required")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}

	// 获取节点的 raw_url，用于后续检查外部订阅
	var rawURL string
	err := r.db.QueryRowContext(ctx, `SELECT raw_url FROM nodes WHERE id = ? AND username = ?`, id, username).Scan(&rawURL)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrNodeNotFound
		}
		return fmt.Errorf("get node raw_url: %w", err)
	}
	// DB-level cascade for every caller, including sync/import paths which do
	// not pass through the HTTP handler. SQLite upgrades cannot rely on FK
	// cascades here because user_subaccounts historically had no node FK.
	_, _ = r.db.ExecContext(ctx, `DELETE FROM user_subaccounts WHERE routed_node_id = ? OR routed_node_id IN (SELECT id FROM nodes WHERE parent_node_id = ? AND node_type = 'routed')`, id, id)
	_, _ = r.db.ExecContext(ctx, `DELETE FROM nodes WHERE parent_node_id = ? AND node_type = 'routed'`, id)

	res, err := r.db.ExecContext(ctx, `DELETE FROM nodes WHERE id = ? AND username = ?`, id, username)
	if err != nil {
		return fmt.Errorf("delete node: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("node delete rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNodeNotFound
	}

	// 清除引用了该节点作为中转节点的 chain_proxy_node_id
	_, _ = r.db.ExecContext(ctx, `UPDATE nodes SET chain_proxy_node_id = NULL WHERE chain_proxy_node_id = ? AND username = ?`, id, username)
	// 从其他节点的中转组成员中移除该节点;若中转组因此为空,清除整个中转组配置(防悬空引用)
	r.pruneRelayGroupMember(ctx, id, username)

	// 检查该 raw_url 是否还有其他节点使用
	// 如果没有，则删除对应的外部订阅及其关联的代理集合配置
	if rawURL != "" {
		var count int
		err = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE username = ? AND raw_url = ?`, username, rawURL).Scan(&count)
		if err != nil {
			// 记录错误但不影响删除节点的操作
			return nil
		}

		// 如果没有节点使用该订阅链接，删除外部订阅
		if count == 0 {
			// 首先获取外部订阅的 ID
			var subID int64
			err = r.db.QueryRowContext(ctx, `SELECT id FROM external_subscriptions WHERE username = ? AND url = ?`, username, rawURL).Scan(&subID)
			if err == nil && subID > 0 {
				// 删除关联的代理集合配置
				_, _ = r.db.ExecContext(ctx, `DELETE FROM proxy_provider_configs WHERE external_subscription_id = ?`, subID)
			}
			// 删除外部订阅
			_, err = r.db.ExecContext(ctx, `DELETE FROM external_subscriptions WHERE username = ? AND url = ?`, username, rawURL)
			if err != nil {
				// 记录错误但不影响删除节点的操作
				// 可以在这里添加日志记录
			}
		}
	}

	return nil
}

// DeleteNodeForSync 删除节点但不触发外部订阅清理。
// 用于同步流程中安全地清理过滤节点。
func (r *TrafficRepository) DeleteNodeForSync(ctx context.Context, id int64, username string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return errors.New("node id is required")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}

	var owned int
	if err := r.db.QueryRowContext(ctx, `SELECT 1 FROM nodes WHERE id = ? AND username = ?`, id, username).Scan(&owned); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNodeNotFound
		}
		return fmt.Errorf("check node ownership for sync delete: %w", err)
	}
	_, _ = r.db.ExecContext(ctx, `DELETE FROM user_subaccounts WHERE routed_node_id = ? OR routed_node_id IN (SELECT id FROM nodes WHERE parent_node_id = ? AND node_type = 'routed')`, id, id)
	_, _ = r.db.ExecContext(ctx, `DELETE FROM nodes WHERE parent_node_id = ? AND node_type = 'routed'`, id)
	res, err := r.db.ExecContext(ctx, `DELETE FROM nodes WHERE id = ? AND username = ?`, id, username)
	if err != nil {
		return fmt.Errorf("delete node for sync: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("node delete for sync rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNodeNotFound
	}

	_, _ = r.db.ExecContext(ctx, `UPDATE nodes SET chain_proxy_node_id = NULL WHERE chain_proxy_node_id = ? AND username = ?`, id, username)
	r.pruneRelayGroupMember(ctx, id, username)

	return nil
}

// DeleteNodeByID 仅按 ID 删除代理节点（供管理员使用）。
// 该功能不检查用户名，允许管理员删除任何节点。
func (r *TrafficRepository) DeleteNodeByID(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return errors.New("node id is required")
	}

	// 获取节点信息以进行清理
	var rawURL, username string
	err := r.db.QueryRowContext(ctx, `SELECT raw_url, username FROM nodes WHERE id = ?`, id).Scan(&rawURL, &username)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrNodeNotFound
		}
		return fmt.Errorf("get node info: %w", err)
	}
	_, _ = r.db.ExecContext(ctx, `DELETE FROM user_subaccounts WHERE routed_node_id = ? OR routed_node_id IN (SELECT id FROM nodes WHERE parent_node_id = ? AND node_type = 'routed')`, id, id)
	_, _ = r.db.ExecContext(ctx, `DELETE FROM nodes WHERE parent_node_id = ? AND node_type = 'routed'`, id)

	res, err := r.db.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete node: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("node delete rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNodeNotFound
	}

	// 清除引用了该节点作为中转节点的 chain_proxy_node_id
	_, _ = r.db.ExecContext(ctx, `UPDATE nodes SET chain_proxy_node_id = NULL WHERE chain_proxy_node_id = ?`, id)
	// username 由前面 SELECT 查出;从其他节点的中转组成员中移除该节点,防悬空引用
	r.pruneRelayGroupMember(ctx, id, username)

	// 级联清理该节点(若为 routed 节点)的用户子账号凭据,避免留下孤儿:
	// 否则 user-nodes/node-users 详情会因 routed 节点已删而把这些子账号的流量丢弃,
	// 且 SQLite 外键未开启(无 ON DELETE CASCADE 生效)。物理节点 id 不会匹配任何
	// 子账号的 routed_node_id,对物理节点删除是 no-op。
	_, _ = r.db.ExecContext(ctx, `DELETE FROM user_subaccounts WHERE routed_node_id = ?`, id)

	// 如果没有其他节点使用相同的 raw_url，则清除外部订阅
	if rawURL != "" && username != "" {
		var count int
		err = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE username = ? AND raw_url = ?`, username, rawURL).Scan(&count)
		if err == nil && count == 0 {
			var subID int64
			err = r.db.QueryRowContext(ctx, `SELECT id FROM external_subscriptions WHERE username = ? AND url = ?`, username, rawURL).Scan(&subID)
			if err == nil && subID > 0 {
				_, _ = r.db.ExecContext(ctx, `DELETE FROM proxy_provider_configs WHERE external_subscription_id = ?`, subID)
			}
			_, _ = r.db.ExecContext(ctx, `DELETE FROM external_subscriptions WHERE username = ? AND url = ?`, username, rawURL)
		}
	}

	return nil
}

// 在单个事务中创建多个节点。
func (r *TrafficRepository) BatchCreateNodes(ctx context.Context, nodes []Node) ([]Node, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	if len(nodes) == 0 {
		return nil, errors.New("nodes list is empty")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin batch create nodes tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO nodes (username, raw_url, node_name, protocol, parsed_config, clash_config, enabled, tag, tags, original_server, original_domain, inbound_tag, chain_proxy_node_id, relay_group_name, relay_group_node_ids, relay_orig_server, relay_orig_port) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return nil, fmt.Errorf("prepare insert node: %w", err)
	}
	defer stmt.Close()

	var createdIDs []int64
	for idx, node := range nodes {
		node.Username = strings.TrimSpace(node.Username)
		node.RawURL = strings.TrimSpace(node.RawURL)
		node.NodeName = strings.TrimSpace(node.NodeName)
		node.Protocol = strings.ToLower(strings.TrimSpace(node.Protocol))
		node.Tag = strings.TrimSpace(node.Tag)
		node.InboundTag = strings.TrimSpace(node.InboundTag)

		if node.Username == "" {
			return nil, fmt.Errorf("node %d: username is required", idx+1)
		}
		// RawURL 可以为空（Clash 订阅节点），但 ClashConfig 必须存在
		if node.RawURL == "" && node.ClashConfig == "" {
			return nil, fmt.Errorf("node %d: raw URL or clash config is required", idx+1)
		}
		if node.NodeName == "" {
			return nil, fmt.Errorf("node %d: node name is required", idx+1)
		}
		if node.Protocol == "" {
			return nil, fmt.Errorf("node %d: protocol is required", idx+1)
		}
		// 默认标签策略同 CreateNode:tag 空 / "手动输入" 时改用 OriginalServer
		if (node.Tag == "" || node.Tag == "手动输入") && node.OriginalServer != "" {
			node.Tag = node.OriginalServer
		}
		if node.Tag == "" {
			node.Tag = "手动输入"
		}
		tagsJSON := serializeNodeTags(&node)

		enabled := 0
		if node.Enabled {
			enabled = 1
		}

		res, err := stmt.ExecContext(ctx, node.Username, node.RawURL, node.NodeName, node.Protocol, node.ParsedConfig, node.ClashConfig, enabled, node.Tag, tagsJSON, node.OriginalServer, node.OriginalDomain, node.InboundTag, node.ChainProxyNodeID, node.RelayGroupName, serializeRelayGroupNodeIDs(node.RelayGroupNodeIDs), node.RelayOrigServer, node.RelayOrigPort)
		if err != nil {
			return nil, fmt.Errorf("insert node %d: %w", idx+1, err)
		}

		id, err := res.LastInsertId()
		if err != nil {
			return nil, fmt.Errorf("fetch node %d id: %w", idx+1, err)
		}

		createdIDs = append(createdIDs, id)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit batch create nodes: %w", err)
	}

	// 获取创建的节点
	var created []Node
	for i, id := range createdIDs {
		node, err := r.GetNode(ctx, id, nodes[i].Username)
		if err != nil {
			return nil, fmt.Errorf("fetch created node %d: %w", i+1, err)
		}
		created = append(created, node)
	}

	return created, nil
}

// 删除特定用户的所有节点。
func (r *TrafficRepository) DeleteAllUserNodes(ctx context.Context, username string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}

	_, _ = r.db.ExecContext(ctx, `DELETE FROM user_subaccounts WHERE routed_node_id IN (
		SELECT id FROM nodes WHERE username = ? OR parent_node_id IN (SELECT id FROM nodes WHERE username = ?)
	)`, username, username)
	_, _ = r.db.ExecContext(ctx, `DELETE FROM nodes WHERE node_type = 'routed' AND parent_node_id IN (SELECT id FROM nodes WHERE username = ?)`, username)
	_, err := r.db.ExecContext(ctx, `DELETE FROM nodes WHERE username = ?`, username)
	if err != nil {
		return fmt.Errorf("delete all user nodes: %w", err)
	}

	return nil
}

// DeleteNodesByInboundTag 删除与服务器名称和入站标记匹配的所有节点。
// 从远程服务器删除入站时使用。
func (r *TrafficRepository) DeleteNodesByInboundTag(ctx context.Context, serverName, inboundTag string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}

	serverName = strings.TrimSpace(serverName)
	inboundTag = strings.TrimSpace(inboundTag)
	if serverName == "" || inboundTag == "" {
		return 0, errors.New("server name and inbound tag are required")
	}

	_, _ = r.db.ExecContext(ctx, `DELETE FROM user_subaccounts WHERE routed_node_id IN (SELECT id FROM nodes WHERE original_server = ? AND inbound_tag = ?)`, serverName, inboundTag)
	res, err := r.db.ExecContext(ctx, `DELETE FROM nodes WHERE original_server = ? AND inbound_tag = ?`, serverName, inboundTag)
	if err != nil {
		return 0, fmt.Errorf("delete nodes by inbound tag: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete nodes rows affected: %w", err)
	}

	return affected, nil
}

// RefreshNodesServerAddress 把指定服务器下所有节点的 clash_config.server 字段批量替换为 newAddr。
// 场景:服务器 IP 漂移 / 新配置了域名,要把已存在的节点同步指向新地址。
// 用 SQLite JSON1 的 json_set + json_extract,跳过 server 字段已经等于 newAddr 的行。
// 返回实际改动的行数。
func (r *TrafficRepository) RefreshNodesServerAddress(ctx context.Context, serverName, newAddr string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	serverName = strings.TrimSpace(serverName)
	newAddr = strings.TrimSpace(newAddr)
	if serverName == "" || newAddr == "" {
		return 0, nil
	}
	// 只刷 v4/域名/通用节点(ip_family != 'v6')。v6 节点(含用 v6 域名、server 不含冒号的)由
	// RefreshNodesServerAddressV6 单独刷新,不在此被 v4 地址污染 —— 按 ip_family 列而非"是否含冒号"判定,
	// 因为 v6 节点改用 v6 域名后 server 不再含冒号。
	res, err := r.db.ExecContext(ctx, `
		UPDATE nodes
		SET clash_config = json_set(clash_config, '$.server', ?),
		    updated_at = CURRENT_TIMESTAMP
		WHERE original_server = ?
		  AND clash_config IS NOT NULL
		  AND json_valid(clash_config) = 1
		  AND IFNULL(relay_orig_server, '') = ''
		  AND IFNULL(ip_family, '') != 'v6'
		  AND IFNULL(json_extract(clash_config, '$.server'), '') != ?
	`, newAddr, serverName, newAddr)
	if err != nil {
		return 0, fmt.Errorf("refresh node server address: %w", err)
	}
	affected, _ := res.RowsAffected()

	// 上面的 UPDATE 刻意跳过了配中转的节点(它们的 clash.server 是**中转地址**,不能动),
	// 但那些节点记录的「原始地址」relay_orig_server 同样指向本服务器,IP 漂移后一样会失效
	// —— 取消中转时会把节点还原成一个早已不通的旧 IP。这里补上它。
	if n, rerr := r.refreshRelayOrigServerAddress(ctx, serverName, newAddr); rerr != nil {
		return affected, rerr
	} else {
		affected += n
	}
	return affected, nil
}

// refreshRelayOrigServerAddress 把配了中转的节点的「原始地址」(relay_orig_server)同步到 newAddr。
//
// 只动 **IP 形态** 的原始地址:域名本来就免疫 IP 漂移,按"配了域名的无需修改"的约定保持不变。
// IP/域名判定放在 Go 层用 net.ParseIP 做 —— SQL 里靠 GLOB 猜 IPv4 形态既不准也覆盖不到 IPv6。
// 配中转的节点通常只有个位数,逐行更新的开销可以忽略。
func (r *TrafficRepository) refreshRelayOrigServerAddress(ctx context.Context, serverName, newAddr string) (int64, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, IFNULL(relay_orig_server, '') FROM nodes
		 WHERE original_server = ? AND IFNULL(relay_orig_server, '') != '' AND IFNULL(relay_orig_server, '') != ?`,
		serverName, newAddr)
	if err != nil {
		return 0, fmt.Errorf("list relay nodes: %w", err)
	}
	type relayNode struct {
		id   int64
		orig string
	}
	var targets []relayNode
	for rows.Next() {
		var n relayNode
		if err := rows.Scan(&n.id, &n.orig); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan relay node: %w", err)
		}
		// 域名不动 —— 它不受 IP 漂移影响,改成新 IP 反而是降级。
		if net.ParseIP(strings.TrimSpace(n.orig)) == nil {
			continue
		}
		targets = append(targets, n)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate relay nodes: %w", err)
	}
	rows.Close()

	var updated int64
	for _, t := range targets {
		res, uerr := r.db.ExecContext(ctx,
			`UPDATE nodes SET relay_orig_server = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
			newAddr, t.id)
		if uerr != nil {
			return updated, fmt.Errorf("update relay_orig_server for node %d: %w", t.id, uerr)
		}
		n, _ := res.RowsAffected()
		updated += n
	}
	return updated, nil
}

// RefreshNodesServerAddressV6 把指定服务器下「IPv6 节点」(clash server 含 ':')的 server 字段
// 批量替换为 newV6。与 RefreshNodesServerAddress 互补:前者只动 v4/域名节点,本函数只动 v6 节点。
// IP 漂移时两者分别用各自的新地址调用,保证 v4/v6 双节点不串。
func (r *TrafficRepository) RefreshNodesServerAddressV6(ctx context.Context, serverName, newV6 string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	serverName = strings.TrimSpace(serverName)
	newV6 = strings.TrimSpace(newV6)
	if serverName == "" || newV6 == "" {
		return 0, nil
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE nodes
		SET clash_config = json_set(clash_config, '$.server', ?),
		    updated_at = CURRENT_TIMESTAMP
		WHERE original_server = ?
		  AND clash_config IS NOT NULL
		  AND json_valid(clash_config) = 1
		  AND IFNULL(relay_orig_server, '') = ''
		  AND IFNULL(ip_family, '') = 'v6'
		  AND IFNULL(json_extract(clash_config, '$.server'), '') LIKE '%:%'
		  AND IFNULL(json_extract(clash_config, '$.server'), '') != ?
	`, newV6, serverName, newV6)
	if err != nil {
		return 0, fmt.Errorf("refresh node server address v6: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected, nil
}

// 当服务器名称更改时，UpdateNodesByServerName 会更新所有节点。
// 这将更新该服务器中节点的original_server 字段和tag 字段。
func (r *TrafficRepository) UpdateNodesByServerName(ctx context.Context, oldName, newName string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}

	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if oldName == "" || newName == "" {
		return 0, errors.New("old name and new name are required")
	}

	if oldName == newName {
		return 0, nil
	}

	// 更新original_server和tag字段
	// 同时更新包含 [server_name] 前缀的node_name
	res, err := r.db.ExecContext(ctx, `
		UPDATE nodes
		SET original_server = ?,
		    tag = REPLACE(tag, ?, ?),
		    node_name = REPLACE(node_name, ?, ?),
		    updated_at = CURRENT_TIMESTAMP
		WHERE original_server = ?`,
		newName,
		"远程:"+oldName, "远程:"+newName,
		"["+oldName+"]", "["+newName+"]",
		oldName)
	if err != nil {
		return 0, fmt.Errorf("update nodes by server name: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("update nodes rows affected: %w", err)
	}

	return affected, nil
}

// 按服务器名称和入站标签更新节点配置。
// family 限定只更新某一 IP 版本的节点(按 ip_family 列判定,不再靠 clash server 是否含冒号):
//
//	"" → 全部(向后兼容);"v4" → 只更新 v4/域名/通用节点(ip_family != 'v6');"v6" → 只更新 IPv6 节点(ip_family = 'v6')。
//
// v4/v6 双节点共享同一 inbound_tag,编辑入站时需各自用对应 server 的配置分别更新,避免互相覆盖。
func (r *TrafficRepository) UpdateNodeByInboundTag(ctx context.Context, serverName, inboundTag, clashConfig, family string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	serverName = strings.TrimSpace(serverName)
	inboundTag = strings.TrimSpace(inboundTag)
	if serverName == "" || inboundTag == "" {
		return errors.New("server name and inbound tag are required")
	}

	query := `
		UPDATE nodes
		SET clash_config = ?, parsed_config = ?, updated_at = CURRENT_TIMESTAMP
		WHERE original_server = ? AND inbound_tag = ?
		  AND COALESCE(node_type, 'physical') != 'routed'`
	switch family {
	case "v4":
		query += ` AND IFNULL(ip_family, '') != 'v6'`
	case "v6":
		query += ` AND IFNULL(ip_family, '') = 'v6'`
	}

	_, err := r.db.ExecContext(ctx, query, clashConfig, clashConfig, serverName, inboundTag)
	if err != nil {
		return fmt.Errorf("update node by inbound tag: %w", err)
	}

	return nil
}

// HasOtherNodesOnInbound 判断某 (original_server, inbound_tag) 下,除 excludeIDs 之外是否还有别的节点。
// 用于双栈删除守卫:v4/v6 双节点共享同一 inbound_tag,删其中一个时若还有兄弟节点,应只删节点、
// 保留远程入站;两个都删了(都在 excludeIDs 里)才删入站。
func (r *TrafficRepository) HasOtherNodesOnInbound(ctx context.Context, serverName, inboundTag string, excludeIDs []int64) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("traffic repository not initialized")
	}
	serverName = strings.TrimSpace(serverName)
	inboundTag = strings.TrimSpace(inboundTag)
	if serverName == "" || inboundTag == "" {
		return false, nil
	}
	query := `SELECT 1 FROM nodes WHERE original_server = ? AND inbound_tag = ?`
	args := []any{serverName, inboundTag}
	if len(excludeIDs) > 0 {
		placeholders := make([]string, len(excludeIDs))
		for i, id := range excludeIDs {
			placeholders[i] = "?"
			args = append(args, id)
		}
		query += ` AND id NOT IN (` + strings.Join(placeholders, ",") + `)`
	}
	query += ` LIMIT 1`
	var one int
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("has other nodes on inbound: %w", err)
	}
	return true, nil
}

// ===== 路由出站(routed node)专用 CRUD =====
// routed 节点是一个虚拟节点:挂在某物理父节点下,代表"该 inbound 上一条 marktag-rule + 一个 outbound"。
// 套餐绑用户时自动给用户开子账号(user_subaccounts)并加进 rule.user 数组。

// 插入一条 routed 节点。基本字段(username/raw_url/node_name/protocol 等)由调用方传入,
// 路由出站元数据(outbound/rule/admin)单独写入 routed_* 列。
func (r *TrafficRepository) CreateRoutedNode(ctx context.Context, detail RoutedNodeDetail) (RoutedNodeDetail, error) {
	if r == nil || r.db == nil {
		return RoutedNodeDetail{}, errors.New("traffic repository not initialized")
	}
	n := detail.Node
	n.NodeName = strings.TrimSpace(n.NodeName)
	if n.NodeName == "" {
		return RoutedNodeDetail{}, errors.New("node name is required")
	}
	if n.ParentNodeID == nil || *n.ParentNodeID <= 0 {
		return RoutedNodeDetail{}, errors.New("parent_node_id is required for routed node")
	}
	if detail.RoutedOutboundTag == "" || detail.RoutedRuleMarktag == "" {
		return RoutedNodeDetail{}, errors.New("routed_outbound_tag, routed_rule_marktag are required")
	}
	// 注:RoutedAdminEmail 允许为空 — 用户私有路由出站(routed_owner='user')无 admin 占位 client。
	enabled := 0
	if n.Enabled {
		enabled = 1
	}
	if n.Tag == "" {
		n.Tag = "路由出站"
	}
	if n.Protocol == "" {
		n.Protocol = "routed"
	}
	owner := strings.TrimSpace(n.RoutedOwner)
	if owner == "" {
		owner = "shared"
	}
	// routed 节点的多标签同步 — 不动 Tag(已根据 "路由出站" 默认值兜底),仅序列化 Tags
	tagsJSON := serializeNodeTags(&n)
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO nodes (
			username, raw_url, node_name, protocol, parsed_config, clash_config, enabled, tag, tags,
			original_server, original_domain, inbound_tag, chain_proxy_node_id,
			node_type, parent_node_id,
			routed_outbound_tag, routed_outbound_json, routed_rule_marktag,
			routed_admin_email, routed_admin_credential, routed_owner
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'routed', ?, ?, ?, ?, ?, ?, ?)`,
		n.Username, n.RawURL, n.NodeName, n.Protocol, n.ParsedConfig, n.ClashConfig, enabled, n.Tag, tagsJSON,
		n.OriginalServer, n.OriginalDomain, n.InboundTag, n.ChainProxyNodeID,
		*n.ParentNodeID,
		detail.RoutedOutboundTag, detail.RoutedOutboundJSON, detail.RoutedRuleMarktag,
		detail.RoutedAdminEmail, detail.RoutedAdminCredential, owner,
	)
	if err != nil {
		return RoutedNodeDetail{}, fmt.Errorf("create routed node: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return RoutedNodeDetail{}, fmt.Errorf("fetch routed node id: %w", err)
	}
	return r.GetRoutedNodeDetail(ctx, id)
}

// 按 id 读取 routed 节点完整元数据(含 routed_* 字段)。
func (r *TrafficRepository) GetRoutedNodeDetail(ctx context.Context, id int64) (RoutedNodeDetail, error) {
	if r == nil || r.db == nil {
		return RoutedNodeDetail{}, errors.New("traffic repository not initialized")
	}
	var d RoutedNodeDetail
	var enabled int
	err := r.db.QueryRowContext(ctx, `
		SELECT id, username, raw_url, node_name, protocol, parsed_config, clash_config, enabled,
		       COALESCE(tag, ''), COALESCE(original_server, ''), COALESCE(original_domain, ''),
		       COALESCE(inbound_tag, ''), chain_proxy_node_id,
		       COALESCE(node_type, 'physical'), parent_node_id,
		       COALESCE(routed_outbound_tag, ''), COALESCE(routed_outbound_json, ''),
		       COALESCE(routed_rule_marktag, ''),
		       COALESCE(routed_admin_email, ''), COALESCE(routed_admin_credential, ''),
		       COALESCE(routed_owner, 'shared'),
		       created_at, updated_at
		FROM nodes WHERE id = ? LIMIT 1`, id).Scan(
		&d.ID, &d.Username, &d.RawURL, &d.NodeName, &d.Protocol, &d.ParsedConfig, &d.ClashConfig, &enabled,
		&d.Tag, &d.OriginalServer, &d.OriginalDomain,
		&d.InboundTag, &d.ChainProxyNodeID,
		&d.NodeType, &d.ParentNodeID,
		&d.RoutedOutboundTag, &d.RoutedOutboundJSON,
		&d.RoutedRuleMarktag,
		&d.RoutedAdminEmail, &d.RoutedAdminCredential,
		&d.RoutedOwner,
		&d.CreatedAt, &d.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RoutedNodeDetail{}, ErrNodeNotFound
		}
		return RoutedNodeDetail{}, fmt.Errorf("get routed node detail: %w", err)
	}
	d.Enabled = enabled != 0
	return d, nil
}

// 列出某物理父节点下所有 routed 子节点(管理员视角)。
func (r *TrafficRepository) ListRoutedNodesByParent(ctx context.Context, parentNodeID int64) ([]RoutedNodeDetail, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, username, raw_url, node_name, protocol, parsed_config, clash_config, enabled,
		       COALESCE(tag, ''), COALESCE(original_server, ''), COALESCE(original_domain, ''),
		       COALESCE(inbound_tag, ''), chain_proxy_node_id,
		       COALESCE(node_type, 'physical'), parent_node_id,
		       COALESCE(routed_outbound_tag, ''), COALESCE(routed_outbound_json, ''),
		       COALESCE(routed_rule_marktag, ''),
		       COALESCE(routed_admin_email, ''), COALESCE(routed_admin_credential, ''),
		       COALESCE(routed_owner, 'shared'),
		       created_at, updated_at
		FROM nodes WHERE node_type = 'routed' AND parent_node_id = ? ORDER BY created_at DESC`, parentNodeID)
	if err != nil {
		return nil, fmt.Errorf("list routed nodes by parent: %w", err)
	}
	defer rows.Close()
	var out []RoutedNodeDetail
	for rows.Next() {
		var d RoutedNodeDetail
		var enabled int
		if err := rows.Scan(
			&d.ID, &d.Username, &d.RawURL, &d.NodeName, &d.Protocol, &d.ParsedConfig, &d.ClashConfig, &enabled,
			&d.Tag, &d.OriginalServer, &d.OriginalDomain,
			&d.InboundTag, &d.ChainProxyNodeID,
			&d.NodeType, &d.ParentNodeID,
			&d.RoutedOutboundTag, &d.RoutedOutboundJSON,
			&d.RoutedRuleMarktag,
			&d.RoutedAdminEmail, &d.RoutedAdminCredential,
			&d.RoutedOwner,
			&d.CreatedAt, &d.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan routed node: %w", err)
		}
		d.Enabled = enabled != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

const primaryAdminUsernameSetting = "primary_admin_username"

// GetPrimaryAdminUsername returns the immutable logical owner of this master.
// Fresh installations persist it during setup. Upgraded databases backfill it
// once from the earliest-created user, so adding another role='admin' row later
// cannot grant ownership or TG administrator privileges.
func (r *TrafficRepository) GetPrimaryAdminUsername(ctx context.Context) string {
	if r == nil || r.db == nil {
		return "admin"
	}
	if username, err := r.GetSystemSetting(ctx, primaryAdminUsernameSetting); err == nil && strings.TrimSpace(username) != "" {
		return strings.TrimSpace(username)
	}
	var username string
	err := r.db.QueryRowContext(ctx, `SELECT username FROM users ORDER BY created_at ASC, username ASC LIMIT 1`).Scan(&username)
	if err != nil || strings.TrimSpace(username) == "" {
		return "admin"
	}
	username = strings.TrimSpace(username)
	// Best effort: concurrent callers choose the same deterministic first row.
	_ = r.SetSystemSetting(ctx, primaryAdminUsernameSetting, username)
	return username
}

func (r *TrafficRepository) SetPrimaryAdminUsername(ctx context.Context, username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("primary admin username is required")
	}
	return r.SetSystemSetting(ctx, primaryAdminUsernameSetting, username)
}

// GetSystemNodeOwner 返回"系统节点"应该归属的 username。
// 用途:NodeSyncListener 自动同步、remote_manage 批量同步等"系统侧"创建节点时,需要一个
// username 字段来归属节点。不能硬编码 "admin" 字面字符串(系统里 admin 用户名可能是注册时
// 任意输入的)。本函数按 created_at 升序取第一个 role='admin' 的用户名;若系统中无 admin
// (极端情况),回退到字面字符串 "admin" 以保持与旧行为兼容。
func (r *TrafficRepository) GetSystemNodeOwner(ctx context.Context) string {
	return r.GetPrimaryAdminUsername(ctx)
}

// ListNonAdminUsernames 返回所有 role != 'admin' 的用户名集合(即"普通用户")。
// 用途:admin 视角的节点过滤 — admin 看到所有非"普通用户私有"的节点。
// 设计原因:NodeSyncListener 自动同步节点时硬编码 username="admin"(字面字符串,
// 不一定对应真实 admin 账号),所以"反向过滤"比"白名单 admin"更安全。
func (r *TrafficRepository) ListNonAdminUsernames(ctx context.Context) (map[string]bool, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT username FROM users WHERE role != ?`, RoleAdmin)
	if err != nil {
		return nil, fmt.Errorf("list non-admin usernames: %w", err)
	}
	defer rows.Close()
	out := make(map[string]bool)
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out[u] = true
	}
	return out, rows.Err()
}

// LogUserRoutedOutboundAction 记录一次用户路由出站操作(create/delete),用于"每日次数限制"。
// 每次 routing 变更都会触发 agent 重启 xray,频次必须受控。
func (r *TrafficRepository) LogUserRoutedOutboundAction(ctx context.Context, username, action string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO user_routed_outbound_actions(username, action) VALUES(?, ?)`,
		username, action,
	)
	return err
}

// CountUserRoutedOutboundActionsToday 统计某用户当日(本地时间起始)以来的操作次数。
func (r *TrafficRepository) CountUserRoutedOutboundActionsToday(ctx context.Context, username string) (int, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	var n int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM user_routed_outbound_actions WHERE username = ? AND created_at >= ?`,
		username, dayStart.UTC().Format("2006-01-02 15:04:05"),
	).Scan(&n)
	return n, err
}

// MarkNodeAsRouted 将一个已存在的物理节点升级为路由出站节点。
// 用途:同步 inbound 时发现节点的客户端 email 命中 xray routing.rules.user[] 且有具体 outboundTag,
// 则把 node_type 标记为 routed,写入 routed_outbound_tag,并把 parent_node_id 指向同一 inbound 下的 master 节点。
// 只对当前为 physical 的节点生效,避免覆盖手动配置或 routed_owner=user 的私有路由出站节点。
// parentNodeID == 0 表示不知道 master,只更 type/tag,parent 留空(此时路由出站管理面板暂时查不到该节点,等下次同步时回填)。
func (r *TrafficRepository) MarkNodeAsRouted(ctx context.Context, nodeID int64, outboundTag string, parentNodeID int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if parentNodeID > 0 {
		_, err := r.db.ExecContext(ctx,
			`UPDATE nodes SET node_type = 'routed', routed_outbound_tag = ?, parent_node_id = ?, updated_at = CURRENT_TIMESTAMP
			 WHERE id = ? AND (node_type IS NULL OR node_type = '' OR node_type = 'physical' OR (node_type = 'routed' AND parent_node_id IS NULL))`,
			outboundTag, parentNodeID, nodeID,
		)
		return err
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE nodes SET node_type = 'routed', routed_outbound_tag = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE id = ? AND (node_type IS NULL OR node_type = '' OR node_type = 'physical')`,
		outboundTag, nodeID,
	)
	return err
}

// UpdateNodeInboundTag 把已绑定服务器节点的 inbound_tag 改为新值。
// 用途:dedup 时通过 clash 配置指纹匹配到已存在节点,但 agent 这次扫到的 inbound_tag 与库里的不一致
// (用户改了 tag,或老版本 agent tag 命名规则与新版不同),把库里 tag 校正过去,下次同步直接走 tag 匹配。
func (r *TrafficRepository) UpdateNodeInboundTag(ctx context.Context, nodeID int64, inboundTag string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE nodes SET inbound_tag = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		inboundTag, nodeID,
	)
	return err
}

// ClaimExternalNode 把一个"外部节点"(original_server=” AND inbound_tag=”)升级为受管节点:
// 填上 original_server / inbound_tag / tag / clash_config(用 agent 转出来的新 config 覆盖)。
// 用于迁移场景下,把 mmw 时代手工录入的节点跟 agent 扫描出来的同 server:port 入站绑定。
func (r *TrafficRepository) ClaimExternalNode(ctx context.Context, nodeID int64, originalServer, inboundTag, tag, clashConfig string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE nodes SET original_server = ?, inbound_tag = ?, tag = ?, clash_config = ?, parsed_config = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE id = ? AND (original_server IS NULL OR original_server = '')
		   AND (inbound_tag IS NULL OR inbound_tag = '')`,
		originalServer, inboundTag, tag, clashConfig, clashConfig, nodeID,
	)
	return err
}

// CountUserRoutedOutbounds 统计某用户创建的"用户私有路由出站"数量(routed_owner='user'),用于配额校验。
func (r *TrafficRepository) CountUserRoutedOutbounds(ctx context.Context, username string) (int, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	var n int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM nodes WHERE node_type='routed' AND routed_owner='user' AND username = ?`,
		username,
	).Scan(&n)
	return n, err
}

// ListUserRoutedOutbounds 列出某用户创建的私有路由出站(routed_owner='user'),按创建时间倒序。
func (r *TrafficRepository) ListUserRoutedOutbounds(ctx context.Context, username string) ([]RoutedNodeDetail, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, username, raw_url, node_name, protocol, parsed_config, clash_config, enabled,
		       COALESCE(tag, ''), COALESCE(original_server, ''), COALESCE(original_domain, ''),
		       COALESCE(inbound_tag, ''), chain_proxy_node_id,
		       COALESCE(node_type, 'physical'), parent_node_id,
		       COALESCE(routed_outbound_tag, ''), COALESCE(routed_outbound_json, ''),
		       COALESCE(routed_rule_marktag, ''),
		       COALESCE(routed_admin_email, ''), COALESCE(routed_admin_credential, ''),
		       COALESCE(routed_owner, 'shared'),
		       created_at, updated_at
		FROM nodes WHERE node_type='routed' AND routed_owner='user' AND username = ? ORDER BY created_at DESC`, username)
	if err != nil {
		return nil, fmt.Errorf("list user routed outbounds: %w", err)
	}
	defer rows.Close()
	var out []RoutedNodeDetail
	for rows.Next() {
		var d RoutedNodeDetail
		var enabled int
		if err := rows.Scan(
			&d.ID, &d.Username, &d.RawURL, &d.NodeName, &d.Protocol, &d.ParsedConfig, &d.ClashConfig, &enabled,
			&d.Tag, &d.OriginalServer, &d.OriginalDomain,
			&d.InboundTag, &d.ChainProxyNodeID,
			&d.NodeType, &d.ParentNodeID,
			&d.RoutedOutboundTag, &d.RoutedOutboundJSON,
			&d.RoutedRuleMarktag,
			&d.RoutedAdminEmail, &d.RoutedAdminCredential,
			&d.RoutedOwner,
			&d.CreatedAt, &d.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan user routed outbound: %w", err)
		}
		d.Enabled = enabled != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListRoutedAdminEmails 返回所有 nodes.routed_admin_email 非空的 email 集合。
// 用途:OrphanXrayClientCleaner 把这些占位 admin email 加入白名单,避免误删 inbound 上
// 跟着 routed 出站一起加的 admin client(routed_owner='shared' 时才有,'user' 路径下为空)。
func (r *TrafficRepository) ListRoutedAdminEmails(ctx context.Context) (map[string]bool, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT routed_admin_email FROM nodes WHERE routed_admin_email IS NOT NULL AND routed_admin_email != ''`)
	if err != nil {
		return nil, fmt.Errorf("list routed admin emails: %w", err)
	}
	defer rows.Close()
	out := make(map[string]bool)
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return nil, fmt.Errorf("scan routed admin email: %w", err)
		}
		if email != "" {
			out[email] = true
		}
	}
	return out, rows.Err()
}

// 删除一个 routed 节点(级联会自动清 user_subaccounts via FK)。
// agent 侧的 inbound client / outbound / rule 清理由调用方负责。
func (r *TrafficRepository) DeleteRoutedNode(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	_, _ = r.db.ExecContext(ctx, `DELETE FROM user_subaccounts WHERE routed_node_id = ?`, id)
	_, err := r.db.ExecContext(ctx, `DELETE FROM nodes WHERE id = ? AND node_type = 'routed'`, id)
	return err
}
