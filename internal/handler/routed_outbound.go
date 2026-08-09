package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"miaomiaowux/internal/license"
	"miaomiaowux/internal/storage"

	"github.com/google/uuid"
)

// routingMutateLocks 是 auto-detected routed 节点更新 routing rule 时的 per-server 锁。
// 套餐绑用户路径 (packages.go) 对每个 routed 节点并发跑 addUserToRoutedNode,
// 同台服务器多个 auto-detected routed 节点会并发跑 mutateRoutingRuleUserByOutboundTag
// (GET routing → 本地改 → SET routing)。两个 goroutine 都拿到 v1,各自加自己的 user,
// 后写的 SET 会覆盖先写的 SET,导致部分子用户的路由 rule 丢失。
// 加锁后同服务器内串行,跨服务器仍并行。
var routingMutateLocks sync.Map // map[int64]*sync.Mutex (key=serverID)

func acquireRoutingMutateLock(serverID int64) *sync.Mutex {
	m, _ := routingMutateLocks.LoadOrStore(serverID, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu
}

// RoutedOutboundHandler 管理"路由出站"虚拟节点。
// 创建时自动:
//  1. 给父物理节点的 inbound 加一个占位 admin client(email = _admin__<short>__<label>)
//  2. 调 agent 加 outbound(tag = routed:<short>:<label>)
//  3. 调 agent 加 routing rule(带 marktag,user=[admin_email],prepend 到 rules[])
//  4. 在 nodes 表插一行 node_type='routed' 关联到父节点
//
// 删除时反向:agent 移除 rule + outbound + 占位 client,DB 删 routed node(级联清子账号)。
type RoutedOutboundHandler struct {
	repo           *storage.TrafficRepository
	remoteManage   *RemoteManageHandler
	licenseManager *license.Manager // 用 setter 注入,见 SetLicenseManager
}

func NewRoutedOutboundHandler(repo *storage.TrafficRepository, rm *RemoteManageHandler) *RoutedOutboundHandler {
	return &RoutedOutboundHandler{repo: repo, remoteManage: rm}
}

// SetLicenseManager 注入 license 管理器供 create() 做配额检查。
// nil = 不检查(开发 / 自托管无许可证场景);跟 nodes.go 同款 pattern。
func (h *RoutedOutboundHandler) SetLicenseManager(mgr *license.Manager) {
	h.licenseManager = mgr
}

func (h *RoutedOutboundHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.list(w, r)
	case http.MethodPost:
		h.create(w, r)
	case http.MethodDelete:
		h.delete(w, r)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// 列出某父节点下所有 routed 子节点。
// GET /api/admin/nodes/routed-outbound?parent_id=X
func (h *RoutedOutboundHandler) list(w http.ResponseWriter, r *http.Request) {
	parentID, err := strconv.ParseInt(r.URL.Query().Get("parent_id"), 10, 64)
	if err != nil || parentID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "parent_id 必填")
		return
	}
	items, err := h.repo.ListRoutedNodesByParent(r.Context(), parentID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("list routed nodes: %v", err))
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items})
}

type createRoutedOutboundReq struct {
	ParentNodeID int64                  `json:"parent_node_id"`
	Label        string                 `json:"label"`     // 必填,如 "WTT" / "HK-T4"
	Outbound     map[string]interface{} `json:"outbound"`  // xray outbound 完整定义(无 tag,由后端生成 namespacedTag)
	NodeName     string                 `json:"node_name"` // 订阅里展示用,可空,默认 "<parent>-<label>"
}

// 创建路由出站节点。
// POST /api/admin/nodes/routed-outbound
func (h *RoutedOutboundHandler) create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 用 license 限 routed 出站节点总数 — 这是真正占 server xray 资源的"节点"。
	// 同一 inbound 下 N 个 routed outbound 算 N 个,符合"路由出站节点是多个,只有一个入站,也算多个"。
	if h.licenseManager != nil {
		status := h.licenseManager.GetStatus()
		maxNodes := 20
		if status.Plan != nil {
			maxNodes = status.Plan.MaxNodes
		}
		if count, cerr := h.repo.CountLicensedNodes(ctx); cerr == nil && count >= int64(maxNodes) {
			writeJSONError(w, http.StatusForbidden, fmt.Sprintf("已达到路由出站节点数量上限 (%d/%d)，请升级许可证", count, maxNodes))
			return
		}
	}

	var req createRoutedOutboundReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ParentNodeID <= 0 || strings.TrimSpace(req.Label) == "" || req.Outbound == nil {
		writeJSONError(w, http.StatusBadRequest, "parent_node_id, label, outbound 都必填")
		return
	}
	labelSlug := slugify(req.Label)
	if labelSlug == "" {
		writeJSONError(w, http.StatusBadRequest, "label 只能包含字母数字和短横线,长度 2-32")
		return
	}

	parent, err := h.repo.GetNodeByID(ctx, req.ParentNodeID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("父节点不存在: %v", err))
		return
	}
	if parent.NodeType != "" && parent.NodeType != "physical" {
		writeJSONError(w, http.StatusBadRequest, "父节点必须是物理节点,不能挂在另一个 routed 节点下")
		return
	}
	if strings.TrimSpace(parent.OriginalServer) == "" || strings.TrimSpace(parent.InboundTag) == "" {
		writeJSONError(w, http.StatusBadRequest, "父节点缺少 original_server 或 inbound_tag,无法定位 agent inbound")
		return
	}

	// 反查 server_id
	serverID, err := h.resolveServerIDByName(ctx, parent.OriginalServer)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("无法定位父节点所属 agent server: %v", err))
		return
	}

	// 命名空间生成:用父节点 ID + label 保唯一,前缀清晰
	shortID := fmt.Sprintf("p%d", parent.ID)
	outboundTag := fmt.Sprintf("routed:%s:%s", shortID, labelSlug)
	marktag := outboundTag
	// 占位 client email 用 creator(父节点 owner)前缀 — 不再用 "_admin__" 共享占位。
	// 历史 BUG:`_admin__<short>__<label>` 不带 creator username,多 admin 系统下 admin A 和
	// admin B 用同一节点会共享同一 uuid → xray 端流量合并 → master 端无法区分归属。
	// 现在用 `<creator>__<short>__<label>` 让每个 admin 都有专属 client,跟普通用户子账号同款命名。
	creatorUsername := strings.TrimSpace(parent.Username)
	if creatorUsername == "" {
		creatorUsername = h.repo.GetSystemNodeOwner(ctx)
	}
	adminEmail := fmt.Sprintf("%s__%s__%s", creatorUsername, shortID, labelSlug)

	// 检查唯一性(同父节点同 label 不能重复)
	existing, _ := h.repo.ListRoutedNodesByParent(ctx, parent.ID)
	for _, ex := range existing {
		if ex.RoutedOutboundTag == outboundTag {
			writeJSONError(w, http.StatusConflict, fmt.Sprintf("已存在相同 label 的路由出站: %s", req.Label))
			return
		}
	}

	// 准备 outbound:强制设 tag 防止调用方乱传
	outboundCopy := cloneMap(req.Outbound)
	outboundCopy["tag"] = outboundTag

	// 准备 admin client 凭据。按 parent.Protocol 走 generateCredential 选对字段(vless=id / trojan=password
	// / hy=auth / ss=password+method 长度),然后把 email 覆盖成 _admin__ 占位。
	// 之前这里直接硬编码 {id: uuid},导致 trojan/ss/hy routed 节点的 admin 占位 client 字段名错位,
	// xray reload 失败 + 客户端连不上。
	adminCred, _, err := generateRoutedClientCred(parent.Protocol, "", adminEmail)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("生成 admin client 凭据失败: %v", err))
		return
	}
	inboundFlow, err := h.peekInboundFirstClientFlow(ctx, serverID, parent.InboundTag)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("读取父 inbound 失败: %v", err))
		return
	}
	if inboundFlow != "" {
		adminCred["flow"] = inboundFlow
	}

	// === Step 1: 给 agent inbound 加 admin client(幂等) ===
	// 先 peek 看 agent 端是否已有同 email 的 client(历史残留 / 同 label 重试 / 主控 DB 被清但 agent 没清),
	// 命中 → 复用其 primary key + flow,避免 xray "User already exists" 启动失败。
	pkField := primaryKeyFieldForProtocol(parent.Protocol)
	if existingUUID, existingFlow, perr := peekInboundClientByEmail(ctx, h.remoteManage, serverID, parent.InboundTag, adminEmail); perr == nil && existingUUID != "" {
		log.Printf("[RoutedCreate] inbound %s already has admin client email=%s pk=%s — reusing", parent.InboundTag, adminEmail, existingUUID)
		adminCred[pkField] = existingUUID
		if existingFlow != "" {
			adminCred["flow"] = existingFlow
		}
	} else if err := addClientToInbound(ctx, h.remoteManage, serverID, parent.InboundTag, adminCred); err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("加 admin client 失败: %v", err))
		return
	}

	// === Step 1.5: vless+reality 出站 → 把伪装 SNI 加进父 inbound 的 sniffing.excludeDomains ===
	// reality outbound 连远端时用 serverName 字段做伪装(实际是公开域如 microsoft.com),
	// 父 inbound 默认开 sniffing 会把这个伪装域嗅探成「真实目标」,routing 按 domain 分流时
	// 会用错误的域去匹配,流量绕错路。把伪装 SNI 加进 excludeDomains 让 sniffing 跳过即可。
	// soft-fail:老 agent 不支持新 action / inbound 不存在等场景下,只记日志不阻塞 outbound 创建。
	if snis := extractRealitySNIs(req.Outbound); len(snis) > 0 {
		if err := addInboundSniffingExcludes(ctx, h.remoteManage, serverID, parent.InboundTag, snis); err != nil {
			log.Printf("[RoutedCreate] soft-fail: add reality SNI %v to inbound %q sniffing.excludeDomains: %v", snis, parent.InboundTag, err)
		} else {
			log.Printf("[RoutedCreate] added reality SNI %v to inbound %q sniffing.excludeDomains", snis, parent.InboundTag)
		}
	}

	// === Step 2: 加 outbound ===
	addOutBody, _ := json.Marshal(map[string]interface{}{"action": "add", "outbound": outboundCopy})
	if _, err := h.remoteManage.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/outbounds", addOutBody); err != nil {
		// rollback: 删 admin client
		removeClientFromInbound(ctx, h.remoteManage, serverID, parent.InboundTag, adminEmail)
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("加 outbound 失败: %v", err))
		return
	}

	// === Step 3: 加 routing rule ===
	rule := map[string]interface{}{
		"type":        "field",
		"marktag":     marktag,
		"user":        []string{adminEmail},
		"inboundTag":  []string{parent.InboundTag},
		"outboundTag": outboundTag,
	}
	addRuleBody, _ := json.Marshal(map[string]interface{}{"action": "add_rule", "rule": rule})
	if _, err := h.remoteManage.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/routing", addRuleBody); err != nil {
		// rollback: 删 outbound + admin client
		removeOutBody, _ := json.Marshal(map[string]string{"action": "remove", "tag": outboundTag})
		h.remoteManage.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/outbounds", removeOutBody)
		removeClientFromInbound(ctx, h.remoteManage, serverID, parent.InboundTag, adminEmail)
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("加 routing rule 失败: %v", err))
		return
	}

	// === Step 4: 持久化 routed node ===
	// routed 节点的 clash_config / parsed_config 完全继承父节点(同 inbound,网络/TLS/reality 参数都一样),
	// 仅替换"客户端凭据"为 admin 占位:
	//   - VLESS/VMess: uuid → admin uuid
	//   - Trojan: password → admin uuid
	//   - SS: password 拼接 admin password
	// 节点名换成 routed.NodeName。订阅生成时再用用户子账号 uuid 覆盖(见 buildRoutedProxyForUser)。
	parentID := parent.ID
	nodeName := strings.TrimSpace(req.NodeName)
	if nodeName == "" {
		nodeName = fmt.Sprintf("%s-%s", parent.NodeName, req.Label)
	}
	clashWithAdmin := cloneClashWithCredential(parent.ClashConfig, parent.Protocol, adminCred, nodeName)
	parsedWithAdmin := parent.ParsedConfig // parsed_config 是 xray inbound 结构,与凭据无关,直接继承
	outboundJSONBytes, _ := json.Marshal(outboundCopy)
	credBytes, _ := json.Marshal(adminCred)
	detail := storage.RoutedNodeDetail{
		Node: storage.Node{
			Username:       parent.Username,
			RawURL:         parent.RawURL,
			NodeName:       nodeName,
			Protocol:       parent.Protocol,
			ParsedConfig:   parsedWithAdmin,
			ClashConfig:    clashWithAdmin,
			Enabled:        true,
			Tag:            "路由出站",
			OriginalServer: parent.OriginalServer,
			OriginalDomain: parent.OriginalDomain,
			InboundTag:     parent.InboundTag,
			NodeType:       "routed",
			ParentNodeID:   &parentID,
		},
		RoutedOutboundTag:     outboundTag,
		RoutedOutboundJSON:    string(outboundJSONBytes),
		RoutedRuleMarktag:     marktag,
		RoutedAdminEmail:      adminEmail,
		RoutedAdminCredential: string(credBytes),
	}
	created, err := h.repo.CreateRoutedNode(ctx, detail)
	if err != nil {
		log.Printf("[RoutedOutbound] DB insert failed after agent ops succeeded: %v - agent 已变更但 DB 未记录,需人工清理", err)
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("DB 写入失败,agent 已修改,需人工修复: %v", err))
		return
	}

	// 给 creator 自己也写一行 user_subaccounts:让 creator 拉订阅时(buildRoutedProxyForUser)
	// 能拿到这个 routed 节点 + 占位 client 凭据,流量上报后 ResolveUsernameByEmail 命中 → 归 creator。
	// 之前 admin 没这行 → 用户视角"看不到自己的路由出站流量"。
	if _, suErr := h.repo.UpsertUserSubaccount(ctx, storage.UserSubaccount{
		Username:       creatorUsername,
		RoutedNodeID:   created.ID,
		Email:          adminEmail,
		CredentialJSON: string(credBytes),
		IsActive:       true,
	}); suErr != nil {
		log.Printf("[RoutedOutbound] creator subaccount upsert failed (node %d, creator %s): %v — 节点已创建,流量归属需手动修复", created.ID, creatorUsername, suErr)
	}

	log.Printf("[RoutedOutbound] created routed node id=%d tag=%s parent=%d creator=%s", created.ID, outboundTag, parent.ID, creatorUsername)
	respondJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"node":    created,
	})
}

// 删除路由出站节点。
// DELETE /api/admin/nodes/routed-outbound?id=X
func (h *RoutedOutboundHandler) delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "id 必填")
		return
	}
	detail, err := h.repo.GetRoutedNodeDetail(ctx, id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("routed 节点不存在: %v", err))
		return
	}
	serverID, err := h.resolveServerIDByName(ctx, detail.OriginalServer)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("无法定位 agent server: %v", err))
		return
	}

	state, err := loadPackageServerConfig(ctx, h.remoteManage, map[int64]*packageConfigState{}, serverID)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "读取 Agent 完整配置失败: "+err.Error())
		return
	}
	if err := removeManagedRoute(state.config, detail.RoutedRuleMarktag); err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	removeTaggedConfigEntry(state.config, "outbounds", detail.RoutedOutboundTag)
	subaccs, err := h.repo.ListSubaccountsByRoutedNode(ctx, id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取路由子账户失败: "+err.Error())
		return
	}
	for _, sa := range subaccs {
		if err := removeManagedClient(state.config, detail.InboundTag, sa.Email); err != nil {
			writeJSONError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	if err := removeManagedClient(state.config, detail.InboundTag, detail.RoutedAdminEmail); err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := validateManagedConfig(state.config); err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	candidate, err := json.MarshalIndent(state.config, "", "  ")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	operationID := "routed-delete-" + uuid.NewString()
	targets := []xrayConfigTransactionTarget{{ServerID: serverID, Config: string(candidate)}}
	if err := applyXrayConfigTransaction(ctx, h.remoteManage, operationID, targets); err != nil {
		writeJSONError(w, http.StatusBadGateway, "删除路由配置失败，节点已保留: "+err.Error())
		return
	}

	if err := h.repo.DeleteRoutedNode(ctx, id); err != nil {
		_ = finishXrayConfigTransaction(context.WithoutCancel(ctx), h.remoteManage, operationID, targets, false)
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("DB 删除失败: %v", err))
		return
	}
	if err := finishXrayConfigTransaction(context.WithoutCancel(ctx), h.remoteManage, operationID, targets, true); err != nil {
		log.Printf("[RoutedOutbound] delete operation %s committed; agent cleanup incomplete: %v", operationID, err)
	}
	go h.remoteManage.refreshXraySnapshot(serverID)
	respondJSON(w, http.StatusOK, map[string]any{"success": true})
}

// ===== helpers =====

func (h *RoutedOutboundHandler) resolveServerIDByName(ctx context.Context, serverName string) (int64, error) {
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return 0, err
	}
	for _, s := range servers {
		if s.Name == serverName {
			return s.ID, nil
		}
	}
	return 0, errors.New("server not found in remote_servers by name " + serverName)
}

// 读父 inbound,返回第一个 client 的 flow 字段(VLESS Reality 子 client 必须继承)。
func (h *RoutedOutboundHandler) peekInboundFirstClientFlow(ctx context.Context, serverID int64, inboundTag string) (string, error) {
	return peekInboundFirstClientFlow(ctx, h.remoteManage, serverID, inboundTag)
}

// mutateRoutingRuleUserByOutboundTag 在 routing.rules 里找 outboundTag 匹配的 rule,
// 给它的 user[] 数组加/删一个 email,然后用 agent 的 `set` action 把整个 routing 推回去。
// 用途:auto-detected routed 节点没有 marktag,agent 的 add_user_to_rule 需要 marktag,绕开它。
// add=true 表示新增 email(去重 append);add=false 表示移除。
func mutateRoutingRuleUserByOutboundTag(ctx context.Context, rm *RemoteManageHandler, serverID int64, outboundTag, userEmail string, add bool) error {
	// 串行化同服务器的 GET-modify-SET,防止并发覆盖。
	mu := acquireRoutingMutateLock(serverID)
	defer mu.Unlock()

	raw, err := rm.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/routing", nil)
	if err != nil {
		return fmt.Errorf("get routing: %w", err)
	}
	var resp struct {
		Success bool                   `json:"success"`
		Routing map[string]interface{} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("parse routing: %w", err)
	}
	if resp.Routing == nil {
		return fmt.Errorf("no routing config")
	}
	rules, _ := resp.Routing["rules"].([]interface{})
	matched := -1
	for i, ru := range rules {
		rm, _ := ru.(map[string]interface{})
		if rm == nil {
			continue
		}
		if t, _ := rm["outboundTag"].(string); t == outboundTag {
			matched = i
			break
		}
	}
	if matched < 0 {
		return fmt.Errorf("no routing rule with outboundTag=%q", outboundTag)
	}
	rule := rules[matched].(map[string]interface{})
	users, _ := rule["user"].([]interface{})
	if add {
		for _, u := range users {
			if s, _ := u.(string); s == userEmail {
				return nil // 已存在,幂等
			}
		}
		users = append(users, userEmail)
	} else {
		filtered := users[:0]
		for _, u := range users {
			if s, _ := u.(string); s != userEmail {
				filtered = append(filtered, u)
			}
		}
		users = filtered
	}
	rule["user"] = users
	rules[matched] = rule
	resp.Routing["rules"] = rules

	// no_restart=true:批量套餐绑用户场景,主控在循环末尾会统一对受影响服务器重启,
	// 不让 agent 为每条路由变更都串行重启一次(N 个 routed 节点能省 N×(1~3s))。
	body, _ := json.Marshal(map[string]interface{}{
		"action":     "set",
		"routing":    resp.Routing,
		"no_restart": true,
	})
	if _, err := rm.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/routing", body); err != nil {
		return fmt.Errorf("set routing: %w", err)
	}
	return nil
}

// peekInboundFirstClientFlow 给非 RoutedOutboundHandler 的调用方用(addUserToRoutedNode 直接拿 *RemoteManageHandler)。
func peekInboundFirstClientFlow(ctx context.Context, rm *RemoteManageHandler, serverID int64, inboundTag string) (string, error) {
	result, err := rm.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/inbounds", nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		Success  bool                     `json:"success"`
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return "", err
	}
	for _, ib := range resp.Inbounds {
		if tag, _ := ib["tag"].(string); tag != inboundTag {
			continue
		}
		settings, _ := ib["settings"].(map[string]interface{})
		return vlessFlowFromInbound(settings), nil
	}
	return "", fmt.Errorf("inbound %s not found", inboundTag)
}

// vlessFlowFromInbound 从父入站的 settings 推断 VLESS routed 子账户应继承的 flow:
// 只信**父入站实际的 client flow**——扫所有 client,取第一个非空 flow(兼容 clients[0] 恰好无 flow 的
// 子账户/占位、client 被重排、或自定义 flow)。取不到 → ""。
//
// 不能用 streamSettings.security==reality 兜底加 "xtls-rprx-vision":reality 分 with-vision 与 without-vision
// 两种,后者的 client 本就没有 flow,一律塞 vision 会让 reality-without-vision 节点的 routed 出站配置与父节点
// 不一致(客户端连不上)。vision 节点每个 client 必带 flow=xtls-rprx-vision,靠扫 client 就能正确继承。
func vlessFlowFromInbound(settings map[string]interface{}) string {
	if settings != nil {
		if clients, ok := settings["clients"].([]interface{}); ok {
			for _, c := range clients {
				if cm, ok := c.(map[string]interface{}); ok {
					if f, ok := cm["flow"].(string); ok && strings.TrimSpace(f) != "" {
						return f
					}
				}
			}
		}
	}
	return ""
}

// primaryKeyFieldForProtocol 返回该协议的"主认证字段名",routed cred 复用 / peek 后回写主字段时用。
// 之前 routed_outbound.go 硬编码 `id`,trojan 节点的 admin / 用户子账号 cred 也被写成 {"id":...},
// 但 xray trojan 协议需要 `password` 字段 → 客户端连不上 + xray reload 失败。
func primaryKeyFieldForProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "vless", "vmess":
		return "id"
	case "trojan", "shadowsocks", "ss", "anytls":
		return "password"
	case "hysteria", "hysteria2", "hy2":
		return "auth"
	case "snell":
		return "psk"
	}
	return "id"
}

// generateRoutedClientCred 用 generateCredential 按 protocol 选对字段名 + 长度(SS 按 method),
// 然后覆盖 email 为 routed 路径自己的命名规则。
// 替代 routed_outbound.go / user_routed_outbound.go 之前手写 `{id: uuid.New()}` 的硬编码。
func generateRoutedClientCred(protocol, method, email string) (map[string]interface{}, string, error) {
	cred, _, err := generateCredential(protocol, storage.User{Username: "routed"}, method, "")
	if err != nil {
		return nil, "", err
	}
	cred["email"] = email
	b, err := json.Marshal(cred)
	if err != nil {
		return cred, "", err
	}
	return cred, string(b), nil
}

// peekInboundClientByEmail 在 agent 上的某 inbound 里按 email 查现存 client。
// 命中返回该 client 的 uuid + flow;不存在返回空字符串(err==nil)。
// 用途:routed 创建 Step 1 add admin client 之前做幂等检查 —
// agent matchClientCredential 现在只看 primary key(id),不再 fallback email,
// 直接 add 同 email 不同 uuid 的 client 会被 agent 接受,但 xray 实际启动时会拒绝
// "User already exists" 导致 routing 改完但 xray 无法 restart。
func peekInboundClientByEmail(ctx context.Context, rm *RemoteManageHandler, serverID int64, inboundTag, email string) (uuid, flow string, err error) {
	result, ferr := rm.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/inbounds", nil)
	if ferr != nil {
		return "", "", ferr
	}
	var resp struct {
		Success  bool                     `json:"success"`
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if jerr := json.Unmarshal(result, &resp); jerr != nil {
		return "", "", jerr
	}
	for _, ib := range resp.Inbounds {
		if tag, _ := ib["tag"].(string); tag != inboundTag {
			continue
		}
		settings, _ := ib["settings"].(map[string]interface{})
		if settings == nil {
			return "", "", nil
		}
		clients, _ := settings["clients"].([]interface{})
		for _, c := range clients {
			cm, _ := c.(map[string]interface{})
			if cm == nil {
				continue
			}
			if e, _ := cm["email"].(string); e == email {
				id, _ := cm["id"].(string)
				if id == "" {
					id, _ = cm["password"].(string) // trojan/ss fallback
				}
				fl, _ := cm["flow"].(string)
				return id, fl, nil
			}
		}
		return "", "", nil // inbound found, email 不在
	}
	return "", "", fmt.Errorf("inbound %s not found", inboundTag)
}

// 给目标 inbound 加一个 client — 走 agent 原子 add-client,在 inboundsMu 锁内完成 read-modify-write。
// 主控不再持有 inbound 快照,从根本上消除并发绑套餐丢 client 的问题。
func addClientToInbound(ctx context.Context, rm *RemoteManageHandler, serverID int64, inboundTag string, client map[string]interface{}) error {
	return mutateInboundClient(ctx, rm, serverID, inboundTag, "add-client", client)
}

// extractRealitySNIs 从 outbound JSON 抽出 reality 出站的 SNI(serverName)列表。
// 返回非空切片 = outbound 是 vless+reality 且有效 SNI;返回 nil = 协议不匹配或字段缺失。
//
// 处理边界:
//   - serverName 可以是 string(单值)或 []string(数组),xray 文档两种都支持
//   - 兼容 serverNames 复数命名(xray 历史曾用过此字段名)
//   - 数组里的非 string 元素 / 空字符串自动跳过
func extractRealitySNIs(outbound map[string]interface{}) []string {
	if outbound == nil {
		return nil
	}
	proto, _ := outbound["protocol"].(string)
	if strings.ToLower(proto) != "vless" {
		return nil
	}
	stream, _ := outbound["streamSettings"].(map[string]interface{})
	if stream == nil {
		return nil
	}
	if sec, _ := stream["security"].(string); strings.ToLower(sec) != "reality" {
		return nil
	}
	reality, _ := stream["realitySettings"].(map[string]interface{})
	if reality == nil {
		return nil
	}
	collect := func(v interface{}) []string {
		switch x := v.(type) {
		case string:
			s := strings.TrimSpace(x)
			if s != "" {
				return []string{s}
			}
		case []interface{}:
			out := make([]string, 0, len(x))
			for _, item := range x {
				if s, ok := item.(string); ok {
					s = strings.TrimSpace(s)
					if s != "" {
						out = append(out, s)
					}
				}
			}
			return out
		}
		return nil
	}
	// 优先 serverName(主流),其次 serverNames(历史命名兼容)
	if snis := collect(reality["serverName"]); len(snis) > 0 {
		return snis
	}
	return collect(reality["serverNames"])
}

// addInboundSniffingExcludes 调 agent 的 add-sniffing-exclude action,把若干域名幂等追加到
// inbound.sniffing.excludeDomains。agent 端去重 + soft 初始化 sniffing 字段。
// 老 agent 不识别该 action → 400 错误;调用方应 soft-fail(log + continue)避免阻塞主流程。
func addInboundSniffingExcludes(ctx context.Context, rm *RemoteManageHandler, serverID int64, inboundTag string, domains []string) error {
	if len(domains) == 0 {
		return nil
	}
	body, _ := json.Marshal(map[string]interface{}{
		"action":  "add-sniffing-exclude",
		"tag":     inboundTag,
		"domains": domains,
	})
	return mutateInbound(ctx, rm, serverID, inboundTag, "add-sniffing-exclude", body)
}

// 从目标 inbound 移除一个 client(按 email 匹配)。
// agent 的 matchClientCredential 在 id/password 等主键缺失时会回退到 email,所以这里只传 email 也能匹配。
func removeClientFromInbound(ctx context.Context, rm *RemoteManageHandler, serverID int64, inboundTag, email string) error {
	return mutateInboundClient(ctx, rm, serverID, inboundTag, "remove-client", map[string]interface{}{"email": email})
}

// mutateInboundClient 统一处理所有协议的 client 增删。Agent 会先把新配置原子写盘，再尝试
// remove+add 热替换运行态 inbound；后一步失败时 HTTP 仍是 200，但响应带 runtime_warning。
// 忽略它会让整个 inbound 从运行态消失（Reality/SS2022 等全部用户同时超时），直到下次重启。
func mutateInboundClient(ctx context.Context, rm *RemoteManageHandler, serverID int64, inboundTag, action string, client map[string]interface{}) error {
	body, _ := json.Marshal(map[string]interface{}{
		"action": action,
		"tag":    inboundTag,
		"client": client,
	})
	return mutateInbound(ctx, rm, serverID, inboundTag, action, body)
}

// mutateInbound is the only write path for Agent inbound mutations. Keep the raw
// request form so non-client actions (for example add-sniffing-exclude) receive
// the same persisted-config/runtime convergence guarantee.
func mutateInbound(ctx context.Context, rm *RemoteManageHandler, serverID int64, inboundTag, action string, body []byte) error {
	raw, err := rm.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/inbounds", body)
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	var resp struct {
		RuntimeWarning string `json:"runtime_warning"`
	}
	if json.Unmarshal(raw, &resp) == nil && strings.TrimSpace(resp.RuntimeWarning) != "" {
		log.Printf("[InboundClient] %s persisted but runtime apply failed server=%d tag=%s: %s; restarting xray",
			action, serverID, inboundTag, resp.RuntimeWarning)
		// 客户端断开不能中止故障恢复；配置已落盘，必须把运行态恢复起来。
		recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		if rerr := rm.restartXrayWithRecovery(recoveryCtx, serverID, "InboundClientRuntimeRecovery"); rerr != nil {
			return fmt.Errorf("%s persisted but runtime apply failed (%s), xray restart failed: %w",
				action, resp.RuntimeWarning, rerr)
		}
	}
	return nil
}

// 按 marktag 找到 rule 并删除。GET routing → 找 index → POST remove_rule {index}。
func removeRuleByMarktag(ctx context.Context, rm *RemoteManageHandler, serverID int64, marktag string) error {
	result, err := rm.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/routing", nil)
	if err != nil {
		return err
	}
	var resp struct {
		Success bool                   `json:"success"`
		Routing map[string]interface{} `json:"routing"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return err
	}
	if resp.Routing == nil {
		return nil
	}
	rules, _ := resp.Routing["rules"].([]interface{})
	for i, ru := range rules {
		rmap, _ := ru.(map[string]interface{})
		if t, _ := rmap["marktag"].(string); t == marktag {
			body, _ := json.Marshal(map[string]interface{}{"action": "remove_rule", "index": i})
			_, err := rm.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/routing", body)
			return err
		}
	}
	return nil
}

// routingRuleAddition 描述"给某条 routing rule 加一个 user email"的待办,
// 由 prepareRoutedNodeForUser 产出,applyRoutingAdditionsBatch 在 per-server 锁内一次性应用。
type routingRuleAddition struct {
	ServerID    int64
	Marktag     string // 优先匹配
	OutboundTag string // marktag 空时 fallback
	UserEmail   string
}

// routedNodeUserCred 包含算 cred 后的所有上下文,供 add-client(单点 / batch)和 routing rule 改动复用。
type routedNodeUserCred struct {
	ServerID       int64
	InboundTag     string
	Marktag        string
	OutboundTag    string
	UserEmail      string
	Credential     map[string]interface{}
	CredentialJSON string
	Username       string
	RoutedNodeID   int64
}

// computeRoutedNodeUserCred 解析 routed 节点 + 算 email/credential(复用已存或新建)。
// 不调 agent inbound add-client、不写 DB。供 prepareRoutedNodeForUser(单点)和 collectRoutedBatchItem(批量)共用。
func computeRoutedNodeUserCred(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, user storage.User, routedNodeID int64) (*routedNodeUserCred, error) {
	routed, err := repo.GetRoutedNodeDetail(ctx, routedNodeID)
	if err != nil {
		return nil, fmt.Errorf("get routed node %d: %w", routedNodeID, err)
	}
	if routed.NodeType != "routed" {
		return nil, fmt.Errorf("node %d is not a routed node", routedNodeID)
	}

	serverIDList, err := repo.ListRemoteServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list servers: %w", err)
	}
	var serverID int64
	for _, s := range serverIDList {
		if s.Name == routed.OriginalServer {
			serverID = s.ID
			break
		}
	}
	if serverID == 0 {
		return nil, fmt.Errorf("server %s not found", routed.OriginalServer)
	}

	// 算用户 email:legacy `_admin__xxx` → `<user>__xxx`;auto-detected → `<user>-<outboundTag>`
	var userEmail string
	if strings.HasPrefix(routed.RoutedAdminEmail, "_admin__") {
		suffix := strings.TrimPrefix(routed.RoutedAdminEmail, "_admin__")
		userEmail = fmt.Sprintf("%s__%s", user.Username, suffix)
	} else if routed.RoutedOutboundTag != "" {
		userEmail = fmt.Sprintf("%s-%s", user.Username, routed.RoutedOutboundTag)
	} else {
		return nil, fmt.Errorf("routed node %d has neither admin_email nor outbound_tag", routedNodeID)
	}

	// 复用已存子账号凭据(续费/恢复路径) or 新建
	var credJSON string
	var credential map[string]interface{}
	newCredential := false
	existing, _ := repo.GetUserSubaccount(ctx, routedNodeID, user.Username)
	if existing != nil {
		json.Unmarshal([]byte(existing.CredentialJSON), &credential)
		credJSON = existing.CredentialJSON
		userEmail = existing.Email // saved 优先,避免命名规则变动导致 email 漂移
		// 修复历史存量:VLESS Reality 复用旧子账户凭据时,若缺 flow 就从父 inbound 稳健补上并回写,
		// 否则历史无 flow 的子账户重新绑定/加节点时会一直复用无 flow 的凭据 → 客户端连不上。
		if strings.EqualFold(routed.Protocol, "vless") && credential != nil {
			if _, hasFlow := credential["flow"]; !hasFlow {
				if flow, ferr := peekInboundFirstClientFlow(ctx, rm, serverID, routed.InboundTag); ferr == nil && flow != "" {
					credential["flow"] = flow
					if b, merr := json.Marshal(credential); merr == nil {
						credJSON = string(b)
					}
				}
			}
		}
	} else {
		newCredential = true
		// 用 generateRoutedClientCred 按 routed 节点继承的 protocol 选对字段(vless=id / trojan=password / ...)
		newCred, newCredJSON, gerr := generateRoutedClientCred(routed.Protocol, "", userEmail)
		if gerr != nil {
			return nil, fmt.Errorf("generate routed user cred: %w", gerr)
		}
		credential = newCred
		credJSON = newCredJSON
		// flow 优先取 admin credential;auto-detected 没存 → 从 inbound 第一个 client 反查
		var flow string
		if routed.RoutedAdminCredential != "" {
			var adminCred map[string]interface{}
			if err := json.Unmarshal([]byte(routed.RoutedAdminCredential), &adminCred); err == nil {
				if f, ok := adminCred["flow"].(string); ok {
					flow = f
				}
			}
		}
		if flow == "" {
			if f, err := peekInboundFirstClientFlow(ctx, rm, serverID, routed.InboundTag); err == nil {
				flow = f
			}
		}
		if flow != "" {
			credential["flow"] = flow
			if b, err := json.Marshal(credential); err == nil {
				credJSON = string(b)
			}
		}
	}
	if newCredential {
		claimed, claimErr := repo.ClaimUserSubaccount(ctx, storage.UserSubaccount{
			Username:       user.Username,
			RoutedNodeID:   routedNodeID,
			Email:          userEmail,
			CredentialJSON: credJSON,
			IsActive:       true,
		})
		if claimErr != nil {
			return nil, fmt.Errorf("claim routed user credential: %w", claimErr)
		}
		if claimed == nil {
			return nil, errors.New("claim routed user credential returned no row")
		}
		// A concurrent request may have won. Always send the DB winner so Agent
		// sees one deterministic credential for this email.
		userEmail, credJSON = claimed.Email, claimed.CredentialJSON
		if err := json.Unmarshal([]byte(credJSON), &credential); err != nil || credential == nil {
			return nil, fmt.Errorf("decode claimed routed credential: %w", err)
		}
	}

	return &routedNodeUserCred{
		ServerID:       serverID,
		InboundTag:     routed.InboundTag,
		Marktag:        routed.RoutedRuleMarktag,
		OutboundTag:    routed.RoutedOutboundTag,
		UserEmail:      userEmail,
		Credential:     credential,
		CredentialJSON: credJSON,
		Username:       user.Username,
		RoutedNodeID:   routedNodeID,
	}, nil
}

// prepareRoutedNodeForUser 做 addUserToRoutedNode 的前置工作:算 email/cred、加 client 到 inbound、
// UPSERT user_subaccounts。返回 routing rule 改动描述,**不动 routing**。
// 调用方负责把所有 addition 聚合后调 applyRoutingAdditionsBatch(per-server 锁内一次 GET+SET)。
func prepareRoutedNodeForUser(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, user storage.User, routedNodeID int64) (*routingRuleAddition, error) {
	info, err := computeRoutedNodeUserCred(ctx, rm, repo, user, routedNodeID)
	if err != nil {
		return nil, err
	}

	// 1. 加 client 到 inbound — agent 端 inboundsMu 锁内,跨节点可并发。
	if err := addClientToInbound(ctx, rm, info.ServerID, info.InboundTag, info.Credential); err != nil {
		return nil, fmt.Errorf("add client to inbound: %w", err)
	}

	// 2. UPSERT user_subaccounts(is_active=1)
	if _, err := repo.UpsertUserSubaccount(ctx, storage.UserSubaccount{
		Username:       info.Username,
		RoutedNodeID:   info.RoutedNodeID,
		Email:          info.UserEmail,
		CredentialJSON: info.CredentialJSON,
		IsActive:       true,
	}); err != nil {
		log.Printf("[RoutedNode] DB upsert subaccount failed (agent client 已加,需排查): %v", err)
		return nil, fmt.Errorf("upsert subaccount: %w", err)
	}

	return &routingRuleAddition{
		ServerID:    info.ServerID,
		Marktag:     info.Marktag,
		OutboundTag: info.OutboundTag,
		UserEmail:   info.UserEmail,
	}, nil
}

// routedBatchItem 批量套餐绑定路径专用:不调 agent、不写 DB,只算 cred + 描述 batch 操作。
// 调用方收集 per-server → 一次 POST /api/child/batch-apply → 全成功后批量 UpsertUserSubaccount。
type routedBatchItem struct {
	ServerID       int64
	InboundTag     string
	Marktag        string
	OutboundTag    string
	UserEmail      string
	Credential     map[string]interface{}
	CredentialJSON string
	Username       string
	RoutedNodeID   int64
}

// collectRoutedBatchItem 算 cred,**不调 agent、不写 DB**,返回 batch 描述。
func collectRoutedBatchItem(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, user storage.User, routedNodeID int64) (*routedBatchItem, error) {
	info, err := computeRoutedNodeUserCred(ctx, rm, repo, user, routedNodeID)
	if err != nil {
		return nil, err
	}
	return &routedBatchItem{
		ServerID:       info.ServerID,
		InboundTag:     info.InboundTag,
		Marktag:        info.Marktag,
		OutboundTag:    info.OutboundTag,
		UserEmail:      info.UserEmail,
		Credential:     info.Credential,
		CredentialJSON: info.CredentialJSON,
		Username:       info.Username,
		RoutedNodeID:   info.RoutedNodeID,
	}, nil
}

// ErrAgentBatchNotSupported 老 agent 没 /api/child/batch-apply 端点时返回,调用方应 fallback。
var ErrAgentBatchNotSupported = errors.New("agent batch-apply endpoint not supported")

// applyRoutedBatchOrFallback 同台 server 上的 routed 节点改动一次性发给 agent,
// 老 agent 不支持就 fallback 到逐项 prepareRoutedNodeForUser + applyRoutingAdditionsBatch。
// 返回收集到的人类可读 warning 列表(给前端 toast 用,空切片=全成功)。
// label 仅用于日志(如 "PackageAssign" / "PackageUpdate")。
func applyRoutedBatchOrFallback(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, serverID int64, items []routedBatchItem, label string) []string {
	if len(items) == 0 {
		return nil
	}
	// 把 batchItem → user(主要拿 Username,fallback 时 prepareRoutedNodeForUser 需要 User 对象)。
	// 简单起见这里只用 Username 字段,prepareRoutedNodeForUser 内部不依赖 user 的其它字段。
	err := applyRoutedBatchToAgent(ctx, rm, repo, serverID, items)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrAgentBatchNotSupported) {
		log.Printf("[%s] batch-apply server=%d failed: %v", label, serverID, err)
		return []string{fmt.Sprintf("服务器 %d 批量绑定失败", serverID)}
	}

	// 老 agent fallback:逐项 prepareRoutedNodeForUser(每项各发 1 次 add-client + 写 DB),
	// 然后一次 applyRoutingAdditionsBatch 把所有 routing 改动 GET+SET 推回。
	log.Printf("[%s] agent server=%d 不支持 batch-apply,fallback per-item", label, serverID)
	var warnings []string
	var routingAdds []routingRuleAddition
	for _, it := range items {
		user := storage.User{Username: it.Username}
		add, perr := prepareRoutedNodeForUser(ctx, rm, repo, user, it.RoutedNodeID)
		if perr != nil {
			log.Printf("[%s] fallback prepare failed user=%s node=%d: %v", label, it.Username, it.RoutedNodeID, perr)
			warnings = append(warnings, fmt.Sprintf("用户 %s 路由出站绑定失败", it.Username))
			continue
		}
		if add != nil {
			routingAdds = append(routingAdds, *add)
		}
	}
	if len(routingAdds) > 0 {
		if rerr := applyRoutingAdditionsBatch(ctx, rm, serverID, routingAdds); rerr != nil {
			log.Printf("[%s] fallback routing batch server=%d failed: %v", label, serverID, rerr)
			warnings = append(warnings, fmt.Sprintf("服务器 %d 路由规则批量更新失败", serverID))
		}
	}
	return warnings
}

// applyRoutedBatchToAgent 把同台 server 上的 routed 节点批量改动(inbound add-client + routing add-user)
// 一次 POST /api/child/batch-apply 提交。
//   - 成功:批量 UpsertUserSubaccount 写 DB,返回 nil
//   - agent 不支持(404)→ 返回 ErrAgentBatchNotSupported,caller 走 prepareRoutedNodeForUser fallback
//   - 其它失败 → 返回 wrapped error,DB 不写(下次重试幂等)
func applyRoutedBatchToAgent(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, serverID int64, items []routedBatchItem) error {
	if len(items) == 0 {
		return nil
	}
	// 同服务器 batch 写盘也要走 routingMutateLocks,跟 applyRoutingAdditionsBatch 串行,
	// 避免 batch 与单点 routing mutate 并发改 routing 数组。
	mu := acquireRoutingMutateLock(serverID)
	defer mu.Unlock()

	type batchInboundClient struct {
		Tag    string                 `json:"tag"`
		Client map[string]interface{} `json:"client"`
	}
	type batchRoutingAddition struct {
		Marktag     string `json:"marktag,omitempty"`
		OutboundTag string `json:"outbound_tag,omitempty"`
		UserEmail   string `json:"user_email"`
	}
	type batchReq struct {
		InboundClients       []batchInboundClient   `json:"inbound_clients,omitempty"`
		RoutingUserAdditions []batchRoutingAddition `json:"routing_user_additions,omitempty"`
		NoRestart            bool                   `json:"no_restart,omitempty"`
	}

	req := batchReq{NoRestart: true}
	for _, it := range items {
		req.InboundClients = append(req.InboundClients, batchInboundClient{
			Tag:    it.InboundTag,
			Client: it.Credential,
		})
		req.RoutingUserAdditions = append(req.RoutingUserAdditions, batchRoutingAddition{
			Marktag:     it.Marktag,
			OutboundTag: it.OutboundTag,
			UserEmail:   it.UserEmail,
		})
	}

	body, _ := json.Marshal(req)
	raw, err := rm.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/batch-apply", body)
	if err != nil {
		// 老 agent 没这个端点 → 路径处理由 caller fallback。检测错误信息中的 404 / not found / unknown route。
		msg := err.Error()
		low := strings.ToLower(msg)
		if strings.Contains(low, "404") || strings.Contains(low, "not found") || strings.Contains(low, "method not allowed") {
			return ErrAgentBatchNotSupported
		}
		return fmt.Errorf("batch-apply server=%d: %w", serverID, err)
	}

	var resp struct {
		Success         bool     `json:"success"`
		InboundResults  []string `json:"inbound_results"`
		RoutingResults  []string `json:"routing_results"`
		RuntimeWarnings []string `json:"runtime_warnings"`
		Message         string   `json:"message"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("parse batch-apply response: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("batch-apply rejected: %s", resp.Message)
	}

	// 全部 agent ops 成功 → 批量写 DB。即使个别 item 在 agent 端返回了 "err: ..."
	// (比如 rule 没找到),也只跳过该 item 的 upsert,不影响其它。
	for i, it := range items {
		if i < len(resp.InboundResults) && strings.HasPrefix(resp.InboundResults[i], "err:") {
			log.Printf("[RoutedBatch] inbound add-client err server=%d item=%d: %s", serverID, i, resp.InboundResults[i])
			continue
		}
		if i < len(resp.RoutingResults) && strings.HasPrefix(resp.RoutingResults[i], "err:") {
			log.Printf("[RoutedBatch] routing add-user err server=%d item=%d: %s", serverID, i, resp.RoutingResults[i])
			continue
		}
		if _, err := repo.UpsertUserSubaccount(ctx, storage.UserSubaccount{
			Username:       it.Username,
			RoutedNodeID:   it.RoutedNodeID,
			Email:          it.UserEmail,
			CredentialJSON: it.CredentialJSON,
			IsActive:       true,
		}); err != nil {
			log.Printf("[RoutedBatch] DB upsert subaccount failed user=%s node=%d: %v", it.Username, it.RoutedNodeID, err)
		}
	}
	for _, w := range resp.RuntimeWarnings {
		log.Printf("[RoutedBatch] agent runtime warning server=%d: %s", serverID, w)
	}
	return nil
}

// applyRoutingAdditionsBatch 把同台服务器多个 routing rule 改动一次 GET+SET 推回。
// 调用方应该把 additions 按 ServerID 分组后,per-server 调一次本函数。
// 失败时 routing 未更新,但 client 已在 inbound 里 + DB 有 subaccount 记录,
// 重试本函数即可幂等补全(去重 append email)。
func applyRoutingAdditionsBatch(ctx context.Context, rm *RemoteManageHandler, serverID int64, additions []routingRuleAddition) error {
	if len(additions) == 0 {
		return nil
	}
	mu := acquireRoutingMutateLock(serverID)
	defer mu.Unlock()

	raw, err := rm.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/routing", nil)
	if err != nil {
		return fmt.Errorf("get routing: %w", err)
	}
	var resp struct {
		Success bool                   `json:"success"`
		Routing map[string]interface{} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("parse routing: %w", err)
	}
	if resp.Routing == nil {
		return fmt.Errorf("no routing config")
	}
	rules, _ := resp.Routing["rules"].([]interface{})

	for _, a := range additions {
		matched := -1
		for i, ru := range rules {
			r, _ := ru.(map[string]interface{})
			if r == nil {
				continue
			}
			if a.Marktag != "" {
				if mt, _ := r["marktag"].(string); mt == a.Marktag {
					matched = i
					break
				}
			} else if a.OutboundTag != "" {
				if t, _ := r["outboundTag"].(string); t == a.OutboundTag {
					matched = i
					break
				}
			}
		}
		if matched < 0 {
			log.Printf("[RoutedBatch] rule not found server=%d marktag=%q outboundTag=%q, skip", serverID, a.Marktag, a.OutboundTag)
			continue
		}
		rule := rules[matched].(map[string]interface{})
		users, _ := rule["user"].([]interface{})
		// 去重 append
		exists := false
		for _, u := range users {
			if s, _ := u.(string); s == a.UserEmail {
				exists = true
				break
			}
		}
		if !exists {
			users = append(users, a.UserEmail)
			rule["user"] = users
		}
		rules[matched] = rule
	}
	resp.Routing["rules"] = rules

	body, _ := json.Marshal(map[string]interface{}{
		"action":     "set",
		"routing":    resp.Routing,
		"no_restart": true, // 主控统一在末尾 restartXrayInParallel
	})
	if _, err := rm.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/routing", body); err != nil {
		return fmt.Errorf("set routing: %w", err)
	}
	return nil
}

// addUserToRoutedNode 是单节点版的包装,给非套餐路径(单用户加路由出站等)用,
// 保留 prepare 失败时已加 client 不回滚的语义 — 调用方按需 removeClient + remove subaccount。
func addUserToRoutedNode(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, user storage.User, routedNodeID int64) error {
	add, err := prepareRoutedNodeForUser(ctx, rm, repo, user, routedNodeID)
	if err != nil {
		return err
	}
	if add == nil {
		return nil
	}
	if err := applyRoutingAdditionsBatch(ctx, rm, add.ServerID, []routingRuleAddition{*add}); err != nil {
		// routing 失败 → 回滚 client(保留旧语义,单节点路径用户期望"失败即清理")。
		// DB 里 UpsertUserSubaccount 已写入 is_active=true,这里只 remove client;
		// 下次手动重试 batch 可幂等补全 routing,DB 记录复用。
		routed, gerr := repo.GetRoutedNodeDetail(ctx, routedNodeID)
		if gerr == nil && routed.InboundTag != "" {
			removeClientFromInbound(ctx, rm, add.ServerID, routed.InboundTag, add.UserEmail)
		}
		return err
	}
	return nil
}

// removeUserFromRoutedNode 把用户从 routing rule.user[] 移除 + 从 inbound 移除 client。
// is_active 置 0,credential 保留 — 下次绑定/续费可无缝恢复。
func removeUserFromRoutedNode(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, username string, routedNodeID int64) error {
	routed, err := repo.GetRoutedNodeDetail(ctx, routedNodeID)
	if err != nil {
		return fmt.Errorf("get routed node %d: %w", routedNodeID, err)
	}
	sa, err := repo.GetUserSubaccount(ctx, routedNodeID, username)
	if err != nil || sa == nil {
		return nil // 没有子账号,无事可做
	}

	servers, err := repo.ListRemoteServers(ctx)
	if err != nil {
		return fmt.Errorf("list servers: %w", err)
	}
	var serverID int64
	for _, s := range servers {
		if s.Name == routed.OriginalServer {
			serverID = s.ID
			break
		}
	}
	if serverID == 0 {
		return fmt.Errorf("server %s not found", routed.OriginalServer)
	}

	// 1. 从 rule.user[] 移除。同 add 路径分两种 routed 节点处理。
	// 任一步失败都不能提前把 DB 标成 inactive，否则 enforcer 会误以为断流完成，
	// Agent 恢复后也失去补偿重试依据。
	var opErr error
	if routed.RoutedRuleMarktag != "" {
		body, _ := json.Marshal(map[string]interface{}{
			"action":     "remove_user_from_rule",
			"marktag":    routed.RoutedRuleMarktag,
			"user_email": sa.Email,
			"no_restart": true, // 主控 PackageUnbind 在末尾统一重启,见 packages.go restartXrayInParallel
		})
		if _, err := rm.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/routing", body); err != nil {
			opErr = errors.Join(opErr, fmt.Errorf("remove user from rule by marktag: %w", err))
		}
	} else if routed.RoutedOutboundTag != "" {
		if err := mutateRoutingRuleUserByOutboundTag(ctx, rm, serverID, routed.RoutedOutboundTag, sa.Email, false); err != nil {
			opErr = errors.Join(opErr, fmt.Errorf("remove user from rule by outbound tag: %w", err))
		}
	}

	// 2. 从 inbound 移除 client
	if err := removeClientFromInbound(ctx, rm, serverID, routed.InboundTag, sa.Email); err != nil {
		opErr = errors.Join(opErr, err)
	}
	if opErr != nil {
		return opErr
	}

	// 3. DB 置 is_active=0(凭据保留)
	return repo.SetSubaccountActive(ctx, sa.ID, false)
}

var labelRe = regexp.MustCompile(`^[a-zA-Z0-9-]{2,32}$`)

// slugify 把用户输入的 label 转成 outbound tag / email 用的 slug,只允许 [a-z0-9-]
func slugify(s string) string {
	s = strings.TrimSpace(s)
	if !labelRe.MatchString(s) {
		return ""
	}
	return strings.ToLower(s)
}

func cloneMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// cloneClashWithCredential 克隆父节点的 clash_config(单 proxy JSON)并替换关键凭据字段为 newCred,
// 用于 routed 节点存储 admin 占位版本的 clash 配置。返回 JSON 字符串;失败返回原 clash。
func cloneClashWithCredential(parentClash, protocol string, newCred map[string]interface{}, newName string) string {
	if parentClash == "" {
		return ""
	}
	var pc map[string]interface{}
	if err := json.Unmarshal([]byte(parentClash), &pc); err != nil {
		return parentClash
	}
	// 节点名换
	if newName != "" {
		pc["name"] = newName
	}
	// 凭据字段替换
	switch strings.ToLower(protocol) {
	case "vless", "vmess":
		if id, ok := newCred["id"].(string); ok && id != "" {
			pc["uuid"] = id
		}
	case "trojan":
		if pw, ok := newCred["password"].(string); ok && pw != "" {
			pc["password"] = pw
		} else if id, ok := newCred["id"].(string); ok && id != "" {
			// admin client 可能只有 id,用作 trojan password fallback
			pc["password"] = id
		}
	case "shadowsocks", "ss":
		// SS2022 user password 拼到节点 master password 后面 `master:userPass`。
		// 父 clash_config 可能已经是 `master:firstClient`(node 创建时拼好的 admin 视角默认值),
		// 也可能只 master(空 inbound),统一剥到只剩 master 再拼,避免三段叠加。
		if userPass, ok := newCred["password"].(string); ok && userPass != "" {
			if nodePass, ok := pc["password"].(string); ok && nodePass != "" {
				if idx := strings.Index(nodePass, ":"); idx >= 0 {
					nodePass = nodePass[:idx]
				}
				pc["password"] = nodePass + ":" + userPass
			} else {
				pc["password"] = userPass
			}
		}
	case "hysteria2", "hysteria", "hy2":
		if auth, ok := newCred["auth"].(string); ok && auth != "" {
			pc["password"] = auth
		}
	case "snell":
		// snell v4/v5 每用户独立 psk;routed 节点的 clash 必须换成本 client 的 psk,否则订阅里是父节点(admin)的 psk → 连不上
		if psk, ok := newCred["psk"].(string); ok && psk != "" {
			pc["psk"] = psk
		}
	case "anytls":
		// anytls 每用户独立 password;换成本 client 的 password,否则订阅里是父节点(admin)的 password → 连不上
		if pw, ok := newCred["password"].(string); ok && pw != "" {
			pc["password"] = pw
		}
	case "socks", "http":
		if user, ok := newCred["user"].(string); ok && user != "" {
			pc["username"] = user
		}
		if pass, ok := newCred["pass"].(string); ok && pass != "" {
			pc["password"] = pass
		}
	case "mieru":
		if user, ok := newCred["username"].(string); ok && user != "" {
			pc["username"] = user
		}
		if pass, ok := newCred["password"].(string); ok && pass != "" {
			pc["password"] = pass
		}
	}
	b, err := json.Marshal(pc)
	if err != nil {
		return parentClash
	}
	return string(b)
}
