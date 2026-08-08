package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"miaomiaowux/internal/storage"
	"miaomiaowux/internal/traffic"
	"miaomiaowux/internal/version"
)

// TrafficHandler 处理与流量相关的 API 请求
type TrafficHandler struct {
	repo      *storage.TrafficRepository
	collector *traffic.Collector
}

// 创建一个新的流量处理程序
func NewTrafficHandler(repo *storage.TrafficRepository, collector *traffic.Collector) *TrafficHandler {
	return &TrafficHandler{
		repo:      repo,
		collector: collector,
	}
}

// SerHTTP 路由流量 API 请求
func (h *TrafficHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/traffic")
	path = strings.TrimPrefix(path, "/")

	switch {
	case path == "" || path == "servers":
		h.handleServers(w, r)
	case strings.HasPrefix(path, "servers/"):
		h.handleServerDetail(w, r, strings.TrimPrefix(path, "servers/"))
	case path == "users":
		h.handleUsers(w, r)
	case strings.HasPrefix(path, "users/"):
		h.handleUserDetail(w, r, strings.TrimPrefix(path, "users/"))
	case path == "snapshots":
		h.handleSnapshots(w, r)
	case path == "node-snapshots":
		h.handleNodeSnapshots(w, r)
	case path == "user-snapshots":
		h.handleUserSnapshots(w, r)
	case path == "server-system-snapshots":
		h.handleServerSystemSnapshots(w, r)
	case path == "server-period-totals":
		h.handleServerPeriodTotals(w, r)
	case path == "user-nodes":
		h.handleUserNodes(w, r)
	case path == "user-period-totals":
		h.handleUserPeriodTotals(w, r)
	case path == "node-users":
		h.handleNodeUsers(w, r)
	case path == "node-totals":
		h.handleNodeTotals(w, r)
	case path == "user-connections":
		h.handleUserConnections(w, r)
	case path == "node-connections":
		h.handleNodeConnections(w, r)
	case path == "period":
		h.handleLedgerPeriod(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleUserPeriodTotals is the legacy-snapshot companion of handleUserNodes.
// Both endpoints derive their values from user_email_traffic with the same
// attribution and current-package estimate, so a parent user row always equals
// the sum of its drill-down rows for pre-ledger/incomplete ranges.
func (h *TrafficHandler) handleUserPeriodTotals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	date := strings.TrimSpace(r.URL.Query().Get("date"))
	if _, err := time.Parse("2006-01-02", date); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "date must be YYYY-MM-DD"})
		return
	}
	ctx := r.Context()
	baseUp, baseDown := h.emailBaseline(ctx, date)
	attr, err := h.repo.BuildEmailAttributor(ctx)
	if err != nil {
		h.writeJSON(w, 500, map[string]any{"success": false, "error": err.Error()})
		return
	}
	rows, err := h.repo.ListUserEmailTraffic(ctx)
	if err != nil {
		h.writeJSON(w, 500, map[string]any{"success": false, "error": err.Error()})
		return
	}
	type dirs struct{ up, down float64 }
	totals := map[string]dirs{}
	packages := map[string]*storage.Package{}
	for _, row := range rows {
		at := attr.Classify(row.Email, row.ServerID)
		if at.Username == "" {
			continue
		}
		e := subEmailBaseline(row, baseUp, baseDown)
		pkg, ok := packages[at.Username]
		if !ok {
			if u, e := h.repo.GetUser(ctx, at.Username); e == nil && u.PackageID > 0 {
				pkg, _ = h.repo.GetPackage(ctx, u.PackageID)
			}
			packages[at.Username] = pkg
		}
		weight := 1.0
		if pkg != nil {
			weight = float64(pkg.TrafficMultiplier())
			if len(at.Shares) > 0 {
				weight = 0
				for _, share := range at.Shares {
					scale := share.Scale
					if scale < 1 {
						scale = 1
					}
					weight += pkg.MultiplierForNode(share.NodeID) * float64(pkg.TrafficMultiplier()) / float64(scale)
				}
			}
		}
		d := totals[at.Username]
		d.up += float64(e.Uplink) * weight
		d.down += float64(e.Downlink) * weight
		totals[at.Username] = d
	}
	items := make([]periodTrafficItem, 0, len(totals))
	for username, d := range totals {
		items = append(items, periodTrafficItem{Username: username, Uplink: d.up, Downlink: d.down, Used: d.up + d.down})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Used > items[j].Used })
	h.writeJSON(w, http.StatusOK, map[string]any{"success": true, "date": date, "items": items})
}

// handleServerPeriodTotals 返回从 date 当日 00:00 到当前的服务器流量。
// 当前值与服务管理共用 GetServerTrafficUsed；历史基线则按同一台服务器的
// traffic_source 和 traffic_stats_mode 从对应快照计算，避免前端重复实现统计口径。
func (h *TrafficHandler) handleServerPeriodTotals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	date := strings.TrimSpace(r.URL.Query().Get("date"))
	if _, err := time.Parse("2006-01-02", date); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "date must be YYYY-MM-DD"})
		return
	}

	ctx := r.Context()
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	nodeSnapshots, err := h.repo.GetNodeTrafficSnapshots(ctx, date)
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	systemSnapshots, err := h.repo.GetServerSystemTrafficSnapshots(ctx, date)
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	type directions struct{ up, down int64 }
	nodeBase := make(map[int64]directions)
	for _, snap := range nodeSnapshots {
		base := nodeBase[snap.ServerID]
		base.up += snap.Uplink
		base.down += snap.Downlink
		nodeBase[snap.ServerID] = base
	}
	systemBase := make(map[int64]directions)
	for _, snap := range systemSnapshots {
		systemBase[snap.ServerID] = directions{up: snap.TxCycle, down: snap.RxCycle}
	}

	applyMode := func(value directions, mode string) int64 {
		switch mode {
		case "upload":
			return value.up
		case "download":
			return value.down
		case "max":
			if value.up > value.down {
				return value.up
			}
			return value.down
		default:
			return value.up + value.down
		}
	}

	type periodTotal struct {
		ServerID   int64  `json:"server_id"`
		ServerName string `json:"server_name"`
		Used       int64  `json:"used"`
	}
	items := make([]periodTotal, 0, len(servers))
	for _, server := range servers {
		current, currentErr := h.repo.GetServerTrafficUsed(ctx, server.ID)
		if currentErr != nil {
			log.Printf("[Traffic API] server-period-totals: current server=%d: %v", server.ID, currentErr)
			continue
		}
		base := nodeBase[server.ID]
		if server.TrafficSource == "system" {
			base = systemBase[server.ID]
		}
		used := current - applyMode(base, server.TrafficStatsMode)
		if used < 0 {
			// 快照可能来自旧统计源或服务器计数器重建；不能向前端返回负流量。
			used = 0
		}
		items = append(items, periodTotal{ServerID: server.ID, ServerName: server.Name, Used: used})
	}
	h.writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "date": date, "items": items})
}

// handleUserNodes 返回某用户在每个节点上的流量(细分到 routed 子账号 / 普通 inbound),
// 数据来源: user_email_traffic + user_subaccounts 反查 routed_node_id + user_inbound_configs 反查
// 该用户在某 server 上的 inbound 节点。
//
// 整个套餐周期(date 为空)直接返回采集时计价并写入 weighted_* 的计费流量,与用户总用量同源,
// 修改倍率不会追溯重算历史。带 date 的历史筛选仍依赖只保存裸量的快照表,因此暂按当前倍率折算。
//
// GET /api/admin/traffic/user-nodes?username=share
//
// 响应: { items: [ { node_id, node_name, server_name, uplink, downlink, last_uplink, last_downlink } ] }
func (h *TrafficHandler) handleUserNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	date := strings.TrimSpace(r.URL.Query().Get("date"))
	baseUp, baseDown := h.emailBaseline(ctx, date)

	// 仅日期筛选需要读时倍率；整周期直接使用入库时已折算的 weighted_*。
	var pkg *storage.Package
	if date != "" {
		if user, uerr := h.repo.GetUser(ctx, username); uerr == nil && user.PackageID > 0 {
			if p, perr := h.repo.GetPackage(ctx, user.PackageID); perr == nil {
				pkg = p
			}
		}
	}

	// 统一归因器:每条 email 确定性归到"恰好一个用户 + 一/多个节点"。
	// routed email(含被停用的子账号 / admin 占位)永不落父入站,消除父/routed 双算。
	attr, err := h.repo.BuildEmailAttributor(ctx)
	if err != nil {
		log.Printf("[Traffic API] user-nodes: build attributor failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "build attribution failed"})
		return
	}
	allEmailTraffic, err := h.repo.ListUserEmailTraffic(ctx)
	if err != nil {
		log.Printf("[Traffic API] user-nodes: list user_email_traffic failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "list email traffic failed"})
		return
	}

	type item struct {
		NodeID       int64  `json:"node_id"`
		NodeName     string `json:"node_name"`
		ServerName   string `json:"server_name"`
		Uplink       int64  `json:"uplink"`
		Downlink     int64  `json:"downlink"`
		LastUplink   int64  `json:"last_uplink"`
		LastDownlink int64  `json:"last_downlink"`
	}
	byNode := make(map[int64]*item)

	addToNode := func(ns storage.NodeShare, uet storage.UserEmailTraffic) {
		if existing, ok := byNode[ns.NodeID]; ok {
			existing.Uplink += uet.Uplink
			existing.Downlink += uet.Downlink
			existing.LastUplink += uet.LastUplink
			existing.LastDownlink += uet.LastDownlink
			return
		}
		byNode[ns.NodeID] = &item{
			NodeID:       ns.NodeID,
			NodeName:     ns.NodeName,
			ServerName:   ns.ServerName,
			Uplink:       uet.Uplink,
			Downlink:     uet.Downlink,
			LastUplink:   uet.LastUplink,
			LastDownlink: uet.LastDownlink,
		}
	}

	for _, uet := range allEmailTraffic {
		at := attr.Classify(uet.Email, uet.ServerID)
		if at.Username != username {
			continue
		}
		uet = subEmailBaseline(uet, baseUp, baseDown)
		if date == "" {
			uet.Uplink = int64(uet.WeightedUplink)
			uet.Downlink = int64(uet.WeightedDownlink)
		}
		if len(at.Shares) == 0 {
			addToNode(storage.NodeShare{NodeID: 0, NodeName: "未归属", Scale: 1}, uet)
			continue
		}
		for _, ns := range at.Shares {
			addToNode(ns, storage.ScaledEmailTraffic(uet, ns.Scale))
		}
	}

	out := make([]item, 0, len(byNode))
	for _, it := range byNode {
		// 日期快照没有 weighted_*，仅该兼容路径按当前倍率折算。
		if date != "" {
			if mult := pkg.MultiplierForNode(it.NodeID) * float64(pkg.TrafficMultiplier()); mult != 1 {
				it.Uplink = int64(float64(it.Uplink) * mult)
				it.Downlink = int64(float64(it.Downlink) * mult)
				it.LastUplink = int64(float64(it.LastUplink) * mult)
				it.LastDownlink = int64(float64(it.LastDownlink) * mult)
			}
		}
		out = append(out, *it)
	}
	// 按总流量降序(用加权后的值排,与展示口径一致)
	sort.Slice(out, func(i, j int) bool {
		return (out[i].Uplink + out[i].Downlink) > (out[j].Uplink + out[j].Downlink)
	})

	period := map[string]any{"start": nil, "end": nil}
	if start, end, perr := h.repo.GetUserPackagePeriod(ctx, username); perr == nil {
		if start != nil {
			period["start"] = start.Format("2006-01-02")
		}
		if end != nil {
			period["end"] = end.Format("2006-01-02")
		}
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"success": true, "items": out, "package_period": period})
}

// handleNodeUsers 返回某节点上各用户的流量(节点视图 drilldown 反向用)。
// 走 user_email_traffic + user_subaccounts/user_inbound_configs 反查,与 handleUserNodes 对称。
//
// GET /api/admin/traffic/node-users?node_id=42
//
// 响应: { items: [ { username, uplink, downlink, last_uplink, last_downlink } ] }
func (h *TrafficHandler) handleNodeUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	nodeIDStr := strings.TrimSpace(r.URL.Query().Get("node_id"))
	nodeID, err := strconv.ParseInt(nodeIDStr, 10, 64)
	if err != nil || nodeID <= 0 {
		http.Error(w, "node_id is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	date := strings.TrimSpace(r.URL.Query().Get("date"))
	baseUp, baseDown := h.emailBaseline(ctx, date)

	// 校验节点存在(404)。
	if _, err := h.repo.GetNodeByID(ctx, nodeID); err != nil {
		h.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "error": "node not found"})
		return
	}

	// 统一归因器(与 user-nodes 共用):每条 email 归到"恰好一个用户 + 一/多个节点"。
	// routed/物理由归因器判定,本接口只挑"归到本节点"的 share,天然不会把 routed 流量算到父入站。
	attr, err := h.repo.BuildEmailAttributor(ctx)
	if err != nil {
		log.Printf("[Traffic API] node-users: build attributor failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "build attribution failed"})
		return
	}

	allEmailTraffic, err := h.repo.ListUserEmailTraffic(ctx)
	if err != nil {
		log.Printf("[Traffic API] node-users: list user_email_traffic failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "list email traffic failed"})
		return
	}

	type item struct {
		Username     string `json:"username"`
		Uplink       int64  `json:"uplink"`
		Downlink     int64  `json:"downlink"`
		LastUplink   int64  `json:"last_uplink"`
		LastDownlink int64  `json:"last_downlink"`
	}
	byUser := make(map[string]*item)
	// 字段语义:Uplink/Downlink 用 cycle-delta(uet.Uplink/Downlink)— 跟对称的 user-nodes 接口一致,
	// 且 collector 的 XrayRestartDetector 已正确累加 xray 重启前的流量。LastUplink/LastDownlink 仍保留
	// cumulative 原值供参考。(旧实现曾故意用 cumulative 避免"用户>节点",但导致两个详情接口口径不一致
	// 且重启后丢失之前流量,已改回 cycle-delta。)
	addUser := func(username string, uet storage.UserEmailTraffic) {
		if existing, ok := byUser[username]; ok {
			existing.Uplink += uet.Uplink
			existing.Downlink += uet.Downlink
			existing.LastUplink += uet.LastUplink
			existing.LastDownlink += uet.LastDownlink
			return
		}
		byUser[username] = &item{
			Username:     username,
			Uplink:       uet.Uplink,
			Downlink:     uet.Downlink,
			LastUplink:   uet.LastUplink,
			LastDownlink: uet.LastDownlink,
		}
	}

	for _, uet := range allEmailTraffic {
		at := attr.Classify(uet.Email, uet.ServerID)
		if at.Username == "" {
			continue
		}
		// 挑该 email 归到本节点的 share(通常至多一个)。
		var hit *storage.NodeShare
		for i := range at.Shares {
			if at.Shares[i].NodeID == nodeID {
				hit = &at.Shares[i]
				break
			}
		}
		if hit == nil {
			continue
		}
		e := subEmailBaseline(uet, baseUp, baseDown)
		addUser(at.Username, storage.ScaledEmailTraffic(e, hit.Scale))
	}

	out := make([]item, 0, len(byUser))
	for _, it := range byUser {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool {
		return (out[i].Uplink + out[i].Downlink) > (out[j].Uplink + out[j].Downlink)
	})

	h.writeJSON(w, http.StatusOK, map[string]any{"success": true, "items": out})
}

// handleNodeTotals 返回每个节点(物理入站 + routed 出站)的 email 派生总量,与 node-users / user-nodes
// 同源同口径:物理节点 = 其非-routed 用户 email 之和(**自动排除被路由出去的流量**);routed 节点 =
// 其子账号 email 之和。取代"节点视图直接用 node_traffic 入站总量(含 routed)"的旧口径,消除父/routed 双算。
// 支持 date(当日/本周/本月,服务端减 email 快照)。
//
// GET /api/admin/traffic/node-totals?date=2026-07-08
// 响应: { items: [ { node_id, node_name, server_name, node_type, uplink, downlink, last_uplink, last_downlink } ] }
func (h *TrafficHandler) handleNodeTotals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	date := strings.TrimSpace(r.URL.Query().Get("date"))
	baseUp, baseDown := h.emailBaseline(ctx, date)

	attr, err := h.repo.BuildEmailAttributor(ctx)
	if err != nil {
		log.Printf("[Traffic API] node-totals: build attributor failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "build attribution failed"})
		return
	}
	nodes, err := h.repo.ListAllNodes(ctx)
	if err != nil {
		log.Printf("[Traffic API] node-totals: list nodes failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "list nodes failed"})
		return
	}
	nodeTypeByID := make(map[int64]string, len(nodes))
	for _, n := range nodes {
		nodeTypeByID[n.ID] = n.NodeType
	}
	allEmailTraffic, err := h.repo.ListUserEmailTraffic(ctx)
	if err != nil {
		log.Printf("[Traffic API] node-totals: list user_email_traffic failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "list email traffic failed"})
		return
	}

	type item struct {
		NodeID       int64  `json:"node_id"`
		NodeName     string `json:"node_name"`
		ServerName   string `json:"server_name"`
		NodeType     string `json:"node_type"`
		Uplink       int64  `json:"uplink"`
		Downlink     int64  `json:"downlink"`
		LastUplink   int64  `json:"last_uplink"`
		LastDownlink int64  `json:"last_downlink"`
	}
	byNode := make(map[int64]*item)
	emailSumByServer := make(map[int64]int64) // 对账用:每 server 归因成功的 email 总和

	// ===== 三段式归因(见 plan)。=====
	// 旧实现对**所有**节点走 email 归因,email=纯 username 时落到均分兜底 → 同 server 多节点平摊。
	// xray 上报本就是 inbound-tag 维度(node_traffic 精确),物理节点直接用它,只有 routed 节点才需要 email。

	// (a) name→id:物理节点 OriginalServer 是名字,node_traffic 是 server_id。
	nameToID := make(map[string]int64)
	if servers, serr := h.repo.ListRemoteServers(ctx); serr == nil {
		for _, s := range servers {
			nameToID[s.Name] = s.ID
		}
	}
	// (b) routed 节点 id → inbound_tag:用来把 routed 流量归到父物理入站 (server_id, inbound_tag)。
	routedInboundTagByNodeID := make(map[int64]string, len(nodes))
	for _, n := range nodes {
		if n.NodeType == "routed" {
			routedInboundTagByNodeID[n.ID] = n.InboundTag
		}
	}

	// (c) 第一趟:email 归因。routed 节点直接落地(现状口径正确);
	//     物理节点这一趟只记 email 结果作 fallback,并累加"被路由出去"的量供扣除。
	fallbackByNode := make(map[int64]*item)                      // 物理节点的 email 归因结果(仅无 node_traffic 时用)
	routedByInbound := make(map[string]struct{ up, down int64 }) // "<sid>|<tag>" → 该物理入站下 routed 出去的量
	for _, uet := range allEmailTraffic {
		at := attr.Classify(uet.Email, uet.ServerID)
		if at.Username == "" {
			continue
		}
		e := subEmailBaseline(uet, baseUp, baseDown)
		emailSumByServer[uet.ServerID] += e.Uplink + e.Downlink
		for _, ns := range at.Shares {
			s := storage.ScaledEmailTraffic(e, ns.Scale)
			if at.Routed {
				// routed 节点:直接计入结果(email 是唯一能区分落地机的维度)。
				it, ok := byNode[ns.NodeID]
				if !ok {
					it = &item{NodeID: ns.NodeID, NodeName: ns.NodeName, ServerName: ns.ServerName, NodeType: nodeTypeByID[ns.NodeID]}
					byNode[ns.NodeID] = it
				}
				it.Uplink += s.Uplink
				it.Downlink += s.Downlink
				it.LastUplink += s.LastUplink
				it.LastDownlink += s.LastDownlink
				// 同时累加到父物理入站,供物理节点扣除。父入站 = (uet.ServerID, routed 节点的 inbound_tag)。
				if tag := routedInboundTagByNodeID[ns.NodeID]; tag != "" {
					k := strconv.FormatInt(uet.ServerID, 10) + "|" + tag
					agg := routedByInbound[k]
					agg.up += s.Uplink
					agg.down += s.Downlink
					routedByInbound[k] = agg
				}
			} else {
				// 物理节点:先攒着当 fallback,后面优先用 node_traffic。
				it, ok := fallbackByNode[ns.NodeID]
				if !ok {
					it = &item{NodeID: ns.NodeID, NodeName: ns.NodeName, ServerName: ns.ServerName, NodeType: nodeTypeByID[ns.NodeID]}
					fallbackByNode[ns.NodeID] = it
				}
				it.Uplink += s.Uplink
				it.Downlink += s.Downlink
				it.LastUplink += s.LastUplink
				it.LastDownlink += s.LastDownlink
			}
		}
	}

	// (d) node_traffic(inbound-tag 维度)建图,减 date baseline。
	nodeBase := h.nodeTrafficBaseline(ctx, date)
	ntByKey := make(map[string]struct{ up, down int64 }) // "<sid>|<tag>" → 入站流量(已减 baseline)
	if nts, e2 := h.repo.GetAllNodeTraffic(ctx); e2 == nil {
		for _, nt := range nts {
			if nt.Type != "inbound" {
				continue
			}
			up, down := subNodeBaseline(nt.ServerID, nt.Tag, nt.Uplink, nt.Downlink, nodeBase)
			ntByKey[strconv.FormatInt(nt.ServerID, 10)+"|"+nt.Tag] = struct{ up, down int64 }{up, down}
		}
	}

	// (e) 第二趟:物理节点。优先 node_traffic[tag] − routed;查不到 key(空 tag/无上报)则 fallback email。
	//     同 (sid,tag) 多个物理节点时,node_traffic 一份无法区分 —— pickNode 选套餐优先/最小 ID 的主节点拿全部,
	//     其余记 0(不再均分)。
	physByKey := make(map[string][]storage.Node) // "<sid>|<tag>" → 该键下的物理节点
	for _, n := range nodes {
		if n.NodeType == "routed" {
			continue
		}
		sid, ok := nameToID[n.OriginalServer]
		if !ok || n.InboundTag == "" {
			continue // 无 server / 空 tag → 走 fallback
		}
		k := strconv.FormatInt(sid, 10) + "|" + n.InboundTag
		physByKey[k] = append(physByKey[k], n)
	}
	primaryPhysNodeID := make(map[int64]bool) // 已用 node_traffic 分配的物理节点(不再走 fallback)
	for k, group := range physByKey {
		nt, hasNT := ntByKey[k]
		if !hasNT {
			continue // node_traffic 无此入站数据 → 组内各节点走 fallback
		}
		// 选主节点:同 tag 多节点时套餐优先/最小 ID(与 pickNode 一致的确定性)。单节点即它本身。
		primary := group[0]
		for _, n := range group[1:] {
			if n.ID < primary.ID {
				primary = n
			}
		}
		routed := routedByInbound[k]
		up := nt.up - routed.up
		if up < 0 {
			up = 0
		}
		down := nt.down - routed.down
		if down < 0 {
			down = 0
		}
		byNode[primary.ID] = &item{
			NodeID: primary.ID, NodeName: primary.NodeName, ServerName: primary.OriginalServer,
			NodeType: "physical", Uplink: up, Downlink: down,
		}
		for _, n := range group {
			primaryPhysNodeID[n.ID] = true // 组内所有节点都已定,其余非主节点隐式为 0
		}
	}
	// fallback:未被 node_traffic 覆盖的物理节点,用 email 归因结果。
	for id, it := range fallbackByNode {
		if primaryPhysNodeID[id] {
			continue
		}
		if _, done := byNode[id]; done {
			continue
		}
		byNode[id] = it
	}

	// 对账参照(仅全周期):Σemail 归因 ≈ Σnode_traffic 入站。物理节点现在直接用 node_traffic,
	// 这个对账主要监控 email 侧(routed 归位 + fallback)是否与 xray 上报对得上;漂移过大 → 有未按 user 计数的流量。
	if date == "" {
		if nts, e2 := h.repo.GetAllNodeTraffic(ctx); e2 == nil {
			inboundByServer := make(map[int64]int64)
			for _, nt := range nts {
				if nt.Type == "inbound" {
					inboundByServer[nt.ServerID] += nt.Uplink + nt.Downlink
				}
			}
			for sid, inb := range inboundByServer {
				em := emailSumByServer[sid]
				if inb > 0 {
					driftPct := float64(inb-em) * 100 / float64(inb)
					if driftPct > 15 || driftPct < -15 {
						log.Printf("[Traffic API] node-totals reconcile: server %d inbound=%d email_sum=%d drift=%.1f%%", sid, inb, em, driftPct)
					}
				}
			}
		}
	}

	out := make([]item, 0, len(byNode))
	for _, it := range byNode {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool {
		return (out[i].Uplink + out[i].Downlink) > (out[j].Uplink + out[j].Downlink)
	})

	h.writeJSON(w, http.StatusOK, map[string]any{"success": true, "items": out})
}

// handleUserConnections 返回各用户当前并发连接数(跨所有 server 按 username 聚合)。
// 数据来自 agent 每次 traffic 上报的 conn_counts(内存、实时、非持久)。用户视图「当前连接数」列用。
// GET /api/admin/traffic/user-connections → { success, connections: { "<username>": <n> } }
func (h *TrafficHandler) handleUserConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"success": true, "connections": AggregateUserConnCounts()})
}

func (h *TrafficHandler) handleNodeConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	totals, users := AggregateNodeConnCounts()
	h.writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "connections": totals, "users": users,
	})
}

// emailBaseline 加载 <= date 的 email 级 baseline,key = "<server_id>|<email>"。
// date 为空(未选时间范围)→ 返回 nil,subEmailBaseline 不做减法,详情显示全周期 cycle-delta。
func (h *TrafficHandler) emailBaseline(ctx context.Context, date string) (up, down map[string]int64) {
	if date == "" {
		return nil, nil
	}
	snaps, err := h.repo.GetUserEmailTrafficSnapshots(ctx, date)
	if err != nil {
		log.Printf("[Traffic API] email baseline load failed: %v", err)
		return nil, nil
	}
	up = make(map[string]int64, len(snaps))
	down = make(map[string]int64, len(snaps))
	for _, s := range snaps {
		k := strconv.FormatInt(s.ServerID, 10) + "|" + s.Email
		up[k] = s.Uplink
		down[k] = s.Downlink
	}
	return up, down
}

// subEmailBaseline 把 uet 的 cycle-delta(Uplink/Downlink)减去 date 时的 baseline → "自 date 起的增量"。
// nodeTrafficBaseline 加载 <= date 的 node_traffic(inbound 型)baseline,key = "<server_id>|<tag>"。
// date 为空 → nil,不做减法(全周期)。与 emailBaseline 完全对称。
func (h *TrafficHandler) nodeTrafficBaseline(ctx context.Context, date string) map[string]struct{ up, down int64 } {
	if date == "" {
		return nil
	}
	snaps, err := h.repo.GetNodeTrafficSnapshots(ctx, date)
	if err != nil {
		log.Printf("[Traffic API] node baseline load failed: %v", err)
		return nil
	}
	m := make(map[string]struct{ up, down int64 }, len(snaps))
	for _, s := range snaps {
		if s.Type != "inbound" {
			continue // 只减 inbound baseline(与 server 视图口径一致,见 NodeTrafficSnapshot.Type 注释)
		}
		m[strconv.FormatInt(s.ServerID, 10)+"|"+s.Tag] = struct{ up, down int64 }{s.Uplink, s.Downlink}
	}
	return m
}

// subNodeBaseline 把 (serverID, tag) 的 up/down 减去 date baseline → "自 date 起增量",clamp 0。
// base == nil(date 为空)原样返回。仿 subEmailBaseline。
func subNodeBaseline(serverID int64, tag string, up, down int64, base map[string]struct{ up, down int64 }) (int64, int64) {
	if base == nil {
		return up, down
	}
	if b, ok := base[strconv.FormatInt(serverID, 10)+"|"+tag]; ok {
		if up > b.up {
			up -= b.up
		} else {
			up = 0
		}
		if down > b.down {
			down -= b.down
		} else {
			down = 0
		}
	}
	return up, down
}

// clamp 到 0 防 baseline > 当前(快照后 xray 重置等)。Last* 是 cumulative 参考值,不减。
// up == nil(date 为空)直接原样返回。
func subEmailBaseline(uet storage.UserEmailTraffic, up, down map[string]int64) storage.UserEmailTraffic {
	if up == nil {
		return uet
	}
	k := strconv.FormatInt(uet.ServerID, 10) + "|" + uet.Email
	baseUp, hasUp := up[k]
	baseDown, hasDown := down[k]
	// The selected baseline may belong to the previous package/reset cycle.
	// user_email_traffic is reset by raising cycle_base_*, so its current
	// cycle-delta can legitimately be smaller than the historical snapshot.
	// In that case both directions must fall back to the full current cycle,
	// exactly like the dashboard user total. Clamping each direction to zero
	// made the user row non-zero while every node in its drilldown showed 0 B.
	if (hasUp && uet.Uplink < baseUp) || (hasDown && uet.Downlink < baseDown) {
		return uet
	}
	if hasUp {
		uet.Uplink -= baseUp
	}
	if hasDown {
		uet.Downlink -= baseDown
	}
	return uet
}

// ServerTrafficResponse 表示服务器的流量数据
type ServerTrafficResponse struct {
	ServerID   int64                 `json:"server_id"`
	ServerName string                `json:"server_name"`
	Inbounds   []storage.NodeTraffic `json:"inbounds"`
	Outbounds  []storage.NodeTraffic `json:"outbounds"`
	Users      []storage.UserTraffic `json:"users"`
}

// ServersTrafficResponse 表示所有服务器的流量数据
type ServersTrafficResponse struct {
	Success bool                    `json:"success"`
	Servers []ServerTrafficResponse `json:"servers"`
}

func (h *TrafficHandler) handleServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		log.Printf("[Traffic API] Failed to list servers: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to list servers",
		})
		return
	}

	// 获取所有节点流量
	allNodeTraffic, err := h.repo.GetAllNodeTraffic(ctx)
	if err != nil {
		log.Printf("[Traffic API] Failed to get node traffic: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to get node traffic",
		})
		return
	}

	allUserTraffic, err := h.repo.GetAllUserTraffic(ctx)
	if err != nil {
		log.Printf("[Traffic API] Failed to get user traffic: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to get user traffic",
		})
		return
	}

	// 按服务器分组
	nodeByServer := make(map[int64][]storage.NodeTraffic)
	userByServer := make(map[int64][]storage.UserTraffic)

	for _, t := range allNodeTraffic {
		nodeByServer[t.ServerID] = append(nodeByServer[t.ServerID], t)
	}
	for _, t := range allUserTraffic {
		userByServer[t.ServerID] = append(userByServer[t.ServerID], t)
	}

	// 建立服务器 ID → 名称映射
	serverNameMap := make(map[int64]string)
	for _, server := range servers {
		serverNameMap[server.ID] = server.Name
	}

	// 收集所有出现过的 server_id
	allServerIDs := make(map[int64]bool)
	for sid := range nodeByServer {
		allServerIDs[sid] = true
	}
	for sid := range userByServer {
		allServerIDs[sid] = true
	}

	// 建立响应
	var result []ServerTrafficResponse
	for sid := range allServerIDs {
		name, ok := serverNameMap[sid]
		if !ok {
			name = fmt.Sprintf("未知服务器-%d", sid)
		}
		nodeTraffic := nodeByServer[sid]
		// 节点流量始终上下行双向显示,**不再**应用 server.traffic_stats_mode。
		// 原 mode swap 逻辑误把 server 级计费规则(upload/download)套到节点字段上,
		// 让 upload mode server 上所有节点的 downlink 被错误清零(包括 routed 出站节点)。
		// server 视图的「used」计算独立 — 走 storage.GetServerTrafficUsed(),那条路径才正确处理 mode。
		var inbounds, outbounds []storage.NodeTraffic
		for _, t := range nodeTraffic {
			if t.Type == "inbound" {
				inbounds = append(inbounds, t)
			} else {
				outbounds = append(outbounds, t)
			}
		}

		result = append(result, ServerTrafficResponse{
			ServerID:   sid,
			ServerName: name,
			Inbounds:   inbounds,
			Outbounds:  outbounds,
			Users:      userByServer[sid],
		})
	}

	h.writeJSON(w, http.StatusOK, ServersTrafficResponse{
		Success: true,
		Servers: result,
	})
}

func (h *TrafficHandler) handleServerDetail(w http.ResponseWriter, r *http.Request, serverIDStr string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	serverID, err := strconv.ParseInt(serverIDStr, 10, 64)
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Invalid server ID",
		})
		return
	}

	ctx := r.Context()

	// 获取服务器信息
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		h.writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"success": false,
			"error":   "Server not found",
		})
		return
	}

	// 获取节点流量
	nodeTraffic, err := h.repo.GetNodeTrafficByServer(ctx, serverID)
	if err != nil {
		log.Printf("[Traffic API] Failed to get node traffic for server %d: %v", serverID, err)
		nodeTraffic = []storage.NodeTraffic{}
	}

	var inbounds, outbounds []storage.NodeTraffic
	for _, t := range nodeTraffic {
		if t.Type == "inbound" {
			inbounds = append(inbounds, t)
		} else {
			outbounds = append(outbounds, t)
		}
	}

	// 获取用户流量
	userTraffic, err := h.repo.GetUserTrafficByServer(ctx, serverID)
	if err != nil {
		log.Printf("[Traffic API] Failed to get user traffic for server %d: %v", serverID, err)
		userTraffic = []storage.UserTraffic{}
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"server": ServerTrafficResponse{
			ServerID:   server.ID,
			ServerName: server.Name,
			Inbounds:   inbounds,
			Outbounds:  outbounds,
			Users:      userTraffic,
		},
	})
}

// UserTrafficSummary 表示用户在所有服务器上的聚合流量
type UserTrafficSummary struct {
	Username      string                `json:"username"`
	TotalUplink   int64                 `json:"total_uplink"`
	TotalDownlink int64                 `json:"total_downlink"`
	CycleUplink   int64                 `json:"cycle_uplink"`
	CycleDownlink int64                 `json:"cycle_downlink"`
	Servers       []storage.UserTraffic `json:"servers"`
}

func (h *TrafficHandler) handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	allUserTraffic, err := h.repo.GetAllUserTraffic(ctx)
	if err != nil {
		log.Printf("[Traffic API] Failed to get user traffic: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to get user traffic",
		})
		return
	}

	// 按用户名聚合
	userMap := make(map[string]*UserTrafficSummary)
	for _, t := range allUserTraffic {
		if _, ok := userMap[t.Username]; !ok {
			userMap[t.Username] = &UserTrafficSummary{
				Username: t.Username,
			}
		}
		summary := userMap[t.Username]
		summary.TotalUplink += t.TotalUplink + t.Uplink
		summary.TotalDownlink += t.TotalDownlink + t.Downlink
		summary.CycleUplink += t.Uplink
		summary.CycleDownlink += t.Downlink
		summary.Servers = append(summary.Servers, t)
	}

	// 转换为切片
	var result []UserTrafficSummary
	for _, summary := range userMap {
		result = append(result, *summary)
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"users":   result,
	})
}

func (h *TrafficHandler) handleUserDetail(w http.ResponseWriter, r *http.Request, username string) {
	if r.Method == http.MethodDelete {
		// 重置用户流量周期
		h.handleResetUserCycle(w, r, username)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// 获取该用户的所有用户流量
	allUserTraffic, err := h.repo.GetAllUserTraffic(ctx)
	if err != nil {
		log.Printf("[Traffic API] Failed to get user traffic: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to get user traffic",
		})
		return
	}

	// 按用户名过滤
	var userTraffic []storage.UserTraffic
	for _, t := range allUserTraffic {
		if t.Username == username {
			userTraffic = append(userTraffic, t)
		}
	}

	if len(userTraffic) == 0 {
		h.writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"success": false,
			"error":   "User traffic not found",
		})
		return
	}

	// 计算总结
	var totalUplink, totalDownlink, cycleUplink, cycleDownlink int64
	for _, t := range userTraffic {
		totalUplink += t.TotalUplink + t.Uplink
		totalDownlink += t.TotalDownlink + t.Downlink
		cycleUplink += t.Uplink
		cycleDownlink += t.Downlink
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"user": UserTrafficSummary{
			Username:      username,
			TotalUplink:   totalUplink,
			TotalDownlink: totalDownlink,
			CycleUplink:   cycleUplink,
			CycleDownlink: cycleDownlink,
			Servers:       userTraffic,
		},
	})
}

func (h *TrafficHandler) handleResetUserCycle(w http.ResponseWriter, r *http.Request, username string) {
	ctx := r.Context()

	if err := h.repo.ResetUserTrafficCycle(ctx, username); err != nil {
		log.Printf("[Traffic API] Failed to reset user cycle for %s: %v", username, err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to reset user cycle",
		})
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "User cycle reset successfully",
	})
}

func (h *TrafficHandler) handleSnapshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// 解析查询参数
	serverIDStr := r.URL.Query().Get("server_id")
	daysStr := r.URL.Query().Get("days")

	var serverID int64
	if serverIDStr != "" {
		var err error
		serverID, err = strconv.ParseInt(serverIDStr, 10, 64)
		if err != nil {
			serverID = 0
		}
	}

	days := 30
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 {
			days = d
		}
	}

	snapshots, err := h.repo.GetTrafficSnapshots(ctx, serverID, days)
	if err != nil {
		log.Printf("[Traffic API] Failed to get snapshots: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to get snapshots",
		})
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"snapshots": snapshots,
	})
}

func (h *TrafficHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// RemoteTrafficHandler 处理来自远程服务器的流量报告
type RemoteTrafficHandler struct {
	repo      *storage.TrafficRepository
	collector *traffic.Collector
	crypto    *CryptoConfig
	// probeStore 伪装探针指标 ring。HTTP/pull 模式的 agent 没有 WS 连接,
	// 指标只能从这条 traffic POST 进来 —— 不注入的话这些 agent 的
	// CPU/内存/硬盘/延迟永远进不了 ring,伪装页上只剩流量和网速。
	probeStore *ProbeMetricsStore
	// wsHandler 仅用于复用它的探针采集配置组装(HTTP 模式要把同一份配置
	// 捎带在 traffic 响应里下发,否则 agent 根本不会开始采集)。
	wsHandler *RemoteWSHandler
}

// SetProbeStore 注入探针指标 ring(与 WS 侧同一实例)。
func (h *RemoteTrafficHandler) SetProbeStore(s *ProbeMetricsStore) { h.probeStore = s }

// SetWSHandler 注入 WS handler,借用其探针配置组装逻辑。
func (h *RemoteTrafficHandler) SetWSHandler(w *RemoteWSHandler) { h.wsHandler = w }

// 创建一个新的远程流量处理程序
func NewRemoteTrafficHandler(repo *storage.TrafficRepository, collector *traffic.Collector, crypto *CryptoConfig) *RemoteTrafficHandler {
	return &RemoteTrafficHandler{
		repo:      repo,
		collector: collector,
		crypto:    crypto,
	}
}

// RemoteTrafficRequest 表示来自远程服务器的流量报告
type RemoteTrafficRequest struct {
	Stats *traffic.XrayStats `json:"stats,omitempty"`
	// System 系统级网卡累计 RX/TX(来自 agent /proc/net/dev),用于 server.traffic_source='system' 路径。
	// nil = 老 agent 不支持上报,server 视图自动回退 xray 数据源。
	System *RemoteSystemTraffic `json:"system,omitempty"`
	// Sysmetrics / Latency 伪装探针真数据。字段名与 WS 线格式(WSTrafficPayload)完全一致 ——
	// agent 两条上报路径发的是同一份结构,主控这边也必须两条都收。
	Sysmetrics *ProbeSysWire        `json:"sysmetrics,omitempty"`
	Latency    []ProbeLatencySample `json:"latency,omitempty"`
}

// RemoteSystemTraffic 内嵌于 RemoteTrafficRequest,跟 agent 端 sendTrafficData / sendTrafficHTTP 的字段对齐。
type RemoteSystemTraffic struct {
	RxTotal      int64 `json:"rx_total"`
	TxTotal      int64 `json:"tx_total"`
	BootTimeUnix int64 `json:"boot_time_unix"`
}

// 处理来自远程服务器的 POST 请求
func (h *RemoteTrafficHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("User-Agent") != version.AgentUserAgent {
		h.writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "Forbidden",
		})
		return
	}

	ctx := r.Context()

	// 加密中间件处理
	crypto, err := handleHTTPCrypto(r, w, h.crypto)
	if crypto == nil {
		return
	}
	_ = err

	token := crypto.Token
	if token == "" {
		h.writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false,
			"error":   "Missing authentication token",
		})
		return
	}

	// 验证令牌并获取远程服务器
	remoteServer, err := h.repo.GetRemoteServerByToken(ctx, token)
	if err != nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false,
			"error":   "Invalid token",
		})
		return
	}

	// 解析请求体
	var req RemoteTrafficRequest
	if err := json.Unmarshal(crypto.Body, &req); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Invalid request body",
		})
		return
	}

	if req.Stats == nil {
		h.writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "No stats to process",
		})
		return
	}

	// 为该远程查找或创建相应的 XrayServer
	// 现在，我们使用远程服务器 ID 作为伪服务器 ID
	// 在实际实现中，您可能希望将远程服务器与 xray_servers 相关联
	serverID := remoteServer.ID

	// 更新流量报告上的 last_heartbeat — 这取代了单独心跳的需要;
	// 同时检测离线→在线翻转,补发 TG 上线通知(WS 模式 auth 已经发过,
	// HTTP push 模式以前只在这里悄悄翻状态,所以下线通知有、上线通知没有)。
	prevStatus, serverName, serverIP, prevNotified, uErr := h.repo.UpdateRemoteServerLastActivity(ctx, serverID)
	if uErr != nil {
		log.Printf("[Remote Traffic] Failed to update last activity for %s: %v", remoteServer.Name, uErr)
	} else if prevStatus == storage.RemoteServerStatusOffline && prevNotified {
		// 只有下线通知已发过(离线满容忍阈值)才补发上线通知;阈值内恢复(prevNotified=0)保持静默。
		SendServerOnlineNotification(ctx, serverName, serverIP)
	}

	// 处理指标 — remoteServer 已经从 db 取过,直接用其 XrayBootTime
	if err := h.collector.ProcessRemoteMetrics(ctx, serverID, req.Stats, remoteServer.XrayBootTime); err != nil {
		log.Printf("[Remote Traffic] Failed to process metrics from %s: %v", remoteServer.Name, err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to process metrics",
		})
		return
	}

	// 系统级网卡累计:把 delta 累加到 server.system_*_cycle(用于 traffic_source='system')。
	// 老 agent 不上报 → req.System == nil → 跳过,server 视图自动回退 xray 路径。
	// 失败只 log 不阻塞 traffic 流程 — system 数据不可用顶多让 server 视图显示偏小,不致命。
	if req.System != nil {
		if err := h.repo.UpsertRemoteServerSystemTraffic(ctx, serverID, req.System.RxTotal, req.System.TxTotal, req.System.BootTimeUnix); err != nil {
			log.Printf("[Remote Traffic] Failed to upsert system traffic for %s: %v", remoteServer.Name, err)
		}
	}

	// 伪装探针真数据 → 内存 ring。与 WS 分支(remote_ws.go)同一套 ingest,
	// 否则 HTTP/pull 模式的服务器在伪装页上只有流量/网速、没有 CPU/内存/硬盘/延迟。
	if h.probeStore != nil {
		if sm := req.Sysmetrics; sm != nil || req.System != nil {
			snap := ProbeSysSnapshot{}
			if sm != nil {
				snap = ProbeSysSnapshot{
					CPUPct: sm.CPUPct, LoadAvg: sm.LoadAvg,
					MemUsed: sm.MemUsed, MemTotal: sm.MemTotal,
					DiskUsed: sm.DiskUsed, DiskTotal: sm.DiskTotal,
					HasCPU: sm.HasCPU, HasMem: sm.HasMem, HasDisk: sm.HasDisk,
					Uptime: sm.Uptime, CPUModel: sm.CPUModel, CPUCores: sm.CPUCores, CPUThreads: sm.CPUThreads,
					OS: sm.OS, Kernel: sm.Kernel, Arch: sm.Arch,
				}
			}
			if req.System != nil {
				snap.CumulativeUp, snap.CumulativeDown = req.System.TxTotal, req.System.RxTotal
				snap.HasNetwork = true
			}
			h.probeStore.IngestSys(serverID, snap)
		}
		if len(req.Latency) > 0 {
			h.probeStore.IngestLatency(serverID, req.Latency)
		}
	}

	// 在 traffic 上报响应里捎带最新的 config 更新(HTTP-mode agent 没有持久连接,
	// 走 traffic POST 的 response 把变化推回去,agent 收到后调 handleConfigUpdate 应用)。
	configUpdates := map[string]string{}
	if val, _ := h.repo.GetSystemSetting(ctx, "dashboard_refresh_interval_ms"); val != "" {
		configUpdates["traffic_report_interval_ms"] = val
	}
	// 探针采集开关 + ping 目标:WS 模式靠 SendConfigUpdate 主动推,HTTP 模式没有持久连接,
	// 必须搭这趟响应车。不下发的话 agent 的 probeAnyEnabled() 恒为 false,压根不采集。
	if h.wsHandler != nil {
		for k, v := range h.wsHandler.buildProbeConfigUpdates(ctx, serverID) {
			configUpdates[k] = v
		}
	}
	respData, _ := json.Marshal(map[string]interface{}{
		"success":        true,
		"message":        "Traffic data received",
		"config_updates": configUpdates,
	})
	writeHTTPCryptoResponse(w, crypto.Session, respData)
}

func (h *RemoteTrafficHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *TrafficHandler) handleNodeSnapshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	date := r.URL.Query().Get("date")
	if date == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "date is required"})
		return
	}
	snapshots, err := h.repo.GetNodeTrafficSnapshots(r.Context(), date)
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "snapshots": snapshots})
}

func (h *TrafficHandler) handleUserSnapshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	date := r.URL.Query().Get("date")
	if date == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "date is required"})
		return
	}
	snapshots, err := h.repo.GetUserTrafficSnapshots(r.Context(), date)
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "snapshots": snapshots})
}

// handleServerSystemSnapshots 返回每个 server 在 <= date 的最新一份 system_rx_cycle / system_tx_cycle baseline。
// 前端 server 视图 traffic_source='system' 模式下用 (当前 cycle - baseline) 算今日/本周/本月增量,
// 跟 node-snapshots / user-snapshots 用于 xray path 的语义平行。
func (h *TrafficHandler) handleServerSystemSnapshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	date := r.URL.Query().Get("date")
	if date == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "date is required"})
		return
	}
	snapshots, err := h.repo.GetServerSystemTrafficSnapshots(r.Context(), date)
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "snapshots": snapshots})
}
