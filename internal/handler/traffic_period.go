package handler

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"miaomiaowux/internal/storage"
)

type periodTrafficItem struct {
	ServerID   int64   `json:"server_id,omitempty"`
	ServerName string  `json:"server_name,omitempty"`
	NodeID     int64   `json:"node_id,omitempty"`
	NodeName   string  `json:"node_name,omitempty"`
	NodeType   string  `json:"node_type,omitempty"`
	Username   string  `json:"username,omitempty"`
	Uplink     float64 `json:"uplink"`
	Downlink   float64 `json:"downlink"`
	Used       float64 `json:"used"`
}

// handleLedgerPeriod serves exact ingestion-time day buckets. The browser
// sends a semantic range, never a UTC date, so the master owns all calendar
// boundaries.
func (h *TrafficHandler) handleLedgerPeriod(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "error": "method not allowed"})
		return
	}
	rangeName := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("range")))
	view := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("view")))
	if rangeName != "today" && rangeName != "week" && rangeName != "month" {
		h.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "range must be today, week or month"})
		return
	}
	var items []periodTrafficItem
	var start, end string
	var err error
	switch view {
	case "servers":
		items, start, end, err = h.ledgerServerPeriod(r, rangeName)
	case "users":
		items, start, end, err = h.ledgerUserPeriod(r, rangeName)
	case "nodes":
		items, start, end, err = h.ledgerNodePeriod(r, rangeName)
	case "user-nodes":
		items, start, end, err = h.ledgerUserNodesPeriod(r, rangeName)
	case "node-users":
		items, start, end, err = h.ledgerNodeUsersPeriod(r, rangeName)
	default:
		h.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "unsupported period view"})
		return
	}
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": err.Error()})
		return
	}
	response := map[string]any{
		"success": true, "range": rangeName, "range_start": start, "range_end": end,
		"timezone": time.Now().Location().String(), "complete": h.repo.DailyTrafficLedgerComplete(r.Context(), start), "items": items,
	}
	if view == "user-nodes" {
		period := map[string]any{"start": nil, "end": nil}
		if periodStart, periodEnd, periodErr := h.repo.GetUserPackagePeriod(r.Context(), strings.TrimSpace(r.URL.Query().Get("username"))); periodErr == nil {
			if periodStart != nil {
				period["start"] = periodStart.Format("2006-01-02")
			}
			if periodEnd != nil {
				period["end"] = periodEnd.Format("2006-01-02")
			}
		}
		response["package_period"] = period
	}
	h.writeJSON(w, http.StatusOK, response)
}

func (h *TrafficHandler) ledgerUserNodesPeriod(r *http.Request, rangeName string) ([]periodTrafficItem, string, string, error) {
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	rows, start, end, err := h.repo.ListDailyUserNodeTraffic(r.Context(), rangeName, time.Now())
	if err != nil {
		return nil, "", "", err
	}
	nodes, err := h.repo.ListAllNodes(r.Context())
	if err != nil {
		return nil, "", "", err
	}
	nodeByID := map[int64]storage.Node{}
	for _, n := range nodes {
		nodeByID[n.ID] = n
	}
	byNode := map[int64]*periodTrafficItem{}
	for _, row := range rows {
		if row.Username != username {
			continue
		}
		n := nodeByID[row.NodeID]
		name, serverName := n.NodeName, n.OriginalServer
		if row.NodeID == 0 {
			name = "未归属"
		}
		it := byNode[row.NodeID]
		if it == nil {
			it = &periodTrafficItem{NodeID: row.NodeID, NodeName: name, ServerName: serverName}
			byNode[row.NodeID] = it
		}
		it.Uplink += row.WeightedUplink
		it.Downlink += row.WeightedDownlink
		it.Used = it.Uplink + it.Downlink
	}
	out := make([]periodTrafficItem, 0, len(byNode))
	for _, it := range byNode {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Used > out[j].Used })
	return out, start, end, nil
}

func (h *TrafficHandler) ledgerNodeUsersPeriod(r *http.Request, rangeName string) ([]periodTrafficItem, string, string, error) {
	nodeID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("node_id")), 10, 64)
	if err != nil || nodeID <= 0 {
		return nil, "", "", storage.ErrNodeNotFound
	}
	rows, start, end, err := h.repo.ListDailyUserNodeTraffic(r.Context(), rangeName, time.Now())
	if err != nil {
		return nil, "", "", err
	}
	byUser := map[string]*periodTrafficItem{}
	for _, row := range rows {
		if row.NodeID != nodeID || row.Username == "" {
			continue
		}
		it := byUser[row.Username]
		if it == nil {
			it = &periodTrafficItem{Username: row.Username}
			byUser[row.Username] = it
		}
		it.Uplink += row.Uplink
		it.Downlink += row.Downlink
		it.Used = it.Uplink + it.Downlink
	}
	out := make([]periodTrafficItem, 0, len(byUser))
	childrenUp, childrenDown := 0.0, 0.0
	for _, it := range byUser {
		out = append(out, *it)
		childrenUp += it.Uplink
		childrenDown += it.Downlink
	}
	// Physical inbound counters can include clients that no longer map to a DB
	// user. Keep that traffic visible as an explicit reconciliation row so the
	// node parent always equals its drill-down sum.
	if parents, _, _, parentErr := h.ledgerNodePeriod(r, rangeName); parentErr == nil {
		for _, parent := range parents {
			if parent.NodeID != nodeID {
				continue
			}
			missingUp, missingDown := parent.Uplink-childrenUp, parent.Downlink-childrenDown
			if missingUp < 0 {
				missingUp = 0
			}
			if missingDown < 0 {
				missingDown = 0
			}
			if missingUp > 0 || missingDown > 0 {
				out = append(out, periodTrafficItem{Username: "未归属", Uplink: missingUp, Downlink: missingDown, Used: missingUp + missingDown})
			}
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Used > out[j].Used })
	return out, start, end, nil
}

func applyTrafficMode(up, down float64, mode string) float64 {
	switch mode {
	case "upload":
		return up
	case "download":
		return down
	case "max":
		if up > down {
			return up
		}
		return down
	default:
		return up + down
	}
}

func (h *TrafficHandler) ledgerServerPeriod(r *http.Request, rangeName string) ([]periodTrafficItem, string, string, error) {
	ctx := r.Context()
	nodes, start, end, err := h.repo.ListDailyNodeTraffic(ctx, rangeName, time.Now())
	if err != nil {
		return nil, "", "", err
	}
	systems, _, _, err := h.repo.ListDailySystemTraffic(ctx, rangeName, time.Now())
	if err != nil {
		return nil, "", "", err
	}
	type dirs struct{ up, down float64 }
	nodeByServer, systemByServer := map[int64]dirs{}, map[int64]dirs{}
	for _, row := range nodes {
		d := nodeByServer[row.ServerID]
		d.up += float64(row.Uplink)
		d.down += float64(row.Downlink)
		nodeByServer[row.ServerID] = d
	}
	for _, row := range systems {
		systemByServer[row.ServerID] = dirs{float64(row.Uplink), float64(row.Downlink)}
	}
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return nil, "", "", err
	}
	out := make([]periodTrafficItem, 0, len(servers))
	for _, server := range servers {
		d := nodeByServer[server.ID]
		if server.TrafficSource == "system" {
			d = systemByServer[server.ID]
		}
		out = append(out, periodTrafficItem{ServerID: server.ID, ServerName: server.Name, Uplink: d.up, Downlink: d.down, Used: applyTrafficMode(d.up, d.down, server.TrafficStatsMode)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Used > out[j].Used })
	return out, start, end, nil
}

func (h *TrafficHandler) ledgerUserPeriod(r *http.Request, rangeName string) ([]periodTrafficItem, string, string, error) {
	rows, start, end, err := h.repo.ListDailyEmailTraffic(r.Context(), rangeName, time.Now())
	if err != nil {
		return nil, "", "", err
	}
	byUser := map[string]*periodTrafficItem{}
	for _, row := range rows {
		if row.Username == "" {
			continue
		}
		it := byUser[row.Username]
		if it == nil {
			it = &periodTrafficItem{Username: row.Username}
			byUser[row.Username] = it
		}
		it.Uplink += row.WeightedUplink
		it.Downlink += row.WeightedDownlink
		it.Used = it.Uplink + it.Downlink
	}
	out := make([]periodTrafficItem, 0, len(byUser))
	for _, it := range byUser {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Used > out[j].Used })
	return out, start, end, nil
}

func (h *TrafficHandler) ledgerNodePeriod(r *http.Request, rangeName string) ([]periodTrafficItem, string, string, error) {
	ctx := r.Context()
	nodeRows, start, end, err := h.repo.ListDailyNodeTraffic(ctx, rangeName, time.Now())
	if err != nil {
		return nil, "", "", err
	}
	userNodeRows, _, _, err := h.repo.ListDailyUserNodeTraffic(ctx, rangeName, time.Now())
	if err != nil {
		return nil, "", "", err
	}
	nodes, err := h.repo.ListAllNodes(ctx)
	if err != nil {
		return nil, "", "", err
	}
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return nil, "", "", err
	}
	nameToID := map[string]int64{}
	for _, s := range servers {
		nameToID[s.Name] = s.ID
	}
	type dirs struct{ up, down float64 }
	inbound := map[string]dirs{}
	for _, row := range nodeRows {
		if row.Type == "inbound" {
			inbound[strconv.FormatInt(row.ServerID, 10)+"|"+row.Tag] = dirs{float64(row.Uplink), float64(row.Downlink)}
		}
	}
	byNode := map[int64]*periodTrafficItem{}
	routedByInbound := map[string]dirs{}
	nodeByID := map[int64]storage.Node{}
	for _, n := range nodes {
		nodeByID[n.ID] = n
	}
	for _, row := range userNodeRows {
		n, exists := nodeByID[row.NodeID]
		if !exists || n.NodeType != "routed" {
			continue
		}
		it := byNode[n.ID]
		if it == nil {
			it = &periodTrafficItem{NodeID: n.ID, NodeName: n.NodeName, NodeType: "routed", ServerName: n.OriginalServer}
			byNode[n.ID] = it
		}
		it.Uplink += row.Uplink
		it.Downlink += row.Downlink
		it.Used = it.Uplink + it.Downlink
		k := strconv.FormatInt(row.ServerID, 10) + "|" + n.InboundTag
		d := routedByInbound[k]
		d.up += row.Uplink
		d.down += row.Downlink
		routedByInbound[k] = d
	}
	physicalGroups := make(map[string][]storage.Node)
	for _, n := range nodes {
		if n.NodeType == "routed" {
			continue
		}
		sid, ok := nameToID[n.OriginalServer]
		if !ok || n.InboundTag == "" {
			continue
		}
		k := strconv.FormatInt(sid, 10) + "|" + n.InboundTag
		physicalGroups[k] = append(physicalGroups[k], n)
	}
	for k, group := range physicalGroups {
		d, ok := inbound[k]
		if !ok {
			continue
		}
		// One Xray inbound counter cannot be assigned to multiple DB nodes.
		// Deterministically keep the oldest node as the physical owner.
		n := group[0]
		for _, candidate := range group[1:] {
			if candidate.ID < n.ID {
				n = candidate
			}
		}
		rd := routedByInbound[k]
		d.up -= rd.up
		d.down -= rd.down
		if d.up < 0 {
			d.up = 0
		}
		if d.down < 0 {
			d.down = 0
		}
		if _, exists := byNode[n.ID]; !exists {
			byNode[n.ID] = &periodTrafficItem{NodeID: n.ID, NodeName: n.NodeName, NodeType: "physical", ServerName: n.OriginalServer, Uplink: d.up, Downlink: d.down, Used: d.up + d.down}
		}
	}
	out := make([]periodTrafficItem, 0, len(byNode))
	for _, it := range byNode {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Used > out[j].Used })
	return out, start, end, nil
}
