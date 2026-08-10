package handler

import (
	"context"
	"testing"

	"miaomiaowux/internal/storage"
)

func TestNodeTunnelTargetUsesOriginalEndpointAfterInPlaceRelay(t *testing.T) {
	node := storage.Node{
		ClashConfig:     `{"name":"n","type":"vless","server":"relay.example","port":32000}`,
		RelayOrigServer: "origin.example",
		RelayOrigPort:   443,
	}
	target, ok := nodeTunnelTarget(context.Background(), nil, &node)
	if !ok {
		t.Fatal("expected tunnel target")
	}
	if target.port != 443 || !target.addrSet["origin.example"] {
		t.Fatalf("target=%+v, want origin.example:443", target)
	}
}

func TestSubEmailBaselineFallsBackAsOneCycle(t *testing.T) {
	row := storage.UserEmailTraffic{ServerID: 7, Email: "tom__in", Uplink: 13, Downlink: 75}
	key := "7|tom__in"

	// Baseline is from the previous reset cycle. Both directions must retain
	// the current-cycle values; independently clamping them produced 0 B rows.
	got := subEmailBaseline(row, map[string]int64{key: 100}, map[string]int64{key: 200})
	if got.Uplink != 13 || got.Downlink != 75 {
		t.Fatalf("cross-cycle fallback=%d/%d want 13/75", got.Uplink, got.Downlink)
	}

	// A baseline in the same cycle is still subtracted normally.
	got = subEmailBaseline(row, map[string]int64{key: 3}, map[string]int64{key: 5})
	if got.Uplink != 10 || got.Downlink != 70 {
		t.Fatalf("same-cycle delta=%d/%d want 10/70", got.Uplink, got.Downlink)
	}
}

func TestRoutedConnectionStatsUseSubaccountNodeID(t *testing.T) {
	refs := map[int64]storage.InboundNodeRef{
		101: {InboundTag: "shared-in", NodeID: 101, ParentID: 10, NodeType: "routed"},
		102: {InboundTag: "shared-in", NodeID: 102, ParentID: 10, NodeType: "routed"},
	}
	a := routedRefForSubaccount(storage.ActiveSubaccountForLimiter{RoutedNodeID: 101, InboundTag: "shared-in"}, refs)
	b := routedRefForSubaccount(storage.ActiveSubaccountForLimiter{RoutedNodeID: 102, InboundTag: "shared-in"}, refs)
	if a.NodeID != 101 || b.NodeID != 102 {
		t.Fatalf("routed nodes sharing an inbound were merged: a=%+v b=%+v", a, b)
	}
	if connGroupKey("alice", a.ParentID) != connGroupKey("alice", b.ParentID) {
		t.Fatal("routed nodes on the same physical inbound must still share the quota group")
	}
	if connGroupKey("alice", a.NodeID) == connGroupKey("alice", b.NodeID) {
		t.Fatal("routed nodes must have distinct statistics groups")
	}
}

func TestDailyLedgerHistoryKeepsInstallationFirstDay(t *testing.T) {
	const gb = int64(1 << 30)
	rows := []storage.ServerDailyTraffic{
		{ServerID: 1, Date: "2026-08-06", Uplink: 1 * gb, Downlink: 2 * gb},
		{ServerID: 1, Date: "2026-08-07", Uplink: 3 * gb, Downlink: 4 * gb},
		{ServerID: 2, Date: "2026-08-07", Uplink: 5 * gb, Downlink: 6 * gb},
	}
	got := aggregateDailyLedgerHistory(rows, map[int64]string{1: "both", 2: "both"}, 30)
	if len(got) != 2 || got[0].Date != "2026-08-06" || got[0].UsedGB == nil || *got[0].UsedGB != 3 {
		t.Fatalf("installation first day disappeared: %#v", got)
	}
	if got[1].Date != "2026-08-07" || got[1].UsedGB == nil || *got[1].UsedGB != 18 {
		t.Fatalf("second day aggregate mismatch: %#v", got)
	}
}

func TestDailyLedgerHistoryHonorsServerTrafficMode(t *testing.T) {
	const gb = int64(1 << 30)
	rows := []storage.ServerDailyTraffic{
		{ServerID: 1, Date: "2026-08-07", Uplink: 2 * gb, Downlink: 9 * gb},
		{ServerID: 2, Date: "2026-08-07", Uplink: 7 * gb, Downlink: 3 * gb},
		{ServerID: 3, Date: "2026-08-07", Uplink: 4 * gb, Downlink: 6 * gb},
	}
	got := aggregateDailyLedgerHistory(rows, map[int64]string{1: "upload", 2: "download", 3: "max"}, 30)
	if len(got) != 1 || got[0].UsedGB == nil || *got[0].UsedGB != 11 { // 2 + 3 + 6
		t.Fatalf("traffic modes were ignored: %#v", got)
	}
}

func TestDailyLedgerHistoryIncludesOnlySelectedServers(t *testing.T) {
	const gb = int64(1 << 30)
	rows := []storage.ServerDailyTraffic{
		{ServerID: 1, Date: "2026-08-07", Uplink: 2 * gb, Downlink: 3 * gb},
		{ServerID: 2, Date: "2026-08-07", Uplink: 40 * gb, Downlink: 50 * gb},
	}
	// Presence in the modes map is also the traffic-summary selection. Server 2
	// has ledger data but is deliberately absent and must not affect the chart.
	got := aggregateDailyLedgerHistory(rows, map[int64]string{1: "both"}, 30)
	if len(got) != 1 || got[0].UsedGB == nil || *got[0].UsedGB != 5 {
		t.Fatalf("unselected server leaked into daily history: %#v", got)
	}
}
