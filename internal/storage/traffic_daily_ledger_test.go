package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestDailyTrafficLedgerBooksOnlyObservedDelta(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	result, err := repo.db.Exec(`INSERT INTO remote_servers(name,token,status,connection_mode,listen_port,pull_address,pull_port,pull_token) VALUES('s1','t','connected','push',0,'',0,'')`)
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	// First report establishes a cumulative baseline and must not import old traffic.
	if err := repo.UpsertNodeTrafficBatch(ctx, serverID, []NodeTrafficItem{{Tag: "in", Type: "inbound", Uplink: 100, Downlink: 200}}, false); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertNodeTrafficBatch(ctx, serverID, []NodeTrafficItem{{Tag: "in", Type: "inbound", Uplink: 130, Downlink: 260}}, false); err != nil {
		t.Fatal(err)
	}
	shares := []WeightedNodeShare{{NodeID: 42, RawShare: 1, Weight: 2}}
	if err := repo.UpsertTrafficBatch(ctx, serverID, []UserEmailTrafficUpsert{{Email: "alice__in", Uplink: 50, Downlink: 80, Weight: 2, AttributedUsername: "alice", NodeShares: shares}}, []UserTrafficUpsert{{Username: "alice", Uplink: 50, Downlink: 80}}, false); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertTrafficBatch(ctx, serverID, []UserEmailTrafficUpsert{{Email: "alice__in", Uplink: 60, Downlink: 100, Weight: 2, AttributedUsername: "alice", NodeShares: shares}}, []UserTrafficUpsert{{Username: "alice", Uplink: 60, Downlink: 100}}, false); err != nil {
		t.Fatal(err)
	}

	date := trafficLedgerDate(time.Now())
	var up, down int64
	if err := repo.db.QueryRow(`SELECT uplink,downlink FROM traffic_daily_nodes WHERE server_id=? AND tag='in' AND date=?`, serverID, date).Scan(&up, &down); err != nil {
		t.Fatal(err)
	}
	if up != 30 || down != 60 {
		t.Fatalf("node ledger=%d/%d want 30/60", up, down)
	}
	var weightedUp, weightedDown float64
	if err := repo.db.QueryRow(`SELECT uplink,downlink,weighted_uplink,weighted_downlink FROM traffic_daily_user_emails WHERE server_id=? AND email='alice__in' AND date=?`, serverID, date).Scan(&up, &down, &weightedUp, &weightedDown); err != nil {
		t.Fatal(err)
	}
	if up != 10 || down != 20 || weightedUp != 20 || weightedDown != 40 {
		t.Fatalf("email ledger raw=%d/%d weighted=%v/%v", up, down, weightedUp, weightedDown)
	}
	var rawNodeUp, rawNodeDown, weightedNodeUp, weightedNodeDown float64
	if err := repo.db.QueryRow(`SELECT uplink,downlink,weighted_uplink,weighted_downlink FROM traffic_daily_user_nodes WHERE server_id=? AND node_id=42 AND username='alice' AND date=?`, serverID, date).Scan(&rawNodeUp, &rawNodeDown, &weightedNodeUp, &weightedNodeDown); err != nil {
		t.Fatal(err)
	}
	if rawNodeUp != 10 || rawNodeDown != 20 || weightedNodeUp != 20 || weightedNodeDown != 40 {
		t.Fatalf("user-node ledger raw=%v/%v weighted=%v/%v", rawNodeUp, rawNodeDown, weightedNodeUp, weightedNodeDown)
	}
}

func TestExternalSubscriptionUpdateBooksDailyDelta(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "external-ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	id, err := repo.CreateExternalSubscription(ctx, ExternalSubscription{
		Username: "alice", Name: "provider", URL: "https://example.com/sub",
		Upload: 100, Download: 200, TrafficMode: "both",
	})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := repo.GetExternalSubscription(ctx, id, "alice")
	if err != nil {
		t.Fatal(err)
	}
	sub.Upload, sub.Download = 140, 260
	if err := repo.UpdateExternalSubscription(ctx, sub); err != nil {
		t.Fatal(err)
	}
	// Re-saving unchanged metadata must not duplicate the traffic delta.
	if err := repo.UpdateExternalSubscription(ctx, sub); err != nil {
		t.Fatal(err)
	}
	rows, err := repo.ListDailyExternalSubscriptionTraffic(ctx, trafficLedgerDate(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ExternalSubscriptionID != id || rows[0].Uplink != 40 || rows[0].Downlink != 60 {
		t.Fatalf("unexpected external daily traffic: %+v", rows)
	}

	// Provider-side reset: the new counter is the first observed traffic of the
	// new sequence and must not be discarded as a negative delta.
	sub.Upload, sub.Download = 5, 7
	if err := repo.UpdateExternalSubscription(ctx, sub); err != nil {
		t.Fatal(err)
	}
	rows, err = repo.ListDailyExternalSubscriptionTraffic(ctx, trafficLedgerDate(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Uplink != 45 || rows[0].Downlink != 67 {
		t.Fatalf("unexpected external daily traffic after reset: %+v", rows)
	}
}

func TestSystemTrafficLedgerAndDuplicateReport(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "system-ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	result, err := repo.db.Exec(`INSERT INTO remote_servers(name,token,status,connection_mode,listen_port,pull_address,pull_port,pull_token) VALUES('s1','t','connected','push',0,'',0,'')`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := result.LastInsertId()
	if err := repo.UpsertRemoteServerSystemTraffic(ctx, id, 1000, 2000, 123); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertRemoteServerSystemTraffic(ctx, id, 1100, 2300, 123); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertRemoteServerSystemTraffic(ctx, id, 1100, 2300, 123); err != nil {
		t.Fatal(err)
	}
	var up, down int64
	if err := repo.db.QueryRow(`SELECT uplink,downlink FROM traffic_daily_system_servers WHERE server_id=?`, id).Scan(&up, &down); err != nil {
		t.Fatal(err)
	}
	if up != 300 || down != 100 {
		t.Fatalf("system ledger=%d/%d want 300/100", up, down)
	}
}

func TestListServerDailyTrafficUsesConfiguredSource(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "probe-daily.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	xrayRes, err := repo.db.Exec(`INSERT INTO remote_servers(name,token,status,traffic_source) VALUES('x','tx','connected','xray')`)
	if err != nil {
		t.Fatal(err)
	}
	sysRes, err := repo.db.Exec(`INSERT INTO remote_servers(name,token,status,traffic_source) VALUES('s','ts','connected','system')`)
	if err != nil {
		t.Fatal(err)
	}
	xrayID, _ := xrayRes.LastInsertId()
	sysID, _ := sysRes.LastInsertId()
	date := trafficLedgerDate(time.Now())
	_, _ = repo.db.Exec(`INSERT INTO traffic_daily_nodes(server_id,tag,type,date,uplink,downlink) VALUES(?,?,?,?,?,?)`, xrayID, "in", "inbound", date, 10, 20)
	_, _ = repo.db.Exec(`INSERT INTO traffic_daily_nodes(server_id,tag,type,date,uplink,downlink) VALUES(?,?,?,?,?,?)`, sysID, "ignored", "inbound", date, 999, 999)
	_, _ = repo.db.Exec(`INSERT INTO traffic_daily_system_servers(server_id,date,uplink,downlink) VALUES(?,?,?,?)`, sysID, date, 30, 40)
	rows, err := repo.ListServerDailyTraffic(ctx, 30, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := map[int64][2]int64{}
	for _, row := range rows {
		got[row.ServerID] = [2]int64{row.Uplink, row.Downlink}
	}
	if got[xrayID] != [2]int64{10, 20} || got[sysID] != [2]int64{30, 40} {
		t.Fatalf("unexpected daily source selection: %#v", got)
	}
}

func TestCreateServerDailySnapshotsWritesCompleteBundle(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "snapshot-bundle.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	result, err := repo.db.Exec(`INSERT INTO remote_servers(name,token,status,connection_mode,listen_port,pull_address,pull_port,pull_token,system_rx_cycle,system_tx_cycle) VALUES('s1','t','connected','push',0,'',0,'',700,800)`)
	if err != nil {
		t.Fatal(err)
	}
	serverID, _ := result.LastInsertId()
	if _, err := repo.db.Exec(`INSERT INTO node_traffic(server_id,tag,type,uplink,downlink,last_uplink,last_downlink) VALUES(?,?,?,?,?,?,?)`, serverID, "in", "inbound", 100, 200, 100, 200); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.Exec(`INSERT INTO user_traffic(server_id,username,uplink,downlink,last_uplink,last_downlink) VALUES(?,?,?,?,?,?)`, serverID, "alice", 30, 40, 30, 40); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.Exec(`INSERT INTO user_email_traffic(server_id,email,uplink,downlink,last_uplink,last_downlink) VALUES(?,?,?,?,?,?)`, serverID, "alice__in", 30, 40, 30, 40); err != nil {
		t.Fatal(err)
	}
	date := "2026-08-05"
	if err := repo.CreateServerDailySnapshots(ctx, serverID, date); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"traffic_snapshots", "node_traffic_snapshots", "user_traffic_snapshots", "user_email_traffic_snapshots", "server_system_traffic_snapshots"} {
		var count int
		if err := repo.db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE server_id=? AND date=?`, serverID, date).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			t.Fatalf("%s has no snapshot", table)
		}
	}
}
