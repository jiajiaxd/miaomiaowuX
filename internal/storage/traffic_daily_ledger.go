package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Daily traffic ledger stores deltas at ingestion time. Period reports sum
// these immutable day buckets instead of subtracting a fragile midnight
// snapshot from a live cumulative counter.
func (r *TrafficRepository) migrateDailyTrafficLedger() error {
	const schema = `
CREATE TABLE IF NOT EXISTS traffic_daily_nodes (
    server_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    type TEXT NOT NULL,
    date TEXT NOT NULL,
    uplink INTEGER NOT NULL DEFAULT 0,
    downlink INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (server_id, tag, type, date),
    FOREIGN KEY (server_id) REFERENCES remote_servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_traffic_daily_nodes_date ON traffic_daily_nodes(date);
CREATE TABLE IF NOT EXISTS traffic_daily_users (
    server_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    date TEXT NOT NULL,
    uplink INTEGER NOT NULL DEFAULT 0,
    downlink INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (server_id, username, date),
    FOREIGN KEY (server_id) REFERENCES remote_servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_traffic_daily_users_date ON traffic_daily_users(date);
CREATE TABLE IF NOT EXISTS traffic_daily_user_emails (
    server_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    attributed_username TEXT NOT NULL DEFAULT '',
    date TEXT NOT NULL,
    uplink INTEGER NOT NULL DEFAULT 0,
    downlink INTEGER NOT NULL DEFAULT 0,
    weighted_uplink REAL NOT NULL DEFAULT 0,
    weighted_downlink REAL NOT NULL DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (server_id, email, attributed_username, date),
    FOREIGN KEY (server_id) REFERENCES remote_servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_traffic_daily_user_emails_date ON traffic_daily_user_emails(date);
CREATE INDEX IF NOT EXISTS idx_traffic_daily_user_emails_user ON traffic_daily_user_emails(attributed_username);
CREATE TABLE IF NOT EXISTS traffic_daily_user_nodes (
    server_id INTEGER NOT NULL,
    node_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    date TEXT NOT NULL,
    uplink REAL NOT NULL DEFAULT 0,
    downlink REAL NOT NULL DEFAULT 0,
    weighted_uplink REAL NOT NULL DEFAULT 0,
    weighted_downlink REAL NOT NULL DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (server_id, node_id, username, date),
    FOREIGN KEY (server_id) REFERENCES remote_servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_traffic_daily_user_nodes_date ON traffic_daily_user_nodes(date);
CREATE INDEX IF NOT EXISTS idx_traffic_daily_user_nodes_user ON traffic_daily_user_nodes(username);
CREATE INDEX IF NOT EXISTS idx_traffic_daily_user_nodes_node ON traffic_daily_user_nodes(node_id);
CREATE TABLE IF NOT EXISTS traffic_daily_system_servers (
    server_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    uplink INTEGER NOT NULL DEFAULT 0,
    downlink INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (server_id, date),
    FOREIGN KEY (server_id) REFERENCES remote_servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_traffic_daily_system_servers_date ON traffic_daily_system_servers(date);`
	if _, err := r.db.Exec(schema); err != nil {
		return err
	}
	const externalSchema = `
CREATE TABLE IF NOT EXISTS traffic_daily_external_subscriptions (
    external_subscription_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    uplink INTEGER NOT NULL DEFAULT 0,
    downlink INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (external_subscription_id, date),
    FOREIGN KEY (external_subscription_id) REFERENCES external_subscriptions(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_traffic_daily_external_subscriptions_date ON traffic_daily_external_subscriptions(date);`
	if _, err := r.db.Exec(externalSchema); err != nil {
		return err
	}
	const meta = `CREATE TABLE IF NOT EXISTS traffic_daily_meta (key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);`
	if _, err := r.db.Exec(meta); err != nil {
		return err
	}
	if _, err := r.db.Exec(`CREATE TABLE IF NOT EXISTS traffic_daily_incomplete_dates(date TEXT PRIMARY KEY,reason TEXT NOT NULL,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		return err
	}
	now := time.Now()
	var lastHeartbeat string
	if err := r.db.QueryRow(`SELECT value FROM traffic_daily_meta WHERE key='heartbeat_at'`).Scan(&lastHeartbeat); err == nil {
		if last, parseErr := time.Parse(time.RFC3339, lastHeartbeat); parseErr == nil && trafficLedgerDate(last) != trafficLedgerDate(now) {
			// A cumulative counter observed after a cross-midnight master outage
			// cannot reveal how its delta was split between the two dates. Mark
			// every touched date incomplete instead of claiming false precision.
			for day := time.Date(last.Year(), last.Month(), last.Day(), 0, 0, 0, 0, last.Location()); !day.After(now); day = day.AddDate(0, 0, 1) {
				_, _ = r.db.Exec(`INSERT INTO traffic_daily_incomplete_dates(date,reason) VALUES(?,?) ON CONFLICT(date) DO NOTHING`, trafficLedgerDate(day), "master offline across midnight")
			}
		}
	}
	_, err := r.db.Exec(`INSERT INTO traffic_daily_meta(key,value) VALUES('started_at',?) ON CONFLICT(key) DO NOTHING`, time.Now().Format(time.RFC3339))
	if err != nil {
		return err
	}
	// This component was added after the base ledger. Track its own boundary;
	// otherwise an upgraded database would advertise user-node history as
	// complete while the new table is empty for older days.
	if _, err := r.db.Exec(`INSERT INTO traffic_daily_meta(key,value) VALUES('user_nodes_started_at',?) ON CONFLICT(key) DO NOTHING`, time.Now().Format(time.RFC3339)); err != nil {
		return err
	}
	_, err = r.db.Exec(`INSERT INTO traffic_daily_meta(key,value) VALUES('heartbeat_at',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP`, now.Format(time.RFC3339))
	return err
}

func trafficLedgerDate(now time.Time) string { return now.Format("2006-01-02") }

func addDailyNodeTraffic(ctx context.Context, ex sqlExecutor, date string, serverID int64, tag, typ string, up, down int64) error {
	if up == 0 && down == 0 {
		return nil
	}
	_, err := ex.ExecContext(ctx, `INSERT INTO traffic_daily_nodes(server_id,tag,type,date,uplink,downlink)
VALUES(?,?,?,?,?,?) ON CONFLICT(server_id,tag,type,date) DO UPDATE SET
uplink=traffic_daily_nodes.uplink+excluded.uplink,
downlink=traffic_daily_nodes.downlink+excluded.downlink,updated_at=CURRENT_TIMESTAMP`, serverID, tag, typ, date, up, down)
	return err
}

func addDailyUserTraffic(ctx context.Context, ex sqlExecutor, date string, serverID int64, username string, up, down int64) error {
	if up == 0 && down == 0 {
		return nil
	}
	_, err := ex.ExecContext(ctx, `INSERT INTO traffic_daily_users(server_id,username,date,uplink,downlink)
VALUES(?,?,?,?,?) ON CONFLICT(server_id,username,date) DO UPDATE SET
uplink=traffic_daily_users.uplink+excluded.uplink,
downlink=traffic_daily_users.downlink+excluded.downlink,updated_at=CURRENT_TIMESTAMP`, serverID, username, date, up, down)
	return err
}

func addDailyEmailTraffic(ctx context.Context, ex sqlExecutor, date string, serverID int64, email, username string, up, down int64, weight float64) error {
	if up == 0 && down == 0 {
		return nil
	}
	if weight <= 0 {
		weight = 1
	}
	_, err := ex.ExecContext(ctx, `INSERT INTO traffic_daily_user_emails(server_id,email,attributed_username,date,uplink,downlink,weighted_uplink,weighted_downlink)
VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(server_id,email,attributed_username,date) DO UPDATE SET
uplink=traffic_daily_user_emails.uplink+excluded.uplink,
downlink=traffic_daily_user_emails.downlink+excluded.downlink,
weighted_uplink=traffic_daily_user_emails.weighted_uplink+excluded.weighted_uplink,
weighted_downlink=traffic_daily_user_emails.weighted_downlink+excluded.weighted_downlink,
updated_at=CURRENT_TIMESTAMP`, serverID, email, username, date, up, down, float64(up)*weight, float64(down)*weight)
	return err
}

func addDailyUserNodeTraffic(ctx context.Context, ex sqlExecutor, date string, serverID int64, username string, shares []WeightedNodeShare, up, down int64, totalWeight float64) error {
	if username == "" || (up == 0 && down == 0) {
		return nil
	}
	// node_id=0 is an explicit unattributed bucket. It keeps the invariant that
	// a user's parent total equals the sum of the drill-down rows even when the
	// server/node mapping was temporarily unavailable during ingestion.
	if len(shares) == 0 {
		shares = []WeightedNodeShare{{NodeID: 0, RawShare: 1, Weight: totalWeight}}
	}
	for _, share := range shares {
		if share.Weight <= 0 {
			continue
		}
		rawScale := share.RawShare
		if rawScale <= 0 {
			rawScale = 1
		}
		_, err := ex.ExecContext(ctx, `INSERT INTO traffic_daily_user_nodes(server_id,node_id,username,date,uplink,downlink,weighted_uplink,weighted_downlink)
VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(server_id,node_id,username,date) DO UPDATE SET
uplink=traffic_daily_user_nodes.uplink+excluded.uplink,
downlink=traffic_daily_user_nodes.downlink+excluded.downlink,
weighted_uplink=traffic_daily_user_nodes.weighted_uplink+excluded.weighted_uplink,
weighted_downlink=traffic_daily_user_nodes.weighted_downlink+excluded.weighted_downlink,
updated_at=CURRENT_TIMESTAMP`, serverID, share.NodeID, username, date, float64(up)*rawScale, float64(down)*rawScale, float64(up)*share.Weight, float64(down)*share.Weight)
		if err != nil {
			return err
		}
	}
	return nil
}

func addDailySystemTraffic(ctx context.Context, ex sqlExecutor, date string, serverID, up, down int64) error {
	if up == 0 && down == 0 {
		return nil
	}
	_, err := ex.ExecContext(ctx, `INSERT INTO traffic_daily_system_servers(server_id,date,uplink,downlink)
VALUES(?,?,?,?) ON CONFLICT(server_id,date) DO UPDATE SET
uplink=traffic_daily_system_servers.uplink+excluded.uplink,
downlink=traffic_daily_system_servers.downlink+excluded.downlink,updated_at=CURRENT_TIMESTAMP`, serverID, date, up, down)
	return err
}

type DailyTrafficTotal struct {
	ServerID         int64   `json:"server_id,omitempty"`
	Tag              string  `json:"tag,omitempty"`
	Type             string  `json:"type,omitempty"`
	Username         string  `json:"username,omitempty"`
	Email            string  `json:"email,omitempty"`
	Uplink           int64   `json:"uplink"`
	Downlink         int64   `json:"downlink"`
	WeightedUplink   float64 `json:"weighted_uplink,omitempty"`
	WeightedDownlink float64 `json:"weighted_downlink,omitempty"`
}

type DailyUserNodeTraffic struct {
	ServerID                                           int64
	NodeID                                             int64
	Username                                           string
	Uplink, Downlink, WeightedUplink, WeightedDownlink float64
}

type DailyExternalSubscriptionTraffic struct {
	ExternalSubscriptionID int64
	Uplink                 int64
	Downlink               int64
}

// addDailyExternalSubscriptionTraffic stores only the increase observed since
// the previous successful refresh. A provider counter reset starts a new
// monotonic sequence, so the new value itself is the first delta after reset.
func addDailyExternalSubscriptionTraffic(ctx context.Context, ex sqlExecutor, date string, subscriptionID, oldUp, oldDown, newUp, newDown int64) error {
	delta := func(oldValue, newValue int64) int64 {
		if newValue >= oldValue {
			return newValue - oldValue
		}
		return newValue
	}
	uplink, downlink := delta(oldUp, newUp), delta(oldDown, newDown)
	if uplink == 0 && downlink == 0 {
		return nil
	}
	_, err := ex.ExecContext(ctx, `INSERT INTO traffic_daily_external_subscriptions(external_subscription_id,date,uplink,downlink)
VALUES(?,?,?,?) ON CONFLICT(external_subscription_id,date) DO UPDATE SET
uplink=traffic_daily_external_subscriptions.uplink+excluded.uplink,
downlink=traffic_daily_external_subscriptions.downlink+excluded.downlink,updated_at=CURRENT_TIMESTAMP`, subscriptionID, date, uplink, downlink)
	return err
}

func (r *TrafficRepository) ListDailyExternalSubscriptionTraffic(ctx context.Context, date string) ([]DailyExternalSubscriptionTraffic, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT external_subscription_id,SUM(uplink),SUM(downlink) FROM traffic_daily_external_subscriptions WHERE date=? GROUP BY external_subscription_id`, date)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DailyExternalSubscriptionTraffic
	for rows.Next() {
		var item DailyExternalSubscriptionTraffic
		if err := rows.Scan(&item.ExternalSubscriptionID, &item.Uplink, &item.Downlink); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// ServerDailyTraffic is the authoritative per-calendar-day traffic for one
// server. The selected source matches the server traffic view: system ledger for
// system-source servers, Xray node ledger otherwise.
type ServerDailyTraffic struct {
	ServerID int64  `json:"-"`
	Date     string `json:"date"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
}

func (r *TrafficRepository) ListServerDailyTraffic(ctx context.Context, days int, now time.Time) ([]ServerDailyTraffic, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if days <= 0 {
		days = 30
	}
	cutoff := trafficLedgerDate(now.AddDate(0, 0, -(days - 1)))
	const query = `
SELECT n.server_id,n.date,SUM(n.uplink),SUM(n.downlink)
FROM traffic_daily_nodes n
JOIN remote_servers s ON s.id=n.server_id
WHERE n.date>=? AND COALESCE(s.traffic_source,'xray')<>'system'
GROUP BY n.server_id,n.date
UNION ALL
SELECT y.server_id,y.date,SUM(y.uplink),SUM(y.downlink)
FROM traffic_daily_system_servers y
JOIN remote_servers s ON s.id=y.server_id
WHERE y.date>=? AND COALESCE(s.traffic_source,'xray')='system'
GROUP BY y.server_id,y.date
ORDER BY 1,2`
	rows, err := r.db.QueryContext(ctx, query, cutoff, cutoff)
	if err != nil {
		return nil, fmt.Errorf("list server daily traffic: %w", err)
	}
	defer rows.Close()
	out := make([]ServerDailyTraffic, 0, days*4)
	for rows.Next() {
		var row ServerDailyTraffic
		if err := rows.Scan(&row.ServerID, &row.Date, &row.Uplink, &row.Downlink); err != nil {
			return nil, fmt.Errorf("scan server daily traffic: %w", err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func normalizeTrafficRange(value string, now time.Time) (string, string, error) {
	end := trafficLedgerDate(now)
	var start time.Time
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "today":
		start = now
	case "week":
		diff := (int(now.Weekday()) + 6) % 7
		start = now.AddDate(0, 0, -diff)
	case "month":
		start = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	default:
		return "", "", fmt.Errorf("range must be today, week or month")
	}
	return trafficLedgerDate(start), end, nil
}

func (r *TrafficRepository) DailyTrafficLedgerComplete(ctx context.Context, rangeStart string) bool {
	var raw string
	if err := r.db.QueryRowContext(ctx, `SELECT value FROM traffic_daily_meta WHERE key='started_at'`).Scan(&raw); err != nil {
		return false
	}
	started, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false
	}
	// The first partial calendar day is deliberately not advertised as exact.
	// All later days were observed from midnight onward by ingestion-time deltas.
	if rangeStart <= trafficLedgerDate(started) {
		var backfillStart string
		if err := r.db.QueryRowContext(ctx, `SELECT value FROM traffic_daily_meta WHERE key='legacy_snapshot_backfill_start_date'`).Scan(&backfillStart); err != nil || backfillStart > rangeStart {
			return false
		}
	}
	var userNodesRaw string
	if err := r.db.QueryRowContext(ctx, `SELECT value FROM traffic_daily_meta WHERE key='user_nodes_started_at'`).Scan(&userNodesRaw); err != nil {
		return false
	}
	userNodesStarted, err := time.Parse(time.RFC3339, userNodesRaw)
	if err != nil || rangeStart <= trafficLedgerDate(userNodesStarted) {
		var backfillStart string
		if queryErr := r.db.QueryRowContext(ctx, `SELECT value FROM traffic_daily_meta WHERE key='legacy_snapshot_backfill_start_date'`).Scan(&backfillStart); queryErr != nil || backfillStart > rangeStart {
			return false
		}
	}
	var bad int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM traffic_daily_incomplete_dates WHERE date>=? AND date<=?`, rangeStart, trafficLedgerDate(time.Now())).Scan(&bad); err != nil {
		return false
	}
	return bad == 0
}

func (r *TrafficRepository) ListDailyNodeTraffic(ctx context.Context, rangeName string, now time.Time) ([]DailyTrafficTotal, string, string, error) {
	start, end, err := normalizeTrafficRange(rangeName, now)
	if err != nil {
		return nil, "", "", err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT server_id,tag,type,SUM(uplink),SUM(downlink) FROM traffic_daily_nodes WHERE date>=? AND date<=? GROUP BY server_id,tag,type`, start, end)
	if err != nil {
		return nil, "", "", err
	}
	defer rows.Close()
	var out []DailyTrafficTotal
	for rows.Next() {
		var v DailyTrafficTotal
		if err := rows.Scan(&v.ServerID, &v.Tag, &v.Type, &v.Uplink, &v.Downlink); err != nil {
			return nil, "", "", err
		}
		out = append(out, v)
	}
	return out, start, end, rows.Err()
}

func (r *TrafficRepository) ListDailyUserTraffic(ctx context.Context, rangeName string, now time.Time) ([]DailyTrafficTotal, string, string, error) {
	start, end, err := normalizeTrafficRange(rangeName, now)
	if err != nil {
		return nil, "", "", err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT username,SUM(uplink),SUM(downlink) FROM traffic_daily_users WHERE date>=? AND date<=? GROUP BY username`, start, end)
	if err != nil {
		return nil, "", "", err
	}
	defer rows.Close()
	var out []DailyTrafficTotal
	for rows.Next() {
		var v DailyTrafficTotal
		if err := rows.Scan(&v.Username, &v.Uplink, &v.Downlink); err != nil {
			return nil, "", "", err
		}
		out = append(out, v)
	}
	return out, start, end, rows.Err()
}

func (r *TrafficRepository) ListDailyEmailTraffic(ctx context.Context, rangeName string, now time.Time) ([]DailyTrafficTotal, string, string, error) {
	start, end, err := normalizeTrafficRange(rangeName, now)
	if err != nil {
		return nil, "", "", err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT server_id,email,attributed_username,SUM(uplink),SUM(downlink),SUM(weighted_uplink),SUM(weighted_downlink) FROM traffic_daily_user_emails WHERE date>=? AND date<=? GROUP BY server_id,email,attributed_username`, start, end)
	if err != nil {
		return nil, "", "", err
	}
	defer rows.Close()
	var out []DailyTrafficTotal
	for rows.Next() {
		var v DailyTrafficTotal
		if err := rows.Scan(&v.ServerID, &v.Email, &v.Username, &v.Uplink, &v.Downlink, &v.WeightedUplink, &v.WeightedDownlink); err != nil {
			return nil, "", "", err
		}
		out = append(out, v)
	}
	return out, start, end, rows.Err()
}

func (r *TrafficRepository) ListDailyUserNodeTraffic(ctx context.Context, rangeName string, now time.Time) ([]DailyUserNodeTraffic, string, string, error) {
	start, end, err := normalizeTrafficRange(rangeName, now)
	if err != nil {
		return nil, "", "", err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT server_id,node_id,username,SUM(uplink),SUM(downlink),SUM(weighted_uplink),SUM(weighted_downlink) FROM traffic_daily_user_nodes WHERE date>=? AND date<=? GROUP BY server_id,node_id,username`, start, end)
	if err != nil {
		return nil, "", "", err
	}
	defer rows.Close()
	var out []DailyUserNodeTraffic
	for rows.Next() {
		var v DailyUserNodeTraffic
		if err := rows.Scan(&v.ServerID, &v.NodeID, &v.Username, &v.Uplink, &v.Downlink, &v.WeightedUplink, &v.WeightedDownlink); err != nil {
			return nil, "", "", err
		}
		out = append(out, v)
	}
	return out, start, end, rows.Err()
}

func (r *TrafficRepository) ListDailySystemTraffic(ctx context.Context, rangeName string, now time.Time) ([]DailyTrafficTotal, string, string, error) {
	start, end, err := normalizeTrafficRange(rangeName, now)
	if err != nil {
		return nil, "", "", err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT server_id,SUM(uplink),SUM(downlink) FROM traffic_daily_system_servers WHERE date>=? AND date<=? GROUP BY server_id`, start, end)
	if err != nil {
		return nil, "", "", err
	}
	defer rows.Close()
	var out []DailyTrafficTotal
	for rows.Next() {
		var v DailyTrafficTotal
		if err := rows.Scan(&v.ServerID, &v.Uplink, &v.Downlink); err != nil {
			return nil, "", "", err
		}
		out = append(out, v)
	}
	return out, start, end, rows.Err()
}

func (r *TrafficRepository) AuditDailyTrafficLedger(ctx context.Context, now time.Time) (string, error) {
	date := trafficLedgerDate(now)
	var nodeRows, userRows, emailRows, userNodeRows, systemRows int64
	for _, check := range []struct {
		table string
		dst   *int64
	}{
		{"traffic_daily_nodes", &nodeRows}, {"traffic_daily_users", &userRows},
		{"traffic_daily_user_emails", &emailRows}, {"traffic_daily_system_servers", &systemRows},
		{"traffic_daily_user_nodes", &userNodeRows},
	} {
		if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+check.table+` WHERE date=?`, date).Scan(check.dst); err != nil {
			return "", err
		}
	}
	var userUp, userDown, emailUp, emailDown int64
	if err := r.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(uplink),0),COALESCE(SUM(downlink),0) FROM traffic_daily_users WHERE date=?`, date).Scan(&userUp, &userDown); err != nil {
		return "", err
	}
	if err := r.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(uplink),0),COALESCE(SUM(downlink),0) FROM traffic_daily_user_emails WHERE date=? AND attributed_username<>''`, date).Scan(&emailUp, &emailDown); err != nil {
		return "", err
	}
	drift := (userUp + userDown) - (emailUp + emailDown)
	var emailWeighted, userNodeWeighted float64
	if err := r.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(weighted_uplink+weighted_downlink),0) FROM traffic_daily_user_emails WHERE date=? AND attributed_username<>''`, date).Scan(&emailWeighted); err != nil {
		return "", err
	}
	if err := r.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(weighted_uplink+weighted_downlink),0) FROM traffic_daily_user_nodes WHERE date=?`, date).Scan(&userNodeWeighted); err != nil {
		return "", err
	}
	weightedDrift := emailWeighted - userNodeWeighted
	if _, err := r.db.ExecContext(ctx, `INSERT INTO traffic_daily_meta(key,value) VALUES('heartbeat_at',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP`, now.Format(time.RFC3339)); err != nil {
		return "", err
	}
	return fmt.Sprintf("date=%s node_rows=%d user_rows=%d email_rows=%d user_node_rows=%d system_rows=%d user_email_raw_drift=%d email_user_node_weighted_drift=%.3f", date, nodeRows, userRows, emailRows, userNodeRows, systemRows, drift, weightedDrift), nil
}
