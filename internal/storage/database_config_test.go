package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMigrationTimestampsEqualUsesPostgresPrecision(t *testing.T) {
	sqlite := time.Date(2026, 8, 1, 0, 7, 6, 381466714, time.FixedZone("UTC", 0))
	postgres := time.Date(2026, 8, 1, 0, 7, 6, 381466000, time.UTC)
	if !migrationTimestampsEqual(sqlite, postgres) {
		t.Fatalf("sub-microsecond precision loss must not fail migration: sqlite=%v postgres=%v", sqlite, postgres)
	}
	if migrationTimestampsEqual(sqlite, postgres.Add(time.Microsecond)) {
		t.Fatalf("a full microsecond difference must still fail verification")
	}
}

func TestPostgresTimezoneIsUTC(t *testing.T) {
	for _, value := range []string{"UTC", "Etc/UTC", "GMT", "etc/gmt"} {
		if !postgresTimezoneIsUTC(value) {
			t.Fatalf("%q should be accepted as UTC", value)
		}
	}
	for _, value := range []string{"Asia/Shanghai", "America/New_York", "+08:00", ""} {
		if postgresTimezoneIsUTC(value) {
			t.Fatalf("%q must not be accepted as UTC", value)
		}
	}
}

func TestDatabaseConfigRoundTripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	in := DatabaseConfig{Driver: "postgresql", Host: "db", Port: 5432, Database: "mmwx", Username: "app", Password: "secret", SSLMode: "require"}
	if err := SaveDatabaseConfig(dir, in); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, DatabaseConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	got, _, err := LoadDatabaseConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Driver != "postgres" || got.Password != "secret" || got.MaxOpenConns != 30 {
		t.Fatalf("unexpected config: %+v", got)
	}
	if _, leaked := got.SafeView()["password"]; leaked {
		t.Fatal("SafeView leaked password")
	}
}

func TestDatabaseConfigEnvironmentOverride(t *testing.T) {
	t.Setenv("MMWX_DATABASE_DRIVER", "sqlite")
	t.Setenv("MMWX_DATABASE_PATH", "/tmp/override.db")
	cfg, _, err := LoadDatabaseConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Path != "/tmp/override.db" {
		t.Fatalf("path=%q", cfg.Path)
	}
}

func TestAdaptSQLPostgresParameterizedIs(t *testing.T) {
	query := `SELECT 1 FROM users WHERE package_id IS NOT ? OR telegram_id IS ?`
	got := adaptSQL("postgres", query)
	want := `SELECT 1 FROM users WHERE package_id IS DISTINCT FROM $1 OR telegram_id IS NOT DISTINCT FROM $2`
	if got != want {
		t.Fatalf("adapted query mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestDatabaseConfigUsesLegacyBareMetalPath(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, "mmwx.db")
	if err := os.WriteFile(legacy, nil, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := LoadDatabaseConfig(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Path != legacy {
		t.Fatalf("path=%q want=%q", cfg.Path, legacy)
	}
}

func TestDatabaseConfigRepairsStaleLegacyEnvironment(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	legacyPath := filepath.Join(root, "mmwx.db")
	canonicalPath := filepath.Join(dataDir, "mmwx.db")
	legacy, err := NewTrafficRepository(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	canonical, err := NewTrafficRepository(canonicalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := canonical.CreateUser(context.Background(), "admin", "", "Admin", "hash", RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if err := canonical.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_PATH", legacyPath)
	cfg, _, err := LoadDatabaseConfig(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Path != canonicalPath {
		t.Fatalf("path=%q want=%q", cfg.Path, canonicalPath)
	}
}

func TestDatabaseConfigIgnoresMissingStaleLegacyEnvironment(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	legacyPath := filepath.Join(root, "mmwx.db")
	canonicalPath := filepath.Join(dataDir, "mmwx.db")
	canonical, err := NewTrafficRepository(canonicalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := canonical.CreateUser(context.Background(), "admin", "", "Admin", "hash", RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if err := canonical.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_PATH", legacyPath)

	cfg, _, err := LoadDatabaseConfig(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Path != canonicalPath {
		t.Fatalf("path=%q want=%q", cfg.Path, canonicalPath)
	}
}

func TestDatabaseConfigKeepsPopulatedExplicitLegacyDatabase(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	legacyPath := filepath.Join(root, "mmwx.db")
	canonicalPath := filepath.Join(dataDir, "mmwx.db")
	for _, item := range []struct{ path, username string }{{legacyPath, "legacy-admin"}, {canonicalPath, "canonical-admin"}} {
		repo, err := NewTrafficRepository(item.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.CreateUser(context.Background(), item.username, "", item.username, "hash", RoleAdmin, ""); err != nil {
			t.Fatal(err)
		}
		if err := repo.Close(); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("DATABASE_PATH", legacyPath)
	cfg, _, err := LoadDatabaseConfig(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Path != legacyPath {
		t.Fatalf("path=%q want=%q", cfg.Path, legacyPath)
	}
}

func TestPostgresRepositoryIntegration(t *testing.T) {
	if os.Getenv("MMWX_TEST_POSTGRES") == "" {
		t.Skip("set MMWX_TEST_POSTGRES=1 to run")
	}
	host := os.Getenv("MMWX_TEST_POSTGRES_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	port := 55432
	if value, err := strconv.Atoi(os.Getenv("MMWX_TEST_POSTGRES_PORT")); err == nil && value > 0 {
		port = value
	}
	repo, err := NewTrafficRepositoryFromConfig(DatabaseConfig{
		Driver:   "postgres",
		Host:     host,
		Port:     port,
		Database: "mmwx",
		Username: "mmwx",
		Password: "mmwx-test",
		SSLMode:  "disable",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "pg-test", "pg@example.test", "PG Test", "hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(ctx, Node{Username: "pg-test", RawURL: "ss://test", NodeName: "PG Node", Protocol: "ss", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if node.ID <= 0 || node.NodeName != "PG Node" {
		t.Fatalf("unexpected node: %+v", node)
	}
	batch, err := repo.BatchCreateNodes(ctx, []Node{
		{Username: "pg-test", RawURL: "ss://batch-1", NodeName: "Batch 1", Protocol: "ss"},
		{Username: "pg-test", RawURL: "ss://batch-2", NodeName: "Batch 2", Protocol: "ss"},
	})
	if err != nil || len(batch) != 2 || batch[0].ID <= 0 || batch[1].ID <= batch[0].ID {
		t.Fatalf("unexpected batch result: nodes=%+v err=%v", batch, err)
	}
	if err := repo.CreateSession(ctx, "pg-session", "pg-test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if sessions, err := repo.LoadSessions(ctx); err != nil || len(sessions) == 0 {
		t.Fatalf("sessions=%+v err=%v", sessions, err)
	}
	if err := repo.MarkTrafficThresholdNotified(ctx, 123); err != nil {
		t.Fatal(err)
	}
	if marked, err := repo.IsTrafficThresholdNotified(ctx, 123); err != nil || !marked {
		t.Fatalf("marked=%v err=%v", marked, err)
	}
	result, err := repo.db.ExecContext(ctx, `INSERT INTO xray_servers (name, host, port) VALUES (?, ?, ?)`, "PG Server", "127.0.0.1", 10001)
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertTrafficBatch(ctx, serverID,
		[]UserEmailTrafficUpsert{{Email: "pg-test__default", Uplink: 10, Downlink: 20, Weight: 1, AttributedUsername: "pg-test"}},
		[]UserTrafficUpsert{{Username: "pg-test", Uplink: 10, Downlink: 20}}, false); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteToPostgresMigrationIntegration(t *testing.T) {
	if os.Getenv("MMWX_TEST_POSTGRES") == "" {
		t.Skip("set MMWX_TEST_POSTGRES=1 to run")
	}
	host := os.Getenv("MMWX_TEST_POSTGRES_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	port := 55432
	if value, err := strconv.Atoi(os.Getenv("MMWX_TEST_POSTGRES_PORT")); err == nil && value > 0 {
		port = value
	}
	target := DatabaseConfig{Driver: "postgres", Host: host, Port: port, Database: "mmwx", Username: "mmwx", Password: "mmwx-test", SSLMode: "disable"}
	source, err := NewTrafficRepository(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	ctx := context.Background()
	systemConfig, err := source.GetSystemConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	systemConfig.NotifyEnabled = true
	systemConfig.TelegramBotToken = "migration-bot-token"
	systemConfig.TelegramChatID = "migration-chat-id"
	systemConfig.NotifyServerOffline = true
	if err := source.UpdateSystemConfig(ctx, systemConfig); err != nil {
		t.Fatal(err)
	}
	if err := source.SetSystemSetting(ctx, "migration-config-key", "source-value"); err != nil {
		t.Fatal(err)
	}
	if err := source.CreateUser(ctx, "migrated", "migrated@example.test", "Migrated", "hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := source.CreateNode(ctx, Node{Username: "migrated", RawURL: "ss://test", NodeName: "Migrated Node", Protocol: "ss", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := source.db.ExecContext(ctx, `INSERT INTO subscribe_files (id, name, url, type, filename) VALUES (101, 'migration-subscribe', '/migration', 'create', 'migration.yaml')`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.db.ExecContext(ctx, `INSERT INTO custom_rules (id, name, type, mode, content) VALUES (102, 'migration-rule', 'rules', 'append', '[]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.db.ExecContext(ctx, `INSERT INTO custom_rule_applications (id, subscribe_file_id, custom_rule_id, rule_type, rule_mode, applied_content, content_hash) VALUES (103, 101, 102, 'rules', 'append', '[]', 'migration-hash')`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.db.ExecContext(ctx, `INSERT INTO invite_code_uses (code, username, tg_id) VALUES ('migration-code', 'migrated', 6394028004)`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.db.ExecContext(ctx, `INSERT INTO remote_servers (id,name,token,status,last_heartbeat,traffic_source,traffic_stats_mode,system_rx_cycle,system_tx_cycle,system_last_seen_rx,system_last_seen_tx,system_boot_time_unix,traffic_used_offset,last_traffic_reset_at) VALUES (104,'migration-server','migration-server-token','offline','2026-08-02 05:51:58.370742665 -0400 -0400','system','max',123456,654321,923456,954321,17000000,-7777,'2026-08-01T00:00:00+08:00')`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.db.ExecContext(ctx, `INSERT INTO server_xray_config_snapshots (id, server_id, config_json, config_hash, source, status) VALUES (105, 104, '{}', 'valid-hash', 'master_write', 'current'), (106, 999999, '{}', 'orphan-hash', 'master_write', 'old')`); err != nil {
		t.Fatal(err)
	}
	// Reproduce a target schema created by the first PostgreSQL implementation,
	// which mapped SQLite INTEGER to PostgreSQL's 32-bit integer.
	legacyTarget, err := NewTrafficRepositoryFromConfig(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyTarget.db.ExecContext(ctx, `ALTER TABLE invite_code_uses ALTER COLUMN tg_id TYPE INTEGER`); err != nil {
		legacyTarget.Close()
		t.Fatal(err)
	}
	if err := legacyTarget.Close(); err != nil {
		t.Fatal(err)
	}
	report, err := source.MigrateSQLiteToPostgres(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	source.ReleaseDatabaseMigrationGate()
	if report.Rows < 2 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Skipped != 1 {
		t.Fatalf("skipped=%d, want 1 orphan snapshot", report.Skipped)
	}
	postgres, err := NewTrafficRepositoryFromConfig(target)
	if err != nil {
		t.Fatal(err)
	}
	defer postgres.Close()
	migratedConfig, err := postgres.GetSystemConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !migratedConfig.NotifyEnabled || migratedConfig.TelegramBotToken != "migration-bot-token" || migratedConfig.TelegramChatID != "migration-chat-id" || !migratedConfig.NotifyServerOffline {
		t.Fatalf("system config was replaced by PostgreSQL defaults: %+v", migratedConfig)
	}
	migratedSetting, err := postgres.GetSystemSetting(ctx, "migration-config-key")
	if err != nil || migratedSetting != "source-value" {
		t.Fatalf("system setting=%q err=%v", migratedSetting, err)
	}
	if _, err := postgres.GetUser(ctx, "migrated"); err != nil {
		t.Fatal(err)
	}
	var applications int
	if err := postgres.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM custom_rule_applications WHERE subscribe_file_id=? AND custom_rule_id=?`, 101, 102).Scan(&applications); err != nil {
		t.Fatal(err)
	}
	if applications != 1 {
		t.Fatalf("custom rule applications=%d, want 1", applications)
	}
	var telegramID int64
	if err := postgres.db.QueryRowContext(ctx, `SELECT tg_id FROM invite_code_uses WHERE code=?`, "migration-code").Scan(&telegramID); err != nil {
		t.Fatal(err)
	}
	if telegramID != 6394028004 {
		t.Fatalf("telegram id=%d", telegramID)
	}
	var telegramType string
	if err := postgres.db.QueryRowContext(ctx, `SELECT data_type FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='invite_code_uses' AND column_name='tg_id'`).Scan(&telegramType); err != nil {
		t.Fatal(err)
	}
	if telegramType != "bigint" {
		t.Fatalf("telegram type=%s, want bigint", telegramType)
	}
	var heartbeat time.Time
	if err := postgres.db.QueryRowContext(ctx, `SELECT last_heartbeat FROM remote_servers WHERE id=?`, 104).Scan(&heartbeat); err != nil {
		t.Fatal(err)
	}
	if got := heartbeat.UTC().Format(time.RFC3339Nano); got != "2026-08-02T09:51:58.370742Z" {
		t.Fatalf("heartbeat=%s", got)
	}
	var snapshots int
	if err := postgres.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM server_xray_config_snapshots`).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if snapshots != 1 {
		t.Fatalf("snapshots=%d, want only the valid snapshot", snapshots)
	}
	var rx, tx, lastRx, lastTx, boot, offset int64
	var sourceMode, statsMode string
	if err := postgres.db.QueryRowContext(ctx, `SELECT system_rx_cycle,system_tx_cycle,system_last_seen_rx,system_last_seen_tx,system_boot_time_unix,traffic_used_offset,traffic_source,traffic_stats_mode FROM remote_servers WHERE id=?`, 104).Scan(&rx, &tx, &lastRx, &lastTx, &boot, &offset, &sourceMode, &statsMode); err != nil {
		t.Fatal(err)
	}
	if rx != 123456 || tx != 654321 || lastRx != 923456 || lastTx != 954321 || boot != 17000000 || offset != -7777 || sourceMode != "system" || statsMode != "max" {
		t.Fatalf("migrated traffic state changed: rx=%d tx=%d last=%d/%d boot=%d offset=%d source=%s mode=%s", rx, tx, lastRx, lastTx, boot, offset, sourceMode, statsMode)
	}
	marker, err := postgres.GetSystemSetting(ctx, SystemTrafficSnapshotBackfillMarker)
	if err != nil || marker == "" {
		t.Fatalf("migration marker=%q err=%v", marker, err)
	}
}

func TestTopologicalTableOrder(t *testing.T) {
	tables := []string{"custom_rule_applications", "custom_rules", "subscribe_files", "users"}
	ordered, remaining := topologicalTableOrder(tables, map[string][]string{
		"custom_rule_applications": {"subscribe_files", "custom_rules"},
	})
	if len(remaining) != 0 {
		t.Fatalf("remaining=%v", remaining)
	}
	positions := make(map[string]int, len(ordered))
	for index, table := range ordered {
		positions[table] = index
	}
	if positions["subscribe_files"] > positions["custom_rule_applications"] || positions["custom_rules"] > positions["custom_rule_applications"] {
		t.Fatalf("invalid order: %v", ordered)
	}
}

func TestMigrationInsertStatementUpsertsConfigurationTables(t *testing.T) {
	quoted := []string{`"id"`, `"telegram_bot_token"`}
	placeholders := []string{"?", "?"}
	got := migrationInsertStatement("system_config", quoted, placeholders)
	want := `INSERT INTO "system_config" ("id","telegram_bot_token") VALUES (?,?) ON CONFLICT ("id") DO UPDATE SET "telegram_bot_token" = excluded."telegram_bot_token"`
	if got != want {
		t.Fatalf("system_config statement:\n got: %s\nwant: %s", got, want)
	}

	got = migrationInsertStatement("system_settings", []string{`"key"`, `"value"`}, placeholders)
	want = `INSERT INTO "system_settings" ("key","value") VALUES (?,?) ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value"`
	if got != want {
		t.Fatalf("system_settings statement:\n got: %s\nwant: %s", got, want)
	}

	got = migrationInsertStatement("users", []string{`"id"`, `"username"`}, placeholders)
	if !strings.HasSuffix(got, "ON CONFLICT DO NOTHING") {
		t.Fatalf("ordinary table must keep skip semantics: %s", got)
	}
}

func TestTopologicalTableOrderReportsCycle(t *testing.T) {
	_, remaining := topologicalTableOrder([]string{"a", "b"}, map[string][]string{"a": {"b"}, "b": {"a"}})
	if len(remaining) != 2 {
		t.Fatalf("remaining=%v, want both tables", remaining)
	}
}

func TestNormalizePostgresTimestampWithNumericZoneName(t *testing.T) {
	value, err := normalizePostgresValue("2026-08-02 05:51:58.370742665 -0400 -0400", "timestamp without time zone")
	if err != nil {
		t.Fatal(err)
	}
	timestamp, ok := value.(time.Time)
	if !ok {
		t.Fatalf("type=%T", value)
	}
	if got := timestamp.Format(time.RFC3339Nano); got != "2026-08-02T09:51:58.370742665Z" {
		t.Fatalf("timestamp=%s", got)
	}
}

func TestReplacePostgresScalarMax(t *testing.T) {
	query := `SELECT MAX(id), MAX(COALESCE(rx, 0), COALESCE(tx, 0)), SUM(MAX(weighted - baseline, 0)) FROM traffic`
	want := `SELECT MAX(id), GREATEST(COALESCE(rx, 0), COALESCE(tx, 0)), SUM(GREATEST(weighted - baseline, 0)) FROM traffic`
	if got := replacePostgresScalarMax(query); got != want {
		t.Fatalf("query=%s\nwant=%s", got, want)
	}
}

func TestRoutingRulePresetsUpsertDeduplicatesAndPrunes(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "preset-admin", "preset-admin@example.com", "Admin", "hash", RoleAdmin, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	first, err := repo.UpsertRoutingRulePreset(ctx, "preset-admin", "first", `{"type":"field","domain":["example.com"],"outboundTag":"direct"}`)
	if err != nil {
		t.Fatalf("UpsertRoutingRulePreset: %v", err)
	}
	updated, err := repo.UpsertRoutingRulePreset(ctx, "preset-admin", "renamed", first.RuleJSON)
	if err != nil {
		t.Fatalf("deduplicate preset: %v", err)
	}
	if updated.ID != first.ID || updated.Name != "renamed" {
		t.Fatalf("dedup result=%+v, first=%+v", updated, first)
	}

	for index := 0; index < maxRoutingRulePresets+3; index++ {
		rule := fmt.Sprintf(`{"type":"field","domain":["%d.example.com"],"outboundTag":"direct"}`, index)
		if _, err := repo.UpsertRoutingRulePreset(ctx, "preset-admin", fmt.Sprintf("rule-%d", index), rule); err != nil {
			t.Fatalf("insert preset %d: %v", index, err)
		}
	}
	presets, err := repo.ListRoutingRulePresets(ctx, "preset-admin")
	if err != nil {
		t.Fatalf("ListRoutingRulePresets: %v", err)
	}
	if len(presets) != maxRoutingRulePresets {
		t.Fatalf("preset count=%d, want %d", len(presets), maxRoutingRulePresets)
	}
	if err := repo.DeleteRoutingRulePreset(ctx, "preset-admin", presets[0].ID); err != nil {
		t.Fatalf("DeleteRoutingRulePreset: %v", err)
	}
}
