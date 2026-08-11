package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type DatabaseStatus struct {
	Driver              string         `json:"driver"`
	Config              map[string]any `json:"config"`
	Size                int64          `json:"size"`
	WALSize             int64          `json:"wal_size,omitempty"`
	SHMSize             int64          `json:"shm_size,omitempty"`
	Open                int            `json:"open_connections"`
	InUse               int            `json:"in_use_connections"`
	Idle                int            `json:"idle_connections"`
	EnvironmentOverride bool           `json:"environment_override"`
}

type DatabaseMigrationReport struct {
	Tables  int   `json:"tables"`
	Rows    int64 `json:"rows"`
	Skipped int64 `json:"skipped"`
}

type DatabaseMigrationProgress struct {
	Phase           string `json:"phase"`
	CurrentTable    string `json:"current_table,omitempty"`
	TotalTables     int    `json:"total_tables"`
	CompletedTables int    `json:"completed_tables"`
	Rows            int64  `json:"rows"`
	Skipped         int64  `json:"skipped"`
}

func (r *TrafficRepository) DatabaseStatus(ctx context.Context) (DatabaseStatus, error) {
	if r == nil || r.db == nil {
		return DatabaseStatus{}, errors.New("database is not initialized")
	}
	stats := r.db.Stats()
	status := DatabaseStatus{Driver: r.config.Driver, Config: r.config.SafeView(), Open: stats.OpenConnections, InUse: stats.InUse, Idle: stats.Idle, EnvironmentOverride: DatabaseConfigUsesEnvironment()}
	if r.config.Driver == "postgres" {
		if err := r.db.QueryRowContext(ctx, `SELECT pg_database_size(current_database())`).Scan(&status.Size); err != nil {
			return status, fmt.Errorf("read PostgreSQL size: %w", err)
		}
		return status, nil
	}
	for path, target := range map[string]*int64{r.config.Path: &status.Size, r.config.Path + "-wal": &status.WALSize, r.config.Path + "-shm": &status.SHMSize} {
		if info, err := os.Stat(path); err == nil {
			*target = info.Size()
		} else if !errors.Is(err, os.ErrNotExist) {
			return status, err
		}
	}
	return status, nil
}

func TestDatabaseConfig(ctx context.Context, cfg DatabaseConfig) error {
	repo, err := NewTrafficRepositoryFromConfig(cfg)
	if err != nil {
		return err
	}
	return repo.Close()
}

// MigrateSQLiteToPostgres copies one consistent SQLite snapshot into an empty
// PostgreSQL schema. The write gate blocks new writes for the copy and config
// switch window, so a successful report never silently omits concurrent data.
func (r *TrafficRepository) MigrateSQLiteToPostgres(ctx context.Context, targetConfig DatabaseConfig) (DatabaseMigrationReport, error) {
	return r.MigrateSQLiteToPostgresWithProgress(ctx, targetConfig, nil)
}

func (r *TrafficRepository) MigrateSQLiteToPostgresWithProgress(ctx context.Context, targetConfig DatabaseConfig, notify func(DatabaseMigrationProgress)) (DatabaseMigrationReport, error) {
	if r == nil || r.db == nil || r.config.Driver != "sqlite" {
		return DatabaseMigrationReport{}, errors.New("only a running SQLite database can be migrated")
	}
	if err := targetConfig.Validate(); err != nil {
		return DatabaseMigrationReport{}, err
	}
	if targetConfig.Driver != "postgres" {
		return DatabaseMigrationReport{}, errors.New("migration target must be PostgreSQL")
	}
	target, err := NewTrafficRepositoryFromConfig(targetConfig)
	if err != nil {
		return DatabaseMigrationReport{}, err
	}
	defer target.Close()
	var existing int64
	if err := target.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&existing); err != nil {
		return DatabaseMigrationReport{}, err
	}
	if existing != 0 {
		return DatabaseMigrationReport{}, errors.New("target PostgreSQL database is not empty")
	}

	r.db.writes.Lock()
	keepWriteGate := false
	defer func() {
		if !keepWriteGate {
			r.db.writes.Unlock()
		}
	}()
	sourceTx, err := r.db.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return DatabaseMigrationReport{}, err
	}
	defer sourceTx.Rollback()
	targetTx, err := target.db.BeginTx(ctx, nil)
	if err != nil {
		return DatabaseMigrationReport{}, err
	}
	defer targetTx.Rollback()

	tables, err := sqliteTables(ctx, sourceTx)
	if err != nil {
		return DatabaseMigrationReport{}, err
	}
	tables, err = postgresForeignKeyOrder(ctx, targetTx, tables)
	if err != nil {
		return DatabaseMigrationReport{}, err
	}
	progress := DatabaseMigrationProgress{Phase: "preparing", TotalTables: len(tables)}
	if notify != nil {
		notify(progress)
	}
	if err := widenPostgresIntegersForSQLiteData(ctx, sourceTx, targetTx, tables); err != nil {
		return DatabaseMigrationReport{}, err
	}
	report := DatabaseMigrationReport{}
	for _, table := range tables {
		progress.Phase = "copying"
		progress.CurrentTable = table
		if notify != nil {
			notify(progress)
		}
		sourceColumns, err := sqliteColumns(ctx, sourceTx, table)
		if err != nil {
			return report, err
		}
		targetColumns, err := postgresColumns(ctx, targetTx, table)
		if err != nil {
			return report, err
		}
		allowed := make(map[string]bool, len(targetColumns))
		for _, column := range targetColumns {
			allowed[column] = true
		}
		columns := sourceColumns[:0]
		for _, column := range sourceColumns {
			if allowed[column] {
				columns = append(columns, column)
			}
		}
		if len(columns) == 0 {
			progress.CompletedTables++
			continue
		}
		targetTypes, err := postgresColumnTypes(ctx, targetTx, table)
		if err != nil {
			return report, err
		}
		foreignKeys, err := postgresForeignKeysForTable(ctx, targetTx, table)
		if err != nil {
			return report, err
		}
		count, skipped, err := copyTable(ctx, sourceTx, targetTx, table, columns, targetTypes, foreignKeys)
		if err != nil {
			return report, fmt.Errorf("copy table %s: %w", table, err)
		}
		report.Tables++
		report.Rows += count
		report.Skipped += skipped
		progress.CompletedTables++
		progress.Rows = report.Rows
		progress.Skipped = report.Skipped
		if notify != nil {
			notify(progress)
		}
		if contains(columns, "id") {
			if _, err := targetTx.ExecContext(ctx, `SELECT setval(pg_get_serial_sequence(?, 'id'), COALESCE((SELECT MAX(id) FROM `+quoteIdentifier(table)+`), 1), COALESCE((SELECT MAX(id) FROM `+quoteIdentifier(table)+`), 0) > 0)`, table); err != nil {
				// Tables without a serial sequence legitimately return NULL here.
				if !strings.Contains(strings.ToLower(err.Error()), "null") {
					return report, fmt.Errorf("reset sequence %s: %w", table, err)
				}
			}
		}
	}
	// A migration is not successful merely because every INSERT returned nil.
	// Verify the fields that determine the displayed server traffic before the
	// target transaction can commit or database.json can switch drivers.
	if err := verifyMigratedServerTrafficState(ctx, sourceTx, targetTx); err != nil {
		return report, fmt.Errorf("verify server traffic state: %w", err)
	}
	// The target already contains verified cycle/offset values. Suppress the
	// legacy startup repair that used to replace them with Xray aggregates.
	if _, err := targetTx.ExecContext(ctx, `INSERT INTO system_settings(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP`, SystemTrafficSnapshotBackfillMarker, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return report, fmt.Errorf("mark verified server traffic migration: %w", err)
	}
	if err := targetTx.Commit(); err != nil {
		return report, err
	}
	if err := sourceTx.Commit(); err != nil {
		return report, err
	}
	// Keep writes blocked until the handler atomically saves database.json and
	// asks the service manager to restart. This closes the final copy/switch gap.
	keepWriteGate = true
	if notify != nil {
		notify(DatabaseMigrationProgress{Phase: "completed", TotalTables: len(tables), CompletedTables: len(tables), Rows: report.Rows, Skipped: report.Skipped})
	}
	return report, nil
}

type migratedServerTrafficState struct {
	SystemRx, SystemTx, LastSeenRx, LastSeenTx, Boot, Offset int64
	Source, Mode                                             string
	NodeUp, NodeDown                                         int64
}

func verifyMigratedServerTrafficState(ctx context.Context, source *sql.Tx, target *dialectTx) error {
	readSource := func() (map[int64]migratedServerTrafficState, error) {
		rows, err := source.QueryContext(ctx, `SELECT r.id,COALESCE(r.system_rx_cycle,0),COALESCE(r.system_tx_cycle,0),COALESCE(r.system_last_seen_rx,0),COALESCE(r.system_last_seen_tx,0),COALESCE(r.system_boot_time_unix,0),COALESCE(r.traffic_used_offset,0),COALESCE(r.traffic_source,'xray'),COALESCE(r.traffic_stats_mode,'both'),COALESCE((SELECT SUM(n.uplink) FROM node_traffic n WHERE n.server_id=r.id),0),COALESCE((SELECT SUM(n.downlink) FROM node_traffic n WHERE n.server_id=r.id),0) FROM remote_servers r ORDER BY r.id`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		result := map[int64]migratedServerTrafficState{}
		for rows.Next() {
			var id int64
			var value migratedServerTrafficState
			if err := rows.Scan(&id, &value.SystemRx, &value.SystemTx, &value.LastSeenRx, &value.LastSeenTx, &value.Boot, &value.Offset, &value.Source, &value.Mode, &value.NodeUp, &value.NodeDown); err != nil {
				return nil, err
			}
			result[id] = value
		}
		return result, rows.Err()
	}
	readTarget := func() (map[int64]migratedServerTrafficState, error) {
		rows, err := target.QueryContext(ctx, `SELECT r.id,COALESCE(r.system_rx_cycle,0),COALESCE(r.system_tx_cycle,0),COALESCE(r.system_last_seen_rx,0),COALESCE(r.system_last_seen_tx,0),COALESCE(r.system_boot_time_unix,0),COALESCE(r.traffic_used_offset,0),COALESCE(r.traffic_source,'xray'),COALESCE(r.traffic_stats_mode,'both'),COALESCE((SELECT SUM(n.uplink) FROM node_traffic n WHERE n.server_id=r.id),0),COALESCE((SELECT SUM(n.downlink) FROM node_traffic n WHERE n.server_id=r.id),0) FROM remote_servers r ORDER BY r.id`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		result := map[int64]migratedServerTrafficState{}
		for rows.Next() {
			var id int64
			var value migratedServerTrafficState
			if err := rows.Scan(&id, &value.SystemRx, &value.SystemTx, &value.LastSeenRx, &value.LastSeenTx, &value.Boot, &value.Offset, &value.Source, &value.Mode, &value.NodeUp, &value.NodeDown); err != nil {
				return nil, err
			}
			result[id] = value
		}
		return result, rows.Err()
	}
	sourceState, err := readSource()
	if err != nil {
		return fmt.Errorf("read SQLite traffic state: %w", err)
	}
	targetState, err := readTarget()
	if err != nil {
		return fmt.Errorf("read PostgreSQL traffic state: %w", err)
	}
	if len(sourceState) != len(targetState) {
		return fmt.Errorf("server count differs: sqlite=%d postgres=%d", len(sourceState), len(targetState))
	}
	for id, expected := range sourceState {
		actual, ok := targetState[id]
		if !ok {
			return fmt.Errorf("server %d is missing in PostgreSQL", id)
		}
		if actual != expected {
			return fmt.Errorf("server %d differs: sqlite=%+v postgres=%+v", id, expected, actual)
		}
	}
	sourceReset := map[int64]*time.Time{}
	rows, err := source.QueryContext(ctx, `SELECT id,last_traffic_reset_at FROM remote_servers ORDER BY id`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var raw any
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return err
		}
		if raw == nil {
			sourceReset[id] = nil
			continue
		}
		normalized, err := normalizePostgresValue(raw, "timestamp without time zone")
		if err != nil {
			rows.Close()
			return fmt.Errorf("normalize server %d last reset: %w", id, err)
		}
		value, ok := normalized.(time.Time)
		if !ok {
			rows.Close()
			return fmt.Errorf("server %d last reset has type %T", id, normalized)
		}
		value = value.UTC()
		sourceReset[id] = &value
	}
	if err := rows.Close(); err != nil {
		return err
	}
	targetRows, err := target.QueryContext(ctx, `SELECT id,last_traffic_reset_at FROM remote_servers ORDER BY id`)
	if err != nil {
		return err
	}
	for targetRows.Next() {
		var id int64
		var actual sql.NullTime
		if err := targetRows.Scan(&id, &actual); err != nil {
			targetRows.Close()
			return err
		}
		expected := sourceReset[id]
		if expected == nil && actual.Valid {
			targetRows.Close()
			return fmt.Errorf("server %d last reset unexpectedly set", id)
		}
		if expected != nil && (!actual.Valid || !migrationTimestampsEqual(actual.Time, *expected)) {
			targetRows.Close()
			return fmt.Errorf("server %d last reset differs: sqlite=%v postgres=%v", id, expected, actual)
		}
	}
	if err := targetRows.Close(); err != nil {
		return err
	}
	return nil
}

// PostgreSQL timestamps have microsecond precision while SQLite may preserve
// Go's full nanosecond value in its textual representation. The copy is
// lossless at PostgreSQL's supported precision, so verification must compare
// the values after applying that precision instead of rejecting a sub-
// microsecond difference.
func migrationTimestampsEqual(left, right time.Time) bool {
	return left.UTC().Truncate(time.Microsecond).Equal(right.UTC().Truncate(time.Microsecond))
}

// ReleaseDatabaseMigrationGate is only used when publishing the new config or
// scheduling the restart fails after a successful copy.
func (r *TrafficRepository) ReleaseDatabaseMigrationGate() {
	if r != nil && r.db != nil {
		r.db.writes.Unlock()
	}
}

func sqliteTables(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func sqliteColumns(ctx context.Context, tx *sql.Tx, table string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(`+quoteIdentifier(table)+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var cid, notNull, pk int
		var name, kind string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &pk); err != nil {
			return nil, err
		}
		result = append(result, name)
	}
	return result, rows.Err()
}

func postgresColumns(ctx context.Context, tx *dialectTx, table string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=? ORDER BY ordinal_position`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func postgresColumnTypes(ctx context.Context, tx *dialectTx, table string) (map[string]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT column_name, data_type FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=?`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var name, kind string
		if err := rows.Scan(&name, &kind); err != nil {
			return nil, err
		}
		result[name] = kind
	}
	return result, rows.Err()
}

type migrationForeignKey struct {
	ParentTable   string
	ChildColumns  []string
	ParentColumns []string
}

func postgresForeignKeysForTable(ctx context.Context, tx *dialectTx, table string) ([]migrationForeignKey, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT fk.conname, parent.relname, child_column.attname, parent_column.attname
		FROM pg_constraint AS fk
		JOIN pg_class AS child ON child.oid = fk.conrelid
		JOIN pg_namespace AS child_ns ON child_ns.oid = child.relnamespace
		JOIN pg_class AS parent ON parent.oid = fk.confrelid
		JOIN LATERAL unnest(fk.conkey) WITH ORDINALITY AS child_key(attnum, ord) ON TRUE
		JOIN LATERAL unnest(fk.confkey) WITH ORDINALITY AS parent_key(attnum, ord) ON parent_key.ord = child_key.ord
		JOIN pg_attribute AS child_column ON child_column.attrelid = child.oid AND child_column.attnum = child_key.attnum
		JOIN pg_attribute AS parent_column ON parent_column.attrelid = parent.oid AND parent_column.attnum = parent_key.attnum
		WHERE fk.contype = 'f' AND child_ns.nspname = current_schema() AND child.relname = ?
		ORDER BY fk.conname, child_key.ord`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []migrationForeignKey
	var lastConstraint string
	for rows.Next() {
		var constraint, parentTable, childColumn, parentColumn string
		if err := rows.Scan(&constraint, &parentTable, &childColumn, &parentColumn); err != nil {
			return nil, err
		}
		if constraint != lastConstraint {
			result = append(result, migrationForeignKey{ParentTable: parentTable})
			lastConstraint = constraint
		}
		index := len(result) - 1
		result[index].ChildColumns = append(result[index].ChildColumns, childColumn)
		result[index].ParentColumns = append(result[index].ParentColumns, parentColumn)
	}
	return result, rows.Err()
}

// widenPostgresIntegersForSQLiteData upgrades legacy PostgreSQL schemas made
// by older versions, where plain SQLite INTEGER columns became int4. Only
// columns that actually contain an out-of-range value are changed, keeping
// this compatible with an already-created but otherwise empty migration DB.
func widenPostgresIntegersForSQLiteData(ctx context.Context, source *sql.Tx, target *dialectTx, tables []string) error {
	for _, table := range tables {
		rows, err := source.QueryContext(ctx, `PRAGMA table_info(`+quoteIdentifier(table)+`)`)
		if err != nil {
			return err
		}
		var integerColumns []string
		for rows.Next() {
			var cid, notNull, pk int
			var name, kind string
			var defaultValue sql.NullString
			if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &pk); err != nil {
				rows.Close()
				return err
			}
			if strings.Contains(strings.ToUpper(kind), "INT") {
				integerColumns = append(integerColumns, name)
			}
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, column := range integerColumns {
			var targetType string
			err := target.QueryRowContext(ctx, `SELECT data_type FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=? AND column_name=?`, table, column).Scan(&targetType)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			if !strings.EqualFold(targetType, "integer") {
				continue
			}
			var exceeds bool
			query := `SELECT EXISTS(SELECT 1 FROM ` + quoteIdentifier(table) + ` WHERE ` + quoteIdentifier(column) + ` < -2147483648 OR ` + quoteIdentifier(column) + ` > 2147483647)`
			if err := source.QueryRowContext(ctx, query).Scan(&exceeds); err != nil {
				return err
			}
			if !exceeds {
				continue
			}
			if _, err := target.ExecContext(ctx, `ALTER TABLE `+quoteIdentifier(table)+` ALTER COLUMN `+quoteIdentifier(column)+` TYPE BIGINT`); err != nil {
				return fmt.Errorf("widen PostgreSQL column %s.%s to bigint: %w", table, column, err)
			}
		}
	}
	return nil
}

// postgresForeignKeyOrder returns parent tables before tables that reference
// them. SQLite's table list is alphabetical, which is not a valid copy order
// once PostgreSQL starts enforcing foreign keys during the migration.
func postgresForeignKeyOrder(ctx context.Context, tx *dialectTx, tables []string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT child.relname, parent.relname
		FROM pg_constraint AS fk
		JOIN pg_class AS child ON child.oid = fk.conrelid
		JOIN pg_namespace AS child_ns ON child_ns.oid = child.relnamespace
		JOIN pg_class AS parent ON parent.oid = fk.confrelid
		JOIN pg_namespace AS parent_ns ON parent_ns.oid = parent.relnamespace
		WHERE fk.contype = 'f'
		  AND child_ns.nspname = current_schema()
		  AND parent_ns.nspname = current_schema()
		ORDER BY child.relname, parent.relname`)
	if err != nil {
		return nil, fmt.Errorf("read PostgreSQL foreign keys: %w", err)
	}
	defer rows.Close()
	dependencies := make(map[string][]string)
	for rows.Next() {
		var child, parent string
		if err := rows.Scan(&child, &parent); err != nil {
			return nil, err
		}
		if child != parent { // Row order handles ordinary self references.
			dependencies[child] = append(dependencies[child], parent)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ordered, remaining := topologicalTableOrder(tables, dependencies)
	if len(remaining) != 0 {
		return nil, fmt.Errorf("PostgreSQL foreign key cycle between tables: %s", strings.Join(remaining, ", "))
	}
	return ordered, nil
}

func topologicalTableOrder(tables []string, dependencies map[string][]string) ([]string, []string) {
	available := make(map[string]bool, len(tables))
	done := make(map[string]bool, len(tables))
	for _, table := range tables {
		available[table] = true
	}
	ordered := make([]string, 0, len(tables))
	for len(ordered) < len(tables) {
		progress := false
		for _, table := range tables {
			if done[table] {
				continue
			}
			ready := true
			for _, parent := range dependencies[table] {
				if available[parent] && !done[parent] {
					ready = false
					break
				}
			}
			if ready {
				done[table] = true
				ordered = append(ordered, table)
				progress = true
			}
		}
		if !progress {
			break
		}
	}
	remaining := make([]string, 0, len(tables)-len(ordered))
	for _, table := range tables {
		if !done[table] {
			remaining = append(remaining, table)
		}
	}
	return ordered, remaining
}

func copyTable(ctx context.Context, source *sql.Tx, target *dialectTx, table string, columns []string, targetTypes map[string]string, foreignKeys []migrationForeignKey) (int64, int64, error) {
	quoted := make([]string, len(columns))
	placeholders := make([]string, len(columns))
	for i, column := range columns {
		quoted[i] = quoteIdentifier(column)
		placeholders[i] = "?"
	}
	selected := make([]string, len(quoted))
	for i, column := range quoted {
		selected[i] = `child.` + column
	}
	query := `SELECT ` + strings.Join(selected, ",") + ` FROM ` + quoteIdentifier(table) + ` AS child`
	var filters []string
	for index, foreignKey := range foreignKeys {
		var nullable, matches []string
		for columnIndex := range foreignKey.ChildColumns {
			childColumn := `child.` + quoteIdentifier(foreignKey.ChildColumns[columnIndex])
			parentColumn := fmt.Sprintf(`parent_%d.%s`, index, quoteIdentifier(foreignKey.ParentColumns[columnIndex]))
			nullable = append(nullable, childColumn+` IS NULL`)
			matches = append(matches, parentColumn+` = `+childColumn)
		}
		filters = append(filters, `((`+strings.Join(nullable, ` OR `)+`) OR EXISTS (SELECT 1 FROM `+quoteIdentifier(foreignKey.ParentTable)+fmt.Sprintf(` AS parent_%d WHERE `, index)+strings.Join(matches, ` AND `)+`))`)
	}
	if len(filters) != 0 {
		query += ` WHERE ` + strings.Join(filters, ` AND `)
	}
	if contains(columns, "id") {
		query += ` ORDER BY child."id"`
	}
	rows, err := source.QueryContext(ctx, query)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	stmt := migrationInsertStatement(table, quoted, placeholders)
	var count, eligible int64
	for rows.Next() {
		eligible++
		values := make([]any, len(columns))
		destinations := make([]any, len(columns))
		for i := range values {
			destinations[i] = &values[i]
		}
		if err := rows.Scan(destinations...); err != nil {
			return count, 0, err
		}
		for i, column := range columns {
			value, err := normalizePostgresValue(values[i], targetTypes[column])
			if err != nil {
				return count, 0, fmt.Errorf("normalize %s.%s: %w", table, column, err)
			}
			values[i] = value
		}
		result, err := target.ExecContext(ctx, stmt, values...)
		if err != nil {
			return count, 0, err
		}
		if affected, err := result.RowsAffected(); err == nil {
			count += affected
		}
	}
	if err := rows.Err(); err != nil {
		return count, 0, err
	}
	if err := rows.Close(); err != nil {
		return count, 0, err
	}
	var total int64
	if err := source.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+quoteIdentifier(table)).Scan(&total); err != nil {
		return count, 0, err
	}
	return count, total - eligible, nil
}

// migrationInsertStatement keeps source configuration authoritative when the
// freshly initialized PostgreSQL schema already contains default rows. Both
// system_config(id=1) and system_settings keys are created during repository
// initialization, so ON CONFLICT DO NOTHING would silently retain defaults and
// discard the SQLite notification token, API token, theme, and other settings.
func migrationInsertStatement(table string, quoted, placeholders []string) string {
	stmt := `INSERT INTO ` + quoteIdentifier(table) + ` (` + strings.Join(quoted, ",") + `) VALUES (` + strings.Join(placeholders, ",") + `)`
	conflictColumn := ""
	switch table {
	case "system_config":
		conflictColumn = "id"
	case "system_settings":
		conflictColumn = "key"
	}
	if conflictColumn == "" {
		return stmt + ` ON CONFLICT DO NOTHING`
	}

	updates := make([]string, 0, len(quoted)-1)
	for _, column := range quoted {
		if column == quoteIdentifier(conflictColumn) {
			continue
		}
		updates = append(updates, column+` = excluded.`+column)
	}
	return stmt + ` ON CONFLICT (` + quoteIdentifier(conflictColumn) + `) DO UPDATE SET ` + strings.Join(updates, ",")
}

func normalizePostgresValue(value any, targetType string) (any, error) {
	if value == nil || (targetType != "timestamp without time zone" && targetType != "timestamp with time zone") {
		return value, nil
	}
	if timestamp, ok := value.(time.Time); ok {
		return timestamp.UTC(), nil
	}
	text, ok := value.(string)
	if !ok {
		if bytes, bytesOK := value.([]byte); bytesOK {
			text, ok = string(bytes), true
		}
	}
	if !ok || strings.TrimSpace(text) == "" {
		return value, nil
	}
	// time.Time.String may append both the numeric offset and a location name.
	// A fixed location named "-0400" therefore produces "-0400 -0400";
	// PostgreSQL and time.Parse both reject that duplicated numeric zone name.
	parts := strings.Fields(text)
	if len(parts) >= 2 && parts[len(parts)-1] == parts[len(parts)-2] && len(parts[len(parts)-1]) == 5 && (parts[len(parts)-1][0] == '+' || parts[len(parts)-1][0] == '-') {
		text = strings.Join(parts[:len(parts)-1], " ")
	}
	layouts := []string{
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05.999999999 -0700",
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if timestamp, err := time.Parse(layout, text); err == nil {
			return timestamp.UTC(), nil
		}
	}
	return nil, fmt.Errorf("unsupported timestamp %q", text)
}

func quoteIdentifier(value string) string { return `"` + strings.ReplaceAll(value, `"`, `""`) + `"` }
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
