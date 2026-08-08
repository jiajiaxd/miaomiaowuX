package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	SubscribeTypeCreate  = "create"
	SubscribeTypeImport  = "import"
	SubscribeTypeUpload  = "upload"
	SubscribeTypePackage = "package"
)

// subscribeFileSelectClause 返回 subscribe_files 的 SELECT 列表,可选用表别名前缀。
// 之前用 const + JOIN 手抄列表的写法存在不一致(GetUserSubscriptions 漏了 selected_custom_rule_ids /
// selected_override_script_ids 两列,scanSubscribeFile 扫描时 destination 数量对不上,直接 500)。
// 单源定义,所有调用方一律走这里 — 列数永远跟 scanSubscribeFile 同步。
func subscribeFileSelectClause(alias string) string {
	pfx := ""
	if alias != "" {
		pfx = alias + "."
	}
	cols := []string{
		pfx + "id", pfx + "name", "COALESCE(" + pfx + "description, '')",
		pfx + "url", pfx + "type", pfx + "filename",
		"COALESCE(" + pfx + "file_short_code, '')",
		"COALESCE(" + pfx + "custom_short_code, '')",
		"COALESCE(" + pfx + "auto_sync_custom_rules, 0)",
		"COALESCE(" + pfx + "template_filename, '')",
		"COALESCE(" + pfx + "selected_tags, '[]')",
		"COALESCE(" + pfx + "selected_node_ids, '[]')",
		"COALESCE(" + pfx + "selected_custom_rule_ids, '[]')",
		"COALESCE(" + pfx + "selected_override_script_ids, '[]')",
		"COALESCE(" + pfx + "stats_server_ids, '')",
		pfx + "traffic_limit",
		pfx + "expire_at",
		"COALESCE(" + pfx + "sort_order, 0)",
		"COALESCE(" + pfx + "raw_output, 0)",
		"COALESCE(" + pfx + "created_by, '')",
		pfx + "created_at", pfx + "updated_at",
	}
	return strings.Join(cols, ", ")
}

// subscribeFileSelectCols 历史 const,所有原本拼字符串的地方继续走它,保持调用点不变。
var subscribeFileSelectCols = subscribeFileSelectClause("")

// marshalIDArray 把 ID 切片序列化为 JSON 数组字符串(nil/空 → "[]")。
func marshalIDArray(ids []int64) string {
	if len(ids) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ids)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func scanSubscribeFile(scanner interface{ Scan(dest ...any) error }) (SubscribeFile, error) {
	var file SubscribeFile
	var autoSync, rawOutput int
	var tagsJSON, nodeIDsJSON, customRuleIDsJSON, overrideScriptIDsJSON string
	var trafficLimit sql.NullFloat64
	var expireAt sql.NullTime
	if err := scanner.Scan(
		&file.ID, &file.Name, &file.Description, &file.URL, &file.Type, &file.Filename,
		&file.FileShortCode, &file.CustomShortCode,
		&autoSync,
		&file.TemplateFilename, &tagsJSON, &nodeIDsJSON,
		&customRuleIDsJSON, &overrideScriptIDsJSON,
		&file.StatsServerIDs, &trafficLimit, &expireAt,
		&file.SortOrder, &rawOutput, &file.CreatedBy,
		&file.CreatedAt, &file.UpdatedAt,
	); err != nil {
		return file, err
	}
	file.AutoSyncCustomRules = autoSync != 0
	file.RawOutput = rawOutput != 0
	if trafficLimit.Valid {
		file.TrafficLimit = &trafficLimit.Float64
	}
	if expireAt.Valid {
		file.ExpireAt = &expireAt.Time
	}
	if tagsJSON != "" && tagsJSON != "[]" {
		_ = json.Unmarshal([]byte(tagsJSON), &file.SelectedTags)
	}
	if file.SelectedTags == nil {
		file.SelectedTags = []string{}
	}
	if nodeIDsJSON != "" && nodeIDsJSON != "[]" {
		_ = json.Unmarshal([]byte(nodeIDsJSON), &file.SelectedNodeIDs)
	}
	if file.SelectedNodeIDs == nil {
		file.SelectedNodeIDs = []int64{}
	}
	if customRuleIDsJSON != "" && customRuleIDsJSON != "[]" {
		_ = json.Unmarshal([]byte(customRuleIDsJSON), &file.SelectedCustomRuleIDs)
	}
	if file.SelectedCustomRuleIDs == nil {
		file.SelectedCustomRuleIDs = []int64{}
	}
	if overrideScriptIDsJSON != "" && overrideScriptIDsJSON != "[]" {
		_ = json.Unmarshal([]byte(overrideScriptIDsJSON), &file.SelectedOverrideScriptIDs)
	}
	if file.SelectedOverrideScriptIDs == nil {
		file.SelectedOverrideScriptIDs = []int64{}
	}
	return file, nil
}

func (r *TrafficRepository) ListSubscribeFiles(ctx context.Context) ([]SubscribeFile, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	rows, err := r.db.QueryContext(ctx, `SELECT `+subscribeFileSelectCols+` FROM subscribe_files ORDER BY sort_order ASC, created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list subscribe files: %w", err)
	}
	defer rows.Close()

	var files []SubscribeFile
	for rows.Next() {
		file, err := scanSubscribeFile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan subscribe file: %w", err)
		}
		files = append(files, file)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscribe files: %w", err)
	}
	return files, nil
}

func (r *TrafficRepository) GetSubscribeFileByID(ctx context.Context, id int64) (SubscribeFile, error) {
	var file SubscribeFile
	if r == nil || r.db == nil {
		return file, errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return file, errors.New("subscribe file id is required")
	}

	row := r.db.QueryRowContext(ctx, `SELECT `+subscribeFileSelectCols+` FROM subscribe_files WHERE id = ? LIMIT 1`, id)
	file, err := scanSubscribeFile(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return file, ErrSubscribeFileNotFound
		}
		return file, fmt.Errorf("get subscribe file: %w", err)
	}
	return file, nil
}

func (r *TrafficRepository) GetSubscribeFileByName(ctx context.Context, name string) (SubscribeFile, error) {
	var file SubscribeFile
	if r == nil || r.db == nil {
		return file, errors.New("traffic repository not initialized")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return file, errors.New("subscribe file name is required")
	}

	row := r.db.QueryRowContext(ctx, `SELECT `+subscribeFileSelectCols+` FROM subscribe_files WHERE name = ? LIMIT 1`, name)
	file, err := scanSubscribeFile(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return file, ErrSubscribeFileNotFound
		}
		return file, fmt.Errorf("get subscribe file by name: %w", err)
	}
	return file, nil
}

func (r *TrafficRepository) GetSubscribeFileByFilename(ctx context.Context, filename string) (SubscribeFile, error) {
	var file SubscribeFile
	if r == nil || r.db == nil {
		return file, errors.New("traffic repository not initialized")
	}
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return file, errors.New("subscribe file filename is required")
	}

	row := r.db.QueryRowContext(ctx, `SELECT `+subscribeFileSelectCols+` FROM subscribe_files WHERE filename = ? LIMIT 1`, filename)
	file, err := scanSubscribeFile(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return file, ErrSubscribeFileNotFound
		}
		return file, fmt.Errorf("get subscribe file by filename: %w", err)
	}
	return file, nil
}

func (r *TrafficRepository) GetSubscribeFileByShortCode(ctx context.Context, code string) (SubscribeFile, error) {
	var file SubscribeFile
	if r == nil || r.db == nil {
		return file, errors.New("traffic repository not initialized")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return file, errors.New("short code is required")
	}

	row := r.db.QueryRowContext(ctx, `SELECT `+subscribeFileSelectCols+` FROM subscribe_files WHERE custom_short_code = ? OR file_short_code = ? LIMIT 1`, code, code)
	file, err := scanSubscribeFile(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return file, ErrSubscribeFileNotFound
		}
		return file, fmt.Errorf("get subscribe file by short code: %w", err)
	}
	return file, nil
}

func (r *TrafficRepository) CreateSubscribeFile(ctx context.Context, file SubscribeFile) (SubscribeFile, error) {
	if r == nil || r.db == nil {
		return SubscribeFile{}, errors.New("traffic repository not initialized")
	}

	file.Name = strings.TrimSpace(file.Name)
	file.Description = strings.TrimSpace(file.Description)
	file.URL = strings.TrimSpace(file.URL)
	file.Type = strings.ToLower(strings.TrimSpace(file.Type))
	file.Filename = strings.TrimSpace(file.Filename)

	if file.Name == "" {
		return SubscribeFile{}, errors.New("subscribe file name is required")
	}
	if file.Type != SubscribeTypeCreate && file.Type != SubscribeTypeImport && file.Type != SubscribeTypeUpload && file.Type != SubscribeTypePackage {
		return SubscribeFile{}, errors.New("invalid subscribe file type")
	}
	if file.Type == SubscribeTypeImport && file.URL == "" {
		return SubscribeFile{}, errors.New("subscribe file url is required")
	}
	if file.Filename == "" {
		return SubscribeFile{}, errors.New("subscribe file filename is required")
	}

	tagsJSON, _ := json.Marshal(file.SelectedTags)
	if file.SelectedTags == nil {
		tagsJSON = []byte("[]")
	}
	nodeIDsJSON := marshalIDArray(file.SelectedNodeIDs)
	customRuleIDsJSON := marshalIDArray(file.SelectedCustomRuleIDs)
	overrideScriptIDsJSON := marshalIDArray(file.SelectedOverrideScriptIDs)

	const maxRetries = 10
	for i := 0; i < maxRetries; i++ {
		newFileShortCode, err := generateFileShortCode()
		if err != nil {
			return SubscribeFile{}, fmt.Errorf("generate file short code: %w", err)
		}

		res, err := r.db.ExecContext(ctx, `INSERT INTO subscribe_files
			(name, description, url, type, filename, file_short_code, custom_short_code,
			auto_sync_custom_rules, template_filename, selected_tags, selected_node_ids,
			selected_custom_rule_ids, selected_override_script_ids, stats_server_ids,
			traffic_limit, sort_order, raw_output, created_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			file.Name, file.Description, file.URL, file.Type, file.Filename, newFileShortCode, file.CustomShortCode,
			file.TemplateFilename, string(tagsJSON), nodeIDsJSON,
			customRuleIDsJSON, overrideScriptIDsJSON, file.StatsServerIDs,
			file.TrafficLimit, file.SortOrder, boolToInt(file.RawOutput), file.CreatedBy)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") && strings.Contains(strings.ToLower(err.Error()), "file_short_code") {
				continue
			}
			if strings.Contains(strings.ToLower(err.Error()), "unique") && strings.Contains(strings.ToLower(err.Error()), "custom_short_code") {
				return SubscribeFile{}, ErrCustomShortCodeExists
			}
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				return SubscribeFile{}, ErrSubscribeFileExists
			}
			return SubscribeFile{}, fmt.Errorf("create subscribe file: %w", err)
		}

		id, err := res.LastInsertId()
		if err != nil {
			return SubscribeFile{}, fmt.Errorf("fetch subscribe file id: %w", err)
		}
		return r.GetSubscribeFileByID(ctx, id)
	}
	return SubscribeFile{}, errors.New("failed to generate unique file short code after retries")
}

func (r *TrafficRepository) UpdateSubscribeFile(ctx context.Context, file SubscribeFile) (SubscribeFile, error) {
	if r == nil || r.db == nil {
		return SubscribeFile{}, errors.New("traffic repository not initialized")
	}
	if file.ID <= 0 {
		return SubscribeFile{}, errors.New("subscribe file id is required")
	}
	var previousCustomCode string
	if err := r.db.QueryRowContext(ctx, `SELECT COALESCE(custom_short_code, '') FROM subscribe_files WHERE id = ?`, file.ID).Scan(&previousCustomCode); err != nil {
		return SubscribeFile{}, fmt.Errorf("read existing custom short code: %w", err)
	}

	file.Name = strings.TrimSpace(file.Name)
	file.Description = strings.TrimSpace(file.Description)
	file.URL = strings.TrimSpace(file.URL)
	file.Type = strings.ToLower(strings.TrimSpace(file.Type))
	file.Filename = strings.TrimSpace(file.Filename)

	if file.Name == "" {
		return SubscribeFile{}, errors.New("subscribe file name is required")
	}
	if file.Type != SubscribeTypeCreate && file.Type != SubscribeTypeImport && file.Type != SubscribeTypeUpload && file.Type != SubscribeTypePackage {
		return SubscribeFile{}, errors.New("invalid subscribe file type")
	}
	if file.Type == SubscribeTypeImport && file.URL == "" {
		return SubscribeFile{}, errors.New("subscribe file url is required")
	}
	if file.Filename == "" {
		return SubscribeFile{}, errors.New("subscribe file filename is required")
	}

	tagsJSON, _ := json.Marshal(file.SelectedTags)
	if file.SelectedTags == nil {
		tagsJSON = []byte("[]")
	}
	nodeIDsJSON := marshalIDArray(file.SelectedNodeIDs)
	customRuleIDsJSON := marshalIDArray(file.SelectedCustomRuleIDs)
	overrideScriptIDsJSON := marshalIDArray(file.SelectedOverrideScriptIDs)

	res, err := r.db.ExecContext(ctx, `UPDATE subscribe_files SET
		name = ?, description = ?, url = ?, type = ?, filename = ?,
		custom_short_code = ?, auto_sync_custom_rules = ?,
		template_filename = ?, selected_tags = ?, selected_node_ids = ?,
		selected_custom_rule_ids = ?, selected_override_script_ids = ?, stats_server_ids = ?,
		traffic_limit = ?, sort_order = ?, raw_output = ?,
		updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		file.Name, file.Description, file.URL, file.Type, file.Filename,
		file.CustomShortCode, boolToInt(file.AutoSyncCustomRules),
		file.TemplateFilename, string(tagsJSON), nodeIDsJSON,
		customRuleIDsJSON, overrideScriptIDsJSON, file.StatsServerIDs,
		file.TrafficLimit, file.SortOrder, boolToInt(file.RawOutput),
		file.ID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") && strings.Contains(strings.ToLower(err.Error()), "custom_short_code") {
			return SubscribeFile{}, ErrCustomShortCodeExists
		}
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return SubscribeFile{}, ErrSubscribeFileExists
		}
		return SubscribeFile{}, fmt.Errorf("update subscribe file: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return SubscribeFile{}, fmt.Errorf("subscribe file update rows affected: %w", err)
	}
	if affected == 0 {
		return SubscribeFile{}, ErrSubscribeFileNotFound
	}
	// 自定义链接属于可轮换凭据。修改后同步轮换隐藏的自动短码，确保修改前
	// 显示/复制过的旧地址不再能通过 file_short_code 回退继续访问。
	if strings.TrimSpace(previousCustomCode) != strings.TrimSpace(file.CustomShortCode) {
		if err := r.resetFileShortCode(ctx, file.ID); err != nil {
			return SubscribeFile{}, fmt.Errorf("rotate file short code: %w", err)
		}
	}
	return r.GetSubscribeFileByID(ctx, file.ID)
}

func (r *TrafficRepository) DeleteSubscribeFile(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return errors.New("subscribe file id is required")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `DELETE FROM user_subscriptions WHERE subscription_id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete user subscriptions: %w", err)
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM subscribe_files WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete subscribe file: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("subscribe file delete rows affected: %w", err)
	}
	if affected == 0 {
		return ErrSubscribeFileNotFound
	}
	return tx.Commit()
}

func (r *TrafficRepository) ReorderSubscribeFiles(ctx context.Context, ids []int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	for i, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE subscribe_files SET sort_order = ? WHERE id = ?`, i, id); err != nil {
			return fmt.Errorf("update sort order: %w", err)
		}
	}
	return tx.Commit()
}

func (r *TrafficRepository) GetUserPackageSubscription(ctx context.Context, username string) (SubscribeFile, error) {
	var file SubscribeFile
	row := r.db.QueryRowContext(ctx, `SELECT `+subscribeFileSelectCols+`
		FROM subscribe_files sf
		INNER JOIN user_subscriptions us ON sf.id = us.subscription_id
		WHERE us.username = ? AND sf.type = ?
		LIMIT 1`, username, SubscribeTypePackage)
	file, err := scanSubscribeFile(row)
	if err != nil {
		return file, err
	}
	return file, nil
}
