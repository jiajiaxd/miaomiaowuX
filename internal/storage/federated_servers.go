package storage

import (
	"context"
	"database/sql"
	"errors"
)

// federated_servers(消费方侧):标记某台 remote_server 实为"接入的分享服务器",
// 记录拥有方主控 URL 与分享令牌。forwardToRemoteServer 据此把远程操作改走联邦转发。

type FederatedServer struct {
	ServerID   int64  `json:"server_id"`
	OwnerURL   string `json:"owner_url"`
	ShareToken string `json:"share_token"`
	Prefix     string `json:"prefix"` // 消费方在该分享服务器上新增入站时统一加的 tag 前缀
}

func (r *TrafficRepository) ensureFederatedServersTable(ctx context.Context) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if _, err := r.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS federated_servers (
		server_id INTEGER PRIMARY KEY,
		owner_url TEXT NOT NULL,
		share_token TEXT NOT NULL,
		prefix TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return err
	}
	// 旧表补列。ensureTableColumn 使用标准 PRAGMA table_info 形式，
	// PostgreSQL 会由 dialectDB 改写为 information_schema.columns 查询。
	// 不要使用 SQLite 特有的 pragma_table_info(...) 表值函数：它不会
	// 被方言适配器识别，且忽略错误后会在每次查询时重复执行 ADD COLUMN。
	return r.ensureTableColumn("federated_servers", "prefix", "TEXT NOT NULL DEFAULT ''")
}

func (r *TrafficRepository) SetFederatedServer(ctx context.Context, serverID int64, ownerURL, shareToken, prefix string) error {
	if err := r.ensureFederatedServersTable(ctx); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO federated_servers (server_id, owner_url, share_token, prefix) VALUES (?, ?, ?, ?)
		 ON CONFLICT(server_id) DO UPDATE SET owner_url = excluded.owner_url, share_token = excluded.share_token, prefix = excluded.prefix`,
		serverID, ownerURL, shareToken, prefix)
	return err
}

// GetFederatedServer 返回该 server 的联邦信息;非联邦服务器返回 ErrFederatedServerNotFound。
func (r *TrafficRepository) GetFederatedServer(ctx context.Context, serverID int64) (FederatedServer, error) {
	var f FederatedServer
	if err := r.ensureFederatedServersTable(ctx); err != nil {
		return f, err
	}
	err := r.db.QueryRowContext(ctx,
		`SELECT server_id, owner_url, share_token, COALESCE(prefix, '') FROM federated_servers WHERE server_id = ? LIMIT 1`,
		serverID).Scan(&f.ServerID, &f.OwnerURL, &f.ShareToken, &f.Prefix)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return f, ErrFederatedServerNotFound
		}
		return f, err
	}
	return f, nil
}

// ListFederatedServers 返回本主控接入的全部分享服务器(联邦)。
func (r *TrafficRepository) ListFederatedServers(ctx context.Context) ([]FederatedServer, error) {
	if err := r.ensureFederatedServersTable(ctx); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT server_id, owner_url, share_token, COALESCE(prefix, '') FROM federated_servers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []FederatedServer
	for rows.Next() {
		var f FederatedServer
		if err := rows.Scan(&f.ServerID, &f.OwnerURL, &f.ShareToken, &f.Prefix); err != nil {
			return nil, err
		}
		list = append(list, f)
	}
	return list, rows.Err()
}

func (r *TrafficRepository) DeleteFederatedServer(ctx context.Context, serverID int64) error {
	if err := r.ensureFederatedServersTable(ctx); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM federated_servers WHERE server_id = ?`, serverID)
	return err
}

// IsFederatedServer 便捷判断。
func (r *TrafficRepository) IsFederatedServer(ctx context.Context, serverID int64) bool {
	_, err := r.GetFederatedServer(ctx, serverID)
	return err == nil
}
