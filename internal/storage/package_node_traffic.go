package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const bytesPerGiB = 1024 * 1024 * 1024

func packageNodeTrafficTotalTx(ctx context.Context, ex sqlExecutor, username string, nodeID int64) (float64, error) {
	var total float64
	err := ex.QueryRowContext(ctx, `SELECT COALESCE(SUM(weighted_uplink+weighted_downlink),0)
		FROM traffic_daily_user_nodes WHERE username=? AND node_id=?`, username, nodeID).Scan(&total)
	return total, err
}

func replacePackageNodeTrafficBaselinesTx(ctx context.Context, tx *dialectTx, username string, pkg *Package) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM package_user_node_traffic_baselines WHERE username=?`, username); err != nil {
		return err
	}
	if pkg == nil {
		return nil
	}
	for nodeID, limitGB := range pkg.NodeTrafficLimits {
		if limitGB <= 0 {
			continue
		}
		total, err := packageNodeTrafficTotalTx(ctx, tx, username, nodeID)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO package_user_node_traffic_baselines(username,package_id,node_id,baseline)
			VALUES(?,?,?,?)`, username, pkg.ID, nodeID, total); err != nil {
			return err
		}
	}
	return nil
}

func refreshPackageNodeTrafficBaselinesTx(ctx context.Context, tx *dialectTx, username string) error {
	var packageID sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT package_id FROM users WHERE username=?`, username).Scan(&packageID); err != nil {
		return err
	}
	if !packageID.Valid {
		_, err := tx.ExecContext(ctx, `DELETE FROM package_user_node_traffic_baselines WHERE username=?`, username)
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT node_id FROM package_user_node_traffic_baselines WHERE username=? AND package_id=?`, username, packageID.Int64)
	if err != nil {
		return err
	}
	var nodeIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		nodeIDs = append(nodeIDs, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, nodeID := range nodeIDs {
		total, err := packageNodeTrafficTotalTx(ctx, tx, username, nodeID)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE package_user_node_traffic_baselines SET baseline=?,updated_at=CURRENT_TIMESTAMP
			WHERE username=? AND package_id=? AND node_id=?`, total, username, packageID.Int64, nodeID); err != nil {
			return err
		}
	}
	return nil
}

func ensurePackageNodeTrafficBaselinesTx(ctx context.Context, tx *dialectTx, pkg *Package) error {
	if pkg == nil {
		return nil
	}
	for nodeID, limitGB := range pkg.NodeTrafficLimits {
		if limitGB <= 0 {
			continue
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO package_user_node_traffic_baselines(username,package_id,node_id,baseline)
			SELECT u.username, ?, ?, COALESCE((SELECT SUM(d.weighted_uplink+d.weighted_downlink)
				FROM traffic_daily_user_nodes d WHERE d.username=u.username AND d.node_id=?),0)
			FROM users u WHERE u.package_id=?
			ON CONFLICT(username,package_id,node_id) DO NOTHING`, pkg.ID, nodeID, nodeID, pkg.ID)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetPackageNodeTrafficUsage returns the current package-cycle usage for one
// user and node. A missing baseline is created at the current total, which is
// important when an administrator enables a quota on an existing package.
func (r *TrafficRepository) GetPackageNodeTrafficUsage(ctx context.Context, username string, packageID, nodeID int64) (used, limit int64, err error) {
	pkg, err := r.GetPackage(ctx, packageID)
	if err != nil {
		return 0, 0, err
	}
	limitGB := pkg.NodeTrafficLimits[nodeID]
	if limitGB <= 0 {
		return 0, 0, nil
	}
	limit = int64(limitGB * bytesPerGiB)
	var total, baseline float64
	if err = r.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(weighted_uplink+weighted_downlink),0)
		FROM traffic_daily_user_nodes WHERE username=? AND node_id=?`, username, nodeID).Scan(&total); err != nil {
		return 0, limit, err
	}
	err = r.db.QueryRowContext(ctx, `SELECT baseline FROM package_user_node_traffic_baselines
		WHERE username=? AND package_id=? AND node_id=?`, username, packageID, nodeID).Scan(&baseline)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = r.db.ExecContext(ctx, `INSERT INTO package_user_node_traffic_baselines(username,package_id,node_id,baseline)
			VALUES(?,?,?,?) ON CONFLICT(username,package_id,node_id) DO NOTHING`, username, packageID, nodeID, total)
		return 0, limit, err
	}
	if err != nil {
		return 0, limit, err
	}
	if total > baseline {
		used = int64(total - baseline)
	}
	return used, limit, nil
}

type PackageNodeTrafficSuspension struct {
	Username       string
	PackageID      int64
	NodeID         int64
	Kind           string
	CredentialJSON string
}

func (r *TrafficRepository) SavePackageNodeTrafficSuspension(ctx context.Context, s PackageNodeTrafficSuspension) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO package_node_traffic_suspensions(username,package_id,node_id,kind,credential_json)
		VALUES(?,?,?,?,?) ON CONFLICT(username,package_id,node_id,kind) DO UPDATE SET credential_json=excluded.credential_json`,
		s.Username, s.PackageID, s.NodeID, s.Kind, s.CredentialJSON)
	return err
}

func (r *TrafficRepository) ListPackageNodeTrafficSuspensions(ctx context.Context) ([]PackageNodeTrafficSuspension, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT username,package_id,node_id,kind,credential_json FROM package_node_traffic_suspensions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PackageNodeTrafficSuspension
	for rows.Next() {
		var s PackageNodeTrafficSuspension
		if err := rows.Scan(&s.Username, &s.PackageID, &s.NodeID, &s.Kind, &s.CredentialJSON); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *TrafficRepository) DeletePackageNodeTrafficSuspension(ctx context.Context, username string, packageID, nodeID int64, kind string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM package_node_traffic_suspensions WHERE username=? AND package_id=? AND node_id=? AND kind=?`, username, packageID, nodeID, kind)
	return err
}

func (r *TrafficRepository) HasPackageNodeTrafficSuspension(ctx context.Context, username string, nodeID int64) bool {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM package_node_traffic_suspensions WHERE username=? AND node_id=?`, username, nodeID).Scan(&count)
	return err == nil && count > 0
}

func (r *TrafficRepository) HasPhysicalPackageNodeTrafficSuspension(ctx context.Context, username string, serverID int64, inboundTag string) bool {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*)
		FROM package_node_traffic_suspensions s
		JOIN nodes n ON n.id=s.node_id
		JOIN remote_servers rs ON rs.name=n.original_server
		WHERE s.kind='physical' AND s.username=? AND rs.id=? AND n.inbound_tag=?`,
		username, serverID, inboundTag).Scan(&count)
	return err == nil && count > 0
}

func validatePackageNodeTrafficLimits(limits map[int64]float64) error {
	for nodeID, limit := range limits {
		if nodeID <= 0 || limit < 0 {
			return fmt.Errorf("invalid node traffic limit for node %d", nodeID)
		}
	}
	return nil
}
