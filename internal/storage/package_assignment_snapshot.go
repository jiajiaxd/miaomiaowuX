package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// UserPackageAssignmentSnapshot captures every package-assignment column that
// can be changed before remote Xray provisioning finishes. It is used to
// restore the exact previous row when any Agent rejects the coordinated
// configuration transaction.
type UserPackageAssignmentSnapshot struct {
	Username             string
	PackageID            *int64
	PackageStartDate     *time.Time
	PackageEndDate       *time.Time
	IsReset              bool
	ResetDay             int
	TrafficLimitOverride *int64
}

func (r *TrafficRepository) GetUserPackageAssignmentSnapshot(ctx context.Context, username string) (*UserPackageAssignmentSnapshot, error) {
	var packageID sql.NullInt64
	var start, end sql.NullTime
	var isReset int
	var resetDay int
	var override sql.NullInt64
	err := r.db.QueryRowContext(ctx, `
		SELECT package_id, package_start_date, package_end_date,
		       COALESCE(is_reset,0), COALESCE(reset_day,1), traffic_limit_override
		FROM users WHERE username=?`, username).
		Scan(&packageID, &start, &end, &isReset, &resetDay, &override)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("snapshot user package assignment: %w", err)
	}
	out := &UserPackageAssignmentSnapshot{Username: username, IsReset: isReset != 0, ResetDay: resetDay}
	if packageID.Valid {
		v := packageID.Int64
		out.PackageID = &v
	}
	if start.Valid {
		v := start.Time
		out.PackageStartDate = &v
	}
	if end.Valid {
		v := end.Time
		out.PackageEndDate = &v
	}
	if override.Valid {
		v := override.Int64
		out.TrafficLimitOverride = &v
	}
	return out, nil
}

func (r *TrafficRepository) RestoreUserPackageAssignment(ctx context.Context, snapshot *UserPackageAssignmentSnapshot) error {
	if snapshot == nil {
		return fmt.Errorf("package assignment snapshot is nil")
	}
	var packageID interface{}
	if snapshot.PackageID != nil {
		packageID = *snapshot.PackageID
	}
	var start, end interface{}
	if snapshot.PackageStartDate != nil {
		start = *snapshot.PackageStartDate
	}
	if snapshot.PackageEndDate != nil {
		end = *snapshot.PackageEndDate
	}
	var override interface{}
	if snapshot.TrafficLimitOverride != nil {
		override = *snapshot.TrafficLimitOverride
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE users SET package_id=?, package_start_date=?, package_end_date=?,
		       is_reset=?, reset_day=?, traffic_limit_override=?, updated_at=CURRENT_TIMESTAMP
		WHERE username=?`, packageID, start, end, snapshot.IsReset, snapshot.ResetDay, override, snapshot.Username)
	if err != nil {
		return fmt.Errorf("restore user package assignment: %w", err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return ErrUserNotFound
	}
	return nil
}
