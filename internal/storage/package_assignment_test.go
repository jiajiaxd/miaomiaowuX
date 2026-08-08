package storage

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestAssignPackagePostgresCompatibility(t *testing.T) {
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
	database := os.Getenv("MMWX_TEST_POSTGRES_DATABASE")
	if database == "" {
		database = "mmwx"
	}
	password := os.Getenv("MMWX_TEST_POSTGRES_PASSWORD")
	if password == "" {
		password = "mmwx-test"
	}
	repo, err := NewTrafficRepositoryFromConfig(DatabaseConfig{
		Driver: "postgres", Host: host, Port: port, Database: database,
		Username: "mmwx", Password: password, SSLMode: "disable",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	username := "renew-pg-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := repo.CreateUser(ctx, username, "", "", "hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	pkgID, err := repo.CreatePackage(ctx, Package{Name: username, CycleDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM users WHERE username = ?`, username)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM packages WHERE id = ?`, pkgID)
	})
	now := time.Now()
	if err := repo.AssignPackageToUser(ctx, username, pkgID, now, now.AddDate(0, 1, 0), true, 1); err != nil {
		t.Fatalf("initial package assignment on PostgreSQL: %v", err)
	}
	limit := int64(1234)
	if err := repo.UpdateUserTrafficLimitOverride(ctx, username, &limit); err != nil {
		t.Fatal(err)
	}
	if err := repo.AssignPackageToUser(ctx, username, pkgID, now, now.AddDate(0, 2, 0), true, 1); err != nil {
		t.Fatalf("same-package renewal on PostgreSQL: %v", err)
	}
	user, err := repo.GetUser(ctx, username)
	if err != nil {
		t.Fatal(err)
	}
	if user.PackageID != pkgID || user.PackageEndDate == nil || user.TrafficLimitOverride == nil || *user.TrafficLimitOverride != limit {
		t.Fatalf("renewal state mismatch: %+v", user)
	}
}

func TestAssignPackagePreservesOverrideOnlyForSamePackage(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "package-assignment.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	ctx := context.Background()
	if err := repo.CreateUser(ctx, "renew-user", "", "", "hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	firstID, err := repo.CreatePackage(ctx, Package{Name: "first", CycleDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := repo.CreatePackage(ctx, Package{Name: "second", CycleDays: 30})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	if err := repo.AssignPackageToUser(ctx, "renew-user", firstID, now, now.AddDate(0, 1, 0), false, 1); err != nil {
		t.Fatal(err)
	}
	limit := int64(123456)
	if err := repo.UpdateUserTrafficLimitOverride(ctx, "renew-user", &limit); err != nil {
		t.Fatal(err)
	}

	// Renewing the same package must retain the per-user override.
	if err := repo.AssignPackageToUser(ctx, "renew-user", firstID, now, now.AddDate(0, 2, 0), false, 1); err != nil {
		t.Fatal(err)
	}
	user, err := repo.GetUser(ctx, "renew-user")
	if err != nil {
		t.Fatal(err)
	}
	if user.TrafficLimitOverride == nil || *user.TrafficLimitOverride != limit {
		t.Fatalf("same-package renewal lost override: %v", user.TrafficLimitOverride)
	}

	// Switching packages must clear the override.
	if err := repo.AssignPackageToUser(ctx, "renew-user", secondID, now, now.AddDate(0, 1, 0), false, 1); err != nil {
		t.Fatal(err)
	}
	user, err = repo.GetUser(ctx, "renew-user")
	if err != nil {
		t.Fatal(err)
	}
	if user.TrafficLimitOverride != nil {
		t.Fatalf("package switch retained override: %v", *user.TrafficLimitOverride)
	}
}

func TestAssignNewPackageStartsTrafficAtZeroButRenewalPreservesCycle(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "package-new-cycle.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "fresh-user", "", "", "hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	pkgID, err := repo.CreatePackage(ctx, Package{Name: "test", CycleDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	// 用户绑定套餐前已有历史流量。
	if err := repo.UpsertUserEmailTraffic(ctx, 1, "fresh-user__vless", 0, 0, false, 1, "fresh-user"); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertUserEmailTraffic(ctx, 1, "fresh-user__vless", 100, 100, false, 1, "fresh-user"); err != nil {
		t.Fatal(err)
	}
	if used, _ := repo.GetUserBillableTraffic(ctx, "fresh-user"); used != 200 {
		t.Fatalf("pre-assign traffic = %d, want 200", used)
	}
	now := time.Now()
	if err := repo.AssignPackageToUser(ctx, "fresh-user", pkgID, now, now.AddDate(0, 1, 0), false, 1); err != nil {
		t.Fatal(err)
	}
	if used, _ := repo.GetUserBillableTraffic(ctx, "fresh-user"); used != 0 {
		t.Fatalf("new package inherited historical traffic: %d", used)
	}
	if err := repo.UpsertUserEmailTraffic(ctx, 1, "fresh-user__vless", 150, 150, false, 1, "fresh-user"); err != nil {
		t.Fatal(err)
	}
	if used, _ := repo.GetUserBillableTraffic(ctx, "fresh-user"); used != 100 {
		t.Fatalf("new package delta = %d, want 100", used)
	}
	if err := repo.AssignPackageToUser(ctx, "fresh-user", pkgID, now, now.AddDate(0, 2, 0), false, 1); err != nil {
		t.Fatal(err)
	}
	if used, _ := repo.GetUserBillableTraffic(ctx, "fresh-user"); used != 100 {
		t.Fatalf("same-package renewal reset current cycle: %d", used)
	}
}

func TestNewMonthlyPackagePeriodDoesNotPrecedePackageStart(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "package-period.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "period-user", "", "", "hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	pkgID, err := repo.CreatePackage(ctx, Package{Name: "monthly", CycleDays: 365})
	if err != nil {
		t.Fatal(err)
	}
	// reset_day=1, but a newly assigned package starts today. Its first traffic
	// period must start today rather than at the first day of this month.
	start := time.Now().Add(-time.Minute).Truncate(time.Second)
	if err := repo.AssignPackageToUser(ctx, "period-user", pkgID, start, start.AddDate(1, 0, 0), true, 1); err != nil {
		t.Fatal(err)
	}
	periodStart, _, err := repo.GetUserPackagePeriod(ctx, "period-user")
	if err != nil {
		t.Fatal(err)
	}
	if periodStart == nil || periodStart.Before(start) {
		t.Fatalf("period starts before package assignment: got %v, package start %v", periodStart, start)
	}
}

func TestRecreatedUserDoesNotInheritDeletedUsersTraffic(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "recreated-user.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	const username = "reused-name"
	if err := repo.CreateUser(ctx, username, "", "", "hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertUserEmailTraffic(ctx, 1, username+"__vless", 0, 0, false, 1, username); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertUserEmailTraffic(ctx, 1, username+"__vless", 100, 200, false, 1, username); err != nil {
		t.Fatal(err)
	}
	today := trafficLedgerDate(time.Now())
	// Seed the historical calendar tables explicitly; they used to survive
	// DeleteUser because none of them has a users(username) foreign key.
	if _, err := repo.db.ExecContext(ctx, `INSERT INTO traffic_daily_users(server_id,username,date,uplink,downlink) VALUES(1,?,?,?,?)`, username, today, 100, 200); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteUser(ctx, username); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(ctx, username, "", "", "new-hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if used, err := repo.GetUserBillableTraffic(ctx, username); err != nil || used != 0 {
		t.Fatalf("recreated user inherited billable traffic: used=%d err=%v", used, err)
	}
	rows, _, _, err := repo.ListDailyUserTraffic(ctx, "today", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Username == username {
			t.Fatalf("recreated user inherited calendar traffic: %+v", row)
		}
	}
}
