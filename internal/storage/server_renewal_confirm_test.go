package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestConfirmRemoteServerRenewalIsIdempotent(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "server-renewal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	expiry := time.Date(2030, 8, 14, 0, 0, 0, 0, time.UTC)
	result, err := repo.db.ExecContext(ctx, `INSERT INTO remote_servers(name,token,status,renewal_cycle,expires_at) VALUES(?,?,'connected','quarter',?)`, "renew-test", "renew-token", expiry)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := result.LastInsertId()
	server, processed, err := repo.ConfirmRemoteServerRenewal(ctx, id, "20300814")
	if err != nil || !processed {
		t.Fatalf("first confirmation: processed=%v err=%v", processed, err)
	}
	if got := server.ExpiresAt.Format("2006-01-02"); got != "2030-11-14" {
		t.Fatalf("new expiry=%s", got)
	}
	_, processed, err = repo.ConfirmRemoteServerRenewal(ctx, id, "20300814")
	if err != nil || processed {
		t.Fatalf("duplicate confirmation: processed=%v err=%v", processed, err)
	}
}

func TestListExpiringCertificatesUsesBoundCutoffTime(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "certificates.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	for _, item := range []struct {
		domain    string
		expiresAt time.Time
		autoRenew bool
	}{
		{domain: "soon.example.com", expiresAt: now.AddDate(0, 0, 15), autoRenew: true},
		{domain: "later.example.com", expiresAt: now.AddDate(0, 0, 45), autoRenew: true},
		{domain: "manual.example.com", expiresAt: now.AddDate(0, 0, 10), autoRenew: false},
	} {
		cert := Certificate{
			Domain:        item.domain,
			Email:         "admin@example.com",
			Status:        CertStatusValid,
			ExpiryDate:    &item.expiresAt,
			AutoRenew:     item.autoRenew,
			ChallengeMode: CertChallengeStandalone,
		}
		if err := repo.CreateCertificate(ctx, &cert); err != nil {
			t.Fatalf("CreateCertificate(%s): %v", item.domain, err)
		}
	}

	certs, err := repo.ListExpiringCertificates(ctx, 30)
	if err != nil {
		t.Fatalf("ListExpiringCertificates: %v", err)
	}
	if len(certs) != 1 || certs[0].Domain != "soon.example.com" {
		t.Fatalf("unexpected certificates: %+v", certs)
	}
}
