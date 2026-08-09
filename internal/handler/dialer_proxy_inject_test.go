package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"miaomiaowux/internal/storage"
)

func TestBuildSubscribeFetchNotificationIncludesPackageTraffic(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "subscribe-notify.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "", "alice", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	pkgID, err := repo.CreatePackage(ctx, storage.Package{Name: "100GB 月付", TrafficLimitBytes: 100 * 1024 * 1024 * 1024, CycleDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AssignPackageToUser(ctx, "alice", pkgID, time.Now(), time.Now().AddDate(0, 0, 30), true, 1); err != nil {
		t.Fatal(err)
	}
	message := buildSubscribeFetchNotification(ctx, repo, "alice", "Clash", "203.0.113.1")
	for _, want := range []string{"套餐: `100GB 月付`", "流量: `0.00 GB / 100.00 GB`", "剩余: `100.00 GB`"} {
		if !strings.Contains(message, want) {
			t.Fatalf("notification missing %q:\n%s", want, message)
		}
	}
}

func TestTrafficLimitEnforcerSuspendsSharedRoutedSubaccount(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer agent.Close()
	u, err := url.Parse(agent.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}

	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "routed-limit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	remote := &storage.RemoteServer{
		Name: "test-agent", Token: "test-token", Status: storage.RemoteServerStatusConnected,
		IPAddress: host, ListenPort: mustAtoi(t, port), ConnectionMode: storage.ConnectionModePull,
	}
	if err := repo.CreateRemoteServer(ctx, remote); err != nil {
		t.Fatal(err)
	}
	parent, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", RawURL: "vless://example", NodeName: "parent", Protocol: "vless",
		ClashConfig: `{"name":"parent"}`, Enabled: true, OriginalServer: remote.Name, InboundTag: "vless-443",
	})
	if err != nil {
		t.Fatal(err)
	}
	routed, err := repo.CreateRoutedNode(ctx, storage.RoutedNodeDetail{
		Node: storage.Node{
			Username: "admin", RawURL: "vless://routed", NodeName: "routed", Protocol: "vless",
			ClashConfig: `{"name":"routed"}`, Enabled: true, OriginalServer: remote.Name,
			InboundTag: "vless-443", ParentNodeID: &parent.ID, RoutedOwner: "shared",
		},
		RoutedOutboundTag: "routed-out", RoutedRuleMarktag: "routed-rule", RoutedOutboundJSON: `{}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := json.Marshal(map[string]any{"id": "uuid", "email": "alice-routed"})
	if _, err := repo.UpsertUserSubaccount(ctx, storage.UserSubaccount{
		Username: "alice", RoutedNodeID: routed.ID, Email: "alice-routed",
		CredentialJSON: string(credential), IsActive: true,
	}); err != nil {
		t.Fatal(err)
	}

	enforcer := NewTrafficLimitEnforcer(repo, NewRemoteManageHandler(repo, nil), nil)
	if ok := enforcer.suspendUserRoutedAccess(ctx, "alice"); !ok {
		t.Fatal("shared routed access was not fully suspended")
	}
	sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || sa.IsActive {
		t.Fatalf("subaccount must be retained but inactive: %#v, %v", sa, err)
	}
	mu.Lock()
	defer mu.Unlock()
	// Mutating Agent calls may trigger an asynchronous full-config snapshot
	// refresh. Assert the two required writes without coupling this test to the
	// refresh implementation or goroutine ordering.
	required := map[string]bool{"/api/child/routing": false, "/api/child/inbounds": false}
	for _, path := range paths {
		if _, ok := required[path]; ok {
			required[path] = true
		}
	}
	for path, seen := range required {
		if !seen {
			t.Fatalf("missing agent call %s; got %v", path, paths)
		}
	}
}

func mustAtoi(t *testing.T, value string) int {
	t.Helper()
	var out int
	if _, err := fmt.Sscanf(value, "%d", &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRenewalRequestRestoresExpiredPackageIdentityAndClaimsOnce(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "renewal.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "a@example.com", "alice", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.BindTelegram(ctx, "alice", 12345, "alice"); err != nil {
		t.Fatal(err)
	}
	pkgID, err := repo.CreatePackage(ctx, storage.Package{Name: "monthly", TrafficLimitBytes: 1 << 30, CycleDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(-time.Hour)
	if err := repo.AssignPackageToUser(ctx, "alice", pkgID, end.AddDate(0, 0, -30), end, true, 1); err != nil {
		t.Fatal(err)
	}
	if err := repo.RemoveExpiredPackageFromUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	req, err := repo.CreateRenewalRequest(ctx, "alice", "PAY-123", "web", 0)
	if err != nil {
		t.Fatal(err)
	}
	if req.PackageID != pkgID || req.RenewDays != 30 || req.Passphrase != "PAY-123" {
		t.Fatalf("expired package snapshot incorrect: %#v", req)
	}
	service := NewRenewalService(repo, NewPackageAssignHandler(repo, nil, nil))
	approved, processed, err := service.Approve(ctx, req.RequestToken, 9001)
	if err != nil || !processed || approved.Status != storage.RenewalApproved {
		t.Fatalf("first approval = %#v, %v, %v", approved, processed, err)
	}
	_, processed, err = service.Approve(ctx, req.RequestToken, 9002)
	if err != nil || processed {
		t.Fatalf("second approval must be idempotent: %v, %v", processed, err)
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil || user.PackageID != pkgID || user.PackageEndDate == nil || !user.PackageEndDate.After(time.Now()) {
		t.Fatalf("package was not restored: %#v, %v", user, err)
	}
	stored, err := repo.GetRenewalRequestByToken(ctx, req.RequestToken, true)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Passphrase != "" {
		t.Fatal("passphrase must be cleared after review")
	}
	if err := repo.RemovePackageFromUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateRenewalRequest(ctx, "alice", "PAY-456", "web", 0); err == nil {
		t.Fatal("manual package removal must clear the renewable package snapshot")
	}
}

func TestPackageNodeNameOverridesPersistByNodeID(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "names.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	n1, err := repo.CreateNode(ctx, storage.Node{Username: "admin", NodeName: "same", Protocol: "ss", ClashConfig: `{"name":"same"}`, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	n2, err := repo.CreateNode(ctx, storage.Node{Username: "admin", NodeName: "same", Protocol: "ss", ClashConfig: `{"name":"same"}`, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	pkgID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "named", TrafficLimitBytes: 1 << 30, Nodes: []int64{n1.ID, n2.ID},
		NodeNameOverrides:       map[int64]string{n1.ID: "Hong Kong", n2.ID: "Japan", 999999: "stale"},
		NodeNameOverrideEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := repo.GetPackage(ctx, pkgID)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.NodeNameOverrides[n1.ID] != "Hong Kong" || pkg.NodeNameOverrides[n2.ID] != "Japan" {
		t.Fatalf("overrides crossed nodes: %#v", pkg.NodeNameOverrides)
	}
	if !pkg.NodeNameOverrideEnabled {
		t.Fatal("node name override switch must persist")
	}
	if _, ok := pkg.NodeNameOverrides[999999]; ok {
		t.Fatal("stale node override must not be persisted")
	}
	pkg.Nodes = []int64{n2.ID}
	if err := repo.UpdatePackage(ctx, *pkg); err != nil {
		t.Fatal(err)
	}
	pkg, err = repo.GetPackage(ctx, pkgID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pkg.NodeNameOverrides[n1.ID]; ok {
		t.Fatal("removed node override must be cleaned")
	}
}

func TestApplyPackageNameOverrideUsesNodeID(t *testing.T) {
	pkg := &storage.Package{NodeNameOverrideEnabled: true, NodeNameOverrides: map[int64]string{11: "Hong Kong", 12: "Japan"}}
	p1 := map[string]any{"name": "same"}
	p2 := map[string]any{"name": "same"}
	applyPackageNameOverride(p1, storage.Node{ID: 11}, pkg)
	applyPackageNameOverride(p2, storage.Node{ID: 12}, pkg)
	if p1["name"] != "Hong Kong" || p2["name"] != "Japan" {
		t.Fatalf("overrides crossed nodes: %#v %#v", p1, p2)
	}
}

func TestApplyPackageNameOverrideRequiresEnabledSwitch(t *testing.T) {
	pkg := &storage.Package{NodeNameOverrides: map[int64]string{11: "Hong Kong"}}
	proxy := map[string]any{"name": "original"}
	if applyPackageNameOverride(proxy, storage.Node{ID: 11}, pkg) {
		t.Fatal("disabled package name override must not be applied")
	}
	if proxy["name"] != "original" {
		t.Fatalf("disabled override changed node name: %v", proxy["name"])
	}
}

func TestPackageNameOverridePrecedesMultiplierPrefix(t *testing.T) {
	pkg := &storage.Package{NodeNameOverrideEnabled: true, NodeNameOverrides: map[int64]string{11: "Hong Kong"}, NodeMultipliers: map[int64]float64{11: 2}}
	proxy := map[string]any{"name": "original"}
	node := storage.Node{ID: 11, NodeName: "original"}
	applyPackageNameOverride(proxy, node, pkg)
	applyMultiplierPrefix(proxy, node, pkg, &storage.SystemConfig{NodeNameMultiplierPrefixEnabled: true})
	if got := proxy["name"]; got != "「2」Hong Kong" {
		t.Fatalf("final name = %q", got)
	}
}

// 客户反馈:套餐短链接订阅里链式节点没注入 dialer-proxy,导致它跟原节点实际走同一条链路。
// injectDialerProxyRefs 是套餐订阅 / serveAllNodes 两条路径共用的注入核心,这里钉住它的两个关键行为:
//  1. 引用目标节点在本次输出里的**最终名字**(套餐倍率前缀会改名,必须引用改名后的);
//  2. 目标不在本次输出(被过滤 / 未加入套餐)→ 绝不写 dialer-proxy(否则 Mihomo 悬空引用报错)。
func TestInjectDialerProxyRefsUsesFinalNameAndSkipsDangling(t *testing.T) {
	// 节点 1 = 链式节点(chain → 节点 2);节点 2 = 落地出口,被倍率改名为 "「2」HK";
	// 节点 3 = 链式节点,但目标 99 不在输出里(未加入套餐)。
	chain := map[string]any{"name": "香港V6"}
	exit := map[string]any{"name": "「2」HK"} // 已被 applyMultiplierPrefix 改名后的最终名
	dangling := map[string]any{"name": "上海"}

	finalName := map[int64]string{
		1: "香港V6",
		2: "「2」HK",
		3: "上海",
		// 99 缺席
	}
	refs := []dialerRef{
		{proxy: chain, target: 2},
		{proxy: dangling, target: 99},
	}

	injectDialerProxyRefs(refs, finalName)

	if got := chain["dialer-proxy"]; got != "「2」HK" {
		t.Errorf("链式节点应引用目标的最终(改名后)名字 「2」HK,得到 %v", got)
	}
	if _, ok := dangling["dialer-proxy"]; ok {
		t.Errorf("目标缺席时不能注入 dialer-proxy(会产生悬空引用),但被注入了: %v", dangling["dialer-proxy"])
	}
	_ = exit
}

// 客户反馈:全局 API token 解析出的虚拟用户名 api-token-admin 被 userIsAdmin 误判为非管理员
// (GetUser 查不到 → /api/admin/nodes 返回空列表)。这两个分支在 GetUser 之前返回,不碰 repo。
func TestUserIsAdminRecognizesAPITokenAdmin(t *testing.T) {
	if !userIsAdmin(t.Context(), nil, "api-token-admin") {
		t.Error("api-token-admin 应被识别为管理员")
	}
	if userIsAdmin(t.Context(), nil, "") {
		t.Error("空用户名不应是管理员")
	}
}

func TestRestoreTemplateProxyGroupOrder(t *testing.T) {
	template := `
proxy-groups:
  - name: first
    type: select
    proxies: [DIRECT]
  - name: second
    type: select
    proxies: [DIRECT]
  - name: third
    type: select
    proxies: [DIRECT]
`
	generated := `
proxy-groups:
  - name: third
    type: select
    proxies: [DIRECT]
  - name: generated-relay
    type: url-test
    proxies: [node-a]
  - name: first
    type: select
    proxies: [DIRECT]
  - name: second
    type: select
    proxies: [DIRECT]
`
	result, err := restoreTemplateProxyGroupOrder(template, generated)
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(result), &doc); err != nil {
		t.Fatal(err)
	}
	groups := findYAMLSequence(&doc, "proxy-groups")
	if groups == nil {
		t.Fatal("proxy-groups missing")
	}
	var names []string
	for _, group := range groups.Content {
		names = append(names, yamlMappingString(group, "name"))
	}
	want := []string{"first", "second", "third", "generated-relay"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("group order=%v, want %v", names, want)
	}
}
