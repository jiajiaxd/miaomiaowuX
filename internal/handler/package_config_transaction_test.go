package handler

import (
	"strings"
	"testing"

	"miaomiaowux/internal/storage"
)

func managedConfigFixture() map[string]interface{} {
	return map[string]interface{}{
		"inbounds": []interface{}{map[string]interface{}{
			"tag":      "parent-in",
			"protocol": "vless",
			"settings": map[string]interface{}{
				"clients": []interface{}{map[string]interface{}{"email": "alice__parent-in", "id": "old-id"}},
			},
		}},
		"routing": map[string]interface{}{
			"rules": []interface{}{map[string]interface{}{
				"marktag":     "route-one",
				"outboundTag": "landing-one",
				"user":        []interface{}{"alice__route-one"},
			}},
		},
	}
}

func TestManagedClientUpsertReplacesSameEmail(t *testing.T) {
	cfg := managedConfigFixture()
	if err := upsertManagedClient(cfg, "parent-in", map[string]interface{}{"email": "alice__parent-in", "id": "new-id"}); err != nil {
		t.Fatal(err)
	}
	_, settings, _, _ := managedInbound(cfg, "parent-in")
	clients := settings["clients"].([]interface{})
	if len(clients) != 1 {
		t.Fatalf("clients=%d, want 1", len(clients))
	}
	if got := clients[0].(map[string]interface{})["id"]; got != "new-id" {
		t.Fatalf("credential=%v, want new-id", got)
	}
	if err := validateManagedConfig(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestManagedAccountUpsertAndRemoveByUsername(t *testing.T) {
	cfg := map[string]interface{}{
		"inbounds": []interface{}{map[string]interface{}{
			"tag": "socks-in", "protocol": "socks",
			"settings": map[string]interface{}{"accounts": []interface{}{
				map[string]interface{}{"user": "alice", "pass": "old"},
			}},
		}},
	}
	credential := map[string]interface{}{"user": "alice", "pass": "new"}
	if err := upsertManagedClient(cfg, "socks-in", credential); err != nil {
		t.Fatal(err)
	}
	_, settings, _, _ := managedInbound(cfg, "socks-in")
	accounts := settings["accounts"].([]interface{})
	if len(accounts) != 1 || accounts[0].(map[string]interface{})["pass"] != "new" {
		t.Fatalf("accounts were not replaced: %#v", accounts)
	}
	if err := removeManagedClient(cfg, "socks-in", "", credential); err != nil {
		t.Fatal(err)
	}
	if got := len(settings["accounts"].([]interface{})); got != 0 {
		t.Fatalf("accounts=%d, want 0", got)
	}
}

func TestManagedParentClientAndRouteChangeTogether(t *testing.T) {
	cfg := managedConfigFixture()
	cred := map[string]interface{}{"email": "bob__route-one", "id": "bob-id"}
	if err := upsertManagedClient(cfg, "parent-in", cred); err != nil {
		t.Fatal(err)
	}
	if err := mutateManagedRouteUser(cfg, "route-one", "", "bob__route-one", true); err != nil {
		t.Fatal(err)
	}
	if err := removeManagedClient(cfg, "parent-in", "bob__route-one"); err != nil {
		t.Fatal(err)
	}
	if err := mutateManagedRouteUser(cfg, "route-one", "", "bob__route-one", false); err != nil {
		t.Fatal(err)
	}
	_, settings, _, _ := managedInbound(cfg, "parent-in")
	for _, raw := range settings["clients"].([]interface{}) {
		if raw.(map[string]interface{})["email"] == "bob__route-one" {
			t.Fatal("routed client remained in parent inbound")
		}
	}
	rules := cfg["routing"].(map[string]interface{})["rules"].([]interface{})
	for _, raw := range rules[0].(map[string]interface{})["user"].([]interface{}) {
		if raw == "bob__route-one" {
			t.Fatal("routed email remained in routing rule")
		}
	}
}

func TestValidateManagedConfigRejectsDuplicateEmail(t *testing.T) {
	cfg := managedConfigFixture()
	_, settings, _, _ := managedInbound(cfg, "parent-in")
	settings["clients"] = append(settings["clients"].([]interface{}), map[string]interface{}{"email": "alice__parent-in", "id": "other"})
	err := validateManagedConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "重复 Xray email") {
		t.Fatalf("duplicate was not rejected: %v", err)
	}
}

func TestPackageNodeDiff(t *testing.T) {
	added, removed := packageNodeDiff([]int64{1, 2, 4}, []int64{2, 3, 4})
	if len(added) != 1 || added[0] != 3 || len(removed) != 1 || removed[0] != 1 {
		t.Fatalf("added=%v removed=%v", added, removed)
	}
}

func TestPrivateRouteMutationIsIdempotent(t *testing.T) {
	cfg := managedConfigFixture()
	detail := &storage.RoutedNodeDetail{
		Node:              storage.Node{InboundTag: "parent-in"},
		RoutedRuleMarktag: "private-route",
		RoutedOutboundTag: "private-out",
	}
	if err := upsertPrivateRoute(cfg, detail, "alice-private"); err != nil {
		t.Fatal(err)
	}
	if err := upsertPrivateRoute(cfg, detail, "alice-private"); err != nil {
		t.Fatal(err)
	}
	if err := removeManagedRoute(cfg, "private-route"); err != nil {
		t.Fatal(err)
	}
	if err := removeManagedRoute(cfg, "private-route"); err != nil {
		t.Fatal(err)
	}
}
