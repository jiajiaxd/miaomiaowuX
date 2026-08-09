package handler

import (
	"encoding/json"
	"testing"
)

func testRealityGuardConfig() map[string]any {
	return map[string]any{
		"inbounds": []any{
			map[string]any{
				"tag": "vless-reality-443", "port": float64(443), "protocol": "vless",
				"streamSettings": map[string]any{
					"security": "reality",
					"realitySettings": map[string]any{
						"dest": "speed.cloudflare.com:443", "serverNames": []any{"speed.cloudflare.com"},
					},
				},
			},
		},
		"routing": map[string]any{"rules": []any{map[string]any{"type": "field", "inboundTag": []any{"api"}, "outboundTag": "api"}}},
	}
}

func TestMutateRealityGuardConfigEnableAndDisable(t *testing.T) {
	config := testRealityGuardConfig()
	tag := "vless-reality-443"
	if err := mutateRealityGuardConfig(config, tag, true); err != nil {
		t.Fatalf("enable guard: %v", err)
	}
	inbounds := config["inbounds"].([]any)
	if len(inbounds) != 2 {
		t.Fatalf("inbounds=%d, want 2", len(inbounds))
	}
	guard := findInboundByTag(inbounds, realityGuardTag(tag))
	if guard == nil || guard["protocol"] != "tunnel" || guard["listen"] != "127.0.0.1" {
		t.Fatalf("invalid guard inbound: %#v", guard)
	}
	main := findInboundByTag(inbounds, tag)
	reality := realitySettingsOf(main)
	if got := reality["dest"]; got != "127.0.0.1:39000" {
		t.Fatalf("guarded dest=%v", got)
	}
	rules := config["routing"].(map[string]any)["rules"].([]any)
	if len(rules) != 3 {
		t.Fatalf("rules=%d, want 3", len(rules))
	}
	if got := rules[0].(map[string]any)["outboundTag"]; got != "direct" {
		t.Fatalf("first rule outbound=%v", got)
	}
	if got := rules[1].(map[string]any)["outboundTag"]; got != "block" {
		t.Fatalf("second rule outbound=%v", got)
	}

	if err := mutateRealityGuardConfig(config, tag, false); err != nil {
		t.Fatalf("disable guard: %v", err)
	}
	inbounds = config["inbounds"].([]any)
	if len(inbounds) != 1 || findInboundByTag(inbounds, realityGuardTag(tag)) != nil {
		t.Fatalf("guard inbound was not removed: %#v", inbounds)
	}
	if got := realitySettingsOf(findInboundByTag(inbounds, tag))["dest"]; got != "speed.cloudflare.com:443" {
		t.Fatalf("restored dest=%v", got)
	}
	if got := len(config["routing"].(map[string]any)["rules"].([]any)); got != 1 {
		t.Fatalf("rules after disable=%d", got)
	}
}

func TestMutateRealityGuardConfigUpdatesTargetWithoutDuplicating(t *testing.T) {
	config := testRealityGuardConfig()
	tag := "vless-reality-443"
	if err := mutateRealityGuardConfig(config, tag, true); err != nil {
		t.Fatal(err)
	}
	main := findInboundByTag(config["inbounds"].([]any), tag)
	realitySettingsOf(main)["dest"] = "www.microsoft.com:443"
	realitySettingsOf(main)["serverNames"] = []any{"www.microsoft.com"}
	if err := mutateRealityGuardConfig(config, tag, true); err != nil {
		t.Fatal(err)
	}
	inbounds := config["inbounds"].([]any)
	if len(inbounds) != 2 {
		t.Fatalf("duplicate helper created: %d inbounds", len(inbounds))
	}
	guard := findInboundByTag(inbounds, realityGuardTag(tag))
	settings := guard["settings"].(map[string]any)
	if settings["address"] != "www.microsoft.com" {
		t.Fatalf("helper target=%v", settings["address"])
	}
	rules := config["routing"].(map[string]any)["rules"].([]any)
	if len(rules) != 3 {
		t.Fatalf("duplicate rules created: %d", len(rules))
	}
}

func TestRealityGuardUsesReservedTag(t *testing.T) {
	tag := realityGuardTag("custom-inbound")
	if !isRealityGuardTag(tag) || tag == "custom-inbound" {
		t.Fatalf("unexpected guard tag %q", tag)
	}
}

func TestValidateRealityGuardStealMode(t *testing.T) {
	on, off := true, false
	for _, mode := range []string{"tunnel", "fallback"} {
		if err := validateRealityGuardStealMode(mode, &on); err == nil {
			t.Fatalf("mode %q allowed Reality guard", mode)
		}
		if err := validateRealityGuardStealMode(mode, &off); err != nil {
			t.Fatalf("mode %q rejected disabled guard: %v", mode, err)
		}
	}
	for _, mode := range []string{"", "default"} {
		if err := validateRealityGuardStealMode(mode, &on); err != nil {
			t.Fatalf("mode %q rejected Reality guard: %v", mode, err)
		}
	}
}

func TestFilterInboundsHidesRealityGuardAndRestoresEditFields(t *testing.T) {
	config := testRealityGuardConfig()
	tag := "vless-reality-443"
	if err := mutateRealityGuardConfig(config, tag, true); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"success": true, "inbounds": config["inbounds"]})
	filtered := (&RemoteManageHandler{}).filterInboundsResponse(payload)
	var response struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(filtered, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Inbounds) != 1 {
		t.Fatalf("visible inbounds=%d, want 1", len(response.Inbounds))
	}
	if response.Inbounds[0]["reality_guard"] != true {
		t.Fatalf("reality_guard=%v", response.Inbounds[0]["reality_guard"])
	}
	if got := realitySettingsOf(response.Inbounds[0])["dest"]; got != "speed.cloudflare.com:443" {
		t.Fatalf("editable dest=%v", got)
	}
}
