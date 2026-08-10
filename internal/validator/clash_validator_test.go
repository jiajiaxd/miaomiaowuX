package validator

import "testing"

func TestValidateClashConfigRepairsInvalidGroupReferences(t *testing.T) {
	config := map[string]interface{}{
		"proxies": []interface{}{
			map[string]interface{}{"name": "node-a", "type": "ss"},
		},
		"proxy-groups": []interface{}{
			map[string]interface{}{
				"name":    "select",
				"type":    "select",
				"proxies": []interface{}{"missing-node", "node-a", "missing-group", "fallback", "missing-node", "DIRECT"},
			},
			map[string]interface{}{"name": "fallback", "type": "select", "proxies": []interface{}{"DIRECT"}},
		},
	}

	result := ValidateClashConfig(config)
	if !result.Valid {
		t.Fatalf("repairable config should be valid: %+v", result.Issues)
	}
	if result.FixedConfig == nil {
		t.Fatal("expected a repaired config")
	}
	groups := result.FixedConfig["proxy-groups"].([]interface{})
	refs := groups[0].(map[string]interface{})["proxies"].([]interface{})
	if len(refs) != 3 || refs[0] != "node-a" || refs[1] != "fallback" || refs[2] != "DIRECT" {
		t.Fatalf("unexpected repaired references: %#v", refs)
	}
}

func TestValidateClashConfigAddsFallbackToEmptyGroup(t *testing.T) {
	config := map[string]interface{}{
		"proxy-groups": []interface{}{
			map[string]interface{}{
				"name":    "select",
				"type":    "select",
				"proxies": []interface{}{"removed-node"},
			},
		},
	}

	result := ValidateClashConfig(config)
	if !result.Valid || result.FixedConfig == nil {
		t.Fatalf("expected invalid reference to be repaired: %+v", result.Issues)
	}
	groups := result.FixedConfig["proxy-groups"].([]interface{})
	refs := groups[0].(map[string]interface{})["proxies"].([]interface{})
	if len(refs) != 1 || refs[0] != "DIRECT" {
		t.Fatalf("expected DIRECT fallback, got %#v", refs)
	}
}

func TestValidateClashConfigBreaksCircularGroupReference(t *testing.T) {
	config := map[string]interface{}{
		"proxy-groups": []interface{}{
			map[string]interface{}{"name": "a", "type": "select", "proxies": []interface{}{"b"}},
			map[string]interface{}{"name": "b", "type": "select", "proxies": []interface{}{"a"}},
		},
	}

	result := ValidateClashConfig(config)
	if !result.Valid || result.FixedConfig == nil {
		t.Fatalf("expected cycle to be repaired: %+v", result.Issues)
	}
	groups := result.FixedConfig["proxy-groups"].([]interface{})
	bRefs := groups[1].(map[string]interface{})["proxies"].([]interface{})
	if len(bRefs) != 1 || bRefs[0] != "DIRECT" {
		t.Fatalf("expected back edge to be replaced by DIRECT, got %#v", bRefs)
	}
}

func TestValidateClashConfigStillRejectsMissingGroupName(t *testing.T) {
	config := map[string]interface{}{
		"proxy-groups": []interface{}{
			map[string]interface{}{"type": "select", "proxies": []interface{}{"DIRECT"}},
		},
	}

	if result := ValidateClashConfig(config); result.Valid {
		t.Fatal("an unnamed group is not safely repairable")
	}
}
