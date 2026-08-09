package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"miaomiaowux/internal/storage"

	"github.com/google/uuid"
)

type subaccountActiveSnapshot struct {
	id     int64
	active bool
}

func removeTaggedConfigEntry(config map[string]interface{}, section, tag string) {
	items, _ := config[section].([]interface{})
	kept := make([]interface{}, 0, len(items))
	for _, raw := range items {
		item, _ := raw.(map[string]interface{})
		if item != nil && fmt.Sprint(item["tag"]) == tag {
			continue
		}
		kept = append(kept, raw)
	}
	config[section] = kept
}

func upsertTaggedConfigEntry(config map[string]interface{}, section string, entry map[string]interface{}) {
	tag := strings.TrimSpace(fmt.Sprint(entry["tag"]))
	items, _ := config[section].([]interface{})
	for i, raw := range items {
		item, _ := raw.(map[string]interface{})
		if item != nil && tag != "" && fmt.Sprint(item["tag"]) == tag {
			items[i] = entry
			config[section] = items
			return
		}
	}
	config[section] = append(items, entry)
}

func removeManagedRoute(config map[string]interface{}, marktag string) error {
	routing, _ := config["routing"].(map[string]interface{})
	if routing == nil {
		return errors.New("routing 配置不存在")
	}
	rules, _ := routing["rules"].([]interface{})
	kept := make([]interface{}, 0, len(rules))
	for _, raw := range rules {
		rule, _ := raw.(map[string]interface{})
		if rule != nil && marktag != "" && fmt.Sprint(rule["marktag"]) == marktag {
			continue
		}
		kept = append(kept, raw)
	}
	// Missing is already the requested state. This makes repeated disable and
	// cleaner retries idempotent after an earlier successful transaction.
	routing["rules"] = kept
	return nil
}

func upsertPrivateRoute(config map[string]interface{}, detail *storage.RoutedNodeDetail, email string) error {
	routing, _ := config["routing"].(map[string]interface{})
	if routing == nil {
		routing = map[string]interface{}{}
		config["routing"] = routing
	}
	rules, _ := routing["rules"].([]interface{})
	rule := map[string]interface{}{
		"type":        "field",
		"marktag":     detail.RoutedRuleMarktag,
		"user":        []interface{}{email},
		"inboundTag":  []interface{}{detail.InboundTag},
		"outboundTag": detail.RoutedOutboundTag,
	}
	for i, raw := range rules {
		current, _ := raw.(map[string]interface{})
		if current != nil && fmt.Sprint(current["marktag"]) == detail.RoutedRuleMarktag {
			rules[i] = rule
			routing["rules"] = rules
			return nil
		}
	}
	routing["rules"] = append(rules, rule)
	return nil
}

// syncUserAccessTransactionally switches every physical and routed credential
// owned by one user as one complete-config transaction. deletePrivate also
// removes private routed outbounds; it is used only by account deletion.
func syncUserAccessTransactionally(ctx context.Context, repo *storage.TrafficRepository, rm *RemoteManageHandler, user storage.User, enable, deletePrivate bool) error {
	if rm == nil {
		return errors.New("remote manager unavailable")
	}
	states := map[int64]*packageConfigState{}

	configs, err := repo.GetUserInboundConfigs(ctx, user.Username)
	if err != nil {
		return fmt.Errorf("读取用户入站凭据: %w", err)
	}
	for _, cfg := range configs {
		state, err := loadPackageServerConfig(ctx, rm, states, cfg.ServerID)
		if err != nil {
			return err
		}
		var credential map[string]interface{}
		if err := json.Unmarshal([]byte(cfg.CredentialJSON), &credential); err != nil {
			return fmt.Errorf("解析 %s/%s 凭据: %w", user.Username, cfg.InboundTag, err)
		}
		if enable {
			err = upsertManagedClient(state.config, cfg.InboundTag, credential)
		} else {
			err = removeManagedClient(state.config, cfg.InboundTag, managedCredentialEmail(credential, user.Username+"__"+cfg.InboundTag), credential)
		}
		if err != nil {
			return err
		}
	}

	subaccounts, err := repo.ListUserSubaccounts(ctx, user.Username)
	if err != nil {
		return fmt.Errorf("读取用户路由子账户: %w", err)
	}
	before := make([]subaccountActiveSnapshot, 0, len(subaccounts))
	for _, subaccount := range subaccounts {
		detail, err := repo.GetRoutedNodeDetail(ctx, subaccount.RoutedNodeID)
		if err != nil {
			return fmt.Errorf("读取路由节点 %d: %w", subaccount.RoutedNodeID, err)
		}
		server, err := repo.GetRemoteServerByName(ctx, detail.OriginalServer)
		if err != nil {
			return err
		}
		state, err := loadPackageServerConfig(ctx, rm, states, server.ID)
		if err != nil {
			return err
		}
		var credential map[string]interface{}
		if err := json.Unmarshal([]byte(subaccount.CredentialJSON), &credential); err != nil {
			return fmt.Errorf("解析路由子账户 %d 凭据: %w", subaccount.ID, err)
		}
		if enable {
			if err := upsertManagedClient(state.config, detail.InboundTag, credential); err != nil {
				return err
			}
			if detail.RoutedOwner == "user" {
				if strings.TrimSpace(detail.RoutedOutboundJSON) != "" {
					var outbound map[string]interface{}
					if err := json.Unmarshal([]byte(detail.RoutedOutboundJSON), &outbound); err != nil {
						return fmt.Errorf("解析私有路由 outbound: %w", err)
					}
					upsertTaggedConfigEntry(state.config, "outbounds", outbound)
				}
				if err := upsertPrivateRoute(state.config, &detail, subaccount.Email); err != nil {
					return err
				}
			} else if err := mutateManagedRouteUser(state.config, detail.RoutedRuleMarktag, detail.RoutedOutboundTag, subaccount.Email, true); err != nil {
				return err
			}
		} else {
			if err := removeManagedClient(state.config, detail.InboundTag, subaccount.Email, credential); err != nil {
				return err
			}
			if detail.RoutedOwner == "user" {
				if err := removeManagedRoute(state.config, detail.RoutedRuleMarktag); err != nil {
					return err
				}
				if deletePrivate {
					removeTaggedConfigEntry(state.config, "outbounds", detail.RoutedOutboundTag)
				}
			} else if err := mutateManagedRouteUser(state.config, detail.RoutedRuleMarktag, detail.RoutedOutboundTag, subaccount.Email, false); err != nil {
				return err
			}
		}
		before = append(before, subaccountActiveSnapshot{id: subaccount.ID, active: subaccount.IsActive})
	}

	targets := make([]xrayConfigTransactionTarget, 0, len(states))
	for serverID, state := range states {
		if err := validateManagedConfig(state.config); err != nil {
			return err
		}
		raw, err := json.MarshalIndent(state.config, "", "  ")
		if err != nil {
			return err
		}
		targets = append(targets, xrayConfigTransactionTarget{ServerID: serverID, Config: string(raw)})
	}
	operationID := "user-access-" + uuid.NewString()
	if err := applyXrayConfigTransaction(ctx, rm, operationID, targets); err != nil {
		return err
	}
	var dbErrs []error
	for _, snapshot := range before {
		if err := repo.SetSubaccountActive(ctx, snapshot.id, enable); err != nil {
			dbErrs = append(dbErrs, err)
		}
	}
	if len(dbErrs) > 0 {
		_ = finishXrayConfigTransaction(context.WithoutCancel(ctx), rm, operationID, targets, false)
		for _, snapshot := range before {
			_ = repo.SetSubaccountActive(context.WithoutCancel(ctx), snapshot.id, snapshot.active)
		}
		return fmt.Errorf("保存子账户状态失败: %w", errors.Join(dbErrs...))
	}
	if err := finishXrayConfigTransaction(context.WithoutCancel(ctx), rm, operationID, targets, true); err != nil {
		// activate + database state are already consistent. commit only removes
		// Agent staging files; reporting the business operation as failed here
		// would invite a retry while the requested state is already active.
		log.Printf("[UserAccessTxn] operation %s committed; agent cleanup incomplete: %v", operationID, err)
	}
	for _, target := range targets {
		go rm.refreshXraySnapshot(target.ServerID)
	}
	return nil
}
