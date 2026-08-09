package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const realityGuardTagPrefix = "mmwx-reality-guard-"

const realityGuardStealSelfMessage = "偷自己服务器不能开启 Reality 防偷；两者都会改写 Reality 伪装目标和 tunnel 路由"

func validateRealityGuardStealMode(stealMode string, requested *bool) error {
	if requested == nil || !*requested {
		return nil
	}
	if stealMode == "tunnel" || stealMode == "fallback" {
		return fmt.Errorf("%s", realityGuardStealSelfMessage)
	}
	return nil
}

func realityGuardTag(inboundTag string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(inboundTag)))
	return realityGuardTagPrefix + hex.EncodeToString(sum[:8])
}

func realityGuardMark(inboundTag string) string { return realityGuardTag(inboundTag) }

func isRealityGuardTag(tag string) bool {
	return strings.HasPrefix(strings.TrimSpace(tag), realityGuardTagPrefix)
}

func splitRealityDest(dest string) (string, int, error) {
	dest = strings.TrimSpace(dest)
	if dest == "" {
		return "", 0, fmt.Errorf("Reality dest 不能为空")
	}
	host, portText, err := net.SplitHostPort(dest)
	if err != nil {
		// Xray 界面允许只填域名；与现有生成逻辑一致，默认使用 443。
		if !strings.Contains(dest, ":") {
			return dest, 443, nil
		}
		return "", 0, fmt.Errorf("Reality dest %q 格式错误: %w", dest, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("Reality dest %q 端口无效", dest)
	}
	return host, port, nil
}

func joinRealityDest(host string, port int) string {
	return net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port))
}

func findInboundByTag(inbounds []any, tag string) map[string]any {
	for _, raw := range inbounds {
		ib, _ := raw.(map[string]any)
		if strings.TrimSpace(fmt.Sprint(ib["tag"])) == tag {
			return ib
		}
	}
	return nil
}

func allocateRealityGuardPort(inbounds []any) (int, error) {
	used := make(map[int]bool, len(inbounds))
	for _, raw := range inbounds {
		ib, _ := raw.(map[string]any)
		used[toInt(ib["port"])] = true
	}
	// 仅在 loopback 上监听；从高位范围顺序选取，配置结果稳定且不与已有入站冲突。
	for port := 39000; port <= 59999; port++ {
		if !used[port] {
			return port, nil
		}
	}
	return 0, fmt.Errorf("没有可用的 Reality 防盗本地端口")
}

func realitySettingsOf(inbound map[string]any) map[string]any {
	stream, _ := inbound["streamSettings"].(map[string]any)
	if !strings.EqualFold(strings.TrimSpace(fmt.Sprint(stream["security"])), "reality") {
		return nil
	}
	reality, _ := stream["realitySettings"].(map[string]any)
	return reality
}

// mutateRealityGuardConfig 在一份完整 Xray 配置内同步 Reality 主入站、辅助 tunnel 和两条路由。
// enable=false 同时承担关闭开关及删除主入站后的孤儿清理。
func mutateRealityGuardConfig(config map[string]any, inboundTag string, enable bool) error {
	inbounds, _ := config["inbounds"].([]any)
	guardTag := realityGuardTag(inboundTag)
	mainInbound := findInboundByTag(inbounds, inboundTag)
	guardInbound := findInboundByTag(inbounds, guardTag)

	if !enable {
		if mainInbound != nil && guardInbound != nil {
			settings, _ := guardInbound["settings"].(map[string]any)
			host := strings.TrimSpace(fmt.Sprint(settings["address"]))
			port := toInt(settings["port"])
			if reality := realitySettingsOf(mainInbound); reality != nil && host != "" && port > 0 {
				reality["dest"] = joinRealityDest(host, port)
			}
		}
		filtered := make([]any, 0, len(inbounds))
		for _, raw := range inbounds {
			ib, _ := raw.(map[string]any)
			if strings.TrimSpace(fmt.Sprint(ib["tag"])) != guardTag {
				filtered = append(filtered, raw)
			}
		}
		config["inbounds"] = filtered
		removeRealityGuardRules(config, inboundTag)
		return nil
	}

	if mainInbound == nil || realitySettingsOf(mainInbound) == nil {
		return fmt.Errorf("未找到 Reality 入站 %q", inboundTag)
	}
	reality := realitySettingsOf(mainInbound)

	var targetHost string
	var targetPort int
	var localPort int
	if guardInbound != nil {
		settings, _ := guardInbound["settings"].(map[string]any)
		targetHost = strings.TrimSpace(fmt.Sprint(settings["address"]))
		targetPort = toInt(settings["port"])
		localPort = toInt(guardInbound["port"])
		// 编辑时主入站会先以界面里的原始 dest 完成 replace；若它不再指向当前
		// loopback helper，说明用户修改了伪装目标，应同步更新 helper 的 address/port。
		currentDest := strings.TrimSpace(fmt.Sprint(reality["dest"]))
		if currentDest != joinRealityDest("127.0.0.1", localPort) {
			if host, port, err := splitRealityDest(currentDest); err == nil {
				targetHost, targetPort = host, port
			} else {
				return err
			}
		}
	} else {
		var err error
		targetHost, targetPort, err = splitRealityDest(fmt.Sprint(reality["dest"]))
		if err != nil {
			return err
		}
		localPort, err = allocateRealityGuardPort(inbounds)
		if err != nil {
			return err
		}
	}
	if targetHost == "" || targetPort <= 0 || localPort <= 0 {
		return fmt.Errorf("Reality 防盗辅助入站参数不完整")
	}

	serverNames := toStringSlice(reality["serverNames"])
	if len(serverNames) == 0 {
		return fmt.Errorf("Reality 防盗需要至少一个 serverNames 域名")
	}
	reality["dest"] = joinRealityDest("127.0.0.1", localPort)
	newGuard := map[string]any{
		"listen":   "127.0.0.1",
		"tag":      guardTag,
		"port":     localPort,
		"protocol": "tunnel",
		"settings": map[string]any{"address": targetHost, "port": targetPort, "network": "tcp"},
		"sniffing": map[string]any{"enabled": true, "destOverride": []any{"tls"}, "routeOnly": true},
	}
	if guardInbound == nil {
		config["inbounds"] = append(inbounds, newGuard)
	} else {
		for i, raw := range inbounds {
			ib, _ := raw.(map[string]any)
			if strings.TrimSpace(fmt.Sprint(ib["tag"])) == guardTag {
				inbounds[i] = newGuard
				break
			}
		}
		config["inbounds"] = inbounds
	}

	removeRealityGuardRules(config, inboundTag)
	routing, _ := config["routing"].(map[string]any)
	if routing == nil {
		routing = map[string]any{}
		config["routing"] = routing
	}
	rules, _ := routing["rules"].([]any)
	mark := realityGuardMark(inboundTag)
	allow := map[string]any{"type": "field", "marktag": mark, "inboundTag": []any{guardTag}, "domain": stringSliceToAny(serverNames), "outboundTag": "direct"}
	block := map[string]any{"type": "field", "marktag": mark, "inboundTag": []any{guardTag}, "outboundTag": "block"}
	routing["rules"] = append([]any{allow, block}, rules...)
	return nil
}

func stringSliceToAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func removeRealityGuardRules(config map[string]any, inboundTag string) {
	routing, _ := config["routing"].(map[string]any)
	if routing == nil {
		return
	}
	rules, _ := routing["rules"].([]any)
	mark := realityGuardMark(inboundTag)
	guardTag := realityGuardTag(inboundTag)
	filtered := make([]any, 0, len(rules))
	for _, raw := range rules {
		rule, _ := raw.(map[string]any)
		remove := strings.TrimSpace(fmt.Sprint(rule["marktag"])) == mark
		if !remove {
			for _, tag := range toStringSlice(rule["inboundTag"]) {
				if tag == guardTag {
					remove = true
					break
				}
			}
		}
		if !remove {
			filtered = append(filtered, raw)
		}
	}
	routing["rules"] = filtered
}

// syncRealityGuardConfig 通过完整配置写入保证辅助入站与两条路由一次落盘；失败时恢复原配置。
func (h *RemoteManageHandler) syncRealityGuardConfig(ctx context.Context, serverID int64, inboundTag string, enable bool) error {
	raw, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/xray/config", nil)
	if err != nil {
		return err
	}
	var envelope struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || strings.TrimSpace(envelope.Config) == "" {
		return fmt.Errorf("读取 Xray 完整配置失败")
	}
	original := envelope.Config
	var config map[string]any
	if err := json.Unmarshal([]byte(original), &config); err != nil {
		return fmt.Errorf("解析 Xray 完整配置失败: %w", err)
	}
	if err := mutateRealityGuardConfig(config, inboundTag, enable); err != nil {
		return err
	}
	updated, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"config": string(updated)})
	if _, err := h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/xray/config", payload); err != nil {
		return err
	}
	if err := h.restartXrayWithRecovery(ctx, serverID, "RealityGuardUpdate"); err != nil {
		rollback, _ := json.Marshal(map[string]string{"config": original})
		_, _ = h.forwardToRemoteServer(context.WithoutCancel(ctx), serverID, http.MethodPost, "/api/child/xray/config", rollback)
		_ = h.restartXrayWithRecovery(context.WithoutCancel(ctx), serverID, "RealityGuardRollback")
		return err
	}
	return nil
}
