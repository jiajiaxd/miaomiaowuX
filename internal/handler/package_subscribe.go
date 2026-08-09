package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/MMWOrg/mmwX-plugins/proxyparser/substore"
	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/storage"

	"gopkg.in/yaml.v3"
)

type PackageSubscribeHandler struct {
	repo *storage.TrafficRepository
}

func NewPackageSubscribeHandler(repo *storage.TrafficRepository) http.Handler {
	return &PackageSubscribeHandler{repo: repo}
}

func (h *PackageSubscribeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSubscriptionNoCacheHeaders(w)
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("only GET is supported"))
		return
	}
	if rejectBlockedSubscriptionUA(w, r) {
		return
	}

	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	user, err := h.repo.GetUser(r.Context(), username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	if user.PackageID == 0 {
		if user.Role != storage.RoleAdmin {
			writeError(w, http.StatusNotFound, errors.New("未绑定套餐"))
			return
		}
		h.serveAllNodes(w, r, user)
		return
	}

	pkg, err := h.repo.GetPackage(r.Context(), user.PackageID)
	if err != nil {
		if errors.Is(err, storage.ErrPackageNotFound) {
			writeError(w, http.StatusNotFound, errors.New("套餐不存在"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// Build user credential lookup for per-user proxy configs
	credMap := h.buildUserCredentialMap(r, username)

	// 节点名称倍率前缀:开关开启时,套餐内倍率 != 1 的节点 name 加上 "{Left}{mult}{Right}" 前缀
	// renameMap 收集所有重命名,后面要同步 proxy-groups 里"按全名引用"的列表,避免组找不到节点
	sysCfg, _ := h.repo.GetSystemConfig(r.Context())
	renameMap := make(map[string]string)
	recordRename := func(oldName, newName string, did bool) {
		if did && oldName != "" && newName != "" && oldName != newName {
			renameMap[oldName] = newName
		}
	}

	// packages.nodes 是管理员在套餐内维护的有序数组。套餐订阅必须严格使用该顺序，
	// 不能再被用户节点管理里的个人 node_order 覆盖。
	orderedNodeIDs := orderPackageNodes(r.Context(), h.repo, username, pkg.Nodes)

	// Load nodes from package
	var proxies []map[string]any
	// 链式代理(dialer-proxy)注入基础设施:边追加边记录每个节点的最终输出名 + 待注入引用,
	// 三段追加(套餐物理 / 套餐 routed / 用户私有 routed)全部完成后再统一注入,
	// 这样 dialer-proxy 能引用倍率改名后的最终名字,且只在目标真的出现在输出里时才注入。
	finalNameByNodeID := make(map[int64]string)
	relayGroupSpecs := make(map[string][]int64) // 组名 → 成员节点 ID(按 ID 存,收齐后按最终名建组)
	var relayGroupOrder []string
	var dialerRefs []dialerRef
	noteProxy := func(node storage.Node, proxyConfig map[string]any) {
		if nm, ok := proxyConfig["name"].(string); ok && nm != "" {
			finalNameByNodeID[node.ID] = nm
		}
		if node.ChainProxyNodeID != nil {
			dialerRefs = append(dialerRefs, dialerRef{proxy: proxyConfig, target: *node.ChainProxyNodeID})
		}
		// 中转组:源节点 dialer-proxy 指向组名;成员按 ID 记录,收齐后按最终名(倍率改名后)建 url-test 组
		if len(node.RelayGroupNodeIDs) > 0 && node.RelayGroupName != "" {
			proxyConfig["dialer-proxy"] = node.RelayGroupName
			if _, seen := relayGroupSpecs[node.RelayGroupName]; !seen {
				relayGroupSpecs[node.RelayGroupName] = node.RelayGroupNodeIDs
				relayGroupOrder = append(relayGroupOrder, node.RelayGroupName)
			}
		}
	}
	for _, nodeID := range orderedNodeIDs {
		node, err := h.repo.GetNodeByID(r.Context(), nodeID)
		if err != nil || !node.Enabled {
			continue
		}
		// routed 节点:克隆父 inbound 的 clash 模板,替换 uuid 为该用户子账号 uuid + 节点名
		if node.NodeType == "routed" {
			if proxyConfig, ok := buildRoutedProxyForUser(r.Context(), h.repo, node, username); ok {
				oldName, _ := proxyConfig["name"].(string)
				applyPackageNameOverride(proxyConfig, node, pkg)
				applyMultiplierPrefix(proxyConfig, node, pkg, &sysCfg)
				newName, _ := proxyConfig["name"].(string)
				recordRename(oldName, newName, oldName != newName)
				noteProxy(node, proxyConfig)
				proxies = append(proxies, proxyConfig)
			}
			continue
		}
		if node.ClashConfig == "" {
			continue
		}
		var proxyConfig map[string]any
		if err := json.Unmarshal([]byte(node.ClashConfig), &proxyConfig); err != nil {
			continue
		}
		applyUserCredentials(proxyConfig, node, credMap)
		oldName, _ := proxyConfig["name"].(string)
		applyPackageNameOverride(proxyConfig, node, pkg)
		applyMultiplierPrefix(proxyConfig, node, pkg, &sysCfg)
		newName, _ := proxyConfig["name"].(string)
		recordRename(oldName, newName, oldName != newName)
		noteProxy(node, proxyConfig)
		proxies = append(proxies, proxyConfig)
	}

	// 追加用户私有路由出站(routed_owner='user' && username=<creator>):不依赖套餐分配,
	// 创建者一人独享。其 routed 子账号 email 已通过 user_subaccounts 维护,buildRoutedProxyForUser
	// 复用同一套替换 uuid 逻辑。
	if userRouted, err := h.repo.ListUserRoutedOutbounds(r.Context(), username); err == nil {
		for _, n := range userRouted {
			if !n.Enabled {
				continue
			}
			if proxyConfig, ok := buildRoutedProxyForUser(r.Context(), h.repo, n.Node, username); ok {
				oldName, _ := proxyConfig["name"].(string)
				applyPackageNameOverride(proxyConfig, n.Node, pkg)
				applyMultiplierPrefix(proxyConfig, n.Node, pkg, &sysCfg)
				newName, _ := proxyConfig["name"].(string)
				recordRename(oldName, newName, oldName != newName)
				noteProxy(n.Node, proxyConfig)
				proxies = append(proxies, proxyConfig)
			}
		}
	}

	// 所有节点已收齐 → 注入 dialer-proxy(引用倍率改名后的最终名,目标缺席则跳过不产生悬空引用)
	injectDialerProxyRefs(dialerRefs, finalNameByNodeID)

	// 中转组:按最终名(倍率改名后)建 url-test 组;成员缺席(未下发到本订阅)则跳过,防悬空
	var relayGroups []map[string]any
	for _, groupName := range relayGroupOrder {
		memberIDs := relayGroupSpecs[groupName]
		var groupProxies []string
		for _, rid := range memberIDs {
			if nm, ok := finalNameByNodeID[rid]; ok {
				groupProxies = append(groupProxies, nm)
			}
		}
		if len(groupProxies) > 0 {
			relayGroups = append(relayGroups, map[string]any{
				"name": groupName, "type": "url-test", "proxies": groupProxies,
				"url": "http://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50,
			})
		}
	}

	if len(proxies) == 0 {
		writeError(w, http.StatusNotFound, errors.New("套餐内无可用节点"))
		return
	}

	// Load template: 套餐模板 > 系统默认 > 目录第一个
	templateContent, templateName, err := h.loadTemplate(r, pkg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// Surge 模板(.conf):注入 [Proxy] 段后直接输出 Surge 文本,不走 Clash 处理器/格式转换。
	if isSurgeTemplateFile(templateName) {
		surgeResult, serr := injectProxiesIntoSurgeTemplate(templateContent, proxies)
		if serr != nil {
			writeError(w, http.StatusInternalServerError, serr)
			return
		}
		ua := r.Header.Get("User-Agent")
		if ua == "" {
			ua = "unknown"
		}
		SendSubscribeFetchNotification(r.Context(), h.repo, username, ua, GetClientIP(r))
		if silentMgr := GetSilentModeManager(); silentMgr != nil {
			silentMgr.RecordSubscriptionAccessWithIP(username, GetClientIP(r))
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		setSubscriptionName(w, pkg.Name, ".conf")
		h.writeTrafficHeader(r.Context(), w, user, pkg)
		w.Write([]byte(surgeResult))
		return
	}

	// Process template with nodes
	processor := substore.NewTemplateV3Processor(nil, nil)
	result, err := processor.ProcessTemplate(templateContent, proxies)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	result, err = injectProxiesIntoTemplate(result, proxies)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	result, err = restoreTemplateProxyGroupOrder(templateContent, result)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 节点名重命名了 → 同步 proxy-groups 里手写的全名引用(模板若用 filter 自动会用新名,这里兜底全名引用场景)
	if len(renameMap) > 0 {
		if rewritten, rerr := rewriteProxyGroupRefs([]byte(result), renameMap); rerr == nil {
			result = string(rewritten)
		}
	}

	// 中转组:把 url-test 组追加进 proxy-groups(成员名已是倍率改名后的最终名)
	if len(relayGroups) > 0 {
		if rg, rgErr := injectRelayGroupsIntoTemplate(result, relayGroups); rgErr == nil {
			result = rg
		}
	}

	clientType := resolveClientType(r)
	// 套餐订阅走独立处理器，不能依赖普通订阅路径的信息节点注入。
	// 普通模式只给 Clash 系 YAML 客户端添加；“仅 V2Ray”模式则在 URI 转换前添加，
	// 由 producer 将两个 SS 占位节点转换为客户端可展示的链接。
	if sysCfg.EnableSubInfoNodes && shouldAddPackageSubInfoNodes(clientType, sysCfg.SubInfoV2RayOnly) {
		limit := resolveTrafficLimitBytes(&user, pkg)
		used, _ := h.repo.GetUserBillableTraffic(r.Context(), username)
		remaining := limit - used
		if remaining < 0 {
			remaining = 0
		}
		result = string(prependSubInfoNodesToClash([]byte(result), sysCfg, user.PackageEndDate, remaining))
	}

	// 通知 admin "用户拉了套餐订阅" + 静默期记录访问 IP — 跟 SubscriptionHandler L286 同款。
	// 之前套餐订阅这条路径完全没有这两个调用,所以 admin tg 从来收不到「用户拉套餐订阅」通知。
	// 放在这里:此前所有可能失败的步骤(查套餐 / 拼节点 / 加模板 / 渲染)都已成功,
	// 仅剩格式转换 + 写响应。语义清晰:订阅会真正发出去时才通知,提前 writeError 不会触发。
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		ua = "unknown"
	}
	SendSubscribeFetchNotification(r.Context(), h.repo, username, ua, GetClientIP(r))
	if silentMgr := GetSilentModeManager(); silentMgr != nil {
		silentMgr.RecordSubscriptionAccessWithIP(username, GetClientIP(r))
	}

	// Format conversion
	if clientType == "" || clientType == "clash" || clientType == "clashmeta" {
		// 原样 YAML 输出(不经 producer)→ 过滤 snell v6(mihomo 只支持 v1–v5,v6 会整份拒载)
		result = string(filterSnellV6FromClashYAML([]byte(result)))
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		// 显式带 t=clash/clashmeta 通常是浏览器/调试预览,不想被强制下载;只有完全不带 t(典型 Clash 客户端拉取)才下发 attachment
		setSubscriptionName(w, pkg.Name, "")
		h.writeTrafficHeader(r.Context(), w, user, pkg)
		w.Write([]byte(result))
		return
	}

	converted, err := h.convertFormat(r, []byte(result), clientType)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	setSubscriptionName(w, pkg.Name, "")
	h.writeTrafficHeader(r.Context(), w, user, pkg)
	w.Write(converted)
}

func shouldAddPackageSubInfoNodes(clientType string, v2rayOnly bool) bool {
	if v2rayOnly {
		return isV2RayClientType(clientType)
	}
	switch strings.ToLower(strings.TrimSpace(clientType)) {
	case "", "clash", "clashmeta", "stash", "egern":
		return true
	default:
		return false
	}
}

// setSubscriptionName 让客户端显示套餐名作为订阅名。
// Content-Disposition 用 RFC5987(filename*=UTF-8”)避免中文套餐名乱码;
// 再附 profile-title(Surge/Loon/QX 优先认此头显示订阅名)。ext 为扩展名(可空)。
func setSubscriptionName(w http.ResponseWriter, name, ext string) {
	if strings.TrimSpace(name) == "" {
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(name)+ext)
	w.Header().Set("profile-title", "base64:"+base64.StdEncoding.EncodeToString([]byte(name)))
}

func orderPackageNodes(_ context.Context, _ *storage.TrafficRepository, _ string, pkgNodes []int64) []int64 {
	return append([]int64(nil), pkgNodes...)
}

// loadTemplate 按请求客户端类型选择模板。Clash 与 Surge 各自使用套餐绑定模板，
// 未绑定时回退到对应的系统默认模板，再回退到目录中同类型的第一个模板。
// pkg 为 nil 时跳过套餐模板这一级(serveAllNodes 等无套餐上下文场景)。
// loadTemplate 返回模板内容与文件名(文件名用于判断 Clash/Surge 格式)。
func (h *PackageSubscribeHandler) loadTemplate(r *http.Request, pkg *storage.Package) (content string, filename string, err error) {
	templatesDir := "rule_templates"
	wantSurge := isSurgeClientType(resolveClientType(r))

	var candidates []string
	// 最高优先:订阅所属用户若有模板管理权限且设了个人默认模板(且本人拥有该模板),用它覆盖套餐/系统默认。
	// 归属校验不过(模板被删/改归属)时静默跳过,自动回退到下面的套餐/系统默认。
	if !wantSurge {
		username := strings.TrimSpace(auth.UsernameFromContext(r.Context()))
		if username != "" {
			if s, err := h.repo.GetUserSettings(r.Context(), username); err == nil {
				if f := strings.TrimSpace(s.DefaultTemplateFilename); f != "" && userHasTemplatePermission(r.Context(), h.repo, username) {
					if owner, _ := h.repo.GetRuleTemplateOwner(r.Context(), f); owner == username {
						candidates = append(candidates, f)
					}
				}
			}
		}
	}
	if pkg != nil {
		filename := pkg.TemplateFilename
		if wantSurge {
			filename = pkg.SurgeTemplateFilename
			// 兼容迁移前曾写在通用字段中的 Surge 模板。
			if strings.TrimSpace(filename) == "" && isSurgeTemplateFile(pkg.TemplateFilename) {
				filename = pkg.TemplateFilename
			}
		}
		if strings.TrimSpace(filename) != "" {
			candidates = append(candidates, filename)
		}
	}
	if cfg, err := h.repo.GetSystemConfig(r.Context()); err == nil {
		filename := cfg.DefaultTemplateFilename
		if wantSurge {
			filename = cfg.DefaultSurgeTemplateFilename
		}
		if strings.TrimSpace(filename) != "" {
			candidates = append(candidates, filename)
		}
	}
	for _, name := range candidates {
		if isSurgeTemplateFile(name) != wantSurge {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(templatesDir, name))
		if rerr == nil {
			return string(data), name, nil
		}
	}

	entries, derr := os.ReadDir(templatesDir)
	if derr == nil {
		for _, e := range entries {
			if e.IsDir() || !isRuleTemplateFile(e.Name()) || isSurgeTemplateFile(e.Name()) != wantSurge {
				continue
			}
			data, rerr := os.ReadFile(filepath.Join(templatesDir, e.Name()))
			if rerr == nil {
				return string(data), e.Name(), nil
			}
		}
	}
	return "", "", errors.New("未找到可用模板，请管理员配置模板")
}

func (h *PackageSubscribeHandler) serveAllNodes(w http.ResponseWriter, r *http.Request, user storage.User) {
	allNodes, err := h.repo.ListAllNodes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	var proxies []map[string]any
	finalNameByNodeID := make(map[int64]string)
	var dialerRefs []dialerRef
	for _, node := range allNodes {
		if !node.Enabled || node.ClashConfig == "" {
			continue
		}
		var proxyConfig map[string]any
		if err := json.Unmarshal([]byte(node.ClashConfig), &proxyConfig); err != nil {
			continue
		}
		if nm, ok := proxyConfig["name"].(string); ok && nm != "" {
			finalNameByNodeID[node.ID] = nm
		} else {
			finalNameByNodeID[node.ID] = node.NodeName
		}
		if node.ChainProxyNodeID != nil {
			dialerRefs = append(dialerRefs, dialerRef{proxy: proxyConfig, target: *node.ChainProxyNodeID})
		}
		proxies = append(proxies, proxyConfig)
	}
	injectDialerProxyRefs(dialerRefs, finalNameByNodeID)
	if len(proxies) == 0 {
		writeError(w, http.StatusNotFound, errors.New("无可用节点"))
		return
	}
	// serveAllNodes 是"无套餐上下文,导出全部节点"的旁路调试入口 — 传 nil 走系统默认模板。
	templateContent, templateName, err := h.loadTemplate(r, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if isSurgeTemplateFile(templateName) {
		surgeResult, serr := injectProxiesIntoSurgeTemplate(templateContent, proxies)
		if serr != nil {
			writeError(w, http.StatusInternalServerError, serr)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(surgeResult))
		return
	}
	processor := substore.NewTemplateV3Processor(nil, nil)
	result, err := processor.ProcessTemplate(templateContent, proxies)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	result, err = injectProxiesIntoTemplate(result, proxies)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	result, err = restoreTemplateProxyGroupOrder(templateContent, result)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	clientType := resolveClientType(r)
	if clientType == "" || clientType == "clash" || clientType == "clashmeta" {
		// 同主路径:原样 YAML 输出前过滤 snell v6,防 mihomo 整份拒载
		result = string(filterSnellV6FromClashYAML([]byte(result)))
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		if clientType == "" {
			w.Header().Set("Content-Disposition", `attachment; filename="all-nodes.yaml"`)
		}
		w.Write([]byte(result))
		return
	}
	converted, err := h.convertFormat(r, []byte(result), clientType)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(converted)
}

func (h *PackageSubscribeHandler) writeTrafficHeader(ctx context.Context, w http.ResponseWriter, user storage.User, pkg *storage.Package) {
	// 有效上限 = 用户级覆写 ?? 套餐流量。<=0 = 不限流量,不发这个头。
	limitBytes := resolveTrafficLimitBytes(&user, pkg)
	if limitBytes <= 0 {
		return
	}
	// 已用流量 = 裸流量(SUM(uplink+downlink)) × 套餐倍率(oneway×1 / twoway×2),
	// 与限额判定口径一致(traffic_limit_enforcer.go:已用×TrafficMultiplier 比限额),
	// 这样客户端显示的已用/剩余与实际被断流的时机吻合。
	// 之前这里硬编码 download=0,导致客户端永远显示已用 0。
	used, _ := h.repo.GetUserBillableTraffic(ctx, user.Username)
	info := fmt.Sprintf("upload=0; download=%d; total=%d", used, limitBytes)
	// expire:有到期日输出实际时间戳;永久套餐(PackageEndDate 为 nil)输出长期占位
	// (2099-12-31),避免小火箭等客户端因缺失/为 0 的 expire 识别不了。见 appendExpire。
	info = appendExpire(info, user.PackageEndDate)
	w.Header().Set("subscription-userinfo", info)
}

func (h *PackageSubscribeHandler) convertFormat(r *http.Request, yamlData []byte, clientType string) ([]byte, error) {
	var rootNode yaml.Node
	if err := yaml.Unmarshal(yamlData, &rootNode); err != nil {
		return nil, err
	}

	config, err := yamlNodeToMap(&rootNode)
	if err != nil {
		return nil, err
	}

	proxiesRaw, ok := config["proxies"]
	if !ok {
		return nil, errors.New("no proxies in config")
	}

	proxiesArray, ok := proxiesRaw.([]interface{})
	if !ok {
		return nil, errors.New("proxies is not an array")
	}

	var proxies []substore.Proxy
	for _, p := range proxiesArray {
		proxyMap, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		proxies = append(proxies, substore.Proxy(proxyMap))
	}
	if isSurgeClientType(clientType) {
		normalizeSurgeProxies(proxies)
	}

	if clientType == "clash-to-surge" {
		sub := NewSubscriptionHandlerConcrete(h.repo, "subscribes")
		return sub.convertClashToSurge(config, proxies)
	}

	// shadowrocket / clash-to-shadowrocket 显式取对应 producer(工厂里两者都注册成 "shadowrocket");其余走工厂。
	producer := shadowrocketProducerFor(clientType)
	if producer == nil {
		producer, err = substore.GetDefaultFactory().GetProducer(clientType)
		if err != nil {
			return nil, err
		}
	}

	systemConfig, _ := h.repo.GetSystemConfig(r.Context())
	opts := &substore.ProduceOptions{
		FullConfig:              config,
		ClientCompatibilityMode: systemConfig.ClientCompatibilityMode,
	}

	result, err := producer.Produce(proxies, clientType, opts)
	if err != nil {
		return nil, err
	}

	switch v := result.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	default:
		return nil, fmt.Errorf("unexpected produce result type: %T", result)
	}
}

type credKey struct {
	serverName string
	inboundTag string
}

func (h *PackageSubscribeHandler) buildUserCredentialMap(r *http.Request, username string) map[credKey]string {
	ctx := r.Context()
	userConfigs, err := h.repo.GetUserInboundConfigs(ctx, username)
	if err != nil || len(userConfigs) == 0 {
		return nil
	}
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return nil
	}
	idToName := make(map[int64]string, len(servers))
	for _, s := range servers {
		idToName[s.ID] = s.Name
	}
	m := make(map[credKey]string, len(userConfigs))
	for _, cfg := range userConfigs {
		if name, ok := idToName[cfg.ServerID]; ok {
			m[credKey{name, cfg.InboundTag}] = cfg.CredentialJSON
		}
	}
	return m
}

// rewriteProxyGroupRefs 给定 YAML 文档 + 节点名映射,把每个 proxy-group 的 proxies 数组里
// 命中的旧名替换为新名。模板若用 filter/regex 选节点会自动用 proxies 数组里的新名,
// 这里专门兜底"模板里手写全名引用"的场景,避免代理组指向不存在的节点。
// 解析失败 / proxy-groups 缺失 → 原样返回。
func rewriteProxyGroupRefs(data []byte, rename map[string]string) ([]byte, error) {
	if len(rename) == 0 || len(data) == 0 {
		return data, nil
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return data, err
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return data, nil
	}
	doc := root.Content[0]
	modified := false
	for i := 0; i < len(doc.Content)-1; i += 2 {
		if doc.Content[i].Value != "proxy-groups" {
			continue
		}
		groups := doc.Content[i+1]
		if groups.Kind != yaml.SequenceNode {
			break
		}
		for _, g := range groups.Content {
			if g.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j < len(g.Content)-1; j += 2 {
				if g.Content[j].Value != "proxies" {
					continue
				}
				pxs := g.Content[j+1]
				if pxs.Kind != yaml.SequenceNode {
					continue
				}
				for _, pn := range pxs.Content {
					if pn.Kind != yaml.ScalarNode {
						continue
					}
					if newName, ok := rename[pn.Value]; ok {
						pn.Value = newName
						modified = true
					}
				}
			}
		}
		break
	}
	if !modified {
		return data, nil
	}
	out, err := MarshalYAMLWithIndent(&root)
	if err != nil {
		return data, err
	}
	return []byte(RemoveUnicodeEscapeQuotes(string(out))), nil
}

// dialerRef 记录一个待注入 dialer-proxy 的 proxy 及其链式目标节点 ID。
type dialerRef struct {
	proxy  map[string]any
	target int64
}

// injectDialerProxyRefs 给链式代理节点注入 dialer-proxy,引用目标节点在本次输出里的**最终名字**
// (套餐路径含倍率前缀 → 必须引用改名后的名字,否则 Mihomo 找不到该出口)。
// 目标不在本次输出中(被过滤 / 未加入套餐 / 已停用)→ 跳过,绝不产生悬空引用。
func injectDialerProxyRefs(refs []dialerRef, finalNameByNodeID map[int64]string) {
	for _, ref := range refs {
		if name, ok := finalNameByNodeID[ref.target]; ok && name != "" {
			ref.proxy["dialer-proxy"] = name
		}
	}
}

// applyMultiplierPrefix 按系统开关给节点名加倍率前缀,效果 "「2」原节点名"。
//   - 开关关 / 套餐空 / 节点倍率 == 1 → 不动 name,返回 ("","",false)
//   - routed 子节点通过 ParentNodeID 自动回退到父物理节点的套餐倍率
//   - 前缀左右分隔符由 SystemConfig.NodeNameMultiplierLeft / Right 决定,默认 「」
//   - 返回 (oldName, newName, true) 给调用方收集 renameMap,后续要同步 proxy-groups 引用
func applyMultiplierPrefix(proxy map[string]any, node storage.Node, pkg *storage.Package, cfg *storage.SystemConfig) (string, string, bool) {
	if proxy == nil || cfg == nil || pkg == nil || !cfg.NodeNameMultiplierPrefixEnabled {
		return "", "", false
	}
	mult := pkg.MultiplierForNode(node.ID)
	if mult == 1.0 {
		return "", "", false
	}
	name, _ := proxy["name"].(string)
	if name == "" {
		name = node.NodeName
	}
	left := cfg.NodeNameMultiplierLeft
	if left == "" {
		left = "「"
	}
	right := cfg.NodeNameMultiplierRight
	if right == "" {
		right = "」"
	}
	// 整数倍率不带小数(2 → "2" 而非 "2.0")
	var multStr string
	if mult == float64(int64(mult)) {
		multStr = strconv.FormatInt(int64(mult), 10)
	} else {
		multStr = strconv.FormatFloat(mult, 'f', -1, 64)
	}
	newName := left + multStr + right + name
	proxy["name"] = newName
	return name, newName, true
}

// applyPackageNameOverride 只根据稳定的节点 ID 应用套餐内名称，不依赖原名或列表顺序。
func applyPackageNameOverride(proxy map[string]any, node storage.Node, pkg *storage.Package) bool {
	if proxy == nil || pkg == nil || !pkg.NodeNameOverrideEnabled || len(pkg.NodeNameOverrides) == 0 {
		return false
	}
	name := strings.TrimSpace(pkg.NodeNameOverrides[node.ID])
	if name == "" {
		return false
	}
	proxy["name"] = name
	return true
}

func applyUserCredentials(proxy map[string]any, node storage.Node, credMap map[credKey]string) {
	if credMap == nil || node.InboundTag == "" {
		return
	}
	credJSON, ok := credMap[credKey{node.OriginalServer, node.InboundTag}]
	if !ok {
		// OriginalServer 为空或与凭据所在服务器名不一致时(常见于外部中转 / 手动创建、host 未命中
		// 已注册服务器的节点 → enforceLicenseIfNodeHostMatchesServer 不 claim → OriginalServer 留空),
		// 按 inbound_tag 唯一匹配兜底 —— 与 provisioning(resolveNodeServer 的 inbound_tag 兜底)对齐。
		// 否则订阅静默回退到节点自带的基础凭据(创建者/admin),导致 per-user 统计/限速失效、
		// 删号/解绑套餐后仍可连(用户订阅里用的根本不是自己的凭据,而是入站 base user 的)。
		credJSON, ok = credByInboundTagUnique(credMap, node.InboundTag)
		if !ok {
			return
		}
	}
	var cred map[string]any
	if err := json.Unmarshal([]byte(credJSON), &cred); err != nil {
		return
	}
	applyCredToProxy(proxy, node.Protocol, cred)
}

// credByInboundTagUnique 按 inbound_tag 在(某用户的)credMap 里兜底查凭据:恰好命中一个条目才返回。
// credMap 是 per-user 的,故命中即该用户在某服务器该入站的凭据;命中多个(同 tag 分布在多台服务器,
// 歧义)则放弃兜底,交由 {server,tag} 精确匹配处理,绝不乱套到别的服务器凭据。
func credByInboundTagUnique(credMap map[credKey]string, inboundTag string) (string, bool) {
	var found string
	n := 0
	for k, v := range credMap {
		if k.inboundTag == inboundTag {
			found = v
			n++
			if n > 1 {
				return "", false
			}
		}
	}
	return found, n == 1
}

// applyCredToProxy 按协议把用户凭据(cred = credential_json 解析结果)写进 clash proxy 的对应字段。
// 物理节点(applyUserCredentials)和 routed 节点(buildRoutedProxyForUser)共用,避免协议分支两处维护
// 不一致(历史 bug:routed 只覆盖了 uuid,导致 SS/Trojan/HY2 保留创建者凭据)。
func applyCredToProxy(proxy map[string]any, protocol string, cred map[string]any) {
	switch protocol {
	case "vless", "vmess":
		if id, ok := cred["id"].(string); ok && id != "" {
			proxy["uuid"] = id
		}
	case "ss", "shadowsocks":
		if userPass, ok := cred["password"].(string); ok && userPass != "" {
			if nodePass, ok := proxy["password"].(string); ok && nodePass != "" {
				// 仅 SS2022 需要 "master:userPass" 双段拼接(老 SS 单段密码不该改)。
				cipher, _ := proxy["cipher"].(string)
				if strings.HasPrefix(cipher, "2022-") {
					// 兜底:存量 clash_config 可能还是老格式 "master:firstClient" — 剥掉冒号后段,
					// 只保留 master,再拼当前用户密码,得到正确的两段。新节点直接 nodePass 就是 master 一段。
					if idx := strings.Index(nodePass, ":"); idx >= 0 {
						nodePass = nodePass[:idx]
					}
					proxy["password"] = nodePass + ":" + userPass
				}
			}
		}
	case "trojan", "anytls":
		if password, ok := cred["password"].(string); ok && password != "" {
			proxy["password"] = password
		}
	case "snell":
		// Snell v4/v5:每用户 psk → clash snell 节点的 psk 字段(逐用户独立密钥)。
		if psk, ok := cred["psk"].(string); ok && psk != "" {
			proxy["psk"] = psk
		}
	case "mieru":
		// mieru:每用户 username+password → clash mieru 节点(逐用户独立凭据)。
		if username, ok := cred["username"].(string); ok && username != "" {
			proxy["username"] = username
		}
		if password, ok := cred["password"].(string); ok && password != "" {
			proxy["password"] = password
		}
	case "hysteria2", "hysteria", "hy2":
		// HY2 客户端凭据 auth → clash hysteria2 节点的 password 字段。
		if auth, ok := cred["auth"].(string); ok && auth != "" {
			proxy["password"] = auth
		}
	case "socks", "http":
		// socks5/http 入站每用户独立账号:credential_json 存 {user,pass}(见 generateCredential),
		// clash socks5/http 节点字段是 username/password(见 inboundToClashProxy)。
		// 缺这一分支时,订阅会保留节点自带的基础(创建者/admin)账号 → 用户拿到的是 admin 凭据。
		if user, ok := cred["user"].(string); ok && user != "" {
			proxy["username"] = user
		}
		if pass, ok := cred["pass"].(string); ok && pass != "" {
			proxy["password"] = pass
		}
	}
}

// buildRoutedProxyForUser 为某用户 + 某 routed 节点生成订阅条目:
//   - 取父物理节点的 ClashConfig 作为协议/streamSettings 模板
//   - 用 user_subaccounts.credential_json 里的 uuid 覆盖
//   - 节点名换成 routed 节点的 NodeName
//
// 返回 (proxy_map, true) 或 (nil, false)(用户未绑定子账号 / 未 active / 父节点不可用 → 跳过)。
func buildRoutedProxyForUser(ctx context.Context, repo *storage.TrafficRepository, routedNode storage.Node, username string) (map[string]any, bool) {
	// 子账号必须 is_active=1,否则该用户当前没有访问权(下线 / 未绑套餐 / 暂停)
	sa, err := repo.GetUserSubaccount(ctx, routedNode.ID, username)
	if err != nil || sa == nil || !sa.IsActive {
		return nil, false
	}

	// clash_config 来源优先级:
	//   1. 父节点的 clash_config(绑定到普通 inbound 物理节点的标准 routed)
	//   2. routed 节点自身的 clash_config(纯出站 server 场景:server 上没默认 inbound,
	//      同步入站时识别不出 parent,但 routed 节点入库时已克隆了完整可连配置)
	var clashJSON string
	if routedNode.ParentNodeID != nil && *routedNode.ParentNodeID > 0 {
		if parent, perr := repo.GetNodeByID(ctx, *routedNode.ParentNodeID); perr == nil && parent.Enabled && parent.ClashConfig != "" {
			clashJSON = parent.ClashConfig
		}
	}
	if clashJSON == "" && strings.TrimSpace(routedNode.ClashConfig) != "" {
		clashJSON = routedNode.ClashConfig
	}
	if clashJSON == "" {
		return nil, false
	}

	var proxy map[string]any
	if err := json.Unmarshal([]byte(clashJSON), &proxy); err != nil {
		return nil, false
	}
	// 按协议覆盖当前用户在该 routed 节点上的凭据(vless/vmess→uuid;ss→master:userPass;trojan→password;
	// hy2→auth)。此前只覆盖了 uuid,导致 SS/Trojan/HY2 保留了模板里创建者的凭据 → 用户串到创建者身份、
	// 匹配不到 routed 路由规则而走错出口。改用与物理节点一致的 applyCredToProxy。
	var cred map[string]any
	if err := json.Unmarshal([]byte(sa.CredentialJSON), &cred); err == nil {
		applyCredToProxy(proxy, routedNode.Protocol, cred)
	}
	proxy["name"] = routedNode.NodeName
	return proxy, true
}
