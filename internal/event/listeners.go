package event

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"

	"miaomiaowux/internal/storage"
)

// InboundToClashFunc 入站转 Clash 配置的函数类型
type InboundToClashFunc func(serverID int64, inbound map[string]any) (string, error)

// NodeSyncListener 节点同步监听器
type NodeSyncListener struct {
	repo           *storage.TrafficRepository
	inboundToClash InboundToClashFunc
}

// 创建节点同步监听器
func NewNodeSyncListener(repo *storage.TrafficRepository, converter InboundToClashFunc) *NodeSyncListener {
	return &NodeSyncListener{
		repo:           repo,
		inboundToClash: converter,
	}
}

// 处理入站事件
func (l *NodeSyncListener) Handle(event InboundEvent) {
	ctx := context.Background()

	switch event.Type {
	case EventInboundAdded:
		l.handleAdded(ctx, event)
	case EventInboundRemoved:
		l.handleRemoved(ctx, event)
	case EventInboundUpdated:
		l.handleUpdated(ctx, event)
	}
}

func (l *NodeSyncListener) handleAdded(ctx context.Context, event InboundEvent) {
	// 获取服务器信息
	server, err := l.repo.GetRemoteServer(ctx, event.ServerID)
	if err != nil {
		log.Printf("[NodeSync] Failed to get server %d: %v", event.ServerID, err)
		return
	}

	if event.Tag == "api" {
		return
	}
	// tunnel:默认跳过(不进节点表);但「转发已有节点」(ForwardNodeID>0)时,克隆源节点生成配套节点
	if event.Protocol == "tunnel" {
		if event.ForwardNodeID > 0 {
			l.createForwardTunnelNode(ctx, event, server)
		}
		return
	}

	// 生成节点名称：优先使用自定义名称，否则使用 tag 或 protocol:port
	var nodeName string
	if event.NodeName != "" {
		nodeName = event.NodeName
	} else if event.Tag != "" {
		nodeName = fmt.Sprintf("[%s] %s", server.Name, event.Tag)
	} else {
		nodeName = fmt.Sprintf("[%s] %s:%d", server.Name, event.Protocol, event.Port)
	}

	// 系统节点归属的 username(真实 admin,不是字面值 "admin")
	sysOwner := l.repo.GetSystemNodeOwner(ctx)

	// 转换为 Clash 配置
	clashConfig, err := l.inboundToClash(event.ServerID, event.Inbound)
	if err != nil {
		log.Printf("[NodeSync] Failed to convert inbound to clash: %v", err)
		return
	}
	// 自签证书:给 clash 节点加 skip-cert-verify(客户端跳过证书校验才能连自签证书)。
	if event.Insecure {
		clashConfig = withSkipCertVerify(clashConfig)
	}

	// 先扫所有"外部节点"(从 mmw 迁移过来的、original_server='' 的节点),
	// 按 server 地址(可能是 IP / Domain / PullAddress 之一)+ port + protocol 匹配,
	// 命中即把外部节点"升级"为受管节点(填上 original_server + inbound_tag),
	// 而不是新建一条重复节点。
	if matched := l.tryClaimExternalNode(ctx, server, event, clashConfig); matched {
		return
	}

	// 解析 clash 配置 — inboundToClash 已用 chooseClashServerHost 把 server 填成 v4 host
	// (Domain → PullAddress → IPv4)。
	var clashMap map[string]any
	if err := json.Unmarshal([]byte(clashConfig), &clashMap); err != nil {
		log.Printf("[NodeSync] Failed to parse clash config: %v", err)
		return
	}
	v4Host, _ := clashMap["server"].(string)
	// v6 节点 host:优先 v6 专用域名(DomainV6),否则 IPv6 字面地址
	v6Host := chooseClashServerHostV6(server)

	// 按 ip_version / 中转 决定要建哪些节点(name + clash server host + 可选 port 覆盖 + 中转原值 + IP 版本归属)
	type nodePlan struct {
		name          string
		host          string
		family        string // "v4"(v4/域名/中转/通用) | "v6"(IPv6 节点),写入 nodes.ip_family
		port          int    // >0 覆盖 clash port(中转用);0=沿用原 port
		relayOrigHost string // 非空=中转节点,记原服务器 host 到 relay_orig_server
		relayOrigPort int
	}
	var plans []nodePlan
	if relayHost := strings.TrimSpace(event.RelayServer); relayHost != "" {
		// 中转:单节点,clash server/port=中转地址;原服务器=v4Host + 原 clash 端口记到 relay_orig_*。
		// 中转优先,忽略 ip_version(中转是单一地址,不分 v4/v6)。
		origPort := clashPortOf(clashMap)
		relayPort := event.RelayPort
		if relayPort <= 0 {
			relayPort = origPort // 端口默认填节点端口
		}
		plans = []nodePlan{{name: nodeName, host: relayHost, family: "v4", port: relayPort, relayOrigHost: v4Host, relayOrigPort: origPort}}
	} else {
		switch event.IPVersion {
		case "v6":
			// 勾 v6:用 v6 域名 / IPv6 字面地址
			if v6Host == "" {
				log.Printf("[NodeSync] server %s 无 IPv6,ip_version=v6 跳过创建", server.Name)
				return
			}
			plans = []nodePlan{{name: nodeName, host: v6Host, family: "v6"}}
		case "both":
			plans = []nodePlan{{name: nodeName, host: v4Host, family: "v4"}}
			if v6Host != "" {
				plans = append(plans, nodePlan{name: nodeName + "(v6)", host: v6Host, family: "v6"})
			} else {
				log.Printf("[NodeSync] server %s 无 IPv6,both 退化为仅 v4", server.Name)
			}
		default: // "" / "v4" —— 现状行为
			plans = []nodePlan{{name: nodeName, host: v4Host, family: "v4"}}
		}
	}

	// admin 已同步过的同 server 节点(按 server-host + protocol + port 去重)
	existingNodes, _ := l.repo.ListNodes(ctx, sysOwner)
	// 已占用的节点名集合 —— 撞名(不同物理节点碰巧同名)时用 UniqueNodeName 加后缀,保证订阅侧 proxy name 唯一
	takenNames := make(map[string]bool, len(existingNodes))
	for _, n := range existingNodes {
		takenNames[n.NodeName] = true
	}

	for _, p := range plans {
		// 真重复(同 server-host + protocol + port)才 skip —— 带上 host,避免「both」时 v4/v6 同 proto+port 互相误杀
		if nodeWithHostProtoPortExists(existingNodes, server.Name, p.host, event.Protocol, event.Port) {
			log.Printf("[NodeSync] Node with same host/protocol/port exists, skip: %s @ %s", p.name, p.host)
			continue
		}
		// 撞名但物理坐标不同(如同名的 VLESS / HY2)→ 加协议后缀,而不是丢弃
		name := storage.UniqueNodeName(p.name, event.Protocol, takenNames)

		cfg, err := cloneClashWithServerPort(clashMap, name, p.host, p.port)
		if err != nil {
			log.Printf("[NodeSync] Failed to build clash config for %s: %v", name, err)
			continue
		}
		node := storage.Node{
			Username:       sysOwner,
			NodeName:       name,
			Protocol:       event.Protocol,
			ClashConfig:    cfg,
			ParsedConfig:   cfg,
			Enabled:        true,
			Tag:            fmt.Sprintf("远程:%s", server.Name),
			OriginalServer: server.Name,
			InboundTag:     event.Tag,
			IPFamily:       p.family,
		}
		if p.relayOrigHost != "" {
			node.RelayOrigServer = p.relayOrigHost
			node.RelayOrigPort = p.relayOrigPort
		}
		created, err := l.repo.CreateNode(ctx, node)
		if err != nil {
			log.Printf("[NodeSync] Failed to create node %s: %v", name, err)
			continue
		}
		takenNames[name] = true
		log.Printf("[NodeSync] Created node: %s", name)
		l.prependNodeOrder(ctx, sysOwner, created.ID)
	}
}

// chooseClashServerHostV6 返回 IPv6 节点的 clash server host:优先用 v6 专用域名(DomainV6),
// 否则回落到 IPv6 字面地址(IPAddressV6)。两者都空 → 返回空(该 server 无 v6,跳过建 v6 节点)。
//
// 锁定入口 IP 时:忽略域名/DDNS/v6,v6 节点同样只用手填的「服务器地址」(PullAddress→IPAddress),
// 与 handler 层 chooseClashServerHost 的锁定分支保持一致 —— NAT 机的动态出口 IPv6 连不上。
func chooseClashServerHostV6(server *storage.RemoteServer) string {
	if server.LockEntryIP {
		if p := strings.TrimSpace(server.PullAddress); p != "" {
			return p
		}
		return strings.TrimSpace(server.IPAddress)
	}
	if d := strings.TrimSpace(server.DomainV6); d != "" {
		return d
	}
	return strings.TrimSpace(server.IPAddressV6)
}

// cloneClashWithServer 浅拷贝 clash proxy map,覆盖顶层 name 与 server,返回 JSON。
// clash proxy 是扁平对象(server/name/port/type/uuid... 均顶层),浅拷贝足够 —— 只改顶层键,
// 不触碰 ws-opts/reality-opts 等嵌套结构,两节点共享嵌套引用也安全。
func cloneClashWithServer(clashMap map[string]any, name, serverHost string) (string, error) {
	return cloneClashWithServerPort(clashMap, name, serverHost, 0)
}

// cloneClashWithServerPort 同 cloneClashWithServer,额外在 port>0 时覆盖顶层 port(中转用)。
func cloneClashWithServerPort(clashMap map[string]any, name, serverHost string, port int) (string, error) {
	cp := make(map[string]any, len(clashMap))
	for k, v := range clashMap {
		cp[k] = v
	}
	cp["name"] = name
	cp["server"] = serverHost
	if port > 0 {
		cp["port"] = port
	}
	b, err := json.Marshal(cp)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// withSkipCertVerify 给 clash proxy JSON 顶层加 skip-cert-verify=true(自签证书客户端跳过校验)。
func withSkipCertVerify(clashJSON string) string {
	var m map[string]any
	if json.Unmarshal([]byte(clashJSON), &m) != nil {
		return clashJSON
	}
	m["skip-cert-verify"] = true
	b, err := json.Marshal(m)
	if err != nil {
		return clashJSON
	}
	return string(b)
}

// clashPortOf 从 clash proxy map 读出顶层 port(float64/int 兼容),取不到返回 0。
func clashPortOf(m map[string]any) int {
	switch v := m["port"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

// nodeWithHostProtoPortExists 判断 existing 中是否已有 同 server名 + 同 clash server host + 同协议 + 同端口 的节点。
func nodeWithHostProtoPortExists(existing []storage.Node, serverName, host, protocol string, port int) bool {
	for _, n := range existing {
		if n.OriginalServer != serverName {
			continue
		}
		var cfg map[string]any
		if err := json.Unmarshal([]byte(n.ClashConfig), &cfg); err != nil {
			continue
		}
		if h, _ := cfg["server"].(string); h != host {
			continue
		}
		if proto, _ := cfg["type"].(string); !protocolEquivalent(proto, protocol) {
			continue
		}
		var p int
		switch v := cfg["port"].(type) {
		case float64:
			p = int(v)
		case int:
			p = v
		}
		if p == port {
			return true
		}
	}
	return false
}

// prependNodeOrder 把新节点 ID 放到用户节点排序表最前面(去重)——
// 用户拖过顺序后直接 append 会把新节点甩到底部,不直观。
func (l *NodeSyncListener) prependNodeOrder(ctx context.Context, owner string, nodeID int64) {
	settings, err := l.repo.GetUserSettings(ctx, owner)
	if err != nil {
		return
	}
	filtered := make([]int64, 0, len(settings.NodeOrder)+1)
	filtered = append(filtered, nodeID)
	for _, id := range settings.NodeOrder {
		if id != nodeID {
			filtered = append(filtered, id)
		}
	}
	settings.NodeOrder = filtered
	if err := l.repo.UpsertUserSettings(ctx, settings); err != nil {
		log.Printf("[NodeSync] prepend new node to node_order failed: %v", err)
	}
}

// createForwardTunnelNode 为「转发已有节点」生成的 tunnel 创建配套节点:
// 配置克隆源节点,但 name 拼接 " | Tunnel"、server 改为 tunnel 服务器 IP、port 改为 tunnel 监听端口、
// inbound_tag = tunnel tag、original_server = tunnel 服务器名(便于管理/删除时定位)。
func (l *NodeSyncListener) createForwardTunnelNode(ctx context.Context, event InboundEvent, server *storage.RemoteServer) {
	src, err := l.repo.GetNodeByID(ctx, event.ForwardNodeID)
	if err != nil {
		log.Printf("[NodeSync] forward-tunnel: 源节点 %d 不存在: %v", event.ForwardNodeID, err)
		return
	}
	// 与 syncInboundsToNodes / InboundToClashProxyByServerID 同优先序:
	// Domain → 非私有 PullAddress → IPAddress;不能用 chooseClashServerHost(在 handler 包,跨包麻烦)就内联一遍
	serverHost := strings.TrimSpace(server.Domain)
	if serverHost == "" {
		if p := strings.TrimSpace(server.PullAddress); p != "" {
			if ip := net.ParseIP(p); ip == nil || (!ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()) {
				serverHost = p
			}
		}
	}
	if serverHost == "" {
		serverHost = strings.TrimSpace(server.IPAddress)
	}
	if serverHost == "" {
		log.Printf("[NodeSync] forward-tunnel: 服务器 %s 无 IP/域名,跳过", server.Name)
		return
	}

	sysOwner := l.repo.GetSystemNodeOwner(ctx)
	// 撞名(如源节点已有同名 Tunnel 配套)→ 加协议后缀保证唯一,而不是丢弃
	existingNodes, _ := l.repo.ListNodes(ctx, sysOwner)
	takenNames := make(map[string]bool, len(existingNodes))
	for _, n := range existingNodes {
		takenNames[n.NodeName] = true
	}
	nodeName := storage.UniqueNodeName(src.NodeName+" | Tunnel", src.Protocol, takenNames)

	// 克隆源节点 clash 配置,改 name/server/port(端口取 tunnel 监听端口)
	var clashMap map[string]any
	if err := json.Unmarshal([]byte(src.ClashConfig), &clashMap); err != nil {
		log.Printf("[NodeSync] forward-tunnel: 解析源节点 clash 配置失败: %v", err)
		return
	}
	clashMap["name"] = nodeName
	clashMap["server"] = server.IPAddress
	clashMap["port"] = event.Port
	clashJSON, err := json.Marshal(clashMap)
	if err != nil {
		log.Printf("[NodeSync] forward-tunnel: 序列化 clash 配置失败: %v", err)
		return
	}

	node := storage.Node{
		Username:       sysOwner,
		NodeName:       nodeName,
		Protocol:       src.Protocol,
		ClashConfig:    string(clashJSON),
		ParsedConfig:   string(clashJSON),
		Enabled:        true,
		Tag:            fmt.Sprintf("远程:%s", server.Name),
		OriginalServer: server.Name,
		InboundTag:     event.Tag,
	}
	if _, err := l.repo.CreateNode(ctx, node); err != nil {
		log.Printf("[NodeSync] forward-tunnel: 创建配套节点失败: %v", err)
	} else {
		log.Printf("[NodeSync] forward-tunnel: 已创建配套节点: %s (-> %s:%d)", nodeName, server.IPAddress, event.Port)
	}
}

// protocolEquivalent 判断 clash type 与 xray protocol 是否同一种协议。
// clash 用 `type: ss`,xray 用 `protocol: shadowsocks`,其他名字一致。
func protocolEquivalent(clashType, xrayProtocol string) bool {
	a := strings.ToLower(strings.TrimSpace(clashType))
	b := strings.ToLower(strings.TrimSpace(xrayProtocol))
	if a == b {
		return true
	}
	norm := func(s string) string {
		if s == "ss" {
			return "shadowsocks"
		}
		return s
	}
	return norm(a) == norm(b)
}

// tryClaimExternalNode 扫所有"外部节点"(original_server=” 且 inbound_tag=”),
// 看是否有节点的 clash_config 指向 (server 的 IP/Domain/PullAddress 之一) + 同 port + 同 protocol,
// 命中即把该节点 UPDATE 为受管节点(填上 original_server + inbound_tag),返回 true。
// 这避免迁移场景下:mmw 原有节点 + agent 扫描新创建节点 → 重复 2 条节点的问题。
func (l *NodeSyncListener) tryClaimExternalNode(ctx context.Context, server *storage.RemoteServer, event InboundEvent, agentClashConfig string) bool {
	// 候选地址:能让外部节点 server 字段命中该 remote_server 的所有可能形式
	candidates := map[string]bool{}
	for _, a := range []string{server.IPAddress, server.Domain, server.PullAddress} {
		if strings.TrimSpace(a) != "" {
			candidates[a] = true
		}
	}
	if len(candidates) == 0 {
		return false
	}

	allNodes, err := l.repo.ListAllNodes(ctx)
	if err != nil {
		log.Printf("[NodeSync] tryClaimExternalNode: list all nodes failed: %v", err)
		return false
	}
	for _, n := range allNodes {
		// 只看"外部节点":没关联 server / inbound,且不是 routed 子节点
		if strings.TrimSpace(n.OriginalServer) != "" || strings.TrimSpace(n.InboundTag) != "" {
			continue
		}
		if n.NodeType == "routed" {
			continue
		}
		var cfg map[string]any
		if err := json.Unmarshal([]byte(n.ClashConfig), &cfg); err != nil {
			continue
		}
		srv, _ := cfg["server"].(string)
		if !candidates[srv] {
			continue
		}
		var port int
		switch p := cfg["port"].(type) {
		case float64:
			port = int(p)
		case int:
			port = p
		}
		if port != event.Port {
			continue
		}
		proto, _ := cfg["type"].(string)
		if !protocolEquivalent(proto, event.Protocol) {
			continue
		}

		// 命中:更新该节点
		log.Printf("[NodeSync] Claim external node id=%d name=%q for %s/%s:%d", n.ID, n.NodeName, server.Name, event.Protocol, event.Port)
		// 用 agent 转出来的 clash_config 替换,但保留原节点名(用户可能改过中文名)
		var newCfg map[string]any
		if err := json.Unmarshal([]byte(agentClashConfig), &newCfg); err == nil {
			if name, _ := cfg["name"].(string); name != "" {
				newCfg["name"] = name
			}
			if updated, err := json.Marshal(newCfg); err == nil {
				agentClashConfig = string(updated)
			}
		}
		if err := l.repo.ClaimExternalNode(ctx, n.ID, server.Name, event.Tag, fmt.Sprintf("远程:%s", server.Name), agentClashConfig); err != nil {
			log.Printf("[NodeSync] ClaimExternalNode failed: %v", err)
			return false
		}
		return true
	}
	return false
}

func (l *NodeSyncListener) handleRemoved(ctx context.Context, event InboundEvent) {
	server, err := l.repo.GetRemoteServer(ctx, event.ServerID)
	if err != nil {
		log.Printf("[NodeSync] Failed to get server %d: %v", event.ServerID, err)
		return
	}

	// 删除对应节点
	if _, err := l.repo.DeleteNodesByInboundTag(ctx, server.Name, event.Tag); err != nil {
		log.Printf("[NodeSync] Failed to delete nodes: %v", err)
	} else {
		log.Printf("[NodeSync] Deleted nodes for inbound: %s/%s", server.Name, event.Tag)
	}
}

func (l *NodeSyncListener) handleUpdated(ctx context.Context, event InboundEvent) {
	server, err := l.repo.GetRemoteServer(ctx, event.ServerID)
	if err != nil {
		log.Printf("[NodeSync] Failed to get server %d: %v", event.ServerID, err)
		return
	}

	clashConfig, err := l.inboundToClash(event.ServerID, event.Inbound)
	if err != nil {
		log.Printf("[NodeSync] Failed to convert inbound to clash: %v", err)
		return
	}
	// 自签证书:给 clash 节点加 skip-cert-verify(客户端跳过证书校验才能连自签证书)。
	if event.Insecure {
		clashConfig = withSkipCertVerify(clashConfig)
	}

	// 中转:该 (server,tag) 下若存在中转节点 —— 本次编辑新填了中转地址,或节点本就配了中转 ——
	// 必须把重生成的配置改写成中转地址(而非源站 host)后全量更新。否则:
	//   1. 编辑时新增中转不生效(节点仍是源站配置)—— 用户报告的问题;
	//   2. 编辑已配中转的节点(改协议/安全,中转字段空)会把中转地址冲回源站。
	// 下面基于 chooseClashServerHost 的 v4/v6 更新只对「非中转」节点生效。
	if l.applyRelayNodesOnUpdate(ctx, server.Name, event, clashConfig) {
		log.Printf("[NodeSync] Updated relay node(s) for inbound: %s/%s", server.Name, event.Tag)
	}
	// Update physical nodes one by one so an omitted/blank node_name cannot
	// replace a user's saved name with the converter's generated default. This
	// also avoids one relay sibling preventing non-relay v4/v6 siblings from
	// being refreshed.
	l.updatePhysicalNodesPreservingNames(ctx, server, event.Tag, clashConfig)
	l.refreshRoutedChildrenAfterInboundUpdate(ctx, server.Name, event.Tag)
	log.Printf("[NodeSync] Updated node(s) for inbound: %s/%s", server.Name, event.Tag)
}

func (l *NodeSyncListener) updatePhysicalNodesPreservingNames(ctx context.Context, server *storage.RemoteServer, inboundTag, baseClash string) {
	nodes, err := l.repo.ListAllNodes(ctx)
	if err != nil {
		log.Printf("[NodeSync] Failed to list nodes while preserving names: %v", err)
		return
	}
	var base map[string]any
	if err := json.Unmarshal([]byte(baseClash), &base); err != nil {
		log.Printf("[NodeSync] Failed to parse updated clash config: %v", err)
		return
	}
	for _, node := range nodes {
		if node.NodeType == "routed" || node.OriginalServer != server.Name || node.InboundTag != inboundTag {
			continue
		}
		if strings.TrimSpace(node.RelayOrigServer) != "" {
			continue // applyRelayNodesOnUpdate already handled this node.
		}
		host, _ := base["server"].(string)
		if strings.EqualFold(strings.TrimSpace(node.IPFamily), "v6") {
			host = chooseClashServerHostV6(server)
			if host == "" {
				continue
			}
		}
		cfg, err := cloneClashWithServer(base, node.NodeName, host)
		if err != nil {
			log.Printf("[NodeSync] Failed to preserve node %d name: %v", node.ID, err)
			continue
		}
		if err := l.repo.UpdateNodeProxyConfigs(ctx, node.ID, cfg, cfg); err != nil {
			log.Printf("[NodeSync] Failed to update physical node %d: %v", node.ID, err)
		}
	}
}

func (l *NodeSyncListener) refreshRoutedChildrenAfterInboundUpdate(ctx context.Context, serverName, inboundTag string) {
	nodes, err := l.repo.ListAllNodes(ctx)
	if err != nil {
		return
	}
	for _, parent := range nodes {
		if parent.NodeType == "routed" || parent.OriginalServer != serverName || parent.InboundTag != inboundTag {
			continue
		}
		children, err := l.repo.ListRoutedNodesByParent(ctx, parent.ID)
		if err != nil {
			continue
		}
		for _, child := range children {
			var credential map[string]interface{}
			if json.Unmarshal([]byte(child.RoutedAdminCredential), &credential) != nil {
				continue
			}
			// 每个物理父节点可能分别是 v4、v6 或中转节点。必须基于该父节点刚刚
			// 更新后的实际配置重建，不能统一套用事件里的 v4 基础配置。
			clash := cloneClashWithCredentialForUpdate(parent.ClashConfig, parent.Protocol, credential, child.NodeName)
			if err := l.repo.UpdateRoutedNodeProxyConfigs(ctx, child.ID, parent.ParsedConfig, clash, parent.Protocol); err != nil {
				log.Printf("[NodeSync] update routed child %d after inbound edit failed: %v", child.ID, err)
			}
		}
	}
}

func cloneClashWithCredentialForUpdate(base, protocol string, cred map[string]interface{}, name string) string {
	var cfg map[string]interface{}
	if json.Unmarshal([]byte(base), &cfg) != nil {
		return base
	}
	cfg["name"] = name
	switch strings.ToLower(protocol) {
	case "vless", "vmess":
		cfg["uuid"] = cred["id"]
	case "trojan", "anytls":
		cfg["password"] = cred["password"]
	case "hysteria", "hysteria2", "hy2":
		cfg["password"] = cred["auth"]
	case "snell":
		cfg["psk"] = cred["psk"]
	case "shadowsocks", "ss":
		if userPass := strings.TrimSpace(fmt.Sprint(cred["password"])); userPass != "" && userPass != "<nil>" {
			master := strings.TrimSpace(fmt.Sprint(cfg["password"]))
			if i := strings.Index(master, ":"); i >= 0 {
				master = master[:i]
			}
			cfg["password"] = master + ":" + userPass
		}
	case "socks", "socks5", "http":
		cfg["username"] = cred["user"]
		cfg["password"] = cred["pass"]
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return base
	}
	return string(out)
}

// applyRelayNodesOnUpdate 处理「编辑入站时的中转节点」:该 (serverName, tag) 下若有中转节点
// (event 本次新填了 RelayServer,或节点已有 relay_orig_server),就用重生成的入站配置
// (协议/传输/安全已更新)但把 server/port 改写成中转地址、把源服务器地址记回 relay_orig_*,
// 逐节点全量更新。返回 true 表示已按中转处理完(调用方 return,不再走普通 v4/v6 更新)。
//
// 走全量 UpdateNode 而非 UpdateNodeByInboundTag,是因为后者只改 clash/parsed_config、不写 relay_orig_*。
func (l *NodeSyncListener) applyRelayNodesOnUpdate(ctx context.Context, serverName string, event InboundEvent, regenClash string) bool {
	newRelay := strings.TrimSpace(event.RelayServer)

	// regenClash 的 server/port 就是 inboundToClash 用 chooseClashServerHost 填的源站地址。
	var m map[string]any
	if json.Unmarshal([]byte(regenClash), &m) != nil {
		return false
	}
	origHost, _ := m["server"].(string)
	origPort := clashPortOf(m)

	sysOwner := l.repo.GetSystemNodeOwner(ctx)
	nodes, err := l.repo.ListNodes(ctx, sysOwner)
	if err != nil {
		return false
	}

	handled := false
	for _, n := range nodes {
		if n.OriginalServer != serverName || n.InboundTag != event.Tag {
			continue
		}
		if n.NodeType == "routed" {
			continue // 子节点在父节点完成后按各自凭据统一重建
		}
		if newRelay == "" && strings.TrimSpace(n.RelayOrigServer) == "" {
			continue // 该节点不是中转,交给普通 v4/v6 更新
		}

		// 中转地址:优先本次新填;否则沿用节点当前的中转(其当前 clash server/port 即中转地址)。
		relayHost := newRelay
		relayPort := event.RelayPort
		if relayHost == "" {
			if s, p, ok := clashServerPortOf(n.ClashConfig); ok {
				relayHost, relayPort = s, p
			}
		}
		if relayPort <= 0 {
			relayPort = origPort // 端口默认填源站(节点)端口
		}

		cfg, cerr := cloneClashWithServerPort(m, n.NodeName, relayHost, relayPort)
		if cerr != nil {
			continue
		}
		n.ClashConfig = cfg
		n.ParsedConfig = cfg
		n.RelayOrigServer = origHost
		n.RelayOrigPort = origPort
		if _, uerr := l.repo.UpdateNode(ctx, n); uerr != nil {
			log.Printf("[NodeSync] Failed to update relay node %s: %v", n.NodeName, uerr)
			continue
		}
		handled = true
	}
	return handled
}

// clashServerPortOf 从 clash proxy JSON 读出顶层 server 与 port,取不到 server 返回 ok=false。
func clashServerPortOf(cfgJSON string) (string, int, bool) {
	var m map[string]any
	if json.Unmarshal([]byte(cfgJSON), &m) != nil {
		return "", 0, false
	}
	s, ok := m["server"].(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", 0, false
	}
	return s, clashPortOf(m), true
}
