package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"miaomiaowux/internal/logger"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"miaomiaowux/internal/storage"

	"github.com/MMWOrg/mmwX-plugins/proxyparser"
	"gopkg.in/yaml.v3"
)

// GeoIP 缓存和 API 配置
const ipInfoToken = "cddae164b36656"

type geoIPResponse struct {
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
}

var geoIPCache = sync.Map{} // 地图[字符串]字符串（ip -> 国家/地区代码）

// 订阅内容缓存（5分钟过期）
const subscriptionCacheTTL = 5 * time.Minute

// 拉取外部订阅时的单次读取上限,防超大 body OOM(订阅内容通常 <几 MB)
const maxSubscriptionBytes = 50 << 20 // 50MB

type subscriptionCacheEntry struct {
	content   []byte
	fetchedAt time.Time
}

var subscriptionCache = sync.Map{} // map[string]*subscriptionCacheEntry (url -> 条目)

// 失效指定URL的订阅内容缓存
func InvalidateSubscriptionContentCache(url string) {
	subscriptionCache.Delete(url)
}

// 查询 IP 的国家代码
func getGeoIPCountryCode(ipOrHost string) string {
	if ipOrHost == "" {
		return ""
	}

	// 如果是域名，先解析为 IP
	ip := ipOrHost
	if net.ParseIP(ipOrHost) == nil {
		// 是域名，需要解析
		ips, err := net.LookupIP(ipOrHost)
		if err != nil || len(ips) == 0 {
			logger.Info("[GeoIP] 域名解析失败", "domain", ipOrHost, "error", err)
			return ""
		}
		ip = ips[0].String()
	}

	// 检查缓存
	if cached, ok := geoIPCache.Load(ip); ok {
		return cached.(string)
	}

	// 查询 API
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://api.ipinfo.io/lite/%s?token=%s", ip, ipInfoToken))
	if err != nil {
		logger.Info("[GeoIP] IP查询失败", "ip", ip, "error", err)
		// 缓存空结果避免重复查询
		geoIPCache.Store(ip, "")
		return ""
	}
	defer resp.Body.Close()

	var result geoIPResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Info("[GeoIP] 响应解析失败", "ip", ip, "error", err)
		geoIPCache.Store(ip, "")
		return ""
	}

	// 缓存结果
	countryCode := strings.ToUpper(result.CountryCode)
	geoIPCache.Store(ip, countryCode)
	logger.Info("[GeoIP] IP地理位置查询成功", "ip", ip, "country", countryCode)
	return countryCode
}

// 通过缓存获取订阅内容（5 分钟 TTL）
func fetchSubscriptionContent(sub *storage.ExternalSubscription) ([]byte, error) {
	cacheKey := sub.URL

	// 检查缓存
	if cached, ok := subscriptionCache.Load(cacheKey); ok {
		entry := cached.(*subscriptionCacheEntry)
		if time.Since(entry.fetchedAt) < subscriptionCacheTTL {
			logger.Info("[SubscriptionCache] 缓存命中", "url", sub.URL)
			return entry.content, nil
		}
		// 缓存过期，删除
		subscriptionCache.Delete(cacheKey)
	}

	logger.Info("[SubscriptionCache] 缓存未命中，正在拉取", "url", sub.URL)

	// SSRF 防护:sub.URL 来自 DB(用户创建的外部订阅),拉取前校验并用安全客户端拒绝内网/云元数据地址。
	if verr := validateFetchURL(sub.URL); verr != nil {
		return nil, verr
	}
	// 拉取订阅内容
	client := newSSRFSafeHTTPClient(30 * time.Second)
	req, err := http.NewRequest(http.MethodGet, sub.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	userAgent := sub.UserAgent
	if userAgent == "" {
		userAgent = "clash-meta/2.4.0"
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch subscription: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// 限制读取大小,防恶意/故障订阅源返回超大 body 触发 OOM(订阅内容通常 <几 MB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSubscriptionBytes))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	// 存入缓存
	subscriptionCache.Store(cacheKey, &subscriptionCacheEntry{
		content:   body,
		fetchedAt: time.Now(),
	})

	return body, nil
}

// preprocessSubscriptionContent 预处理订阅内容。
// URI 解析与内容类型检测统一委托给共享 module proxyparser。
// YAML 的实际解析仍由本地完成（module 不依赖 yaml）。
func preprocessSubscriptionContent(content []byte) ([]byte, error) {
	if proxies, ok := parseCompatibleURIList(string(content)); ok {
		logger.Info("[预处理] 检测到 URI 列表，经严格兼容解析", "count", len(proxies))
		out, mErr := yaml.Marshal(map[string]any{"proxies": proxies})
		if mErr != nil {
			return nil, fmt.Errorf("URI 列表转 YAML 失败: %w", mErr)
		}
		return out, nil
	}
	proxies, kind, decoded, err := proxyparser.Preprocess(content)
	if err != nil {
		return nil, err
	}
	switch kind {
	case proxyparser.ContentURIList:
		logger.Info("[预处理] 检测到 URI 列表，经 proxyparser 解析", "count", len(proxies))
		out, mErr := yaml.Marshal(map[string]any{"proxies": proxies})
		if mErr != nil {
			return nil, fmt.Errorf("URI 列表转 YAML 失败: %w", mErr)
		}
		return out, nil
	case proxyparser.ContentHTML:
		logger.Info("[预处理] 检测到 HTML 内容，跳过")
		return content, nil
	case proxyparser.ContentClashYAML:
		return decoded, nil
	default:
		return decoded, nil
	}
}

// 查找 YAML 文档中的代理节点
func findProxiesNode(root *yaml.Node) *yaml.Node {
	if root == nil {
		return nil
	}

	// 处理文档节点
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		return findProxiesNode(root.Content[0])
	}

	// 句柄映射节点
	if root.Kind == yaml.MappingNode {
		for i := 0; i < len(root.Content)-1; i += 2 {
			keyNode := root.Content[i]
			valueNode := root.Content[i+1]
			if keyNode.Kind == yaml.ScalarNode && keyNode.Value == "proxies" {
				return valueNode
			}
		}
	}

	return nil
}

// 获取订阅内容并返回所有节点名称
func fetchSubscriptionNodeNames(sub *storage.ExternalSubscription) ([]string, error) {
	// 获取订阅内容（带缓存）
	body, err := fetchSubscriptionContent(sub)
	if err != nil {
		return nil, err
	}

	// 预处理内容（处理base64编码）
	body, err = preprocessSubscriptionContent(body)
	if err != nil {
		return nil, fmt.Errorf("preprocess subscription content: %w", err)
	}

	// 解析 YAML 内容
	var rootNode yaml.Node
	if err := yaml.Unmarshal(body, &rootNode); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	// 查找代理节点
	proxiesNode := findProxiesNode(&rootNode)
	if proxiesNode == nil || proxiesNode.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("no proxies found in subscription")
	}

	// 提取节点名称
	var nodeNames []string
	for _, proxyNode := range proxiesNode.Content {
		if proxyNode.Kind != yaml.MappingNode {
			continue
		}

		// 找到“姓名”字段
		for i := 0; i < len(proxyNode.Content)-1; i += 2 {
			keyNode := proxyNode.Content[i]
			valueNode := proxyNode.Content[i+1]
			if keyNode.Kind == yaml.ScalarNode && keyNode.Value == "name" && valueNode.Kind == yaml.ScalarNode {
				nodeNames = append(nodeNames, valueNode.Value)
				break
			}
		}
	}

	return nodeNames, nil
}

// NodeInfo 节点信息（名称和服务器地址）
type NodeInfo struct {
	Name   string `json:"name"`
	Server string `json:"server"`
}

// 获取订阅内容并返回带有名称和服务器的所有节点
func fetchSubscriptionNodes(sub *storage.ExternalSubscription) ([]NodeInfo, error) {
	// 获取订阅内容（带缓存）
	body, err := fetchSubscriptionContent(sub)
	if err != nil {
		return nil, err
	}

	// 预处理内容（处理base64编码）
	body, err = preprocessSubscriptionContent(body)
	if err != nil {
		return nil, fmt.Errorf("preprocess subscription content: %w", err)
	}

	// 解析 YAML 内容
	var rootNode yaml.Node
	if err := yaml.Unmarshal(body, &rootNode); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	// 查找代理节点
	proxiesNode := findProxiesNode(&rootNode)
	if proxiesNode == nil || proxiesNode.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("no proxies found in subscription")
	}

	// 提取节点信息（名称和服务器）
	var nodes []NodeInfo
	for _, proxyNode := range proxiesNode.Content {
		if proxyNode.Kind != yaml.MappingNode {
			continue
		}

		node := NodeInfo{}
		for i := 0; i < len(proxyNode.Content)-1; i += 2 {
			keyNode := proxyNode.Content[i]
			valueNode := proxyNode.Content[i+1]
			if keyNode.Kind == yaml.ScalarNode && valueNode.Kind == yaml.ScalarNode {
				switch keyNode.Value {
				case "name":
					node.Name = valueNode.Value
				case "server":
					node.Server = valueNode.Value
				}
			}
		}
		if node.Name != "" {
			nodes = append(nodes, node)
		}
	}

	return nodes, nil
}

// checkFilterMatches 检查过滤器/排除过滤器/geo-ip-过滤器是否与任何节点匹配
// 返回匹配节点的数量
func checkFilterMatches(sub *storage.ExternalSubscription, filter, excludeFilter, geoIPFilter string) (int, error) {
	// 获取节点
	nodes, err := fetchSubscriptionNodes(sub)
	if err != nil {
		return 0, err
	}

	logger.Info("[checkFilterMatches] 订阅节点信息", "sub_name", sub.Name, "node_count", len(nodes), "filter", filter, "exclude_filter", excludeFilter, "geo_ip_filter", geoIPFilter)

	// 编译正则表达式
	var filterRegex, excludeRegex *regexp.Regexp

	if filter != "" {
		filterRegex, err = regexp.Compile(filter)
		if err != nil {
			logger.Info("[checkFilterMatches] 无效的过滤正则表达式", "error", err)
			return 0, fmt.Errorf("invalid filter regex: %w", err)
		}
	}

	if excludeFilter != "" {
		excludeRegex, err = regexp.Compile(excludeFilter)
		if err != nil {
			logger.Info("[checkFilterMatches] 无效的排除过滤正则表达式", "error", err)
			return 0, fmt.Errorf("invalid exclude-filter regex: %w", err)
		}
	}

	// 构建 GeoIP 过滤国家代码地图
	geoIPCountryCodes := make(map[string]bool)
	if geoIPFilter != "" {
		for _, code := range strings.Split(geoIPFilter, ",") {
			geoIPCountryCodes[strings.TrimSpace(strings.ToUpper(code))] = true
		}
	}

	// 计算匹配节点数
	matchCount := 0
	for _, node := range nodes {
		// 首先应用排除过滤器（删除匹配的名称）
		if excludeRegex != nil && excludeRegex.MatchString(node.Name) {
			continue
		}

		// 应用过滤器和 GeoIP 匹配
		if filterRegex != nil {
			if filterRegex.MatchString(node.Name) {
				// 节点名称与过滤器正则表达式匹配，计算它
				matchCount++
				continue
			}

			// 节点名称不匹配，请检查 GeoIP（如果可用）
			if len(geoIPCountryCodes) > 0 && node.Server != "" {
				countryCode := getGeoIPCountryCode(node.Server)
				if countryCode != "" && geoIPCountryCodes[countryCode] {
					// IP位置匹配，统计一下
					matchCount++
					continue
				}
			}
			// 正则表达式和 GeoIP 都不匹配，跳过此节点
			continue
		}

		// 没有过滤器正则表达式，只有 GeoIP 过滤器
		if len(geoIPCountryCodes) > 0 {
			if node.Server != "" {
				countryCode := getGeoIPCountryCode(node.Server)
				if countryCode != "" && geoIPCountryCodes[countryCode] {
					matchCount++
				}
			}
			continue
		}

		// 根本不过滤，计算所有节点
		matchCount++
	}

	logger.Info("[checkFilterMatches] 匹配结果", "filter", filter, "geo_ip_filter", geoIPFilter, "match_count", matchCount)
	return matchCount, nil
}
