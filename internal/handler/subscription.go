package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"miaomiaowux/internal/logger"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MMWOrg/mmwX-plugins/proxyparser/substore"
	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/scriptengine"
	"miaomiaowux/internal/storage"

	"gopkg.in/yaml.v3"
)

const subscriptionDefaultType = "clash"

// Token失效时返回的YAML内容
const tokenInvalidYAML = `allow-lan: false
dns:
  enable: true
  enhanced-mode: fake-ip
  ipv6: true
  nameserver:
    - https://120.53.53.53/dns-query
    - https://dns.alidns.com/dns-query
  nameserver-policy:
    geosite:cn,private:
      - https://120.53.53.53/dns-query
      - https://dns.alidns.com/dns-query
    geosite:geolocation-!cn:
      - https://dns.cloudflare.com/dns-query
      - https://8.8.8.8/dns-query
  proxy-server-nameserver:
    - https://120.53.53.53/dns-query
    - https://223.5.5.5/dns-query
  respect-rules: true
geo-auto-update: true
geo-update-interval: 24
geodata-loader: standard
geodata-mode: true
geox-url:
  asn: https://github.com/xishang0128/geoip/releases/download/latest/GeoLite2-ASN.mmdb
  geoip: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat
  geosite: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat
  mmdb: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb
log-level: info
mode: rule
port: 7890
proxies:
  - name: ⚠️ 订阅已过期
    type: ss
    server: test.example.com.cn
    port: 443
    password: J6h6sFZp0Xxv7M8K2RZ6nN8c8ZxQpJZcQ4M2YVtPZ5Q=
    cipher: 2022-blake3-chacha20-poly1305
  - name: ⚠️ 请联系管理员
    type: ss
    server: test.example.com.cn
    port: 443
    password: J6h6sFZp0Xxv7M8K2RZ6nN8c8ZxQpJZcQ4M2YVtPZ5Q=
    cipher: 2022-blake3-chacha20-poly1305
proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - ⚠️ 订阅已过期
      - ⚠️ 请联系管理员
rules:
  - MATCH,DIRECT
socks-port: 7891
`

const tokenInvalidFilename = "token_invalid.yaml"

// 令牌无效标志的上下文键
type ContextKey string

const TokenInvalidKey ContextKey = "token_invalid"

type SubscriptionHandler struct {
	repo     *storage.TrafficRepository
	baseDir  string
	fallback string
}

type subscriptionEndpoint struct {
	tokens *auth.TokenStore
	repo   *storage.TrafficRepository
	inner  *SubscriptionHandler
}

func NewSubscriptionHandler(repo *storage.TrafficRepository, baseDir string) http.Handler {
	if repo == nil {
		panic("subscription handler requires repository")
	}

	return newSubscriptionHandler(repo, baseDir, subscriptionDefaultType)
}

// NewSubscriptionHandlerConcrete 创建订阅处理程序并返回具体类型。
// 当其他处理程序需要直接访问 SubscriptionHandler 时使用此方法。
func NewSubscriptionHandlerConcrete(repo *storage.TrafficRepository, baseDir string) *SubscriptionHandler {
	if repo == nil {
		panic("subscription handler requires repository")
	}

	return newSubscriptionHandler(repo, baseDir, subscriptionDefaultType)
}

// 返回一个提供订阅文件的处理程序，允许通过查询参数使用会话令牌或用户令牌。
func NewSubscriptionEndpoint(tokens *auth.TokenStore, repo *storage.TrafficRepository, baseDir string) http.Handler {
	if tokens == nil {
		panic("subscription endpoint requires token store")
	}
	if repo == nil {
		panic("subscription endpoint requires repository")
	}

	inner := newSubscriptionHandler(repo, baseDir, subscriptionDefaultType)
	return &subscriptionEndpoint{tokens: tokens, repo: repo, inner: inner}
}

func newSubscriptionHandler(repo *storage.TrafficRepository, baseDir, fallback string) *SubscriptionHandler {
	if repo == nil {
		panic("subscription handler requires repository")
	}

	if baseDir == "" {
		baseDir = filepath.FromSlash("subscribes")
	}

	cleanedBase := filepath.Clean(baseDir)
	if fallback == "" {
		fallback = subscriptionDefaultType
	}

	return &SubscriptionHandler{repo: repo, baseDir: cleanedBase, fallback: fallback}
}

func setSubscriptionNoCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func (s *subscriptionEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// token 与短码都允许用户主动轮换，入口响应不能被 CDN/反代缓存，否则
	// 已失效的旧 URL 仍可能在源站重启后继续返回历史内容。
	setSubscriptionNoCacheHeaders(w)
	request, ok := s.authorizeRequest(w, r)
	if !ok {
		return
	}

	s.inner.ServeHTTP(w, request)
}

func (s *subscriptionEndpoint) authorizeRequest(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	if r.Method != http.MethodGet {
		// 允许处理程序以方法限制进行响应
		return r, true
	}

	// 严重安全:之前这里信任 ?username=XXX query 参数注入 username 到 context,
	// 任何人都可以构造 `?filename=X&username=admin` 直接绕过 token 拿别人订阅(IDOR/未授权)。
	// 实际短链接处理是用 r.Clone(ContextWithUsername(ctx, x)) 写入 **context**,
	// 不需要也不应该信任 URL query。**移除此分支**,所有未携带有效 token/session 的访问都走 invalid 响应。

	// 检查令牌参数（旧版/直接访问）
	queryToken := strings.TrimSpace(r.URL.Query().Get("token"))
	if queryToken != "" && s.repo != nil {
		username, err := s.repo.ValidateUserToken(r.Context(), queryToken)
		if err == nil {
			ctx := auth.ContextWithUsername(r.Context(), username)
			return r.WithContext(ctx), true
		}
		if !errors.Is(err, storage.ErrTokenNotFound) {
			writeError(w, http.StatusInternalServerError, err)
			return nil, false
		}
	}

	// 检查标头令牌（基于会话的访问）
	headerToken := strings.TrimSpace(r.Header.Get(auth.AuthHeader))
	username, ok := s.tokens.Lookup(headerToken)
	if ok {
		ctx := auth.ContextWithUsername(r.Context(), username)
		return r.WithContext(ctx), true
	}

	// 所有认证方式都失败，设置token失效标记
	ctx := context.WithValue(r.Context(), TokenInvalidKey, true)
	return r.WithContext(ctx), true
}

func (h *SubscriptionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 性能监测：记录总开始时间
	requestStart := time.Now()
	var stepStart time.Time

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("only GET is supported"))
		return
	}
	if rejectBlockedSubscriptionUA(w, r) {
		return
	}

	// 检查是否是token失效场景
	if tokenInvalid, ok := r.Context().Value(TokenInvalidKey).(bool); ok && tokenInvalid {
		h.serveTokenInvalidResponse(w, r)
		return
	}

	// 从上下文中获取用户名
	username := auth.UsernameFromContext(r.Context())

	filename := strings.TrimSpace(r.URL.Query().Get("filename"))
	var subscribeFile storage.SubscribeFile
	var displayName string
	var err error
	var hasSubscribeFile bool
	_ = hasSubscribeFile

	if filename != "" {
		subscribeFile, err = h.repo.GetSubscribeFileByFilename(r.Context(), filename)
		if err != nil {
			if errors.Is(err, storage.ErrSubscribeFileNotFound) {
				writeError(w, http.StatusNotFound, errors.New("not found"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		// 越权防护:token 认证路径下,用户只能访问"自己创建的"或"管理员分配给自己的"订阅文件。
		// 短链接路径(/x/{code})不会走到这里 — 它由 short_link.go 解析后直接转发 + 注入 created_by,
		// 链接本身就是身份证明(谁拿到 code 谁访问),所以那条路径无需此校验。
		// 此校验仅针对 token 认证 + filename 参数的入口,堵住 IDOR(改 filename 拿别人订阅)。
		if username != "" {
			user, uerr := h.repo.GetUser(r.Context(), username)
			if uerr == nil && user.Role != storage.RoleAdmin && subscribeFile.CreatedBy != username {
				allowed := false
				if ids, ierr := h.repo.GetUserSubscriptionIDs(r.Context(), username); ierr == nil {
					for _, id := range ids {
						if id == subscribeFile.ID {
							allowed = true
							break
						}
					}
				}
				if !allowed {
					writeError(w, http.StatusForbidden, errors.New("forbidden: subscription not assigned to user"))
					return
				}
			}
		}
		displayName = subscribeFile.Name
		hasSubscribeFile = true
	} else {
		// TODO: 订阅链接已经配置到客户端，管理员修改文件名后，原订阅链接无法使用
		// 1.0 版本时改为与表里的ID关联，暂时先不改
		// 这里的 t 是**遗留的订阅文件名**语义(不是客户端类型),所以刻意读原始值、
		// 不走 resolveClientType —— auto 模式对它没有意义,翻译过反而会拿客户端名去查订阅。
		legacyName := strings.TrimSpace(r.URL.Query().Get("t"))
		link, err := h.resolveSubscription(r.Context(), legacyName)
		if err != nil {
			if errors.Is(err, storage.ErrSubscriptionNotFound) {
				writeError(w, http.StatusNotFound, err)
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		filename = link.RuleFilename
		displayName = link.Name
		if h.repo != nil {
			subscribeFile, err = h.repo.GetSubscribeFileByFilename(r.Context(), filename)
			if err == nil {
				hasSubscribeFile = true
			} else if !errors.Is(err, storage.ErrSubscribeFileNotFound) {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}
	}
	logger.Info("[⏱️ 耗时监测] 文件查找完成", "step", "file_lookup", "duration_ms", time.Since(stepStart).Milliseconds(), "filename", filename)

	if username != "" {
		clientType := r.Header.Get("User-Agent")
		if clientType == "" {
			clientType = "unknown"
		}
		SendSubscribeFetchNotification(r.Context(), h.repo, username, clientType, GetClientIP(r))
		if silentMgr := GetSilentModeManager(); silentMgr != nil && username != "" {
			silentMgr.RecordSubscriptionAccessWithIP(username, GetClientIP(r))
		}
	}

	cleanedName := filepath.Clean(filename)
	if strings.HasPrefix(cleanedName, "..") || filepath.IsAbs(cleanedName) {
		writeError(w, http.StatusBadRequest, errors.New("invalid rule filename"))
		return
	}

	resolvedPath := filepath.Join(h.baseDir, cleanedName)

	// 验证解析的路径是否在 baseDir 内以防止路径遍历
	absBase, err := filepath.Abs(h.baseDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	absResolved, err := filepath.Abs(resolvedPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !strings.HasPrefix(absResolved, absBase+string(filepath.Separator)) && absResolved != absBase {
		writeError(w, http.StatusBadRequest, errors.New("invalid rule filename"))
		return
	}

	// 模板生成优先级:
	//   - 订阅本身绑了模板 → 用订阅绑定的模板
	//   - 没绑 + 创建者有套餐 + 套餐配了模板 → 用套餐模板
	//   - 还没 + 系统配了默认模板 → 用系统默认模板
	//   - 都没 → 走静态文件路径(原行为)
	var data []byte
	fromTemplate := false
	fromSurgeTemplate := false // Surge 模板直出:data 已是 Surge 文本,跳过 convertSubscription
	if hasSubscribeFile {
		effectiveTemplate := subscribeFile.TemplateFilename
		if effectiveTemplate == "" && h.repo != nil {
			creator := strings.TrimSpace(subscribeFile.CreatedBy)
			if creator != "" {
				if u, uerr := h.repo.GetUser(r.Context(), creator); uerr == nil && u.PackageID > 0 {
					if pkg, perr := h.repo.GetPackage(r.Context(), u.PackageID); perr == nil && pkg != nil && strings.TrimSpace(pkg.TemplateFilename) != "" {
						effectiveTemplate = pkg.TemplateFilename
						logger.Info("[Subscription] 订阅未绑定模板，使用套餐模板", "template", effectiveTemplate, "package_id", pkg.ID)
					}
				}
			}
		}
		// 注意:Clash 系不回退系统默认模板 —— 避免用户精心配的原始 YAML 被"自动套上"覆盖。
		// 但 Surge 系例外:订阅原始文件是 Clash YAML,Surge 客户端本就要转换,没有"原样保留"诉求;
		// 且 Surge 策略组/规则必须靠模板生成。故 Surge 请求在订阅/套餐都无模板时回落到系统 Surge 默认模板。
		if effectiveTemplate == "" && h.repo != nil && isSurgeClientType(resolveClientType(r)) {
			if cfg, cerr := h.repo.GetSystemConfig(r.Context()); cerr == nil {
				if f := strings.TrimSpace(cfg.DefaultSurgeTemplateFilename); f != "" {
					effectiveTemplate = f
					logger.Info("[Subscription] Surge 订阅未绑定模板，回落到系统 Surge 默认模板", "template", effectiveTemplate)
				}
			}
		}
		if effectiveTemplate != "" {
			stepStart = time.Now()
			sfForGen := subscribeFile
			sfForGen.TemplateFilename = effectiveTemplate
			templateData, genErr := h.generateFromTemplate(r.Context(), sfForGen)
			if genErr != nil {
				logger.Info("[Subscription] 模板生成失败，回退到原始文件", "error", genErr, "template", effectiveTemplate)
			} else {
				data = templateData
				fromTemplate = true
				fromSurgeTemplate = isSurgeTemplateFile(effectiveTemplate)
				logger.Info("[⏱️ 耗时监测] 模板生成完成", "step", "template_generate", "duration_ms", time.Since(stepStart).Milliseconds(), "bytes", len(data))
			}
		}
	}
	_ = fromTemplate

	// 文件读取（如果模板生成失败或未绑定模板）
	if len(data) == 0 {
		stepStart = time.Now()
		var readErr error
		data, readErr = os.ReadFile(resolvedPath)
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, readErr)
			} else {
				writeError(w, http.StatusInternalServerError, readErr)
			}
			return
		}
		logger.Info("[⏱️ 耗时监测] 文件读取完成", "step", "file_read", "duration_ms", time.Since(stepStart).Milliseconds(), "bytes", len(data))
	}

	// 外部订阅同步
	stepStart = time.Now()
	// 检查是否启用强制同步外部订阅并仅同步引用的订阅
	if username != "" && h.repo != nil {
		settings, err := h.repo.GetUserSettings(r.Context(), username)
		if err == nil && settings.ForceSyncExternal {
			logger.Info("[Subscription] 用户启用强制同步", "user", username, "cache_expire_minutes", settings.CacheExpireMinutes)

			// 获取当前文件中引用的外部订阅
			usedExternalSubs, err := GetExternalSubscriptionsFromFile(r.Context(), data, username, h.repo)
			if err != nil {
				logger.Info("[Subscription] 获取文件中的外部订阅失败", "error", err)
			} else if len(usedExternalSubs) > 0 {
				logger.Info("[Subscription] 找到当前文件引用的外部订阅", "count", len(usedExternalSubs))

				// 获取用户的外部订阅以检查缓存并获取 URL
				allExternalSubs, err := h.repo.ListExternalSubscriptions(r.Context(), username)
				if err != nil {
					logger.Info("[Subscription] 获取外部订阅列表失败", "error", err)
				} else {
					// 筛选以仅同步当前文件中引用的订阅
					var subsToSync []storage.ExternalSubscription
					subURLMap := make(map[string]string) // URL -> 名称映射

					for _, sub := range allExternalSubs {
						subURLMap[sub.URL] = sub.Name
						if _, used := usedExternalSubs[sub.URL]; used {
							subsToSync = append(subsToSync, sub)
						}
					}

					logger.Info("[Subscription] 强制同步已启用，将同步引用的外部订阅", "sync_count", len(subsToSync), "total_count", len(allExternalSubs))

					// 检查我们是否需要根据缓存过期进行同步
					shouldSync := false
					if settings.CacheExpireMinutes > 0 {
						// 仅检查引用订阅的上次同步时间
						for _, sub := range subsToSync {
							if sub.LastSyncAt == nil {
								// 以前从未同步过
								logger.Info("[Subscription] 订阅从未同步过，将进行同步", "name", sub.Name, "url", sub.URL)
								shouldSync = true
								break
							}

							// 计算时间差（以分钟为单位）
							elapsed := time.Since(*sub.LastSyncAt).Minutes()
							if elapsed >= float64(settings.CacheExpireMinutes) {
								// 缓存已过期
								logger.Info("[Subscription] 订阅缓存已过期，将进行同步", "name", sub.Name, "url", sub.URL, "elapsed_minutes", elapsed, "expire_minutes", settings.CacheExpireMinutes)
								shouldSync = true
								break
							}
						}
						if !shouldSync {
							logger.Info("[Subscription] All referenced subscriptions are within cache time, skipping sync")
						}
					} else {
						// 缓存过期分钟为0，始终同步
						logger.Info("[Subscription] Cache expire minutes is 0, will always sync referenced subscriptions")
						shouldSync = true
					}

					if shouldSync {
						logger.Info("[Subscription] 开始同步用户的外部订阅(仅引用的订阅)", "user", username)
						// 仅同步引用的外部订阅
						if err := syncReferencedExternalSubscriptions(r.Context(), h.repo, h.baseDir, username, subsToSync); err != nil {
							logger.Info("[Subscription] 同步外部订阅失败", "error", err)
							// 记录错误但不要使请求失败
							// 同步是尽力而为的
						} else {
							logger.Info("[Subscription] External subscriptions sync completed successfully")

							// 同步后重新读取订阅文件以获取更新的节点
							updatedData, err := os.ReadFile(resolvedPath)
							if err != nil {
								logger.Info("[Subscription] 同步后重新读取订阅文件失败", "error", err)
							} else {
								data = updatedData
								logger.Info("[Subscription] 同步后重新读取订阅文件成功", "bytes", len(data))
							}
						}
					}
				}
			} else {
				logger.Info("[Subscription] No external subscriptions referenced in current file, skipping sync")
			}
		}
	}
	logger.Info("[⏱️ 耗时监测] 外部订阅同步完成", "step", "external_sync", "duration_ms", time.Since(stepStart).Milliseconds())

	// 流量信息收集
	stepStart = time.Now()
	externalTrafficLimit, externalTrafficUsed := int64(0), int64(0)

	if username != "" && h.repo != nil {
		settings, err := h.repo.GetUserSettings(r.Context(), username)
		if err == nil && settings.SyncTraffic {
			// 解析 YAML 文件，获取其中使用的节点名称
			var yamlConfig map[string]any
			if err := yaml.Unmarshal(data, &yamlConfig); err == nil {
				if proxies, ok := yamlConfig["proxies"].([]any); ok {
					logger.Info("[Subscription] 找到订阅YAML中的代理节点", "count", len(proxies))
					usedNodeNames := make(map[string]bool)
					for _, proxy := range proxies {
						if proxyMap, ok := proxy.(map[string]any); ok {
							if name, ok := proxyMap["name"].(string); ok && name != "" {
								usedNodeNames[name] = true
							}
						}
					}

					if len(usedNodeNames) > 0 {
						nodes, err := h.repo.ListNodes(r.Context(), username)
						if err == nil {
							usedExternalSubs := make(map[string]bool)
							for _, node := range nodes {
								if usedNodeNames[node.NodeName] {
									if node.Tag != "" && node.Tag != "手动输入" {
										usedExternalSubs[node.Tag] = true
									}
								}
							}

							if len(usedExternalSubs) > 0 {
								logger.Info("[Subscription] 找到使用中的外部订阅", "user", username, "count", len(usedExternalSubs))
								externalSubs, err := h.repo.ListExternalSubscriptions(r.Context(), username)
								if err == nil {
									now := time.Now()
									for _, sub := range externalSubs {
										if usedExternalSubs[sub.Name] {
											if sub.Expire != nil && sub.Expire.Before(now) {
												continue
											}
											externalTrafficLimit += sub.Total
											switch sub.TrafficMode {
											case "download":
												externalTrafficUsed += sub.Download
											case "upload":
												externalTrafficUsed += sub.Upload
											default:
												externalTrafficUsed += sub.Upload + sub.Download
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	logger.Info("[⏱️ 耗时监测] 流量信息收集完成", "step", "traffic_info", "duration_ms", time.Since(stepStart).Milliseconds())

	// 节点排序
	stepStart = time.Now()
	// 获取用户的节点排序配置，需要在转换之前使用
	var nodeOrder []int64
	if username != "" && h.repo != nil {
		settings, err := h.repo.GetUserSettings(r.Context(), username)
		if err == nil {
			nodeOrder = settings.NodeOrder
			logger.Info("[Subscription] 用户节点排序配置", "user", username, "node_count", len(nodeOrder))
		}
	}

	// 在转换之前根据节点排序配置调整原始 YAML
	// 这样转换后的任何格式都会保持正确的节点顺序
	if len(nodeOrder) > 0 && username != "" && h.repo != nil {
		var yamlNode yaml.Node
		if err := yaml.Unmarshal(data, &yamlNode); err == nil {
			shouldRewrite := false
			if len(yamlNode.Content) > 0 && yamlNode.Content[0].Kind == yaml.MappingNode {
				rootMap := yamlNode.Content[0]
				for i := 0; i < len(rootMap.Content); i += 2 {
					if rootMap.Content[i].Value == "proxies" {
						proxiesNode := rootMap.Content[i+1]
						if proxiesNode.Kind == yaml.SequenceNode {
							if err := sortProxiesByNodeOrder(r.Context(), h.repo, username, proxiesNode, nodeOrder); err != nil {
								logger.Info("[Subscription] 转换前按节点顺序排序失败", "error", err)
							} else {
								shouldRewrite = true
								logger.Info("[Subscription] Successfully sorted proxies by node order before conversion")
							}
						}
						break
					}
				}
			}

			// 如果排序成功，重新序列化YAML并替换data
			if shouldRewrite {
				if reorderedData, err := MarshalYAMLWithIndent(&yamlNode); err == nil {
					fixed := RemoveUnicodeEscapeQuotes(string(reorderedData))
					data = []byte(fixed)
					logger.Info("[Subscription] Rewrote YAML data with sorted proxies")
				}
			}
		}
	}
	logger.Info("[⏱️ 耗时监测] 节点排序完成", "step", "node_order", "duration_ms", time.Since(stepStart).Milliseconds())

	// 链式代理注入：根据 chain_proxy_node_id 注入 dialer-proxy
	stepStart = time.Now()
	if username != "" && h.repo != nil {
		data = injectChainProxy(r.Context(), h.repo, username, data)
	}
	logger.Info("[⏱️ 耗时监测] 链式代理注入完成", "step", "chain_proxy", "duration_ms", time.Since(stepStart).Milliseconds())

	// 执行覆写脚本（post_fetch 钩子）
	stepStart = time.Now()
	overrideApplied := false
	if username != "" && h.repo != nil {
		if sysCfg, err := h.repo.GetSystemConfig(r.Context()); err == nil && sysCfg.EnableOverrideScripts {
			// 该订阅选中的覆写脚本(空=全部启用的生效)。脚本本就按 username 隔离,不会混入管理员的。
			selectedScriptIDs := makeIDSet(subscribeFile.SelectedOverrideScriptIDs)
			scripts, _ := h.repo.ListOverrideScripts(r.Context(), username, "post_fetch")
			for _, s := range scripts {
				if !s.Enabled {
					continue
				}
				if len(selectedScriptIDs) > 0 && !selectedScriptIDs[s.ID] {
					continue
				}
				modified, err := h.runPostFetchScript(r.Context(), s.Content, data)
				if err != nil {
					logger.Info("[OverrideScript] post_fetch 脚本执行失败", "script", s.Name, "error", err)
					continue
				}
				data = modified
				overrideApplied = true
			}
		}
	}
	logger.Info("[⏱️ 耗时监测] 覆写脚本执行完成", "step", "override_script", "duration_ms", time.Since(stepStart).Milliseconds())

	// 覆写脚本改的是 clash YAML(尤其 rules/rule-providers)。但下面把 clash 转成
	// loon/surge/sing-box 等格式时,substore 各 producer **只搬 proxies/proxy-groups,不搬 rules**
	// (仅 clash/clashmeta/stash 是同构 YAML、原样保留)。于是覆写对 rules 的修改在这些格式下被丢掉,
	// 用户会以为"覆写没生效"甚至"被模板覆盖"——实际是格式转换的固有缺口,与模板无关。
	//
	// 这里不去补每个 producer 的 rules 翻译(工作量/风险都大,另议),而是在**确实会丢**时给个
	// 明确信号:响应头 + WARN 日志,把"静默丢失"变成"知情"。
	if overrideApplied && !clientKeepsClashRules(resolveClientType(r)) {
		w.Header().Set("X-MMWX-Override-Warning", "override-rules-dropped-in-non-clash-format")
		logger.Warn("[OverrideScript] 覆写脚本已执行,但当前客户端格式不保留 clash rules,规则类修改会丢失",
			"user", username, "client_type", resolveClientType(r), "file", subscribeFile.Name)
	}

	// 格式转换
	stepStart = time.Now()
	// 根据参数t的类型调用substore的转换代码
	clientType := resolveClientType(r)
	// 默认浏览器打开时直接输入文本, 不再下载问卷
	contentType := "text/yaml; charset=utf-8; charset=UTF-8"
	ext := filepath.Ext(filename)
	if ext == "" {
		ext = ".yaml"
	}

	// Surge 模板直出:data 已是完整 Surge 配置,不能再当 YAML 转换,直接文本输出。
	if fromSurgeTemplate {
		contentType = "text/plain; charset=utf-8"
		ext = ".conf"
	} else if clientType == "" || clientType == "clash" || clientType == "clashmeta" {
		// 原样 YAML 输出(不经 producer)→ 过滤 snell v6:mihomo 只支持 v1–v5,
		// 保留 v6 节点会让整份配置 fatal 拒载(所有节点全没)。Surge/sing-box 等 v6 可用格式走下面转换分支不受影响。
		data = filterSnellV6FromClashYAML(data)
	} else {
		// clash 和 clashmeta 类型直接输出源文件, 不需要转换
		// 使用子商店生产者转换订阅
		// V2Ray 输出会在下面转换成 Base64 URI，必须在转换前把信息节点放进 Clash proxies；
		// 转换完成后已不再是 YAML，无法沿用后面的 YAML 注入步骤。
		if isV2RayClientType(clientType) && h.repo != nil {
			if sysCfg, cfgErr := h.repo.GetSystemConfig(r.Context()); cfgErr == nil && sysCfg.EnableSubInfoNodes && sysCfg.SubInfoV2RayOnly {
				totalLimit, totalUsed, expireAt := h.resolveSubscriptionTraffic(
					r.Context(), hasSubscribeFile, subscribeFile, externalTrafficLimit, externalTrafficUsed,
				)
				remaining := totalLimit - totalUsed
				if remaining < 0 {
					remaining = 0
				}
				data = prependSubInfoNodesToClash(data, sysCfg, expireAt, remaining)
			}
		}
		convertedData, err := h.convertSubscription(r.Context(), data, clientType)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("failed to convert subscription for client %s: %w", clientType, err))
			return
		}
		data = convertedData

		// 根据客户端类型设置内容类型和扩展名
		switch clientType {
		case "surge", "surgemac", "loon", "qx", "surfboard", "shadowrocket", "clash-to-shadowrocket", "clash-to-surge", "clash-to-loon", "clash-to-loon-kelee":
			// 基于文本的格式
			contentType = "text/plain; charset=utf-8"
			ext = ".txt"
		case "sing-box":
			// JSON格式
			contentType = "application/json; charset=utf-8"
			ext = ".json"
		case "v2ray":
			// Base64 格式
			contentType = "text/plain; charset=utf-8"
			ext = ".txt"
		case "uri":
			// 统一资源定位符格式
			contentType = "text/plain; charset=utf-8"
			ext = ".txt"
		default:
			// 基于 YAML 的格式（clash、clashmeta、stash、shadowrocket、egern）
			contentType = "text/yaml; charset=utf-8"
			ext = ".yaml"
		}
	}
	logger.Info("[⏱️ 耗时监测] 格式转换完成", "step", "format_convert", "duration_ms", time.Since(stepStart).Milliseconds(), "client_type", clientType)

	// 使用订阅名称
	attachmentName := url.PathEscape(displayName)
	totalTrafficLimit, totalTrafficUsed, subExpire := h.resolveSubscriptionTraffic(
		r.Context(), hasSubscribeFile, subscribeFile, externalTrafficLimit, externalTrafficUsed,
	)

	// YAML 重排序
	stepStart = time.Now()
	// 对于 YAML 格式的数据，重新排序以将 rule-providers 放在最后
	// 注意：节点排序已经在转换之前完成，这里只处理其他的YAML重排需求
	if contentType == "text/yaml; charset=utf-8" || contentType == "text/yaml; charset=utf-8; charset=UTF-8" {
		// 使用 yaml.Node 来保持原始类型信息（避免 563905e2 被解析为科学计数法）
		var yamlNode yaml.Node
		if err := yaml.Unmarshal(data, &yamlNode); err == nil {
			// 检查是否有 rule-providers 需要重新排序
			// yamlNode.Content[0] 是文档节点，yamlNode.Content[0].Content 是根映射的键值对
			if len(yamlNode.Content) > 0 && yamlNode.Content[0].Kind == yaml.MappingNode {
				rootMap := yamlNode.Content[0]

				// 注意：节点排序已经在转换之前完成，这里不再重复排序
				// 只处理 WireGuard 修复和字段重排

				// 重新排序 proxies 中每个节点的字段
				for i := 0; i < len(rootMap.Content); i += 2 {
					if rootMap.Content[i].Value == "proxies" {
						proxiesNode := rootMap.Content[i+1]
						if proxiesNode.Kind == yaml.SequenceNode {
							// 先修复 WireGuard 节点的 allowed-ips 字段
							fixWireGuardAllowedIPs(proxiesNode)
							reorderProxies(proxiesNode)
							if h.repo != nil {
								if sysCfg, cfgErr := h.repo.GetSystemConfig(r.Context()); cfgErr == nil && sysCfg.EnableSubInfoNodes && !sysCfg.SubInfoV2RayOnly {
									remainingTraffic := totalTrafficLimit - totalTrafficUsed
									if remainingTraffic < 0 {
										remainingTraffic = 0
									}
									proxiesNode.Content = append(createSubInfoNodes(sysCfg, subExpire, remainingTraffic), proxiesNode.Content...)
								}
							}
						}
						break
					}
				}

				// 重新排序 proxy-groups 中每个代理组的字段
				for i := 0; i < len(rootMap.Content); i += 2 {
					if rootMap.Content[i].Value == "proxy-groups" {
						proxyGroupsNode := rootMap.Content[i+1]
						if proxyGroupsNode.Kind == yaml.SequenceNode {
							reorderProxyGroups(proxyGroupsNode)
							// 读 dialer-proxy-group 字段 → 给顶层 proxies 注入 dialer-proxy
							// (顺序:先 inject 读字段,再 strip 删字段;链式代理已注入的 dialer-proxy 不覆盖)
							injectDialerProxyFromGroups(rootMap)
							stripDialerProxyGroup(proxyGroupsNode)
						}
						break
					}
				}

				// 查找 rule-providers 的位置
				ruleProvidersIdx := -1
				for i := 0; i < len(rootMap.Content); i += 2 {
					if rootMap.Content[i].Value == "rule-providers" {
						ruleProvidersIdx = i
						break
					}
				}

				// 如果找到 rule-providers 且不在最后，则移动到最后
				if ruleProvidersIdx >= 0 && ruleProvidersIdx < len(rootMap.Content)-2 {
					// 提取 rule-providers 的键和值
					keyNode := rootMap.Content[ruleProvidersIdx]
					valueNode := rootMap.Content[ruleProvidersIdx+1]

					// 从原位置删除
					rootMap.Content = append(rootMap.Content[:ruleProvidersIdx], rootMap.Content[ruleProvidersIdx+2:]...)

					// 添加到最后
					rootMap.Content = append(rootMap.Content, keyNode, valueNode)
				}
			}

			// 重新序列化为 YAML (使用2空格缩进)
			if reorderedData, err := MarshalYAMLWithIndent(&yamlNode); err == nil {
				// 修复表情符号转义和引用的数字
				fixed := RemoveUnicodeEscapeQuotes(string(reorderedData))
				data = []byte(fixed)
			}
		}
	}
	logger.Info("[⏱️ 耗时监测] YAML 重排序完成", "step", "yaml_reorder", "duration_ms", time.Since(stepStart).Milliseconds())

	// 系统配置 subscription_output_format == "json" 且当前是 YAML content-type → 转 JSON 输出。
	// 仅影响 Clash 订阅(其它客户端格式如 Surge/Sing-Box 在前面 convertSubscription 那段已切了 content-type,
	// 不会命中这里的 text/yaml 判断)。
	if h.repo != nil {
		if sysCfg, err := h.repo.GetSystemConfig(r.Context()); err == nil && sysCfg.SubscriptionOutputFormat == "json" &&
			(contentType == "text/yaml; charset=utf-8" || contentType == "text/yaml; charset=utf-8; charset=UTF-8") {
			if jsonBytes, jsonErr := marshalSubscriptionJSON(data); jsonErr == nil {
				data = jsonBytes
				contentType = "application/json; charset=utf-8"
				ext = ".json"
			} else {
				logger.Warn("[Subscription] YAML → JSON 转换失败,回落 YAML 输出", "error", jsonErr)
			}
		}
	}

	w.Header().Set("Content-Type", contentType)

	if totalTrafficLimit > 0 {
		headerValue := buildSubscriptionHeader(totalTrafficLimit, totalTrafficUsed, subExpire)
		w.Header().Set("subscription-userinfo", headerValue)
	}
	w.Header().Set("profile-update-interval", "24")
	// 只有非浏览器访问时才添加 content-disposition 头（避免浏览器直接下载）
	userAgent := r.Header.Get("User-Agent")
	isBrowser := strings.Contains(userAgent, "Mozilla") || strings.Contains(userAgent, "Chrome") || strings.Contains(userAgent, "Safari") || strings.Contains(userAgent, "Edge")
	if !isBrowser {
		w.Header().Set("content-disposition", "attachment;filename*=UTF-8''"+attachmentName)
		// profile-title:Surge/Loon/QX 优先认此头显示订阅名(否则回退 URL 短码显示成数字)。
		w.Header().Set("profile-title", "base64:"+base64.StdEncoding.EncodeToString([]byte(displayName)))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	logger.Info("[⏱️ 耗时监测] 请求处理完成", "total_duration_ms", time.Since(requestStart).Milliseconds(), "username", username, "filename", filename)
}

func (h *SubscriptionHandler) resolveSubscription(ctx context.Context, name string) (storage.SubscriptionLink, error) {
	if h == nil {
		return storage.SubscriptionLink{}, errors.New("subscription handler not initialized")
	}

	if h.repo == nil {
		return storage.SubscriptionLink{}, errors.New("subscription repository not configured")
	}

	trimmed := strings.TrimSpace(name)
	if trimmed != "" {
		return h.repo.GetSubscriptionByName(ctx, trimmed)
	}

	if h.fallback != "" {
		link, err := h.repo.GetSubscriptionByName(ctx, h.fallback)
		if err == nil {
			return link, nil
		}
		if !errors.Is(err, storage.ErrSubscriptionNotFound) {
			return storage.SubscriptionLink{}, err
		}
	}

	return h.repo.GetFirstSubscriptionLink(ctx)
}

// generateFromTemplate 基于绑定的 V3 模板生成订阅配置
// 代理节点来源：所有远程服务器的节点（ListAllNodes），按 SelectedTags 过滤
// makeIDSet 把 ID 切片转成集合;空切片返回 nil(调用方据此判断"不过滤=全部生效")。
func makeIDSet(ids []int64) map[int64]bool {
	if len(ids) == 0 {
		return nil
	}
	m := make(map[int64]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func (h *SubscriptionHandler) generateFromTemplate(ctx context.Context, subscribeFile storage.SubscribeFile) ([]byte, error) {
	if subscribeFile.TemplateFilename == "" {
		return nil, errors.New("订阅未绑定模板")
	}

	templatePath := filepath.Join("rule_templates", subscribeFile.TemplateFilename)
	templateContent, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("读取模板文件失败: %w", err)
	}

	// 节点池选择:
	//   - 订阅创建者是普通用户且绑了套餐 → 仅套餐内的节点(避免普通用户订阅里出现他没买的节点)
	//   - 订阅创建者是管理员 / 普通用户没套餐 / 没找到用户 → 沿用旧行为(所有节点)
	// 这跟 routes/nodes.index.tsx 普通用户的"自己导入 + 套餐"视图一致,符合用户预期。
	var nodes []storage.Node
	creator := strings.TrimSpace(subscribeFile.CreatedBy)
	restrictToPackage := false
	if creator != "" {
		if user, uerr := h.repo.GetUser(ctx, creator); uerr == nil && user.Role != storage.RoleAdmin && user.PackageID > 0 {
			if pkg, perr := h.repo.GetPackage(ctx, user.PackageID); perr == nil && pkg != nil {
				restrictToPackage = true
				nodes = make([]storage.Node, 0, len(pkg.Nodes))
				for _, nid := range pkg.Nodes {
					if pn, nerr := h.repo.GetNodeByID(ctx, nid); nerr == nil {
						nodes = append(nodes, pn)
					}
				}
			}
		}
	}
	if !restrictToPackage {
		allNodes, lerr := h.repo.ListAllNodes(ctx)
		if lerr != nil {
			return nil, fmt.Errorf("获取节点列表失败: %w", lerr)
		}
		nodes = allNodes
	}

	// 按订阅创建者的 nodeOrder 重排 nodes — 影响 __PROXY_NODES__ 占位符展开顺序、
	// 也直接决定订阅顶层 proxies 数组顺序。
	// 之前漏掉了这一步,模板订阅生成后节点按 created_at(ListAllNodes 默认 DESC)
	// 或 pkg.Nodes 数组顺序,跟用户在节点管理里拖好的顺序对不上。
	if creator != "" {
		nodes = orderNodesByUserOrder(ctx, h.repo, creator, nodes)
	}

	// 优先按节点 ID 过滤(新模式);为空回退按标签过滤(legacy 兼容)
	selectedNodeIDsMap := make(map[int64]bool, len(subscribeFile.SelectedNodeIDs))
	for _, id := range subscribeFile.SelectedNodeIDs {
		selectedNodeIDsMap[id] = true
	}
	// 普通套餐用户的可见范围已经由 pkg.Nodes 严格限定。这里不能再套订阅文件里保存的
	// selected_node_ids 快照：套餐后续新增节点（Snell v4/v5 最先暴露了这个问题）不在旧快照里，
	// 会在进入模板前被静默过滤，而管理员因不走套餐限制分支不会丢节点。
	// 套餐模式以当前 pkg.Nodes 为唯一真源，使模板注入行为与管理员路径一致。
	hasNodeFilter := !restrictToPackage && len(selectedNodeIDsMap) > 0

	selectedTagsMap := make(map[string]bool)
	for _, tag := range subscribeFile.SelectedTags {
		selectedTagsMap[tag] = true
	}
	hasTagFilter := !restrictToPackage && !hasNodeFilter && len(selectedTagsMap) > 0

	nodeIDToName := make(map[int64]string, len(nodes))
	for _, node := range nodes {
		nodeIDToName[node.ID] = node.NodeName
	}

	// 凭据替换基础设施 — 普通用户只能拿到自己的 uuid/password/auth,不能下发 admin 凭据。
	//   - 普通节点:applyUserCredentials 按协议主键覆写
	//   - routed 节点:buildRoutedProxyForUser 用 user_subaccounts 重建 proxy
	// admin 创建的订阅不走这条路径(用 admin 自己的凭据正常)。
	var credMap map[credKey]string
	if creator != "" && restrictToPackage {
		credMap = buildUserCredMapForCreator(ctx, h.repo, creator)
	}

	nodeByID := make(map[int64]storage.Node, len(nodes))
	for _, node := range nodes {
		nodeByID[node.ID] = node
	}

	// buildProxy:把节点解析成 clash proxy。name 强制取数据库当前 NodeName;链式/中转组的 dialer-proxy
	// 都按 ID 取目标的当前名(改名无影响)。抽成闭包,以便中转组底层成员被标签/ID 过滤掉时也能补建。
	buildProxy := func(node storage.Node) (map[string]any, bool) {
		var proxyConfig map[string]any
		if restrictToPackage && node.NodeType == "routed" {
			// routed:必须有 active 子账号才能给该用户;没的话整个节点过滤掉,
			// 否则会泄露 admin 在父节点的 uuid。
			built, ok := buildRoutedProxyForUser(ctx, h.repo, node, creator)
			if !ok {
				return nil, false
			}
			proxyConfig = built
		} else {
			if node.ClashConfig == "" {
				return nil, false
			}
			if err := json.Unmarshal([]byte(node.ClashConfig), &proxyConfig); err != nil {
				return nil, false
			}
			if credMap != nil {
				applyUserCredentials(proxyConfig, node, credMap)
			}
		}
		proxyConfig["name"] = node.NodeName
		// 链式代理:按 chain_proxy_node_id 取目标的当前名
		if node.ChainProxyNodeID != nil {
			if targetName, ok := nodeIDToName[*node.ChainProxyNodeID]; ok {
				proxyConfig["dialer-proxy"] = targetName
			}
		}
		// 中转组:dialer-proxy 指向中转代理组(与 chain 互斥,存储层已保证)
		if len(node.RelayGroupNodeIDs) > 0 && node.RelayGroupName != "" {
			proxyConfig["dialer-proxy"] = node.RelayGroupName
		}
		return proxyConfig, true
	}

	var proxies []map[string]any
	inRootProxies := make(map[string]bool)
	for _, node := range nodes {
		if !node.Enabled {
			continue
		}
		if hasNodeFilter && !selectedNodeIDsMap[node.ID] {
			continue
		}
		if hasTagFilter && !node.HasAnyTag(selectedTagsMap) {
			continue
		}
		proxyConfig, ok := buildProxy(node)
		if !ok {
			continue
		}
		proxies = append(proxies, proxyConfig)
		inRootProxies[node.NodeName] = true
	}

	// 中转组:按组名去重生成 url-test 代理组(成员按 ID 取当前名);被过滤(标签/ID)但被中转组
	// 引用的底层成员补入根 proxies,避免组内悬空引用。成员删除/禁用则从组剔除。
	relayGroupMap := make(map[string]map[string]any)
	var relayGroupOrder []string
	var extraProxies []map[string]any
	for _, node := range nodes {
		if !node.Enabled || len(node.RelayGroupNodeIDs) == 0 || node.RelayGroupName == "" {
			continue
		}
		if hasNodeFilter && !selectedNodeIDsMap[node.ID] {
			continue
		}
		if hasTagFilter && !node.HasAnyTag(selectedTagsMap) {
			continue
		}
		if _, exists := relayGroupMap[node.RelayGroupName]; exists {
			continue
		}
		var groupProxies []string
		for _, rid := range node.RelayGroupNodeIDs {
			member, ok := nodeByID[rid]
			if !ok || !member.Enabled {
				continue // 底层节点已删除/禁用:从中转组剔除,避免悬空引用
			}
			groupProxies = append(groupProxies, member.NodeName)
			if !inRootProxies[member.NodeName] {
				if pc, ok := buildProxy(member); ok {
					extraProxies = append(extraProxies, pc)
					inRootProxies[member.NodeName] = true
				}
			}
		}
		if len(groupProxies) > 0 {
			relayGroupMap[node.RelayGroupName] = map[string]any{
				"name":      node.RelayGroupName,
				"type":      "url-test",
				"proxies":   groupProxies,
				"url":       "http://www.gstatic.com/generate_204",
				"interval":  300,
				"tolerance": 50,
			}
			relayGroupOrder = append(relayGroupOrder, node.RelayGroupName)
		}
	}
	var relayGroups []map[string]any
	for _, groupName := range relayGroupOrder {
		relayGroups = append(relayGroups, relayGroupMap[groupName])
	}
	proxies = append(proxies, extraProxies...)
	logger.Info("[模板生成] 节点筛选完成", "total", len(nodes), "filtered", len(proxies), "node_filter", hasNodeFilter, "tag_filter", hasTagFilter, "restricted_to_package", restrictToPackage)

	if len(proxies) == 0 {
		return nil, errors.New("无可用节点")
	}

	// Surge 模板(.conf):不走 Clash/YAML 处理器,直接把节点注入 [Proxy] 段后原样输出。
	// 地区分组靠模板里的 policy-regex-filter + include-all-proxies=1 从注入的节点中筛选。
	if isSurgeTemplateFile(subscribeFile.TemplateFilename) {
		surgeResult, serr := injectProxiesIntoSurgeTemplate(string(templateContent), proxies)
		if serr != nil {
			return nil, fmt.Errorf("生成 Surge 配置失败: %w", serr)
		}
		logger.Info("[模板生成] Surge 完成", "subscribe", subscribeFile.Name, "template", subscribeFile.TemplateFilename, "bytes", len(surgeResult))
		return []byte(surgeResult), nil
	}

	processor := substore.NewTemplateV3Processor(nil, nil)
	result, err := processor.ProcessTemplate(string(templateContent), proxies)
	if err != nil {
		return nil, fmt.Errorf("处理模板失败: %w", err)
	}

	result, err = injectProxiesIntoTemplate(result, proxies)
	if err != nil {
		return nil, fmt.Errorf("注入代理节点失败: %w", err)
	}

	// 中转组:把 url-test 代理组追加进 proxy-groups —— 必须在孤儿裁剪前,
	// 否则组成员没被任何 proxy-group 引用会被裁掉,导致 dialer-proxy 悬空。
	if len(relayGroups) > 0 {
		if rg, rgErr := injectRelayGroupsIntoTemplate(result, relayGroups); rgErr == nil {
			result = rg
		} else {
			logger.Info("[模板生成] 中转组注入跳过", "error", rgErr.Error())
		}
	}

	// 孤儿节点裁剪:顶层 proxies: 只保留被 proxy-groups 实际引用的节点,删掉没被引用的
	if pruned, perr := pruneUnreferencedProxies([]byte(result)); perr == nil {
		result = string(pruned)
	} else {
		logger.Info("[模板生成] 孤儿裁剪跳过", "error", perr.Error())
	}

	logger.Info("[模板生成] 完成", "subscribe", subscribeFile.Name, "template", subscribeFile.TemplateFilename, "bytes", len(result))
	return []byte(result), nil
}

// longTermExpireUnix 是"长期/永久订阅"在 subscription-userinfo 里输出的 expire 时间戳。
// 小火箭等客户端把 expire 缺失或 expire=0 当作无效(显示 1970 或直接忽略),无法表达
// "长期有效";业界通行做法是给一个远期时间(此处 2099-12-31 23:59:59 UTC),客户端会
// 明确显示为该到期日,语义上等同"长期"。用 time.Date 构造避免手写时间戳算错。
var longTermExpireUnix = time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC).Unix()

// appendExpire 给 subscription-userinfo 追加 expire 字段。
//   - endDate 非 nil 且在未来 → 输出实际到期时间戳
//   - endDate 为 nil(永久)或已过期占位场景 → 输出 longTermExpireUnix(2099-12-31)
//
// 这样无论套餐订阅还是订阅文件、无论有无到期日,小火箭都能拿到一个有效 expire。
func appendExpire(info string, endDate *time.Time) string {
	exp := longTermExpireUnix
	if endDate != nil {
		exp = endDate.Unix()
	}
	return info + fmt.Sprintf("; expire=%d", exp)
}

func (h *SubscriptionHandler) resolveSubscriptionTraffic(ctx context.Context, hasSubscribeFile bool, subscribeFile storage.SubscribeFile, externalLimit, externalUsed int64) (int64, int64, *time.Time) {
	remoteLimit, remoteUsed := int64(0), int64(0)
	var expireAt *time.Time
	if !hasSubscribeFile || h.repo == nil {
		return externalLimit, externalUsed, nil
	}

	creator := strings.TrimSpace(subscribeFile.CreatedBy)
	usedPackageScope := false
	if creator != "" {
		if user, err := h.repo.GetUser(ctx, creator); err == nil && user.Role != storage.RoleAdmin && user.PackageID > 0 {
			if pkg, err := h.repo.GetPackage(ctx, user.PackageID); err == nil && pkg != nil {
				remoteLimit = resolveTrafficLimitBytes(&user, pkg)
				if billable, err := h.repo.GetUserBillableTraffic(ctx, creator); err == nil {
					remoteUsed = billable
				}
				expireAt = user.PackageEndDate
				usedPackageScope = true
			}
		}
	}

	if !usedPackageScope {
		var serverIDs []int64
		for _, idStr := range strings.Split(subscribeFile.StatsServerIDs, ",") {
			if id, err := strconv.ParseInt(strings.TrimSpace(idStr), 10, 64); err == nil && id > 0 {
				serverIDs = append(serverIDs, id)
			}
		}
		if len(serverIDs) > 0 {
			remoteLimit, remoteUsed, _ = h.repo.GetRemoteServerTrafficTotals(ctx, serverIDs)
		} else {
			remoteLimit, remoteUsed, _ = h.repo.GetAllRemoteServersTrafficTotals(ctx)
		}
	}
	if subscribeFile.TrafficLimit != nil && *subscribeFile.TrafficLimit > 0 {
		remoteLimit = int64(*subscribeFile.TrafficLimit * 1024 * 1024 * 1024)
	}
	return externalLimit + remoteLimit, externalUsed + remoteUsed, expireAt
}

// createSubInfoNodes 创建不会真实连通的 SS 信息节点，供客户端在节点列表顶部展示订阅状态。
func createSubInfoNodes(config storage.SystemConfig, expireAt *time.Time, remainingTraffic int64) []*yaml.Node {
	expireText := config.SubInfoExpirePrefix + " "
	if expireAt == nil {
		expireText += "永久"
	} else {
		expireText += expireAt.Format("2006-01-02")
	}
	trafficText := config.SubInfoTrafficPrefix + " " + formatSubInfoTraffic(remainingTraffic)

	createNode := func(name string) *yaml.Node {
		return &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "name"}, {Kind: yaml.ScalarNode, Value: name},
			{Kind: yaml.ScalarNode, Value: "type"}, {Kind: yaml.ScalarNode, Value: "ss"},
			{Kind: yaml.ScalarNode, Value: "server"}, {Kind: yaml.ScalarNode, Value: "sub.info.node"},
			{Kind: yaml.ScalarNode, Value: "port"}, {Kind: yaml.ScalarNode, Value: "443", Tag: "!!int"},
			{Kind: yaml.ScalarNode, Value: "password"}, {Kind: yaml.ScalarNode, Value: "SubInfoNode"},
			{Kind: yaml.ScalarNode, Value: "cipher"}, {Kind: yaml.ScalarNode, Value: "aes-128-gcm"},
		}}
	}
	return []*yaml.Node{createNode(expireText), createNode(trafficText)}
}

func isV2RayClientType(clientType string) bool {
	switch strings.ToLower(strings.TrimSpace(clientType)) {
	case "v2ray", "v2rayn", "v2rayng", "v2box":
		return true
	}
	return false
}

// prependSubInfoNodesToClash 在格式转换前将信息节点加入 proxies。
// 解析失败时保持原订阅，避免信息展示功能影响正常订阅下发。
func prependSubInfoNodesToClash(data []byte, config storage.SystemConfig, expireAt *time.Time, remainingTraffic int64) []byte {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return data
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return data
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "proxies" || root.Content[i+1].Kind != yaml.SequenceNode {
			continue
		}
		proxies := root.Content[i+1]
		proxies.Content = append(createSubInfoNodes(config, expireAt, remainingTraffic), proxies.Content...)
		out, err := yaml.Marshal(&doc)
		if err == nil {
			return out
		}
		return data
	}
	return data
}

func formatSubInfoTraffic(value int64) string {
	if value <= 0 {
		return "0B"
	}
	if gb := float64(value) / (1024 * 1024 * 1024); gb >= 1 {
		return fmt.Sprintf("%.2fGB", gb)
	}
	if mb := float64(value) / (1024 * 1024); mb >= 1 {
		return fmt.Sprintf("%.2fMB", mb)
	}
	return fmt.Sprintf("%.2fKB", float64(value)/1024)
}

func buildSubscriptionHeader(totalLimit, totalUsed int64, endDate *time.Time) string {
	download := strconv.FormatInt(totalUsed, 10)
	total := strconv.FormatInt(totalLimit, 10)
	return appendExpire("upload=0; download="+download+"; total="+total, endDate)
}

// 将映射的键作为切片返回
func getKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// GetExternalSubscriptionsFromFile 从 YAML 文件内容中提取外部订阅 URL
// 通过分析代理并查询数据库中的 raw_url（外部订阅链接）
// 还检查引用外部订阅的代理提供程序配置的代理提供程序
func GetExternalSubscriptionsFromFile(ctx context.Context, data []byte, username string, repo *storage.TrafficRepository) (map[string]bool, error) {
	usedURLs := make(map[string]bool)

	// 解析 YAML 内容
	var yamlContent map[string]any
	if err := yaml.Unmarshal(data, &yamlContent); err != nil {
		return usedURLs, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// 提取代理并查询数据库以获取其 raw_url
	if proxies, ok := yamlContent["proxies"].([]any); ok {
		logger.Info("[Subscription] 找到订阅文件中的代理节点", "count", len(proxies))

		// 收集所有代理名称
		proxyNames := make(map[string]bool)
		for _, proxy := range proxies {
			if proxyMap, ok := proxy.(map[string]any); ok {
				if name, ok := proxyMap["name"].(string); ok && name != "" {
					proxyNames[name] = true
				}
			}
		}

		if len(proxyNames) > 0 {
			logger.Info("[Subscription] 查询数据库获取外部订阅URL", "proxy_count", len(proxyNames))

			// 查询数据库中具有这些名称的节点
			nodes, err := repo.ListNodes(ctx, username)
			if err != nil {
				logger.Info("[Subscription] 查询节点列表失败", "error", err)
				return usedURLs, fmt.Errorf("failed to list nodes: %w", err)
			}

			// 收集使用到的外部订阅标签（节点的 Tag 字段）
			usedTags := make(map[string]bool)

			// 查找匹配的节点并收集其 raw_url 和标签
			for _, node := range nodes {
				if proxyNames[node.NodeName] {
					// 如果节点有 RawURL，直接使用
					if node.RawURL != "" {
						usedURLs[node.RawURL] = true
						logger.Info("[Subscription] 从节点找到外部订阅URL", "node_name", node.NodeName, "url", node.RawURL)
					}
					// 如果节点有 Tag（外部订阅名称），记录下来
					if node.Tag != "" && node.Tag != "手动输入" {
						usedTags[node.Tag] = true
						logger.Info("[Subscription] 节点来自外部订阅", "node_name", node.NodeName, "tag", node.Tag)
					}
				}
			}

			// 妙妙屋模式：通过节点的 Tag（外部订阅名称）找到外部订阅URL
			if len(usedTags) > 0 {
				logger.Info("[Subscription] 发现使用外部订阅的节点", "tag_count", len(usedTags))

				// 获取所有外部订阅
				externalSubs, err := repo.ListExternalSubscriptions(ctx, username)
				if err != nil {
					logger.Info("[Subscription] 获取外部订阅列表失败", "error", err)
				} else {
					// 根据 Tag（外部订阅名称）找到对应的 URL
					for _, sub := range externalSubs {
						if usedTags[sub.Name] {
							usedURLs[sub.URL] = true
							logger.Info("[Subscription] 从节点Tag找到外部订阅URL", "tag", sub.Name, "url", sub.URL)
						}
					}
				}
			}
		}
	}

	// 另请检查代理组中引用代理提供程序配置的“使用”字段
	// 这处理使用 proxy-providers + use 而不是直接代理的情况
	if proxyGroups, ok := yamlContent["proxy-groups"].([]any); ok {
		logger.Info("[Subscription] 检查 proxy-groups", "group_count", len(proxyGroups))
		providerNames := make(map[string]bool)
		groupNames := make(map[string]bool) // 妙妙屋模式：收集 proxy-group 的名称
		for _, group := range proxyGroups {
			if groupMap, ok := group.(map[string]any); ok {
				// 收集 proxy-group 名称（妙妙屋模式会创建同名的 proxy-group）
				if groupName, ok := groupMap["name"].(string); ok && groupName != "" {
					groupNames[groupName] = true
				}

				// 收集 use 字段中的 provider 名称（客户端模式）
				if useList, ok := groupMap["use"].([]any); ok {
					for _, use := range useList {
						if useName, ok := use.(string); ok && useName != "" {
							providerNames[useName] = true
							logger.Info("[Subscription] 找到 proxy-group 使用的 provider", "provider_name", useName)
						}
					}
				}
			}
		}

		// 合并两种模式的名称
		allNames := make(map[string]bool)
		for name := range providerNames {
			allNames[name] = true
		}
		for name := range groupNames {
			allNames[name] = true
		}

		if len(allNames) > 0 {
			logger.Info("[Subscription] 找到代理集合引用", "count", len(allNames), "from_use", len(providerNames), "from_groups", len(groupNames))

			// 获取该用户的所有代理提供商配置
			configs, err := repo.ListProxyProviderConfigs(ctx, username)
			if err != nil {
				logger.Info("[Subscription] 查询代理集合配置失败", "error", err)
			} else {
				logger.Info("[Subscription] 查询到用户的代理集合配置", "count", len(configs))
				// 获取地图配置 -> URL 的外部订阅
				externalSubs, err := repo.ListExternalSubscriptions(ctx, username)
				if err != nil {
					logger.Info("[Subscription] 获取外部订阅列表失败", "error", err)
				} else {
					logger.Info("[Subscription] 查询到用户的外部订阅", "count", len(externalSubs))
					// 构建外部订阅ID -> URL映射
					subIDToURL := make(map[int64]string)
					for _, sub := range externalSubs {
						subIDToURL[sub.ID] = sub.URL
					}

					// 查找与名称匹配的配置并获取其外部订阅 URL
					for _, config := range configs {
						logger.Info("[Subscription] 检查配置", "config_name", config.Name, "external_sub_id", config.ExternalSubscriptionID, "process_mode", config.ProcessMode)
						if allNames[config.Name] {
							if url, ok := subIDToURL[config.ExternalSubscriptionID]; ok {
								usedURLs[url] = true
								logger.Info("[Subscription] 从代理集合配置找到外部订阅URL", "config_name", config.Name, "mode", config.ProcessMode, "url", url)
							} else {
								logger.Info("[Subscription] 配置的外部订阅ID未找到对应URL", "config_name", config.Name, "external_sub_id", config.ExternalSubscriptionID)
							}
						}
					}
				}
			}
		} else {
			logger.Info("[Subscription] proxy-groups 中未找到引用")
		}
	} else {
		logger.Info("[Subscription] YAML 中未找到 proxy-groups")
	}

	// 检查 proxy-providers 部分（用于客户端模式的代理集合配置）
	// 当处理模式为客户端模式时，YAML 文件中包含 proxy-providers 配置，URL 为内部 API 端点
	if proxyProviders, ok := yamlContent["proxy-providers"].(map[string]any); ok {
		logger.Info("[Subscription] 找到 proxy-providers 配置", "count", len(proxyProviders))

		// 构建配置 ID -> 外部订阅 URL 映射
		configIDToURL := make(map[int64]string)
		configs, err := repo.ListProxyProviderConfigs(ctx, username)
		if err == nil {
			externalSubs, err := repo.ListExternalSubscriptions(ctx, username)
			if err == nil {
				// 构建外部订阅 ID -> URL 映射
				subIDToURL := make(map[int64]string)
				for _, sub := range externalSubs {
					subIDToURL[sub.ID] = sub.URL
				}
				// 将配置 ID 映射到外部订阅 URL
				for _, config := range configs {
					if url, ok := subIDToURL[config.ExternalSubscriptionID]; ok {
						configIDToURL[config.ID] = url
					}
				}
			}
		}

		// 解析每个 provider 的 URL，查找内部 API 端点
		for providerName, provider := range proxyProviders {
			if providerMap, ok := provider.(map[string]any); ok {
				if urlStr, ok := providerMap["url"].(string); ok && urlStr != "" {
					// 检查是否为内部 API 端点：/api/proxy-provider/{id}
					if configIDStr, found := strings.CutPrefix(urlStr, "/api/proxy-provider/"); found {
						if configID, err := strconv.ParseInt(configIDStr, 10, 64); err == nil {
							if url, ok := configIDToURL[configID]; ok {
								usedURLs[url] = true
								logger.Info("[Subscription] 从 proxy-providers 找到外部订阅URL",
									"provider_name", providerName, "config_id", configID, "url", url)
							}
						}
					}
				}
			}
		}
	}

	logger.Info("[Subscription] 找到当前文件引用的外部订阅URL", "count", len(usedURLs))
	return usedURLs, nil
}

// 仅同步指定的外部订阅
func syncReferencedExternalSubscriptions(ctx context.Context, repo *storage.TrafficRepository, subscribeDir, username string, subsToSync []storage.ExternalSubscription) error {
	if repo == nil || username == "" || len(subsToSync) == 0 {
		return fmt.Errorf("invalid parameters")
	}

	// 获取用户设置以检查匹配规则
	userSettings, err := repo.GetUserSettings(ctx, username)
	if err != nil {
		userSettings.MatchRule = "node_name"
		userSettings.SyncScope = "saved_only"
		userSettings.KeepNodeName = true
		userSettings.NodeNameFilter = defaultNodeNameFilterPattern
	}

	logger.Info("[Subscription] 用户需要同步的外部订阅", "user", username, "count", len(subsToSync), "match_rule", userSettings.MatchRule)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// 跟踪已同步的节点总数
	totalNodesSynced := 0

	for _, sub := range subsToSync {
		subSyncStart := time.Now()
		nodeCount, updatedSub, err := syncSingleExternalSubscription(ctx, client, repo, subscribeDir, username, sub, userSettings)
		if err != nil {
			logger.Info("[⏱️ 耗时监测] 同步订阅失败", "name", sub.Name, "url", sub.URL, "error", err, "duration_ms", time.Since(subSyncStart).Milliseconds())
			continue
		}

		totalNodesSynced += nodeCount

		// 更新上次同步时间和节点数
		// 使用包含来自 parseAndUpdateTrafficInfo 的流量信息的 UpdatedSub
		now := time.Now()
		updatedSub.LastSyncAt = &now
		updatedSub.NodeCount = nodeCount
		if err := repo.UpdateExternalSubscription(ctx, updatedSub); err != nil {
			logger.Info("[Subscription] 更新订阅同步时间失败", "name", sub.Name, "error", err)
		}
		logger.Info("[⏱️ 耗时监测] 外部订阅同步完成", "name", sub.Name, "node_count", nodeCount, "duration_ms", time.Since(subSyncStart).Milliseconds())
	}

	logger.Info("[Subscription] 同步完成", "total_nodes", totalNodesSynced, "subscription_count", len(subsToSync))

	// 同步完成后，失效相关缓存：
	// 1. 失效外部订阅内容缓存（proxy_provider_serve.go 中的 5 分钟缓存）
	// 2. 失效代理集合节点缓存
	// 这样下次获取订阅时会使用最新的节点数据
	syncedSubIDs := make(map[int64]bool)
	syncedSubURLs := make(map[string]bool)
	for _, sub := range subsToSync {
		syncedSubIDs[sub.ID] = true
		syncedSubURLs[sub.URL] = true
	}

	// 失效外部订阅内容缓存
	for url := range syncedSubURLs {
		InvalidateSubscriptionContentCache(url)
		logger.Info("[Subscription] 失效外部订阅内容缓存", "url", url)
	}

	return nil
}

func (h *SubscriptionHandler) loadTokenInvalidContent() []byte {
	tokenPath := filepath.Join("data", tokenInvalidFilename)
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		logger.Info("[Token Invalid] 读取data/token_invalid.yaml失败，使用内置默认内容", "path", tokenPath, "error", err)
		return []byte(tokenInvalidYAML)
	}
	if len(data) == 0 {
		logger.Info("[Token Invalid] data/token_invalid.yaml为空，使用内置默认内容", "path", tokenPath)
		return []byte(tokenInvalidYAML)
	}
	logger.Info("[Token Invalid] 使用自定义token_invalid.yaml", "path", tokenPath)
	return data
}

// 通过客户端类型转换提供令牌无效 YAML 内容
func (h *SubscriptionHandler) serveTokenInvalidResponse(w http.ResponseWriter, r *http.Request) {
	data := h.loadTokenInvalidContent()

	// 根据参数t的类型调用substore的转换代码
	clientType := resolveClientType(r)
	contentType := "text/yaml; charset=utf-8"
	ext := ".yaml"

	// 如果指定了客户端类型且不是clash/clashmeta，进行转换
	if clientType != "" && clientType != "clash" && clientType != "clashmeta" {
		convertedData, err := h.convertSubscription(r.Context(), data, clientType)
		if err != nil {
			// 转换失败，记录日志但继续返回YAML
			logger.Info("[Token Invalid] 转换失败", "client_type", clientType, "error", err)
		} else {
			data = convertedData

			// 根据客户端类型设置content type和扩展名
			switch clientType {
			case "surge", "surgemac", "loon", "qx", "surfboard", "shadowrocket", "clash-to-surge", "clash-to-loon", "clash-to-loon-kelee":
				contentType = "text/plain; charset=utf-8"
				ext = ".txt"
			case "sing-box":
				contentType = "application/json; charset=utf-8"
				ext = ".json"
			case "v2ray", "uri":
				contentType = "text/plain; charset=utf-8"
				ext = ".txt"
			default:
				contentType = "text/yaml; charset=utf-8"
				ext = ".yaml"
			}
		}
	}

	// 同主订阅端点:sysConfig 是 JSON 且当前是 YAML content-type 就转 JSON,保持格式一致
	if h.repo != nil {
		if sysCfg, err := h.repo.GetSystemConfig(r.Context()); err == nil && sysCfg.SubscriptionOutputFormat == "json" &&
			(contentType == "text/yaml; charset=utf-8" || contentType == "text/yaml; charset=utf-8; charset=UTF-8") {
			if jsonBytes, jsonErr := marshalSubscriptionJSON(data); jsonErr == nil {
				data = jsonBytes
				contentType = "application/json; charset=utf-8"
				ext = ".json"
			}
		}
	}

	attachmentName := url.PathEscape("Token已失效" + ext)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("profile-update-interval", "24")
	if clientType == "" {
		w.Header().Set("content-disposition", "attachment;filename*=UTF-8''"+attachmentName)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)

	logger.Info("[Token Invalid] 返回Token失效响应", "client_type", clientType)
}

// clientKeepsClashRules 判断某客户端格式是否**原样保留 clash rules/rule-providers**。
//
// 只有同构 YAML 的 clash 系会保留:clash / clashmeta(直出,不经转换)、stash(producer 搬 rules)。
// loon/surge/qx/sing-box/egern/surfboard/shadowrocket 等 producer 只转 proxies,rules 一律丢弃。
// 覆写脚本若改了 rules,在返回 false 的格式下修改会失效 —— 调用方据此提示用户。
func clientKeepsClashRules(clientType string) bool {
	switch strings.ToLower(strings.TrimSpace(clientType)) {
	case "", "clash", "clashmeta", "stash":
		return true
	}
	return false
}

func (h *SubscriptionHandler) runPostFetchScript(ctx context.Context, script string, yamlData []byte) ([]byte, error) {
	var rootNode yaml.Node
	if err := yaml.Unmarshal(yamlData, &rootNode); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	config, err := yamlNodeToMap(&rootNode)
	if err != nil {
		return nil, fmt.Errorf("convert YAML node: %w", err)
	}

	modified, err := scriptengine.RunPostFetch(ctx, script, config)
	if err != nil {
		return nil, err
	}

	out, err := yaml.Marshal(modified)
	if err != nil {
		return nil, fmt.Errorf("marshal YAML: %w", err)
	}
	return out, nil
}

// ConvertSubscription 将 YAML 订阅文件转换为指定的客户端格式
// shadowrocketProducerFor 返回 shadowrocket 系列要用的 producer:
//   - "shadowrocket"          → ShadowrocketProducer(节点转换)
//   - "clash-to-shadowrocket" → ShadowrocketTemplateProducer(完整 clash→shadowrocket 配置)
//
// 二者在工厂里都以 "shadowrocket" 注册(template 覆盖了 plain),无法按类型区分,故显式实例化。
// 其它类型返回 nil,交由调用方走工厂。
func shadowrocketProducerFor(clientType string) substore.Producer {
	switch clientType {
	case "shadowrocket":
		return substore.NewShadowrocketProducer()
	case "clash-to-shadowrocket":
		return substore.NewShadowrocketTemplateProducer()
	default:
		return nil
	}
}

func (h *SubscriptionHandler) convertSubscription(ctx context.Context, yamlData []byte, clientType string) ([]byte, error) {
	// 使用 yaml.Node 解析, 解决值前导零的问题
	var rootNode yaml.Node
	if err := yaml.Unmarshal(yamlData, &rootNode); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	config, err := yamlNodeToMap(&rootNode)
	if err != nil {
		return nil, fmt.Errorf("failed to convert YAML node: %w", err)
	}

	// 读取yaml中proxies属性的节点列表
	proxiesRaw, ok := config["proxies"]
	if !ok {
		return nil, errors.New("no 'proxies' field found in YAML")
	}

	proxiesArray, ok := proxiesRaw.([]interface{})
	if !ok {
		return nil, errors.New("'proxies' field is not an array")
	}

	// 转换成substore的Proxy结构
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

	if len(proxies) == 0 {
		return nil, errors.New("no valid proxies found in YAML")
	}

	// clash-to-surge 类型使用 BuildCompleteSurgeConfig 生成完整的 Surge 配置
	if clientType == "clash-to-surge" {
		return h.convertClashToSurge(config, proxies)
	}

	// clash-to-loon 类型使用 BuildCompleteLoonConfig 生成完整的 Loon 配置(同步自 mmw v0.7.2 #84)
	if clientType == "clash-to-loon" {
		return h.convertClashToLoon(config, proxies)
	}

	// clash-to-loon-kelee 使用 kelee 模板,只填充 Proxy 节点(同步自 mmw v0.7.2 #84)
	if clientType == "clash-to-loon-kelee" {
		result, err := substore.BuildLoonKeleeConfig(proxies)
		if err != nil {
			return nil, fmt.Errorf("failed to build Loon kelee config: %w", err)
		}
		return []byte(result), nil
	}

	// shadowrocket / clash-to-shadowrocket 显式取对应 producer(工厂里两者都注册成 "shadowrocket",
	// template 覆盖了 plain,只能显式实例化);其余类型走工厂。
	producer := shadowrocketProducerFor(clientType)
	if producer == nil {
		producer, err = substore.GetDefaultFactory().GetProducer(clientType)
		if err != nil {
			return nil, fmt.Errorf("unsupported client type '%s': %w", clientType, err)
		}
	}

	// 调用Produce方法生成转换后的节点, 传入完整配置供需要的 Producer 使用（如 Stash）
	// 获取系统配置以获取客户端兼容模式设置
	systemConfig, _ := h.repo.GetSystemConfig(ctx)
	opts := &substore.ProduceOptions{
		FullConfig:              config,
		ClientCompatibilityMode: systemConfig.ClientCompatibilityMode,
	}

	// Surge 系客户端:逐节点探测被过滤的节点,打日志方便排查"订阅没节点"问题。
	// Produce 内部静默 continue 跳过不支持的类型,不打任何日志。
	if isSurgeClientType(clientType) {
		surgeProducer := substore.NewSurgeProducer()
		var filteredNodes []string
		for _, p := range proxies {
			if _, perr := surgeProducer.ProduceOne(p, "", &substore.ProduceOptions{}); perr != nil {
				name, _ := p["name"].(string)
				typ, _ := p["type"].(string)
				filteredNodes = append(filteredNodes, fmt.Sprintf("%s(%s:%v)", name, typ, perr))
			}
		}
		if len(filteredNodes) > 0 {
			logger.Warn("[Surge订阅] 部分节点因类型不受 Surge 支持被过滤",
				"filtered_count", len(filteredNodes), "total", len(proxies),
				"client_type", clientType,
				"nodes", strings.Join(filteredNodes, ", "))
		}
		if len(filteredNodes) == len(proxies) {
			logger.Warn("[Surge订阅] 全部节点被过滤,订阅将没有任何节点",
				"total", len(proxies), "client_type", clientType)
		}
	}

	result, err := producer.Produce(proxies, "", opts)
	if err != nil {
		return nil, fmt.Errorf("failed to produce subscription: %w", err)
	}
	switch v := result.(type) {
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	default:
		return nil, fmt.Errorf("unexpected result type from producer: %T, expected string or []byte", result)
	}
}

// ConvertClashToSurge 使用规则将 Clash 配置转换为 Surge 格式
func (h *SubscriptionHandler) convertClashToSurge(config map[string]interface{}, proxies []substore.Proxy) ([]byte, error) {
	normalizeSurgeProxies(proxies)
	// 解析 Clash 配置结构
	clashConfig := &substore.ClashConfig{}

	// 解析基本字段
	if port, ok := config["port"].(int); ok {
		clashConfig.Port = port
	}
	if socksPort, ok := config["socks-port"].(int); ok {
		clashConfig.SocksPort = socksPort
	}
	if allowLan, ok := config["allow-lan"].(bool); ok {
		clashConfig.AllowLan = allowLan
	}
	if mode, ok := config["mode"].(string); ok {
		clashConfig.Mode = mode
	}
	if logLevel, ok := config["log-level"].(string); ok {
		clashConfig.LogLevel = logLevel
	}
	if externalController, ok := config["external-controller"].(string); ok {
		clashConfig.ExternalController = externalController
	}

	// 解析 DNS 配置
	if dnsRaw, ok := config["dns"].(map[string]interface{}); ok {
		if enable, ok := dnsRaw["enable"].(bool); ok {
			clashConfig.DNS.Enable = enable
		}
		if ipv6, ok := dnsRaw["ipv6"].(bool); ok {
			clashConfig.DNS.IPv6 = ipv6
		}
		if enhancedMode, ok := dnsRaw["enhanced-mode"].(string); ok {
			clashConfig.DNS.EnhancedMode = enhancedMode
		}
		if nameservers, ok := dnsRaw["nameserver"].([]interface{}); ok {
			for _, ns := range nameservers {
				if nsStr, ok := ns.(string); ok {
					clashConfig.DNS.Nameserver = append(clashConfig.DNS.Nameserver, nsStr)
				}
			}
		}
		if defaultNS, ok := dnsRaw["default-nameserver"].([]interface{}); ok {
			for _, ns := range defaultNS {
				if nsStr, ok := ns.(string); ok {
					clashConfig.DNS.DefaultNameserver = append(clashConfig.DNS.DefaultNameserver, nsStr)
				}
			}
		}
	}

	// 解析 proxy-groups
	if groupsRaw, ok := config["proxy-groups"].([]interface{}); ok {
		for _, g := range groupsRaw {
			if gMap, ok := g.(map[string]interface{}); ok {
				group := substore.ClashProxyGroup{}
				if name, ok := gMap["name"].(string); ok {
					group.Name = name
				}
				if gType, ok := gMap["type"].(string); ok {
					group.Type = gType
				}
				if url, ok := gMap["url"].(string); ok {
					group.URL = url
				}
				if interval, ok := gMap["interval"].(int); ok {
					group.Interval = interval
				}
				if tolerance, ok := gMap["tolerance"].(int); ok {
					group.Tolerance = tolerance
				}
				if proxiesArr, ok := gMap["proxies"].([]interface{}); ok {
					for _, p := range proxiesArr {
						if pStr, ok := p.(string); ok {
							group.Proxies = append(group.Proxies, pStr)
						}
					}
				}
				clashConfig.ProxyGroups = append(clashConfig.ProxyGroups, group)
			}
		}
	}

	// 解析 rules
	if rulesRaw, ok := config["rules"].([]interface{}); ok {
		for _, r := range rulesRaw {
			if rStr, ok := r.(string); ok {
				clashConfig.Rules = append(clashConfig.Rules, rStr)
			}
		}
	}

	// 解析 rule-providers
	if providersRaw, ok := config["rule-providers"].(map[string]interface{}); ok {
		clashConfig.RuleProviders = make(map[string]substore.ClashRuleProvider)
		for name, p := range providersRaw {
			if pMap, ok := p.(map[string]interface{}); ok {
				provider := substore.ClashRuleProvider{}
				if pType, ok := pMap["type"].(string); ok {
					provider.Type = pType
				}
				if behavior, ok := pMap["behavior"].(string); ok {
					provider.Behavior = behavior
				}
				if url, ok := pMap["url"].(string); ok {
					provider.URL = url
				}
				if path, ok := pMap["path"].(string); ok {
					provider.Path = path
				}
				if interval, ok := pMap["interval"].(int); ok {
					provider.Interval = interval
				}
				if format, ok := pMap["format"].(string); ok {
					provider.Format = format
				}
				clashConfig.RuleProviders[name] = provider
			}
		}
	}

	// 使用 BuildCompleteSurgeConfig 生成完整 Surge 配置
	// 先探测哪些节点会被过滤,打日志方便排查"订阅没节点"问题。
	surgeProducerForLog := substore.NewSurgeProducer()
	var clashToSurgeFiltered []string
	for _, p := range proxies {
		if _, perr := surgeProducerForLog.ProduceOne(p, "", &substore.ProduceOptions{}); perr != nil {
			name, _ := p["name"].(string)
			typ, _ := p["type"].(string)
			clashToSurgeFiltered = append(clashToSurgeFiltered, fmt.Sprintf("%s(%s:%v)", name, typ, perr))
		}
	}
	if len(clashToSurgeFiltered) > 0 {
		logger.Warn("[clash-to-surge] 部分节点因类型不受 Surge 支持被过滤",
			"filtered_count", len(clashToSurgeFiltered), "total", len(proxies),
			"nodes", strings.Join(clashToSurgeFiltered, ", "))
	}
	if len(clashToSurgeFiltered) == len(proxies) {
		logger.Warn("[clash-to-surge] 全部节点被过滤,订阅将没有任何节点", "total", len(proxies))
	}
	surgeConfig, err := substore.BuildCompleteSurgeConfig(clashConfig, proxies, nil, false)
	if err != nil {
		return nil, fmt.Errorf("failed to build Surge config: %w", err)
	}

	return []byte(surgeConfig), nil
}

// convertClashToLoon 把 Clash config 转成完整 Loon 配置(同步自 mmw v0.7.2 #84)
func (h *SubscriptionHandler) convertClashToLoon(config map[string]interface{}, proxies []substore.Proxy) ([]byte, error) {
	clashConfig := &substore.ClashConfig{}

	if port, ok := config["port"].(int); ok {
		clashConfig.Port = port
	}
	if socksPort, ok := config["socks-port"].(int); ok {
		clashConfig.SocksPort = socksPort
	}
	if allowLan, ok := config["allow-lan"].(bool); ok {
		clashConfig.AllowLan = allowLan
	}
	if mode, ok := config["mode"].(string); ok {
		clashConfig.Mode = mode
	}
	if logLevel, ok := config["log-level"].(string); ok {
		clashConfig.LogLevel = logLevel
	}

	// 解析 proxy-groups
	if groupsRaw, ok := config["proxy-groups"].([]interface{}); ok {
		for _, g := range groupsRaw {
			gMap, ok := g.(map[string]interface{})
			if !ok {
				continue
			}
			group := substore.ClashProxyGroup{}
			if name, ok := gMap["name"].(string); ok {
				group.Name = name
			}
			if gType, ok := gMap["type"].(string); ok {
				group.Type = gType
			}
			if url, ok := gMap["url"].(string); ok {
				group.URL = url
			}
			if interval, ok := gMap["interval"].(int); ok {
				group.Interval = interval
			}
			if tolerance, ok := gMap["tolerance"].(int); ok {
				group.Tolerance = tolerance
			}
			if strategy, ok := gMap["strategy"].(string); ok {
				group.Strategy = strategy
			}
			if proxiesArr, ok := gMap["proxies"].([]interface{}); ok {
				for _, p := range proxiesArr {
					if pStr, ok := p.(string); ok {
						group.Proxies = append(group.Proxies, pStr)
					}
				}
			}
			clashConfig.ProxyGroups = append(clashConfig.ProxyGroups, group)
		}
	}

	// 解析 rules
	if rulesRaw, ok := config["rules"].([]interface{}); ok {
		for _, r := range rulesRaw {
			if rStr, ok := r.(string); ok {
				clashConfig.Rules = append(clashConfig.Rules, rStr)
			}
		}
	}

	// 解析 rule-providers
	if providersRaw, ok := config["rule-providers"].(map[string]interface{}); ok {
		clashConfig.RuleProviders = make(map[string]substore.ClashRuleProvider)
		for name, p := range providersRaw {
			pMap, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			provider := substore.ClashRuleProvider{}
			if pType, ok := pMap["type"].(string); ok {
				provider.Type = pType
			}
			if behavior, ok := pMap["behavior"].(string); ok {
				provider.Behavior = behavior
			}
			if url, ok := pMap["url"].(string); ok {
				provider.URL = url
			}
			if path, ok := pMap["path"].(string); ok {
				provider.Path = path
			}
			if interval, ok := pMap["interval"].(int); ok {
				provider.Interval = interval
			}
			if format, ok := pMap["format"].(string); ok {
				provider.Format = format
			}
			clashConfig.RuleProviders[name] = provider
		}
	}

	loonConfig, err := substore.BuildCompleteLoonConfig(clashConfig, proxies)
	if err != nil {
		return nil, fmt.Errorf("failed to build Loon config: %w", err)
	}

	return []byte(loonConfig), nil
}

// 修复 WireGuard 节点的 allowed-ips 字段类型
func fixWireGuardAllowedIPs(proxiesNode *yaml.Node) {
	if proxiesNode == nil || proxiesNode.Kind != yaml.SequenceNode {
		return
	}

	for _, proxyNode := range proxiesNode.Content {
		if proxyNode.Kind != yaml.MappingNode {
			continue
		}

		// 检查这是否是 WireGuard 节点
		isWireGuard := false
		for i := 0; i < len(proxyNode.Content); i += 2 {
			if i+1 >= len(proxyNode.Content) {
				break
			}
			if proxyNode.Content[i].Value == "type" && proxyNode.Content[i+1].Value == "wireguard" {
				isWireGuard = true
				break
			}
		}

		if !isWireGuard {
			continue
		}

		// 修复 allowed-ips 字段
		for i := 0; i < len(proxyNode.Content); i += 2 {
			if i+1 >= len(proxyNode.Content) {
				break
			}
			keyNode := proxyNode.Content[i]
			valueNode := proxyNode.Content[i+1]

			if keyNode.Value == "allowed-ips" {
				// 如果它已经是序列节点，只需清除所有字符串标签
				if valueNode.Kind == yaml.SequenceNode {
					valueNode.Tag = ""
					valueNode.Style = 0
					// 还清除子节点的标签
					for _, childNode := range valueNode.Content {
						if childNode.Tag == "!!str" {
							childNode.Tag = ""
						}
					}
				} else if valueNode.Kind == yaml.ScalarNode {
					// 如果它是带有 !!str 标签的标量或看起来像 JSON 数组，请清除该标签
					if valueNode.Tag == "!!str" || valueNode.Tag == "tag:yaml.org,2002:str" {
						valueNode.Tag = ""
						valueNode.Style = 0
					}
				}
				break
			}
		}
	}
}

// 重新排序序列节点中每个代理的字段
func reorderProxies(seqNode *yaml.Node) {
	if seqNode == nil || seqNode.Kind != yaml.SequenceNode {
		return
	}

	// 处理序列中的每个代理
	for _, proxyNode := range seqNode.Content {
		if proxyNode.Kind == yaml.MappingNode {
			reorderProxyNode(proxyNode)
		}
	}
}

// reorderProxyNode 重新排序代理配置字段
// 优先顺序：名称、类型、服务器、端口，然后是所有其他字段
func reorderProxyNode(proxyNode *yaml.Node) {
	if proxyNode == nil || proxyNode.Kind != yaml.MappingNode {
		return
	}

	// 按所需顺序排列优先级字段
	priorityFields := []string{"name", "type", "server", "port"}

	// 创建现有字段的地图
	fieldMap := make(map[string]*yaml.Node)
	fieldKeyNodes := make(map[string]*yaml.Node) // 存储原始关键节点以保留风格
	remainingFields := []*yaml.Node{}

	// 解析现有字段
	for i := 0; i < len(proxyNode.Content); i += 2 {
		if i+1 >= len(proxyNode.Content) {
			break
		}
		keyNode := proxyNode.Content[i]
		valueNode := proxyNode.Content[i+1]

		// 对 allowed-ips 字段进行特殊处理，以确保将其视为数组
		if keyNode.Value == "allowed-ips" && valueNode.Kind == yaml.ScalarNode {
			// 如果它是一个看起来像 JSON 数组的标量字符串，请显式标记它
			if valueNode.Tag == "!!str" || (valueNode.Style == yaml.DoubleQuotedStyle &&
				len(valueNode.Value) > 0 && valueNode.Value[0] == '[') {
				// 删除 !!str 标签并让 YAML 推断类型
				valueNode.Tag = ""
				valueNode.Style = 0
			}
		}

		// 检查这是否是优先字段
		isPriority := false
		for _, pf := range priorityFields {
			if keyNode.Value == pf {
				fieldMap[pf] = valueNode
				fieldKeyNodes[pf] = keyNode
				isPriority = true
				break
			}
		}

		// 如果不是优先级字段，请保存键和值以供以后使用
		if !isPriority {
			remainingFields = append(remainingFields, keyNode, valueNode)
		}
	}

	// 使用有序字段重建内容
	newContent := []*yaml.Node{}

	// 首先添加优先级字段（按顺序）
	for _, fieldName := range priorityFields {
		if valueNode, exists := fieldMap[fieldName]; exists {
			// 如果可用，则使用原始关键节点，否则创建新的
			keyNode := fieldKeyNodes[fieldName]
			if keyNode == nil {
				keyNode = &yaml.Node{
					Kind:  yaml.ScalarNode,
					Value: fieldName,
				}
			}
			newContent = append(newContent, keyNode, valueNode)
		}
	}

	// 添加剩余字段
	newContent = append(newContent, remainingFields...)

	// 替换原来的内容
	proxyNode.Content = newContent
}

// 重新排序序列节点中每个代理组的字段
func reorderProxyGroups(seqNode *yaml.Node) {
	if seqNode == nil || seqNode.Kind != yaml.SequenceNode {
		return
	}

	// 按顺序处理每个代理组
	for _, groupNode := range seqNode.Content {
		if groupNode.Kind == yaml.MappingNode {
			reorderProxyGroupFields(groupNode)
		}
	}
}

// injectDialerProxyFromGroups 读 proxy-groups 中各组的 dialer-proxy-group 字段,
// 给该组 proxies 数组里的"叶子节点名"在顶层 proxies 加 dialer-proxy: <值>。
//   - 已有 dialer-proxy 的节点跳过(尊重链式代理 chain_proxy_node_id 注入的)
//   - 引用的 dialer-proxy-group 必须是已存在的代理组,否则跳过
//   - DIRECT / REJECT / PASS 跳过
//   - 同节点被多组绑定时,按 proxy-groups 出现顺序取第一个
func injectDialerProxyFromGroups(rootMap *yaml.Node) {
	var proxyGroupsNode, proxiesNode *yaml.Node
	for i := 0; i < len(rootMap.Content)-1; i += 2 {
		switch rootMap.Content[i].Value {
		case "proxy-groups":
			proxyGroupsNode = rootMap.Content[i+1]
		case "proxies":
			proxiesNode = rootMap.Content[i+1]
		}
	}
	if proxyGroupsNode == nil || proxyGroupsNode.Kind != yaml.SequenceNode {
		return
	}
	if proxiesNode == nil || proxiesNode.Kind != yaml.SequenceNode {
		return
	}

	groupNames := make(map[string]bool)
	type groupInfo struct {
		dialerGroup string
		proxies     []string
	}
	groups := make(map[string]*groupInfo)
	var orderedGroupNames []string
	for _, gNode := range proxyGroupsNode.Content {
		if gNode.Kind != yaml.MappingNode {
			continue
		}
		var name, dialerGroup string
		var pxList []string
		for i := 0; i < len(gNode.Content)-1; i += 2 {
			switch gNode.Content[i].Value {
			case "name":
				name = gNode.Content[i+1].Value
			case "dialer-proxy-group":
				dialerGroup = gNode.Content[i+1].Value
			case "proxies":
				if gNode.Content[i+1].Kind == yaml.SequenceNode {
					for _, pn := range gNode.Content[i+1].Content {
						pxList = append(pxList, pn.Value)
					}
				}
			}
		}
		if name == "" {
			continue
		}
		groupNames[name] = true
		groups[name] = &groupInfo{dialerGroup: dialerGroup, proxies: pxList}
		orderedGroupNames = append(orderedGroupNames, name)
	}

	isBuiltIn := func(v string) bool { return v == "DIRECT" || v == "REJECT" || v == "PASS" }
	nameToDialer := make(map[string]string)
	for _, name := range orderedGroupNames {
		info := groups[name]
		if info.dialerGroup == "" || !groupNames[info.dialerGroup] {
			continue
		}
		for _, p := range info.proxies {
			if isBuiltIn(p) || groupNames[p] {
				continue
			}
			if _, dup := nameToDialer[p]; !dup {
				nameToDialer[p] = info.dialerGroup
			}
		}
	}
	if len(nameToDialer) == 0 {
		return
	}

	for _, pNode := range proxiesNode.Content {
		if pNode.Kind != yaml.MappingNode {
			continue
		}
		var pName string
		hasDialerAlready := false
		for i := 0; i < len(pNode.Content)-1; i += 2 {
			switch pNode.Content[i].Value {
			case "name":
				pName = pNode.Content[i+1].Value
			case "dialer-proxy":
				hasDialerAlready = true
			}
		}
		if hasDialerAlready {
			continue
		}
		target, ok := nameToDialer[pName]
		if !ok {
			continue
		}
		pNode.Content = append(pNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "dialer-proxy"},
			&yaml.Node{Kind: yaml.ScalarNode, Value: target},
		)
	}
}

// pruneUnreferencedProxies 解析模板订阅生成的 YAML,把顶层 proxies: 数组里"未被任何 proxy-group 引用"的节点删掉。
// 复用 substore.CollectUsedProxyNamesFromGroups 拿 used 集合,然后过滤 proxies.Content。
// 无 proxy-groups / used 集合为空(理论上不应该,但若发生) → 不裁剪,原样返回。
// 解析失败 / 重新 Marshal 失败 → 返回原数据 + error,调用方决定是否 fallback。
func pruneUnreferencedProxies(data []byte) ([]byte, error) {
	if len(data) == 0 {
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

	var proxiesNode, groupsNode *yaml.Node
	for i := 0; i < len(doc.Content)-1; i += 2 {
		switch doc.Content[i].Value {
		case "proxies":
			proxiesNode = doc.Content[i+1]
		case "proxy-groups":
			groupsNode = doc.Content[i+1]
		}
	}
	if groupsNode == nil || proxiesNode == nil || proxiesNode.Kind != yaml.SequenceNode {
		return data, nil
	}

	used := substore.CollectUsedProxyNamesFromGroups(groupsNode)
	if len(used) == 0 {
		return data, nil
	}

	kept := make([]*yaml.Node, 0, len(proxiesNode.Content))
	removed := 0
	for _, item := range proxiesNode.Content {
		if item.Kind != yaml.MappingNode {
			kept = append(kept, item)
			continue
		}
		var name string
		for j := 0; j < len(item.Content)-1; j += 2 {
			if item.Content[j].Value == "name" {
				name = item.Content[j+1].Value
				break
			}
		}
		if name == "" || used[name] {
			kept = append(kept, item)
		} else {
			removed++
		}
	}
	if removed == 0 {
		return data, nil
	}
	proxiesNode.Content = kept

	out, err := MarshalYAMLWithIndent(&root)
	if err != nil {
		return data, err
	}
	return []byte(RemoveUnicodeEscapeQuotes(string(out))), nil
}

// stripDialerProxyGroup 把每个代理组的 dialer-proxy-group 字段移除
// (MMW 自定义字段,不应出现在客户端订阅响应里)。
func stripDialerProxyGroup(proxyGroupsNode *yaml.Node) {
	if proxyGroupsNode == nil || proxyGroupsNode.Kind != yaml.SequenceNode {
		return
	}
	for _, groupNode := range proxyGroupsNode.Content {
		if groupNode.Kind != yaml.MappingNode {
			continue
		}
		newContent := make([]*yaml.Node, 0, len(groupNode.Content))
		for i := 0; i < len(groupNode.Content)-1; i += 2 {
			if groupNode.Content[i].Value == "dialer-proxy-group" {
				continue
			}
			newContent = append(newContent, groupNode.Content[i], groupNode.Content[i+1])
		}
		groupNode.Content = newContent
	}
}

// reorderProxyGroupFields 重新排序代理组配置字段
// 优先级顺序：名称、类型、策略、代理、url、间隔、容差、惰性、隐藏
func reorderProxyGroupFields(groupNode *yaml.Node) {
	if groupNode == nil || groupNode.Kind != yaml.MappingNode {
		return
	}

	// 按所需顺序排列优先级字段
	priorityFields := []string{"name", "type", "strategy", "proxies", "url", "interval", "tolerance", "lazy", "hidden"}

	// 创建现有字段的地图
	fieldMap := make(map[string]*yaml.Node)
	remainingFields := []*yaml.Node{}

	// 解析现有字段
	for i := 0; i < len(groupNode.Content); i += 2 {
		if i+1 >= len(groupNode.Content) {
			break
		}
		keyNode := groupNode.Content[i]
		valueNode := groupNode.Content[i+1]

		// 检查这是否是优先字段
		isPriority := false
		for _, pf := range priorityFields {
			if keyNode.Value == pf {
				fieldMap[pf] = valueNode
				isPriority = true
				break
			}
		}

		// 如果不是优先级字段，请保存键和值以供以后使用
		if !isPriority {
			remainingFields = append(remainingFields, keyNode, valueNode)
		}
	}

	// 使用有序字段重建内容
	newContent := []*yaml.Node{}

	// 首先添加优先级字段（按顺序）
	for _, fieldName := range priorityFields {
		if valueNode, exists := fieldMap[fieldName]; exists {
			keyNode := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: fieldName,
			}
			newContent = append(newContent, keyNode, valueNode)
		}
	}

	// 添加剩余字段
	newContent = append(newContent, remainingFields...)

	// 替换原来的内容
	groupNode.Content = newContent
}

// orderNodesByUserOrder 按用户 nodeOrder 重排 storage.Node 数组,顺序逻辑跟
// PackageSubscribeHandler.orderPackageNodes 一致:user.NodeOrder 非空按其位置排;
// 空时 fallback admin 顺序;不在 nodeOrder 里的(新节点)按原 nodes 顺序追加末尾。
// 用于模板订阅生成路径,影响 __PROXY_NODES__ 占位符展开顺序 + 顶层 proxies 顺序。
func orderNodesByUserOrder(ctx context.Context, repo *storage.TrafficRepository, username string, nodes []storage.Node) []storage.Node {
	if len(nodes) == 0 || username == "" {
		return nodes
	}
	var nodeOrder []int64
	if settings, err := repo.GetUserSettings(ctx, username); err == nil {
		nodeOrder = settings.NodeOrder
	}
	if len(nodeOrder) == 0 {
		nodeOrder = computeFallbackNodeOrder(ctx, repo, username)
	}
	if len(nodeOrder) == 0 {
		return nodes
	}

	byID := make(map[int64]storage.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	orderPos := make(map[int64]int, len(nodeOrder))
	for i, id := range nodeOrder {
		orderPos[id] = i
	}

	ordered := make([]storage.Node, 0, len(nodes))
	// 在 nodeOrder 里的节点按位置排
	for _, id := range nodeOrder {
		if n, ok := byID[id]; ok {
			ordered = append(ordered, n)
		}
	}
	// 不在 nodeOrder 里的节点(管理员新加的)按 nodes 原顺序追加末尾
	for _, n := range nodes {
		if _, inOrder := orderPos[n.ID]; !inOrder {
			ordered = append(ordered, n)
		}
	}
	return ordered
}

// sortProxiesByNodeOrder 根据用户配置的节点顺序对 proxies 进行排序
// nodeOrder 是节点 ID 的数组，proxiesNode 是 YAML 中的 proxies 序列节点
func sortProxiesByNodeOrder(ctx context.Context, repo *storage.TrafficRepository, username string, proxiesNode *yaml.Node, nodeOrder []int64) error {
	if proxiesNode == nil || proxiesNode.Kind != yaml.SequenceNode {
		return errors.New("invalid proxies node")
	}

	if len(nodeOrder) == 0 || len(proxiesNode.Content) == 0 {
		return nil
	}

	// 拿全节点的 name→ID 映射:
	// 老逻辑 ListNodes(username) 只返该 username 名下的节点 — 普通用户(share 等)自己没创建节点,
	// 套餐节点是 admin 创建的(username=admin),share 名下查到 0 行 → nodeNameToID 空 →
	// 每个 proxy.name 在排序时找不到 ID,position 全 -1,nodeOrder 完全不生效。
	// 用 ListAllNodes:name→ID 映射跟权限无关,nodeOrder 里的 ID 都能查到,排序正确。
	nodes, err := repo.ListAllNodes(ctx)
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}
	_ = username

	// 创建节点名称 -> 节点ID 的映射
	nodeNameToID := make(map[string]int64)
	for _, node := range nodes {
		nodeNameToID[node.NodeName] = node.ID
	}

	// 创建节点 ID -> 排序位置的映射
	nodeIDToPosition := make(map[int64]int)
	for pos, nodeID := range nodeOrder {
		nodeIDToPosition[nodeID] = pos
	}

	// 创建 proxy 节点的排序信息
	type proxyWithOrder struct {
		node     *yaml.Node
		position int // 在 nodeOrder 中的位置，-1 表示不在 nodeOrder 中
		name     string
	}

	proxiesWithOrder := make([]proxyWithOrder, 0, len(proxiesNode.Content))

	// 解析每个 proxy 节点，获取其名称和排序位置
	for _, proxyNode := range proxiesNode.Content {
		if proxyNode.Kind != yaml.MappingNode {
			continue
		}

		// 查找 proxy 的 name 字段
		var proxyName string
		for i := 0; i < len(proxyNode.Content); i += 2 {
			if proxyNode.Content[i].Value == "name" {
				if i+1 < len(proxyNode.Content) {
					proxyName = proxyNode.Content[i+1].Value
				}
				break
			}
		}

		if proxyName == "" {
			// 如果没有 name 字段，保持原位置（放在最后）
			proxiesWithOrder = append(proxiesWithOrder, proxyWithOrder{
				node:     proxyNode,
				position: -1,
				name:     "",
			})
			continue
		}

		// 查找该节点名称对应的节点 ID
		nodeID, exists := nodeNameToID[proxyName]
		position := -1
		if exists {
			// 查找该节点 ID 在 nodeOrder 中的位置
			if pos, found := nodeIDToPosition[nodeID]; found {
				position = pos
			}
		}

		proxiesWithOrder = append(proxiesWithOrder, proxyWithOrder{
			node:     proxyNode,
			position: position,
			name:     proxyName,
		})
	}

	// 排序：按 position 升序排序，-1 的放在最后
	// 对于 position 相同的节点，保持原有顺序（稳定排序）
	sort.SliceStable(proxiesWithOrder, func(i, j int) bool {
		posI := proxiesWithOrder[i].position
		posJ := proxiesWithOrder[j].position

		// 如果 i 不在 nodeOrder 中，i 应该在 j 之后
		if posI == -1 {
			return false
		}
		// 如果 j 不在 nodeOrder 中，i 应该在 j 之前
		if posJ == -1 {
			return true
		}
		// 都在 nodeOrder 中，按 position 排序
		return posI < posJ
	})

	// 更新 proxiesNode 的内容
	newContent := make([]*yaml.Node, 0, len(proxiesWithOrder))
	for _, p := range proxiesWithOrder {
		newContent = append(newContent, p.node)
	}
	proxiesNode.Content = newContent

	logger.Info("[Subscription] 按节点顺序排序完成", "count", len(proxiesWithOrder), "user", username)
	return nil
}

// clashConfigName 从节点 ClashConfig(JSON)里取 proxy 的 name 字段(可能与 NodeName 分叉)。
func clashConfigName(clashConfig string) string {
	if clashConfig == "" {
		return ""
	}
	var m map[string]any
	if json.Unmarshal([]byte(clashConfig), &m) != nil {
		return ""
	}
	if nm, ok := m["name"].(string); ok {
		return nm
	}
	return ""
}

// injectRelayGroupsIntoRootMap 把中转组(url-test 组)追加进已解析 YAML 根 map 的 proxy-groups;
// 同名组已存在则跳过。返回是否有改动。
func injectRelayGroupsIntoRootMap(rootMap *yaml.Node, relayGroups []map[string]any) bool {
	for i := 0; i < len(rootMap.Content); i += 2 {
		if rootMap.Content[i].Value != "proxy-groups" {
			continue
		}
		groupsNode := rootMap.Content[i+1]
		if groupsNode.Kind != yaml.SequenceNode {
			return false
		}
		existing := make(map[string]bool)
		for _, g := range groupsNode.Content {
			if g.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j < len(g.Content); j += 2 {
				if g.Content[j].Value == "name" {
					existing[g.Content[j+1].Value] = true
					break
				}
			}
		}
		added := false
		for _, rg := range relayGroups {
			name, _ := rg["name"].(string)
			if existing[name] {
				continue
			}
			groupsNode.Content = append(groupsNode.Content, mapToYAMLNode(rg))
			added = true
		}
		return added
	}
	return false
}

// injectChainProxy 是静态 YAML 订阅(不绑模板)的后处理兜底:按节点表把链式/中转组的 dialer-proxy
// 注入到输出 proxies。生成型订阅(模板/套餐)已在生成阶段按 ID 注入,这里对已有 dialer-proxy 的节点跳过。
//
// 匹配用「NodeName + ClashConfig.name」双键:节点改名时只改 NodeName、不改 ClashConfig.name,
// 静态文件里的 proxy 名仍是旧名(ClashConfig.name),双键让它也能命中。dialer-proxy 的值(目标名/组名)
// 一律按 ID 取当前名 —— 存 ID、生成时取最新名,这是根治改名失配的核心。
func injectChainProxy(ctx context.Context, repo *storage.TrafficRepository, username string, data []byte) []byte {
	nodes, err := repo.ListNodes(ctx, username)
	if err != nil {
		return data
	}

	nodeIDToName := make(map[int64]string, len(nodes))
	for _, node := range nodes {
		nodeIDToName[node.ID] = node.NodeName
	}

	// 源 proxy 名 → dialer-proxy 目标(链式=目标当前名;中转组=组名)。源名登记 NodeName 与 ClashConfig.name 双键。
	nameToTarget := make(map[string]string)
	relayGroupMap := make(map[string]map[string]any)
	var relayGroupOrder []string
	addSrc := func(node storage.Node, target string) {
		nameToTarget[node.NodeName] = target
		if cn := clashConfigName(node.ClashConfig); cn != "" && cn != node.NodeName {
			nameToTarget[cn] = target
		}
	}
	for _, node := range nodes {
		if node.ChainProxyNodeID != nil {
			if targetName, ok := nodeIDToName[*node.ChainProxyNodeID]; ok {
				addSrc(node, targetName)
			}
			continue
		}
		if len(node.RelayGroupNodeIDs) > 0 && node.RelayGroupName != "" {
			addSrc(node, node.RelayGroupName)
			if _, exists := relayGroupMap[node.RelayGroupName]; !exists {
				var members []string
				for _, rid := range node.RelayGroupNodeIDs {
					if nm, ok := nodeIDToName[rid]; ok {
						members = append(members, nm)
					}
				}
				if len(members) > 0 {
					relayGroupMap[node.RelayGroupName] = map[string]any{
						"name": node.RelayGroupName, "type": "url-test", "proxies": members,
						"url": "http://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50,
					}
					relayGroupOrder = append(relayGroupOrder, node.RelayGroupName)
				}
			}
		}
	}
	if len(nameToTarget) == 0 {
		return data
	}

	var yamlNode yaml.Node
	if err := yaml.Unmarshal(data, &yamlNode); err != nil {
		return data
	}
	if len(yamlNode.Content) == 0 || yamlNode.Content[0].Kind != yaml.MappingNode {
		return data
	}

	rootMap := yamlNode.Content[0]
	modified := false
	for i := 0; i < len(rootMap.Content); i += 2 {
		if rootMap.Content[i].Value != "proxies" {
			continue
		}
		proxiesNode := rootMap.Content[i+1]
		if proxiesNode.Kind != yaml.SequenceNode {
			break
		}
		for _, proxyNode := range proxiesNode.Content {
			if proxyNode.Kind != yaml.MappingNode {
				continue
			}
			var proxyName string
			hasDialer := false
			for j := 0; j < len(proxyNode.Content); j += 2 {
				switch proxyNode.Content[j].Value {
				case "name":
					proxyName = proxyNode.Content[j+1].Value
				case "dialer-proxy":
					hasDialer = true
				}
			}
			if hasDialer {
				continue // 生成阶段已注入,不重复
			}
			if targetName, ok := nameToTarget[proxyName]; ok {
				proxyNode.Content = append(proxyNode.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Value: "dialer-proxy"},
					&yaml.Node{Kind: yaml.ScalarNode, Value: targetName},
				)
				modified = true
			}
		}
		break
	}

	// 中转组静态兜底:把 url-test 组追加进 proxy-groups
	if len(relayGroupMap) > 0 {
		relayGroups := make([]map[string]any, 0, len(relayGroupMap))
		for _, groupName := range relayGroupOrder {
			relayGroups = append(relayGroups, relayGroupMap[groupName])
		}
		if injectRelayGroupsIntoRootMap(rootMap, relayGroups) {
			modified = true
		}
	}

	if !modified {
		return data
	}

	out, err := MarshalYAMLWithIndent(&yamlNode)
	if err != nil {
		return data
	}
	fixed := RemoveUnicodeEscapeQuotes(string(out))
	logger.Info("[Subscription] 链式/中转组注入完成", "user", username, "srcNames", len(nameToTarget), "relayGroups", len(relayGroupMap))
	return []byte(fixed)
}

// ─── 订阅 YAML → JSON 序列化(从妙妙屋 subscription.go L2506-2679 移植,无 mmw 特化) ───
//
// 用 yaml.Node 解析后手工写出 JSON,这样可以:
//   1. 保留 proxies / proxy-groups 顶层数组的多行格式(可读性)
//   2. 元素内部的 proxy / group 字段按 name → type → server → port 排序(对照 mihomo 客户端常见展示顺序)
//   3. 数字 / bool / null 等 YAML scalar tag 正确转 JSON 字面量(避免 "true" 这种带引号字符串)
//
// 输入是 SubscriptionHandler 早些处理过的 YAML 字节流,输出是 application/json 等价物。
// 仅用于 Clash 订阅(其它 client 类型如 surge / sing-box 不调用此函数)。

func marshalSubscriptionJSON(yamlData []byte) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(yamlData, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected YAML mapping document")
	}

	var buf bytes.Buffer
	rootMap := doc.Content[0]
	buf.WriteString("{\n")

	for i := 0; i < len(rootMap.Content); i += 2 {
		keyNode := rootMap.Content[i]
		valNode := rootMap.Content[i+1]

		buf.WriteString("  ")
		jsonEncodeString(&buf, keyNode.Value)
		buf.WriteString(": ")

		reorder := keyNode.Value == "proxies" || keyNode.Value == "proxy-groups"

		if valNode.Kind == yaml.SequenceNode {
			jsonWriteSeqExpanded(&buf, valNode, reorder)
		} else {
			jsonWriteCompact(&buf, valNode)
		}

		if i+2 < len(rootMap.Content) {
			buf.WriteByte(',')
		}
		buf.WriteByte('\n')
	}

	buf.WriteString("}\n")
	return buf.Bytes(), nil
}

var jsonProxyKeyPriority = []string{"name", "type", "server", "port"}

func jsonWriteSeqExpanded(buf *bytes.Buffer, node *yaml.Node, reorder bool) {
	if len(node.Content) == 0 {
		buf.WriteString("[]")
		return
	}
	buf.WriteString("[\n")
	for i, elem := range node.Content {
		buf.WriteString("    ")
		if reorder && elem.Kind == yaml.MappingNode {
			jsonWriteMappingReordered(buf, elem)
		} else {
			jsonWriteCompact(buf, elem)
		}
		if i < len(node.Content)-1 {
			buf.WriteByte(',')
		}
		buf.WriteByte('\n')
	}
	buf.WriteString("  ]")
}

func jsonWriteCompact(buf *bytes.Buffer, node *yaml.Node) {
	switch node.Kind {
	case yaml.ScalarNode:
		jsonWriteScalar(buf, node)
	case yaml.MappingNode:
		buf.WriteByte('{')
		for i := 0; i < len(node.Content); i += 2 {
			if i > 0 {
				buf.WriteString(", ")
			}
			jsonEncodeString(buf, node.Content[i].Value)
			buf.WriteString(": ")
			jsonWriteCompact(buf, node.Content[i+1])
		}
		buf.WriteByte('}')
	case yaml.SequenceNode:
		buf.WriteByte('[')
		for i, elem := range node.Content {
			if i > 0 {
				buf.WriteString(", ")
			}
			jsonWriteCompact(buf, elem)
		}
		buf.WriteByte(']')
	}
}

func jsonWriteMappingReordered(buf *bytes.Buffer, node *yaml.Node) {
	buf.WriteByte('{')

	keyIdx := make(map[string]int, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		keyIdx[node.Content[i].Value] = i
	}

	written := make(map[int]bool)
	first := true

	for _, key := range jsonProxyKeyPriority {
		idx, ok := keyIdx[key]
		if !ok {
			continue
		}
		if !first {
			buf.WriteString(", ")
		}
		jsonEncodeString(buf, key)
		buf.WriteString(": ")
		jsonWriteCompact(buf, node.Content[idx+1])
		written[idx] = true
		first = false
	}

	for i := 0; i < len(node.Content); i += 2 {
		if written[i] {
			continue
		}
		if !first {
			buf.WriteString(", ")
		}
		jsonEncodeString(buf, node.Content[i].Value)
		buf.WriteString(": ")
		jsonWriteCompact(buf, node.Content[i+1])
		first = false
	}

	buf.WriteByte('}')
}

func jsonWriteScalar(buf *bytes.Buffer, node *yaml.Node) {
	switch node.Tag {
	case "!!null":
		buf.WriteString("null")
	case "!!bool":
		if node.Value == "true" {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case "!!int":
		if n, err := strconv.ParseInt(node.Value, 0, 64); err == nil {
			buf.WriteString(strconv.FormatInt(n, 10))
		} else {
			buf.WriteString(node.Value)
		}
	case "!!float":
		v := strings.ToLower(node.Value)
		if v == ".inf" || v == "+.inf" || v == "-.inf" || v == ".nan" {
			jsonEncodeString(buf, node.Value)
		} else {
			buf.WriteString(node.Value)
		}
	default:
		jsonEncodeString(buf, node.Value)
	}
}

func jsonEncodeString(buf *bytes.Buffer, s string) {
	b, _ := json.Marshal(s)
	buf.Write(b)
}
