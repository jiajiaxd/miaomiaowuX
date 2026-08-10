package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/MMWOrg/mmwX-plugins/proxyparser/substore"
	"miaomiaowux/internal/license"
	"miaomiaowux/internal/storage"

	"github.com/google/uuid"
)

// PackageListHandler 处理列出所有包模板
type PackageListHandler struct {
	repo *storage.TrafficRepository
}

func NewPackageListHandler(repo *storage.TrafficRepository) *PackageListHandler {
	return &PackageListHandler{repo: repo}
}

func (h *PackageListHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	packages, err := h.repo.ListPackages(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"packages": packages,
	})
}

// PackageCreateHandler 处理创建新的包模板
type PackageCreateHandler struct {
	repo           *storage.TrafficRepository
	licenseManager *license.Manager
}

func NewPackageCreateHandler(repo *storage.TrafficRepository) *PackageCreateHandler {
	return &PackageCreateHandler{repo: repo}
}

// SetLicenseManager 注入许可证管理器 — limiter PRO feature gate 需要。
func (h *PackageCreateHandler) SetLicenseManager(mgr *license.Manager) {
	h.licenseManager = mgr
}

// hasNonZeroLimit 任何一项 > 0 都算"启用限速"。0 表示显式不限速,不算"启用"。
func hasNonZeroLimit(m map[int64]float64) bool {
	for _, v := range m {
		if v > 0 {
			return true
		}
	}
	return false
}

func hasNonZeroIntLimit(m map[int64]int) bool {
	for _, v := range m {
		if v > 0 {
			return true
		}
	}
	return false
}

type createPackageRequest struct {
	Name                    string                       `json:"name"`
	Description             string                       `json:"description"`
	TrafficLimitGB          float64                      `json:"traffic_limit_gb"`
	CycleDays               int                          `json:"cycle_days"`
	IsReset                 bool                         `json:"is_reset"`
	ResetDay                int                          `json:"reset_day"`
	Nodes                   []int64                      `json:"nodes"`
	NodeMultipliers         map[int64]float64            `json:"node_multipliers"`    // node_id → 倍率
	NodeNameOverrides       map[int64]string             `json:"node_name_overrides"` // node_id → 套餐内显示名
	NodeNameOverrideEnabled bool                         `json:"node_name_override_enabled"`
	NodeSpeedLimits         map[int64]float64            `json:"node_speed_limits"`  // 套餐 per-node 限速覆盖 (Mbps);0=显式不限速,缺省=继承 SpeedLimitMbps
	NodeDeviceLimits        map[int64]int                `json:"node_device_limits"` // 套餐 per-node 客户端数覆盖;0=显式不限,缺省=继承 DeviceLimit
	SpeedLimitMbps          float64                      `json:"speed_limit_mbps"`
	DeviceLimit             int                          `json:"device_limit"`
	AutoSpeedRules          []storage.AutoSpeedLimitRule `json:"auto_speed_rules"`
	TrafficMode             string                       `json:"traffic_mode"`
	TemplateFilename        string                       `json:"template_filename"`       // Clash 模板;空 = 走系统默认
	SurgeTemplateFilename   string                       `json:"surge_template_filename"` // Surge 模板;空 = 走系统默认
}

func normalizePackageNodeNames(names map[int64]string, nodes []int64) (map[int64]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	allowed := make(map[int64]bool, len(nodes))
	for _, id := range nodes {
		allowed[id] = true
	}
	out := make(map[int64]string, len(names))
	seen := make(map[string]int64, len(names))
	for id, value := range names {
		if !allowed[id] {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if utf8.RuneCountInString(value) > 128 || strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("节点 %d 的套餐内名称无效", id)
		}
		if other, ok := seen[value]; ok && other != id {
			return nil, fmt.Errorf("套餐内节点名称 %q 重复", value)
		}
		seen[value] = id
		out[id] = value
	}
	return out, nil
}

// validatePackageTemplateFilename 非空时校验 rule_templates 下文件存在。空字符串直接通过(表示用系统默认)。
func validatePackageTemplateFilename(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	// 防目录穿越
	if strings.Contains(name, "..") || strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("invalid template filename")
	}
	if _, err := os.Stat(filepath.Join("rule_templates", name)); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("template file not found: %s", name)
		}
		return fmt.Errorf("stat template: %w", err)
	}
	return nil
}

func validatePackageTemplateType(name string, surge bool) error {
	if err := validatePackageTemplateFilename(name); err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	if isSurgeTemplateFile(name) != surge {
		if surge {
			return fmt.Errorf("Surge template must be a .conf file")
		}
		return fmt.Errorf("Clash template cannot be a .conf file")
	}
	return nil
}

func (h *PackageCreateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req createPackageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 验证必填字段
	if req.Name == "" {
		http.Error(w, "Package name is required", http.StatusBadRequest)
		return
	}

	if req.TrafficLimitGB <= 0 {
		http.Error(w, "Traffic limit must be greater than 0", http.StatusBadRequest)
		return
	}

	// limiter 是 PRO feature — SpeedLimitMbps > 0 / AutoSpeedRules 非空 / 任何 per-node 限速值 > 0 都视为启用限速。
	if (req.SpeedLimitMbps > 0 || len(req.AutoSpeedRules) > 0 || hasNonZeroLimit(req.NodeSpeedLimits) || hasNonZeroIntLimit(req.NodeDeviceLimits)) && h.licenseManager != nil && !h.licenseManager.HasFeature("limiter") {
		http.Error(w, "限速器是 PRO 功能,需要许可证", http.StatusForbidden)
		return
	}

	if req.CycleDays <= 0 {
		http.Error(w, "Duration days must be greater than 0", http.StatusBadRequest)
		return
	}

	if req.IsReset && (req.ResetDay < 1 || req.ResetDay > 31) {
		http.Error(w, "Reset day must be between 1 and 31", http.StatusBadRequest)
		return
	}

	if err := validatePackageTemplateType(req.TemplateFilename, false); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validatePackageTemplateType(req.SurgeTemplateFilename, true); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 如果 nil 则初始化空节点数组
	nodes := req.Nodes
	if nodes == nil {
		nodes = []int64{}
	}
	nodeNames, err := normalizePackageNodeNames(req.NodeNameOverrides, nodes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	trafficMode := req.TrafficMode
	if trafficMode == "" {
		trafficMode = "oneway"
	}

	pkg := storage.Package{
		Name:                    req.Name,
		Description:             req.Description,
		TrafficLimitGB:          req.TrafficLimitGB,
		TrafficLimitBytes:       int64(req.TrafficLimitGB * 1024 * 1024 * 1024),
		CycleDays:               req.CycleDays,
		IsReset:                 req.IsReset,
		ResetDay:                req.ResetDay,
		Nodes:                   nodes,
		NodeMultipliers:         req.NodeMultipliers,
		NodeNameOverrides:       nodeNames,
		NodeNameOverrideEnabled: req.NodeNameOverrideEnabled,
		NodeSpeedLimits:         req.NodeSpeedLimits,
		NodeDeviceLimits:        req.NodeDeviceLimits,
		SpeedLimitMbps:          req.SpeedLimitMbps,
		DeviceLimit:             req.DeviceLimit,
		AutoSpeedRules:          req.AutoSpeedRules,
		TrafficMode:             trafficMode,
		TemplateFilename:        strings.TrimSpace(req.TemplateFilename),
		SurgeTemplateFilename:   strings.TrimSpace(req.SurgeTemplateFilename),
	}

	id, err := h.repo.CreatePackage(r.Context(), pkg)
	if err != nil {
		if err == storage.ErrPackageExists {
			http.Error(w, "Package with this name already exists", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      id,
		"message": "Package created successfully",
	})
}

// PackageUpdateHandler 处理更新现有包模板
type PackageUpdateHandler struct {
	repo           *storage.TrafficRepository
	remoteManage   *RemoteManageHandler
	pusher         *LimiterConfigPusher
	licenseManager *license.Manager
}

// SetLicenseManager 注入许可证管理器 — limiter PRO feature gate 需要。
func (h *PackageUpdateHandler) SetLicenseManager(mgr *license.Manager) {
	h.licenseManager = mgr
}

func NewPackageUpdateHandler(repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher) *PackageUpdateHandler {
	return &PackageUpdateHandler{repo: repo, remoteManage: remoteManage, pusher: pusher}
}

type updatePackageRequest struct {
	ID                      int64                        `json:"id"`
	Name                    string                       `json:"name"`
	Description             string                       `json:"description"`
	TrafficLimitGB          float64                      `json:"traffic_limit_gb"`
	CycleDays               int                          `json:"cycle_days"`
	IsReset                 *bool                        `json:"is_reset"`  // 指针:请求未携带时保留库中旧值,不按零值覆盖
	ResetDay                *int                         `json:"reset_day"` // 同上
	Nodes                   []int64                      `json:"nodes"`
	NodeMultipliers         map[int64]float64            `json:"node_multipliers"`    // node_id → 倍率
	NodeNameOverrides       map[int64]string             `json:"node_name_overrides"` // node_id → 套餐内显示名
	NodeNameOverrideEnabled bool                         `json:"node_name_override_enabled"`
	NodeSpeedLimits         map[int64]float64            `json:"node_speed_limits"`  // 套餐 per-node 限速覆盖 (Mbps);0=显式不限速,缺省=继承 SpeedLimitMbps
	NodeDeviceLimits        map[int64]int                `json:"node_device_limits"` // 套餐 per-node 客户端数覆盖;0=显式不限,缺省=继承 DeviceLimit
	SpeedLimitMbps          float64                      `json:"speed_limit_mbps"`
	DeviceLimit             int                          `json:"device_limit"`
	AutoSpeedRules          []storage.AutoSpeedLimitRule `json:"auto_speed_rules"`
	TrafficMode             string                       `json:"traffic_mode"`
	TemplateFilename        string                       `json:"template_filename"`       // Clash 模板;空 = 走系统默认
	SurgeTemplateFilename   string                       `json:"surge_template_filename"` // Surge 模板;空 = 走系统默认
}

func (h *PackageUpdateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req updatePackageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 验证必填字段
	if req.ID <= 0 {
		http.Error(w, "Invalid package ID", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "Package name is required", http.StatusBadRequest)
		return
	}

	if req.TrafficLimitGB <= 0 {
		http.Error(w, "Traffic limit must be greater than 0", http.StatusBadRequest)
		return
	}

	// limiter 是 PRO feature — SpeedLimitMbps > 0 / AutoSpeedRules 非空 / 任何 per-node 限速值 > 0 都视为启用限速。
	if (req.SpeedLimitMbps > 0 || len(req.AutoSpeedRules) > 0 || hasNonZeroLimit(req.NodeSpeedLimits) || hasNonZeroIntLimit(req.NodeDeviceLimits)) && h.licenseManager != nil && !h.licenseManager.HasFeature("limiter") {
		http.Error(w, "限速器是 PRO 功能,需要许可证", http.StatusForbidden)
		return
	}

	if req.CycleDays <= 0 {
		http.Error(w, "Duration days must be greater than 0", http.StatusBadRequest)
		return
	}

	if err := validatePackageTemplateType(req.TemplateFilename, false); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validatePackageTemplateType(req.SurgeTemplateFilename, true); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 如果 nil 则初始化空节点数组
	nodes := req.Nodes
	if nodes == nil {
		nodes = []int64{}
	}
	nodeNames, err := normalizePackageNodeNames(req.NodeNameOverrides, nodes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 获取旧套餐的节点列表，用于后续计算差异
	var oldNodes []int64
	var oldPkg *storage.Package
	if p, err := h.repo.GetPackage(r.Context(), req.ID); err == nil {
		oldPkg = p
		oldNodes = p.Nodes
	}

	// 套餐表单没有按月重置的控件,请求里不带这两个字段。缺省时必须沿用旧值,
	// 否则每保存一次套餐就把 is_reset/reset_day 清成 false/0,已开启的按月重置被静默关闭。
	isReset, resetDay := false, 0
	if oldPkg != nil {
		isReset, resetDay = oldPkg.IsReset, oldPkg.ResetDay
	}
	if req.IsReset != nil {
		isReset = *req.IsReset
	}
	if req.ResetDay != nil {
		resetDay = *req.ResetDay
	}
	if isReset && (resetDay < 1 || resetDay > 31) {
		http.Error(w, "Reset day must be between 1 and 31", http.StatusBadRequest)
		return
	}

	trafficMode := req.TrafficMode
	if trafficMode == "" {
		trafficMode = "oneway"
	}

	pkg := storage.Package{
		ID:                      req.ID,
		Name:                    req.Name,
		Description:             req.Description,
		TrafficLimitGB:          req.TrafficLimitGB,
		TrafficLimitBytes:       int64(req.TrafficLimitGB * 1024 * 1024 * 1024),
		CycleDays:               req.CycleDays,
		IsReset:                 isReset,
		ResetDay:                resetDay,
		Nodes:                   nodes,
		NodeMultipliers:         req.NodeMultipliers,
		NodeNameOverrides:       nodeNames,
		NodeNameOverrideEnabled: req.NodeNameOverrideEnabled,
		NodeSpeedLimits:         req.NodeSpeedLimits,
		NodeDeviceLimits:        req.NodeDeviceLimits,
		SpeedLimitMbps:          req.SpeedLimitMbps,
		DeviceLimit:             req.DeviceLimit,
		AutoSpeedRules:          req.AutoSpeedRules,
		TrafficMode:             trafficMode,
		TemplateFilename:        strings.TrimSpace(req.TemplateFilename),
		SurgeTemplateFilename:   strings.TrimSpace(req.SurgeTemplateFilename),
	}

	if err := h.repo.UpdatePackage(r.Context(), pkg); err != nil {
		if err == storage.ErrPackageNotFound {
			http.Error(w, "Package not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 套餐节点与用户凭据必须作为一次操作完成。这里不能后台异步：保存接口若先返回，用户立即
	// 获取订阅会拿到刚生成的 SS2022 user key，但 Agent/Xray 的 clients 尚未写入，表现为
	// “套餐里看得到节点但节点不通”。等同步结束后再返回，前端提示成功即代表凭据已经下发。
	syncCtx, syncCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Minute)
	defer syncCancel()
	syncErr := h.syncPackageNodesTransactionally(syncCtx, req.ID, oldNodes, nodes)
	if syncErr != nil {
		rollbackWarnings := []string{}
		if oldPkg != nil {
			if err := h.repo.UpdatePackage(syncCtx, *oldPkg); err != nil {
				rollbackWarnings = append(rollbackWarnings, "恢复旧套餐数据库配置失败: "+err.Error())
			}
		}
		log.Printf("[PackageUpdate] package_id=%d node sync failed (database rollback warnings=%d): %v", req.ID, len(rollbackWarnings), syncErr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "套餐节点同步失败，保存操作未生效",
			"failures":          []string{syncErr.Error()},
			"rollback_failures": rollbackWarnings,
			"recovery_required": len(rollbackWarnings) > 0,
		})
		return
	}
	if h.pusher != nil {
		go h.pusher.PushToAllServersForPackage(context.Background(), req.ID)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Package updated successfully",
	})
}

// resolveNodeServer 解析一个 physical 节点应该把用户 client 下发到哪台 server。
//
// 优先 node.OriginalServer(按名字查)。为空时——最常见于**多台服务器共用同一域名**,主控按 host
// 匹配无法唯一识别归属 server,于是 original_server 被留空——退回用 node.InboundTag 在 InboundCache
// 里反查:仅当**唯一**一台已连服务器拥有该 inbound 时才采用。
//
// 返回 (nil, 原因) 时调用方必须**明确告警而非静默跳过**——历史 bug 正是这里静默 return 导致用户
// 永远拿不到自己的 client、只能用管理员的种子配置。
func resolveNodeServer(ctx context.Context, repo *storage.TrafficRepository, rm *RemoteManageHandler, node storage.Node) (*storage.RemoteServer, string) {
	if strings.TrimSpace(node.InboundTag) == "" {
		return nil, "节点无 inbound_tag"
	}
	if name := strings.TrimSpace(node.OriginalServer); name != "" {
		if srv, err := repo.GetRemoteServerByName(ctx, name); err == nil {
			return srv, ""
		}
		// original_server 有值但查不到该 server(被删/改名)→ 继续用 inbound_tag 兜底
	}
	if rm == nil || rm.inboundCache == nil {
		return nil, "original_server 为空且 inbound 缓存不可用"
	}
	ids := rm.inboundCache.FindServersByInboundTag(node.InboundTag)
	switch len(ids) {
	case 1:
		srv, err := repo.GetRemoteServer(ctx, ids[0])
		if err != nil {
			return nil, fmt.Sprintf("inbound %s 反查到 server %d 但读取失败: %v", node.InboundTag, ids[0], err)
		}
		return srv, ""
	case 0:
		return nil, fmt.Sprintf("inbound %s 无归属服务器(该服务器可能未连接,或 original_server 为空且无快照)", node.InboundTag)
	default:
		return nil, fmt.Sprintf("inbound %s 同时存在于 %d 台服务器,无法唯一确定归属(请给各服务器配置唯一域名/host)", node.InboundTag, len(ids))
	}
}

func (h *PackageUpdateHandler) syncInboundUsersAfterNodeChange(ctx context.Context, packageID int64, oldNodes, newNodes []int64) []string {
	oldSet := make(map[int64]bool, len(oldNodes))
	for _, id := range oldNodes {
		oldSet[id] = true
	}
	newSet := make(map[int64]bool, len(newNodes))
	for _, id := range newNodes {
		newSet[id] = true
	}

	var addedNodes, removedNodes []int64
	for _, id := range newNodes {
		if !oldSet[id] {
			addedNodes = append(addedNodes, id)
		}
	}
	for _, id := range oldNodes {
		if !newSet[id] {
			removedNodes = append(removedNodes, id)
		}
	}

	if len(addedNodes) == 0 && len(removedNodes) == 0 {
		return nil
	}

	users, err := h.repo.ListUsersWithPackage(ctx)
	if err != nil {
		log.Printf("[PackageUpdate] Failed to list users with package: %v", err)
		return []string{"读取套餐用户失败，未能同步节点凭据"}
	}

	var targetUsers []storage.User
	for _, u := range users {
		if u.PackageID == packageID {
			targetUsers = append(targetUsers, u)
		}
	}
	if len(targetUsers) == 0 {
		return nil
	}

	log.Printf("[PackageUpdate] Syncing inbound users for package %d: %d added nodes, %d removed nodes, %d users",
		packageID, len(addedNodes), len(removedNodes), len(targetUsers))

	// 移除节点后**仍被套餐占用**的 (server, inbound) 集合。
	// both(v4/v6) 会为同一入站建两个节点(同 server + 同 InboundTag),凭据却是绑在入站上的 ——
	// 只从套餐移除其中一个节点时,该入站的 client 必须保留,否则把还在套餐里的另一个节点也一起废了。
	// add 路径早有 inboundSeen 去重(见下),remove 路径此前没有对应保护。
	// key 用解析后的 server.Name(而非 node.OriginalServer)—— original_server 为空的节点也要能算进
	// "仍被占用"集合,否则移除某节点时会误摘另一个共享同一入站、但 original_server 同样为空的节点的 client。
	stillUsedInbounds := map[string]bool{}
	for _, id := range newNodes {
		node, nerr := h.repo.GetNodeByID(ctx, id)
		if nerr != nil || node.NodeType == "routed" || node.InboundTag == "" {
			continue
		}
		srv, _ := resolveNodeServer(ctx, h.repo, h.remoteManage, node)
		if srv == nil {
			continue
		}
		stillUsedInbounds[srv.Name+"|"+node.InboundTag] = true
	}

	// 只 routed 节点改 routing rules 才需要重启 xray;非 routed 的 add-client / remove-client
	// 由 agent 走 HandlerService 热更新,运行态立即生效。同步路径上每台少 ~3s。
	var mu sync.Mutex
	var warnings []string
	restartNeeded := map[int64]bool{}
	// per-server 收集 routed batch items + inbound add-client items,阶段二 per-server 一次 batch-apply 提交。
	routedBatch := map[int64][]routedBatchItem{}
	inboundBatch := map[int64][]InboundClientAddItem{}
	type inboundFallbackItem struct {
		Username   string
		ServerID   int64
		InboundTag string
		NodeName   string
	}
	var inboundFallbacks []inboundFallbackItem
	// both(v4/v6)会为同一 inbound 建两个节点(同 server + 同 InboundTag)。按节点遍历会让同一
	// (user, server, inbound) 被收集两次 → agent 加两个同 email client → xray "User already exists" 启动失败。
	// 凭据是绑到 inbound(server+tag)而非节点的,按 (user, server, inboundTag) 去重:每个入站每个用户只加一次。
	// routed 节点走 collectRoutedBatchItem(按 node.ID)独立路径,不参与此去重。
	inboundSeen := map[string]bool{}
	// remove 路径同款去重:两个被移除的节点可能共享同一入站,重复摘除会在 agent 侧
	// 变成"第二次 no-op",本身无害,但第一次成功后就该停手,避免重复日志与无谓往返。
	removedSeen := map[string]bool{}
	// 用户间互不影响 + 节点间互不影响 → 全部并发跑。
	// agent 端 inboundsMu 自动同服务器顺序化,master 这边不需要 per-server 锁。
	var bindWg sync.WaitGroup
	for _, user := range targetUsers {
		for _, nodeID := range addedNodes {
			bindWg.Add(1)
			go func(user storage.User, nodeID int64) {
				defer bindWg.Done()
				node, err := h.repo.GetNodeByID(ctx, nodeID)
				if err != nil {
					log.Printf("[PackageUpdate] Failed to get node %d: %v", nodeID, err)
					mu.Lock()
					warnings = append(warnings, fmt.Sprintf("读取新增节点 %d 失败: %v", nodeID, err))
					mu.Unlock()
					return
				}
				if node.NodeType == "routed" {
					if srv, err := h.repo.GetRemoteServerByName(ctx, node.OriginalServer); err == nil {
						mu.Lock()
						restartNeeded[srv.ID] = true
						mu.Unlock()
					}
					item, err := collectRoutedBatchItem(ctx, h.remoteManage, h.repo, user, node.ID)
					if err != nil {
						log.Printf("[PackageUpdate] collect routed item user=%s node=%d failed: %v", user.Username, node.ID, err)
						mu.Lock()
						warnings = append(warnings, fmt.Sprintf("用户 %s 的路由节点 %s 准备失败: %v", user.Username, node.NodeName, err))
						mu.Unlock()
						return
					}
					if item != nil {
						mu.Lock()
						routedBatch[item.ServerID] = append(routedBatch[item.ServerID], *item)
						mu.Unlock()
					}
					return
				}
				if node.InboundTag == "" {
					return
				}
				// original_server 为空(多台共用域名致 host 匹配歧义)时用 inbound_tag 兜底解析;
				// 解析不出则明确 log 跳过,不再静默丢弃用户下发。
				server, reason := resolveNodeServer(ctx, h.repo, h.remoteManage, node)
				if server == nil {
					log.Printf("[PackageUpdate] 跳过节点 %s 对用户 %s 的配置下发: %s", node.NodeName, user.Username, reason)
					mu.Lock()
					warnings = append(warnings, fmt.Sprintf("节点 %s 无法确定服务器: %s", node.NodeName, reason))
					mu.Unlock()
					return
				}
				// 同一 (user, server, inbound) 只收集一次 —— both 的 v4/v6 双节点共享同一入站,避免重复加 client。
				seenKey := user.Username + "|" + server.Name + "|" + node.InboundTag
				mu.Lock()
				if inboundSeen[seenKey] {
					mu.Unlock()
					return
				}
				inboundSeen[seenKey] = true
				mu.Unlock()
				// 阶段一:从 InboundCache 算 cred,收集成 batch item;cache miss / 续费 → fallback 逐项。
				item, collected, cerr := collectInboundClientAddItem(ctx, h.remoteManage.inboundCache, h.repo, user, server.ID, node.InboundTag)
				if cerr != nil {
					mu.Lock()
					inboundFallbacks = append(inboundFallbacks, inboundFallbackItem{Username: user.Username, ServerID: server.ID, InboundTag: node.InboundTag, NodeName: node.NodeName})
					mu.Unlock()
					return
				}
				if collected && item != nil {
					mu.Lock()
					inboundBatch[item.ServerID] = append(inboundBatch[item.ServerID], *item)
					mu.Unlock()
				}
			}(user, nodeID)
		}

		for _, nodeID := range removedNodes {
			bindWg.Add(1)
			go func(user storage.User, nodeID int64) {
				defer bindWg.Done()
				node, err := h.repo.GetNodeByID(ctx, nodeID)
				if err != nil {
					mu.Lock()
					warnings = append(warnings, fmt.Sprintf("读取待移除节点 %d 失败: %v", nodeID, err))
					mu.Unlock()
					return
				}
				if node.NodeType == "routed" {
					if srv, err := h.repo.GetRemoteServerByName(ctx, node.OriginalServer); err == nil {
						mu.Lock()
						restartNeeded[srv.ID] = true
						mu.Unlock()
					}
					if err := removeUserFromRoutedNode(ctx, h.remoteManage, h.repo, user.Username, node.ID); err != nil {
						log.Printf("[PackageUpdate] remove user %s from routed node %d failed: %v", user.Username, node.ID, err)
						mu.Lock()
						warnings = append(warnings, fmt.Sprintf("用户 %s 从路由节点 %s 移除失败: %v", user.Username, node.NodeName, err))
						mu.Unlock()
					}
					return
				}
				if node.InboundTag == "" {
					return
				}
				server, _ := resolveNodeServer(ctx, h.repo, h.remoteManage, node)
				if server == nil {
					mu.Lock()
					warnings = append(warnings, fmt.Sprintf("节点 %s 无法确定服务器，未能移除用户 %s", node.NodeName, user.Username))
					mu.Unlock()
					return
				}
				// 该入站仍被套餐里的其它节点占用(both 的 v4/v6 同入站)→ 不能摘 client。
				if stillUsedInbounds[server.Name+"|"+node.InboundTag] {
					return
				}
				// 同一 (user, server, inbound) 只摘一次 —— 两个被移除的节点可能共享同一入站。
				seenKey := user.Username + "|" + server.Name + "|" + node.InboundTag
				mu.Lock()
				if removedSeen[seenKey] {
					mu.Unlock()
					return
				}
				removedSeen[seenKey] = true
				mu.Unlock()
				cfg, err := h.repo.GetUserInboundConfig(ctx, user.Username, server.ID, node.InboundTag)
				if err != nil {
					mu.Lock()
					warnings = append(warnings, fmt.Sprintf("读取用户 %s 在节点 %s 的凭据失败: %v", user.Username, node.NodeName, err))
					mu.Unlock()
					return
				}
				if cfg == nil {
					mu.Lock()
					warnings = append(warnings, fmt.Sprintf("用户 %s 在节点 %s 的凭据记录不存在，无法确认移除", user.Username, node.NodeName))
					mu.Unlock()
					return
				}
				// 仅在 agent 确认摘除成功时才删 DB 登记行 —— 与 traffic_limit_enforcer.go 的 removed 守卫对齐。
				// 此前无条件删:agent 离线时 client 残留 xray 而登记行没了,removeUserFromAllInbounds(DB 驱动)
				// 从此永远扫不到它 → 残留永久化。保留行则下轮 reconciler / 解绑路径还能重试。
				if err := removeUserFromInbound(ctx, h.remoteManage, *cfg); err != nil {
					log.Printf("[PackageUpdate] Failed to remove user %s from inbound %s on server %d (keep DB row for retry): %v",
						user.Username, cfg.InboundTag, cfg.ServerID, err)
					mu.Lock()
					warnings = append(warnings, fmt.Sprintf("用户 %s 从节点 %s 移除失败: %v", user.Username, node.NodeName, err))
					mu.Unlock()
					return
				}
				if err := h.repo.DeleteUserInboundConfig(ctx, user.Username, server.ID, node.InboundTag); err != nil {
					mu.Lock()
					warnings = append(warnings, fmt.Sprintf("删除用户 %s 在节点 %s 的凭据记录失败: %v", user.Username, node.NodeName, err))
					mu.Unlock()
				}
			}(user, nodeID)
		}
	}
	bindWg.Wait()

	// 阶段二 — per-server 并行调 batch-apply。routed + inbound 各自一批,跨 server 并行。
	var routeWg sync.WaitGroup
	for serverID, items := range routedBatch {
		routeWg.Add(1)
		go func(sid int64, list []routedBatchItem) {
			defer routeWg.Done()
			if ws := applyRoutedBatchOrFallback(ctx, h.remoteManage, h.repo, sid, list, "PackageUpdate"); len(ws) > 0 {
				mu.Lock()
				warnings = append(warnings, ws...)
				mu.Unlock()
			}
		}(serverID, items)
	}
	for serverID, items := range inboundBatch {
		routeWg.Add(1)
		go func(sid int64, list []InboundClientAddItem) {
			defer routeWg.Done()
			if ws := applyInboundBatchOrFallback(ctx, h.remoteManage, h.repo, sid, list, "PackageUpdate"); len(ws) > 0 {
				mu.Lock()
				warnings = append(warnings, ws...)
				mu.Unlock()
			}
		}(serverID, items)
	}
	routeWg.Wait()

	// 阶段三 — cache miss 类 fallback:并发跑逐项 addUserToInbound(老路径)。
	if len(inboundFallbacks) > 0 {
		log.Printf("[PackageUpdate] %d inbound items fell back to per-item add (cache miss / no batch)", len(inboundFallbacks))
		var fbWg sync.WaitGroup
		for _, fb := range inboundFallbacks {
			fbWg.Add(1)
			go func(fb inboundFallbackItem) {
				defer fbWg.Done()
				user := storage.User{Username: fb.Username}
				if err := addUserToInbound(ctx, h.remoteManage, h.repo, user, fb.ServerID, fb.InboundTag); err != nil {
					log.Printf("[PackageUpdate] fallback addUserToInbound user=%s server=%d tag=%s: %v",
						fb.Username, fb.ServerID, fb.InboundTag, err)
					mu.Lock()
					warnings = append(warnings, fmt.Sprintf("节点 %s 添加用户 %s 失败", fb.NodeName, fb.Username))
					mu.Unlock()
				}
			}(fb)
		}
		fbWg.Wait()
	}

	// limiter push 后台异步,不阻塞响应
	if h.pusher != nil {
		for _, user := range targetUsers {
			go h.pusher.PushToAllServersForUser(context.Background(), user.Username)
		}
	}

	restartXrayInParallel(ctx, h.remoteManage, restartNeeded, "PackageUpdate")
	return warnings
}

// PackageDeleteHandler 处理删除包模板
type PackageDeleteHandler struct {
	repo         *storage.TrafficRepository
	remoteManage *RemoteManageHandler
	pusher       *LimiterConfigPusher
}

func NewPackageDeleteHandler(repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher) *PackageDeleteHandler {
	return &PackageDeleteHandler{repo: repo, remoteManage: remoteManage, pusher: pusher}
}

// unbindUserPackage removes every physical and routed client through the same
// coordinated whole-config transaction used by package updates. The package
// row is cleared only after every Agent has activated and verified its target.
func unbindUserPackage(ctx context.Context, repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher, username string) error {
	user, err := repo.GetUser(ctx, username)
	if err != nil {
		return err
	}
	if user.PackageID <= 0 {
		return nil
	}
	pkg, err := repo.GetPackage(ctx, user.PackageID)
	if err != nil {
		return err
	}
	updater := &PackageUpdateHandler{repo: repo, remoteManage: remoteManage, pusher: pusher}
	if err := updater.syncPackageUserNodesTransactionally(ctx, []storage.User{user}, pkg.Nodes, nil); err != nil {
		return fmt.Errorf("同步全部服务器解绑配置失败: %w", err)
	}
	if err := repo.RemovePackageFromUser(ctx, username); err != nil {
		// The database mutation failed after Agents converged. Re-apply the old
		// package as compensation; report both errors if recovery is incomplete.
		rollbackErr := updater.syncPackageUserNodesTransactionally(context.WithoutCancel(ctx), []storage.User{user}, nil, pkg.Nodes)
		return errors.Join(fmt.Errorf("清除套餐绑定失败: %w", err), rollbackErr)
	}
	if pusher != nil {
		go pusher.PushToAllServersForUser(context.Background(), username)
	}
	if sf, err := repo.GetUserPackageSubscription(ctx, username); err == nil && sf.ID > 0 {
		if derr := repo.DeleteSubscribeFile(ctx, sf.ID); derr != nil {
			log.Printf("[PackageUnbind] 删除用户 %s 套餐订阅记录失败: %v", username, derr)
		}
		if sf.Filename != "" {
			_ = os.Remove(filepath.Join("subscribes", sf.Filename))
		}
	}
	return nil
}

// unbindUserPackageLegacy keeps the former incremental implementation for
// reference during the rolling Agent upgrade. Strict paths do not call it.
func unbindUserPackageLegacy(ctx context.Context, repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher, username string) error {
	var mu sync.Mutex
	var operationErrors []error
	var removedPhysical []storage.UserInboundConfig
	var removedRouted []int64
	user, err := repo.GetUser(ctx, username)
	if err != nil {
		return err
	}
	// 只 routed 路径(改 routing rules)需要重启;普通 inbound remove-client 由 agent 热更新。
	restartNeeded := map[int64]bool{}

	// inbound 移除 + routed 下线并发执行 — 每条目独立,失败只 log。
	var wg sync.WaitGroup

	configs, err := repo.GetUserInboundConfigs(ctx, username)
	if err != nil {
		log.Printf("[PackageUnbind] 获取用户 %s 入站配置失败: %v", username, err)
		return fmt.Errorf("读取用户入站凭据失败: %w", err)
	}
	for _, cfg := range configs {
		wg.Add(1)
		go func(cfg storage.UserInboundConfig) {
			defer wg.Done()
			if err := removeUserFromInbound(ctx, remoteManage, cfg); err != nil {
				log.Printf("[PackageUnbind] 从入站 %s(server %d)移除用户 %s 失败: %v", cfg.InboundTag, cfg.ServerID, username, err)
				mu.Lock()
				operationErrors = append(operationErrors, fmt.Errorf("从 server=%d inbound=%s 移除失败: %w", cfg.ServerID, cfg.InboundTag, err))
				mu.Unlock()
				return
			}
			mu.Lock()
			removedPhysical = append(removedPhysical, cfg)
			mu.Unlock()
		}(cfg)
	}

	// 子账号路径:从所有 active routed 节点下线(凭据保留,续费可恢复)
	subaccs, subErr := repo.ListUserSubaccounts(ctx, username)
	if subErr != nil {
		return fmt.Errorf("读取路由子账户失败: %w", subErr)
	}
	for _, sa := range subaccs {
		if !sa.IsActive {
			continue
		}
		wg.Add(1)
		go func(routedNodeID int64) {
			defer wg.Done()
			if node, err := repo.GetNodeByID(ctx, routedNodeID); err == nil && node.OriginalServer != "" {
				if srv, err := repo.GetRemoteServerByName(ctx, node.OriginalServer); err == nil {
					mu.Lock()
					restartNeeded[srv.ID] = true
					mu.Unlock()
				}
			}
			if err := removeUserFromRoutedNode(ctx, remoteManage, repo, username, routedNodeID); err != nil {
				log.Printf("[PackageUnbind] routed node %d 下线用户 %s 失败: %v", routedNodeID, username, err)
				mu.Lock()
				operationErrors = append(operationErrors, fmt.Errorf("从路由节点 %d 移除失败: %w", routedNodeID, err))
				mu.Unlock()
				return
			}
			mu.Lock()
			removedRouted = append(removedRouted, routedNodeID)
			mu.Unlock()
		}(sa.RoutedNodeID)
	}
	wg.Wait()
	if len(operationErrors) > 0 {
		rollbackErr := restoreUnbindChanges(ctx, repo, remoteManage, user, removedPhysical, removedRouted, restartNeeded)
		return errors.Join(errors.Join(operationErrors...), rollbackErr)
	}

	if err := restartXrayInParallelStrict(ctx, remoteManage, restartNeeded, "PackageUnbind"); err != nil {
		rollbackErr := restoreUnbindChanges(ctx, repo, remoteManage, user, removedPhysical, removedRouted, restartNeeded)
		return errors.Join(err, rollbackErr)
	}
	// Agent configuration is now confirmed. Only now remove physical credential
	// rows; until this point they are the durable rollback source.
	for _, cfg := range removedPhysical {
		if err := repo.DeleteUserInboundConfig(ctx, username, cfg.ServerID, cfg.InboundTag); err != nil {
			rollbackErr := restoreUnbindChanges(ctx, repo, remoteManage, user, removedPhysical, removedRouted, restartNeeded)
			return errors.Join(fmt.Errorf("删除 inbound=%s 凭据记录失败: %w", cfg.InboundTag, err), rollbackErr)
		}
	}
	if pusher != nil {
		go pusher.PushToAllServersForUser(context.Background(), username)
	}
	if err := repo.RemovePackageFromUser(ctx, username); err != nil && err != storage.ErrUserNotFound {
		log.Printf("[PackageUnbind] 解绑用户 %s 套餐失败: %v", username, err)
		return err
	}
	// 删除该用户残留的套餐订阅(历史 auto-gen 文件)
	if sf, err := repo.GetUserPackageSubscription(ctx, username); err == nil && sf.ID > 0 {
		if derr := repo.DeleteSubscribeFile(ctx, sf.ID); derr != nil {
			log.Printf("[PackageUnbind] 删除用户 %s 套餐订阅记录失败: %v", username, derr)
		}
		if sf.Filename != "" {
			_ = os.Remove(filepath.Join("subscribes", sf.Filename))
		}
	}
	return nil
}

func restoreUnbindChanges(ctx context.Context, repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, user storage.User, physical []storage.UserInboundConfig, routed []int64, restartNeeded map[int64]bool) error {
	var errs []error
	for _, cfg := range physical {
		if err := addUserToInbound(ctx, remoteManage, repo, user, cfg.ServerID, cfg.InboundTag); err != nil {
			errs = append(errs, fmt.Errorf("rollback inbound server=%d tag=%s: %w", cfg.ServerID, cfg.InboundTag, err))
		}
	}
	for _, nodeID := range routed {
		if err := addUserToRoutedNode(ctx, remoteManage, repo, user, nodeID); err != nil {
			errs = append(errs, fmt.Errorf("rollback routed node=%d: %w", nodeID, err))
		}
	}
	if err := restartXrayInParallelStrict(ctx, remoteManage, restartNeeded, "PackageUnbindRollback"); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (h *PackageDeleteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 从 URL 路径或请求正文中提取 ID
	var id int64
	var err error

	if r.Method == http.MethodDelete {
		// 从 URL 路径提取：/api/admin/packages/123
		pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/admin/packages/"), "/")
		if len(pathParts) > 0 && pathParts[0] != "" {
			id, err = strconv.ParseInt(pathParts[0], 10, 64)
			if err != nil {
				http.Error(w, "Invalid package ID", http.StatusBadRequest)
				return
			}
		}
	} else {
		// 从 JSON 正文中提取
		var req struct {
			ID int64 `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		id = req.ID
	}

	if id <= 0 {
		http.Error(w, "Invalid package ID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	pkg, err := h.repo.GetPackage(ctx, id)
	if err != nil {
		if err == storage.ErrPackageNotFound {
			http.Error(w, "Package not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	users, err := h.repo.ListUsersWithPackage(ctx)
	if err != nil {
		http.Error(w, "读取套餐用户失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	targetUsers := make([]storage.User, 0)
	snapshots := make([]*storage.UserPackageAssignmentSnapshot, 0)
	for _, user := range users {
		if user.PackageID != id {
			continue
		}
		snapshot, snapshotErr := h.repo.GetUserPackageAssignmentSnapshot(ctx, user.Username)
		if snapshotErr != nil {
			http.Error(w, "保存用户套餐状态失败: "+snapshotErr.Error(), http.StatusInternalServerError)
			return
		}
		targetUsers = append(targetUsers, user)
		snapshots = append(snapshots, snapshot)
	}

	updater := &PackageUpdateHandler{repo: h.repo, remoteManage: h.remoteManage, pusher: h.pusher}
	if err := updater.syncPackageUserNodesTransactionally(ctx, targetUsers, pkg.Nodes, nil); err != nil {
		http.Error(w, "套餐删除失败，所有用户与节点配置均已保留: "+err.Error(), http.StatusBadGateway)
		return
	}
	// Agent 已整体切换后再提交用户绑定。任一数据库写入失败，恢复全部
	// assignment，并以另一笔完整配置事务恢复全部 Agent。
	var databaseErr error
	for _, user := range targetUsers {
		if err := h.repo.RemovePackageFromUser(ctx, user.Username); err != nil {
			databaseErr = fmt.Errorf("清除用户 %s 套餐绑定: %w", user.Username, err)
			break
		}
	}
	if databaseErr == nil {
		databaseErr = h.repo.DeletePackage(ctx, id)
	}
	if databaseErr != nil {
		var recoveryErrs []error
		for _, snapshot := range snapshots {
			if err := h.repo.RestoreUserPackageAssignment(context.WithoutCancel(ctx), snapshot); err != nil {
				recoveryErrs = append(recoveryErrs, err)
			}
		}
		if err := updater.syncPackageUserNodesTransactionally(context.WithoutCancel(ctx), targetUsers, nil, pkg.Nodes); err != nil {
			recoveryErrs = append(recoveryErrs, err)
		}
		http.Error(w, errors.Join(fmt.Errorf("套餐删除数据库提交失败: %w", databaseErr), errors.Join(recoveryErrs...)).Error(), http.StatusInternalServerError)
		return
	}

	for _, user := range targetUsers {
		if h.pusher != nil {
			go h.pusher.PushToAllServersForUser(context.Background(), user.Username)
		}
		if sf, getErr := h.repo.GetUserPackageSubscription(ctx, user.Username); getErr == nil && sf.ID > 0 {
			_ = h.repo.DeleteSubscribeFile(ctx, sf.ID)
			if sf.Filename != "" {
				_ = os.Remove(filepath.Join("subscribes", sf.Filename))
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":       "Package deleted successfully",
		"unbound_users": len(targetUsers),
	})
}

// PackageUnassignHandler 处理从用户删除包分配
type PackageUnassignHandler struct {
	repo         *storage.TrafficRepository
	remoteManage *RemoteManageHandler
	pusher       *LimiterConfigPusher
}

func NewPackageUnassignHandler(repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher) *PackageUnassignHandler {
	return &PackageUnassignHandler{repo: repo, remoteManage: remoteManage, pusher: pusher}
}

func (h *PackageUnassignHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	if err := unbindUserPackage(ctx, h.repo, h.remoteManage, h.pusher, req.Username); err != nil {
		if err == storage.ErrUserNotFound {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "套餐解绑失败，原套餐绑定已保留: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Package removed successfully",
	})
}

// PackageAssignHandler 处理将包分配给用户的操作
type PackageAssignHandler struct {
	repo         *storage.TrafficRepository
	remoteManage *RemoteManageHandler
	pusher       *LimiterConfigPusher
}

func NewPackageAssignHandler(repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher) *PackageAssignHandler {
	return &PackageAssignHandler{repo: repo, remoteManage: remoteManage, pusher: pusher}
}

type assignPackageRequest struct {
	Username   string `json:"username"`
	PackageID  int64  `json:"package_id"`
	StartDate  string `json:"start_date"`
	ExpireDate string `json:"expire_date"`
	// IsReset/ResetDay 用指针:nil = 请求未提供 → 回退取套餐自身的 is_reset/reset_day(套餐才是真值源);
	// 非 nil = 调用方显式覆盖。历史 bug:前端恒发 is_reset=false 让套餐的按月重置永远不生效。
	IsReset  *bool `json:"is_reset"`
	ResetDay *int  `json:"reset_day"`
}

func (h *PackageAssignHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req assignPackageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}
	if req.PackageID <= 0 {
		http.Error(w, "Package ID is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	// 先取套餐:既用于 is_reset/reset_day 的回退真值源,也用于默认到期日(CycleDays)。
	pkg, pkgErr := h.repo.GetPackage(ctx, req.PackageID)

	// 解析重置设置:请求提供了就用请求值(管理员显式覆盖),否则回退套餐自身值。
	isReset := false
	resetDay := 0
	if pkg != nil {
		isReset = pkg.IsReset
		resetDay = pkg.ResetDay
	}
	if req.IsReset != nil {
		isReset = *req.IsReset
	}
	if req.ResetDay != nil {
		resetDay = *req.ResetDay
	}
	// 开启按月重置但没有有效重置日 → 取当天(封顶 28,避开月末不存在的日期),与 TG 续期路径一致。
	// 否则 reset_day=0 落库会让 shouldResetThisMonth 永远返回 false —— 开关形同虚设。
	if isReset && resetDay == 0 {
		resetDay = time.Now().Day()
		if resetDay > 28 {
			resetDay = 28
		}
	}
	if isReset && (resetDay < 1 || resetDay > 31) {
		http.Error(w, "Reset day must be between 1 and 31", http.StatusBadRequest)
		return
	}

	var startDate time.Time
	if req.StartDate != "" {
		parsed, err := time.Parse("2006-01-02", req.StartDate)
		if err != nil {
			http.Error(w, "Invalid start_date format, expected YYYY-MM-DD", http.StatusBadRequest)
			return
		}
		startDate = parsed
	} else {
		startDate = time.Now()
	}

	// 计算到期时间：优先使用前端传入的 expire_date，否则默认 start + CycleDays 天
	var endDate time.Time
	if req.ExpireDate != "" {
		parsed, err := time.Parse("2006-01-02", req.ExpireDate)
		if err != nil {
			http.Error(w, "Invalid expire_date format, expected YYYY-MM-DD", http.StatusBadRequest)
			return
		}
		endDate = parsed
	} else if pkgErr == nil && pkg != nil && pkg.CycleDays > 0 {
		endDate = startDate.AddDate(0, 0, pkg.CycleDays)
	} else {
		endDate = startDate.AddDate(0, 1, 0)
	}

	warnings, perr := h.AssignAndProvision(ctx, req.Username, req.PackageID, startDate, endDate, isReset, resetDay)
	if perr != nil {
		if perr == storage.ErrPackageNotFound {
			http.Error(w, "Package not found", http.StatusNotFound)
			return
		}
		if perr == storage.ErrUserNotFound {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, perr.Error(), http.StatusInternalServerError)
		return
	}
	if len(warnings) > 0 {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"message": "Package assigned with warnings", "warnings": warnings})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"message": "Package assigned successfully"})
}

// AssignAndProvision 绑定套餐并真正下发(给套餐节点 inbound 加用户凭据 + 批量推服务器 + 重启 xray + 推限速)。
// 抽自 ServeHTTP,供 web /api/admin/packages/assign 与 TGBOT 注册/兑换共用,确保两条路都生效。
func (h *PackageAssignHandler) AssignAndProvision(ctx context.Context, username string, packageID int64, startDate, endDate time.Time, isReset bool, resetDay int) ([]string, error) {
	snapshot, err := h.repo.GetUserPackageAssignmentSnapshot(ctx, username)
	if err != nil {
		return nil, err
	}
	newPackage, err := h.repo.GetPackage(ctx, packageID)
	if err != nil {
		return nil, err
	}
	var oldNodes []int64
	if snapshot.PackageID != nil && *snapshot.PackageID != packageID {
		if previousPackage, getErr := h.repo.GetPackage(ctx, *snapshot.PackageID); getErr == nil && previousPackage != nil {
			oldNodes = previousPackage.Nodes
		}
	}
	// Rebinding the same package is an explicit consistency repair. Treat every
	// package node as an addition so missing clients/routed users are rebuilt in
	// the complete candidate instead of returning early.
	if snapshot.PackageID != nil && *snapshot.PackageID == packageID {
		oldNodes = nil
	}

	if err := h.repo.AssignPackageToUser(ctx, username, packageID, startDate, endDate, isReset, resetDay); err != nil {
		return nil, err
	}
	user, err := h.repo.GetUser(ctx, username)
	if err != nil {
		_ = h.repo.RestoreUserPackageAssignment(context.WithoutCancel(ctx), snapshot)
		return nil, err
	}
	updater := &PackageUpdateHandler{repo: h.repo, remoteManage: h.remoteManage, pusher: h.pusher}
	if err := updater.syncPackageUserNodesTransactionally(ctx, []storage.User{user}, oldNodes, newPackage.Nodes); err != nil {
		restoreErr := h.repo.RestoreUserPackageAssignment(context.WithoutCancel(ctx), snapshot)
		return nil, errors.Join(fmt.Errorf("套餐配置未能在全部服务器生效: %w", err), restoreErr)
	}
	if h.pusher != nil {
		go h.pusher.PushToAllServersForUser(context.Background(), username)
	}
	return nil, nil
}

// assignAndProvisionLegacy is retained temporarily for rolling upgrades with
// old Agents. New call sites use the coordinated whole-config transaction
// above; strict operations never fall back to this partial-success path.
func (h *PackageAssignHandler) assignAndProvisionLegacy(ctx context.Context, username string, packageID int64, startDate, endDate time.Time, isReset bool, resetDay int) ([]string, error) {
	var warnings []string

	// "套餐未变"的纯续期 / 改到期路径:用户当前就绑着这个 package,client 早已下发到各节点入站,
	// 调整到期时间(以及 reset 设置)只是 DB 变更 —— 到期由 TrafficLimitEnforcer 在 PackageEndDate
	// 过后统一摘除 client,有效期内不按日期动 xray。因此这里无需重新下发 client。
	// 跳过重下发还能避免 GetUserInboundConfig 与 agent 实际 client 漂移时,generateCredential 生成
	// "同 email(username__tag)不同 uuid" 的重复 client(agent matchClientCredential 按 uuid 判重不按 email)。
	// 注意:用户套餐到期后 enforcer 会清空 package_id,故"过期后续费"是 prev.PackageID(0)≠packageID,
	// 仍走下面的重新下发分支,client 会被正常加回。
	samePackage := false
	if prev, perr := h.repo.GetUser(ctx, username); perr == nil && prev.PackageID == packageID {
		samePackage = true
	}

	if err := h.repo.AssignPackageToUser(ctx, username, packageID, startDate, endDate, isReset, resetDay); err != nil {
		return nil, err
	}

	if samePackage {
		// 只推一次 limiter 配置,让 agent 内存 limiter 跟 DB(reset_day / is_active 等)对齐;不碰 xray client。
		if h.pusher != nil {
			go h.pusher.PushToAllServersForUser(context.Background(), username)
		}
		return warnings, nil
	}

	// 获取套餐关联的节点，为每个节点的入站添加用户凭据
	pkg, err := h.repo.GetPackage(ctx, packageID)
	if err != nil {
		log.Printf("[PackageAssign] Failed to get package: %v", err)
	} else {
		user, err := h.repo.GetUser(ctx, username)
		if err != nil {
			log.Printf("[PackageAssign] Failed to get user: %v", err)
		} else {
			var mu sync.Mutex
			// 只收集"必须重启 xray 才能让改动生效"的服务器:
			//   - routed 节点:改了 routing rules → 必须重启
			//   - 非 routed 节点:add-client 已由 agent 走 HandlerService 热更新(replaceRuntimeInbound)→ 不需要重启
			// 早先的版本无差别对所有受影响服务器重启,跨 5 台机器串行能多花 15s。
			restartNeeded := map[int64]bool{}
			// per-server 收集 routed 节点的 batch items + 普通 inbound 加 client items。
			// 新 agent 支持 /api/child/batch-apply → 同 server 所有 client + routing 改动一次 round-trip;
			// 老 agent 不支持 → applyRoutedBatchOrFallback / applyInboundBatchOrFallback 内部 fallback 逐项。
			routedBatch := map[int64][]routedBatchItem{}
			inboundBatch := map[int64][]InboundClientAddItem{}
			// 普通 inbound 节点 cache miss / 续费跳过时,fallback 直接走逐项 addUserToInbound。
			type inboundFallbackItem struct {
				ServerID   int64
				InboundTag string
				NodeName   string
			}
			var inboundFallbacks []inboundFallbackItem

			// both(v4/v6)会为同一 inbound 建两个节点(同 server + 同 InboundTag)。凭据绑到 inbound 而非节点,
			// 按 (server, inboundTag) 去重,避免同一用户同一入站被加两个同 email client → xray "User already exists"。
			// routed 节点走 node.ID 独立路径,不参与此去重。
			inboundSeen := map[string]bool{}
			// 节点绑定并发跑 — routed / inbound 都只在阶段一收集,阶段二 per-server batch 一次性提交。
			var bindWg sync.WaitGroup
			for _, nodeID := range pkg.Nodes {
				bindWg.Add(1)
				go func(nodeID int64) {
					defer bindWg.Done()
					node, err := h.repo.GetNodeByID(ctx, nodeID)
					if err != nil {
						log.Printf("[PackageAssign] Failed to get node %d: %v", nodeID, err)
						return
					}
					if node.NodeType == "routed" {
						if srv, err := h.repo.GetRemoteServerByName(ctx, node.OriginalServer); err == nil {
							mu.Lock()
							restartNeeded[srv.ID] = true
							mu.Unlock()
						}
						item, err := collectRoutedBatchItem(ctx, h.remoteManage, h.repo, user, node.ID)
						if err != nil {
							log.Printf("[PackageAssign] routed node %d collect failed for user %s: %v", node.ID, username, err)
							mu.Lock()
							warnings = append(warnings, fmt.Sprintf("路由出站 %s 添加用户失败", node.NodeName))
							mu.Unlock()
							return
						}
						if item != nil {
							mu.Lock()
							routedBatch[item.ServerID] = append(routedBatch[item.ServerID], *item)
							mu.Unlock()
						}
						return
					}
					if node.InboundTag == "" {
						return
					}
					// original_server 为空(多台共用域名致 host 匹配歧义)时用 inbound_tag 兜底解析;
					// 解析不出则告警回传前端 + log,不再静默丢弃 —— 这正是"用户只拿到管理员配置"的历史根因。
					server, reason := resolveNodeServer(ctx, h.repo, h.remoteManage, node)
					if server == nil {
						log.Printf("[PackageAssign] 跳过节点 %s 对用户 %s 的配置下发: %s", node.NodeName, username, reason)
						mu.Lock()
						warnings = append(warnings, fmt.Sprintf("节点 %s 无法确定所属服务器,已跳过用户配置下发", node.NodeName))
						mu.Unlock()
						return
					}
					// 同一 (server, inbound) 只收集一次 —— both 的 v4/v6 双节点共享同一入站,避免重复加 client。
					seenKey := user.Username + "|" + server.Name + "|" + node.InboundTag
					mu.Lock()
					if inboundSeen[seenKey] {
						mu.Unlock()
						return
					}
					inboundSeen[seenKey] = true
					mu.Unlock()
					// 阶段一:从 InboundCache 算 cred,收集成 batch item;cache miss / 续费 → fallback 逐项。
					item, collected, cerr := collectInboundClientAddItem(ctx, h.remoteManage.inboundCache, h.repo, user, server.ID, node.InboundTag)
					if cerr != nil {
						mu.Lock()
						inboundFallbacks = append(inboundFallbacks, inboundFallbackItem{ServerID: server.ID, InboundTag: node.InboundTag, NodeName: node.NodeName})
						mu.Unlock()
						return
					}
					if collected && item != nil {
						mu.Lock()
						inboundBatch[item.ServerID] = append(inboundBatch[item.ServerID], *item)
						mu.Unlock()
					}
				}(nodeID)
			}
			bindWg.Wait()

			// 阶段二 — per-server 并行调 batch-apply。
			// routed + inbound 各自一批,跨 server 并行;同 server 内 inbound 与 routed 分别一次 round-trip(不合并避免 routed 重启把 inbound 加 client 也"等"上)。
			var routeWg sync.WaitGroup
			for serverID, items := range routedBatch {
				routeWg.Add(1)
				go func(sid int64, list []routedBatchItem) {
					defer routeWg.Done()
					ws := applyRoutedBatchOrFallback(ctx, h.remoteManage, h.repo, sid, list, "PackageAssign")
					if len(ws) > 0 {
						mu.Lock()
						warnings = append(warnings, ws...)
						mu.Unlock()
					}
				}(serverID, items)
			}
			for serverID, items := range inboundBatch {
				routeWg.Add(1)
				go func(sid int64, list []InboundClientAddItem) {
					defer routeWg.Done()
					ws := applyInboundBatchOrFallback(ctx, h.remoteManage, h.repo, sid, list, "PackageAssign")
					if len(ws) > 0 {
						mu.Lock()
						warnings = append(warnings, ws...)
						mu.Unlock()
					}
				}(serverID, items)
			}
			routeWg.Wait()

			// 阶段三 — cache miss 类 fallback:并发跑逐项 addUserToInbound(老路径)。
			if len(inboundFallbacks) > 0 {
				log.Printf("[PackageAssign] %d inbound items fell back to per-item add (cache miss / no batch)", len(inboundFallbacks))
				var fbWg sync.WaitGroup
				for _, fb := range inboundFallbacks {
					fbWg.Add(1)
					go func(fb inboundFallbackItem) {
						defer fbWg.Done()
						if err := addUserToInbound(ctx, h.remoteManage, h.repo, user, fb.ServerID, fb.InboundTag); err != nil {
							log.Printf("[PackageAssign] fallback addUserToInbound user=%s server=%d tag=%s: %v",
								username, fb.ServerID, fb.InboundTag, err)
							mu.Lock()
							warnings = append(warnings, fmt.Sprintf("节点 %s 添加用户失败", fb.NodeName))
							mu.Unlock()
						}
					}(fb)
				}
				fbWg.Wait()
			}

			restartXrayInParallel(ctx, h.remoteManage, restartNeeded, "PackageAssign")
		}
	}

	if h.pusher != nil {
		go h.pusher.PushToAllServersForUser(context.Background(), username)
	}
	return warnings, nil
}

func (h *PackageAssignHandler) autoGenerateSubscription(ctx context.Context, username string, packageID int64) {
	pkg, err := h.repo.GetPackage(ctx, packageID)
	if err != nil {
		log.Printf("[PackageAssign] 自动生成订阅失败: 获取套餐错误: %v", err)
		return
	}

	var proxies []map[string]any
	for _, nodeID := range pkg.Nodes {
		node, err := h.repo.GetNodeByID(ctx, nodeID)
		if err != nil || !node.Enabled || node.ClashConfig == "" {
			continue
		}
		var proxyConfig map[string]any
		if err := json.Unmarshal([]byte(node.ClashConfig), &proxyConfig); err != nil {
			continue
		}
		proxies = append(proxies, proxyConfig)
	}

	if len(proxies) == 0 {
		log.Printf("[PackageAssign] 自动生成订阅跳过: 套餐 %d 无可用节点", packageID)
		return
	}

	templateContent, err := h.loadDefaultTemplate(ctx)
	if err != nil {
		log.Printf("[PackageAssign] 自动生成订阅失败: %v", err)
		return
	}

	processor := substore.NewTemplateV3Processor(nil, nil)
	result, err := processor.ProcessTemplate(templateContent, proxies)
	if err != nil {
		log.Printf("[PackageAssign] 自动生成订阅失败: 处理模板错误: %v", err)
		return
	}

	result, err = injectProxiesIntoTemplate(result, proxies)
	if err != nil {
		log.Printf("[PackageAssign] 自动生成订阅失败: 注入代理错误: %v", err)
		return
	}

	os.MkdirAll("subscribes", 0755)

	existing, err := h.repo.GetUserPackageSubscription(ctx, username)
	if err == nil {
		filePath := filepath.Join("subscribes", existing.Filename)
		if err := os.WriteFile(filePath, []byte(result), 0644); err != nil {
			log.Printf("[PackageAssign] 自动生成订阅失败: 写入文件错误: %v", err)
			return
		}
		existing.Name = fmt.Sprintf("%s - %s", username, pkg.Name)
		existing.Description = "套餐自动生成"
		h.repo.UpdateSubscribeFile(ctx, existing)
		log.Printf("[PackageAssign] 已更新用户 %s 的套餐订阅文件", username)
		return
	}

	filename := fmt.Sprintf("pkg_%s.yaml", username)
	filePath := filepath.Join("subscribes", filename)
	if err := os.WriteFile(filePath, []byte(result), 0644); err != nil {
		log.Printf("[PackageAssign] 自动生成订阅失败: 写入文件错误: %v", err)
		return
	}

	file := storage.SubscribeFile{
		Name:        fmt.Sprintf("%s - %s", username, pkg.Name),
		Description: "套餐自动生成",
		Type:        storage.SubscribeTypePackage,
		Filename:    filename,
		CreatedBy:   username, // 套餐自动生成的订阅归属到该用户，否则后续 GetSubscribeFileByShortCode 拿不到归属用户
	}
	created, err := h.repo.CreateSubscribeFile(ctx, file)
	if err != nil {
		log.Printf("[PackageAssign] 自动生成订阅失败: 创建记录错误: %v", err)
		return
	}
	if err := h.repo.AssignSubscriptionToUser(ctx, username, created.ID); err != nil {
		log.Printf("[PackageAssign] 自动生成订阅失败: 关联用户错误: %v", err)
		return
	}
	log.Printf("[PackageAssign] 已为用户 %s 创建套餐订阅文件", username)
}

func (h *PackageAssignHandler) loadDefaultTemplate(ctx context.Context) (string, error) {
	templatesDir := "rule_templates"
	var candidates []string

	cfg, err := h.repo.GetSystemConfig(ctx)
	if err == nil && cfg.DefaultTemplateFilename != "" {
		candidates = append(candidates, cfg.DefaultTemplateFilename)
	}
	candidates = append(candidates, "default.yaml", "redirhost__v3.yaml")

	for _, name := range candidates {
		content, err := os.ReadFile(filepath.Join(templatesDir, name))
		if err == nil {
			return string(content), nil
		}
	}
	return "", fmt.Errorf("未找到可用模板")
}

// addUserToInbound 获取远程入站配置，添加用户凭据，然后重新提交
// restartXrayInParallel 并发对多台服务器做 xray restart-with-recovery,等全部完成后返回。
// 单台 restartXrayWithRecovery 至少 2s(verify wait),5 台串行 ≥10s;并发后整体只看最慢一台。
// 失败只记日志,不打断 —— 调用方语义里"重启 best-effort",和原顺序版本一致。
func restartXrayInParallel(ctx context.Context, rm *RemoteManageHandler, serverIDs map[int64]bool, logPrefix string) {
	if len(serverIDs) == 0 {
		return
	}
	var wg sync.WaitGroup
	for sid := range serverIDs {
		wg.Add(1)
		go func(sid int64) {
			defer wg.Done()
			if err := rm.restartXrayWithRecovery(ctx, sid, logPrefix); err != nil {
				log.Printf("[%s] restart xray on server %d failed: %v", logPrefix, sid, err)
			}
		}(sid)
	}
	wg.Wait()
}

// restartXrayInParallelStrict is used by operations that promise all-or-fail
// semantics. Unlike the legacy best-effort helper it returns every failed
// target so the caller must not commit the package/user state.
func restartXrayInParallelStrict(ctx context.Context, rm *RemoteManageHandler, serverIDs map[int64]bool, logPrefix string) error {
	if len(serverIDs) == 0 {
		return nil
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	for sid := range serverIDs {
		wg.Add(1)
		go func(serverID int64) {
			defer wg.Done()
			if err := rm.restartXrayWithRecovery(ctx, serverID, logPrefix); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("server %d restart xray: %w", serverID, err))
				mu.Unlock()
			}
		}(sid)
	}
	wg.Wait()
	return errors.Join(errs...)
}

// inboundCredLocks 串行化同一 (user, server, inbound) 的凭据生成 + 写 DB。
// 根治跨操作并发(套餐绑定 + 限速 enforcer / node-sync 同时命中同一 user+inbound)时,两条路径各自
// 查到 DB 无记录 → 各生成不同随机 uuid → agent 按 uuid 去重失效 → 同 email 重复子账户。
var inboundCredLocks sync.Map // key "username|serverID|inboundTag" → *sync.Mutex

func inboundCredLock(username string, serverID int64, inboundTag string) *sync.Mutex {
	key := fmt.Sprintf("%s|%d|%s", username, serverID, inboundTag)
	v, _ := inboundCredLocks.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// getOrCreateInboundCredential 在 (user, server, inbound) 全局锁内原子地拿到该用户在该入站的凭据:
//  1. DB user_inbound_configs 有记录 → 复用(续费 / 重复绑定 / 并发中的第二个请求)
//  2. agent 该入站已有同 email 的 client(settings 快照)→ 复用并回写 DB
//  3. 都没有 → 生成新凭据 + 立即写 DB
//
// 「全局锁 + 生成时立即写 DB」是根治并发重复的核心:串行后第二个并发请求在步骤 1 就命中第一个刚写入的
// 凭据、拿到同一 uuid,agent add-client 按 uuid 幂等 no-op,不再产生同 email 不同 uuid 的重复子账户。
// settings 为该入站 settings 快照(InboundCache 或 live GET 均可)。返回 (credential, credJSON, reused)。
func getOrCreateInboundCredential(ctx context.Context, repo *storage.TrafficRepository,
	user storage.User, serverID int64, inboundTag, protocol string, settings map[string]interface{},
) (map[string]interface{}, string, bool, error) {
	lock := inboundCredLock(user.Username, serverID, inboundTag)
	lock.Lock()
	defer lock.Unlock()

	email := user.Username + "__" + inboundTag

	// 1) DB 复用。
	//
	// 注意 reused 的语义:它表示"凭据是复用的"(调用方据此决定是否仍需下发)。
	// 入站删除后重建同 tag 时,DB 会留下孤儿凭据而 agent 上并没有对应 client;此时若直接
	// reused=true 返回,调用方会跳过下发 → 订阅发出 xray 里不存在的 UUID(TCPing 通但连不上)。
	// 所以这里要拿 agent 实配(settings)核对:agent 缺 client 时仍复用 DB 凭据(订阅 UUID 不变),
	// 但 reused=false 让调用方照常下发一次(add-client 幂等,安全)。
	if existing, _ := repo.GetUserInboundConfig(ctx, user.Username, serverID, inboundTag); existing != nil && existing.Protocol == protocol {
		var cred map[string]interface{}
		if json.Unmarshal([]byte(existing.CredentialJSON), &cred) == nil && cred != nil {
			// settings == nil 表示调用方没拿到 agent 实配(cache miss 等),无从判断 → 维持
			// "DB 有即复用"的旧行为。只有确实拿到实配、且其中没有该 email 的 client 时,
			// 才认定 agent 侧缺失:此时仍复用 DB 凭据(订阅 UUID 不变),但 reused=false
			// 让调用方照常下发一次。
			if settings != nil && extractClientByEmail(settings, email) == nil {
				log.Printf("[InboundCred] DB 有凭据但 agent 缺 client,复用凭据并重新下发 user=%s server=%d tag=%s",
					user.Username, serverID, inboundTag)
				return cred, existing.CredentialJSON, false, nil
			}
			return cred, existing.CredentialJSON, true, nil
		}
	}

	// 2) agent 已有同 email → 复用并回写 DB(主控与 agent 重新对齐,下次直接走步骤 1)
	if reuse := extractClientByEmail(settings, email); reuse != nil {
		b, _ := json.Marshal(reuse)
		credJSON := string(b)
		_ = repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
			Username: user.Username, ServerID: serverID, InboundTag: inboundTag,
			Protocol: protocol, CredentialJSON: credJSON,
		})
		return reuse, credJSON, true, nil
	}

	// 3) 生成新 + 立即写 DB(锁内)。后续 add-client / batch-apply 即便失败也没关系:凭据已 reserve,
	// 下次复用同一份重发,agent 幂等 → 永不重复。
	var method string
	if settings != nil {
		method, _ = settings["method"].(string)
	}
	cred, credJSON, err := generateCredential(protocol, user, method, inboundTag)
	if err != nil {
		return nil, "", false, err
	}
	// VLESS Reality 从现有 client 继承 flow
	if strings.EqualFold(protocol, "vless") {
		if _, hasFlow := cred["flow"]; !hasFlow && settings != nil {
			if clients, ok := settings["clients"].([]interface{}); ok && len(clients) > 0 {
				if first, ok := clients[0].(map[string]interface{}); ok {
					if flow, ok := first["flow"].(string); ok && flow != "" {
						cred["flow"] = flow
						if b, err := json.Marshal(cred); err == nil {
							credJSON = string(b)
						}
					}
				}
			}
		}
	}
	_ = repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: user.Username, ServerID: serverID, InboundTag: inboundTag,
		Protocol: protocol, CredentialJSON: credJSON,
	})
	return cred, credJSON, false, nil
}

func addUserToInbound(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, user storage.User, serverID int64, inboundTag string) error {
	// 只读 inbound 列表,目的是拿到 protocol/method/flow 这些构造 credential 必需的字段。
	// 不再在主控这边修改 inbound:实际的"加 client"由 agent 在 inboundsMu 锁内原子完成,
	// 避免多用户并发绑套餐时主控基于同一份快照各自 append → 后写覆盖先写 → 丢 client。
	result, err := rm.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/inbounds", nil)
	if err != nil {
		return fmt.Errorf("get inbounds: %w", err)
	}

	var resp struct {
		Success  bool                     `json:"success"`
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if err := json.Unmarshal(result, &resp); err != nil || !resp.Success {
		return fmt.Errorf("parse inbounds response: %v", err)
	}

	var targetInbound map[string]interface{}
	for _, ib := range resp.Inbounds {
		if tag, _ := ib["tag"].(string); tag == inboundTag {
			targetInbound = ib
			break
		}
	}
	if targetInbound == nil {
		return fmt.Errorf("inbound %s not found", inboundTag)
	}

	protocol, _ := targetInbound["protocol"].(string)
	settings, _ := targetInbound["settings"].(map[string]interface{})

	// 凭据统一走 getOrCreateInboundCredential:全局锁内查 DB 复用 / 按 email 复用 / 生成 + 立即写 DB。
	// 根治跨操作并发时两条路径各自生成不同 uuid 的重复子账户;flow 继承 + 写 DB 都在其内部完成。
	credential, _, _, err := getOrCreateInboundCredential(ctx, repo, user, serverID, inboundTag, protocol, settings)
	if err != nil {
		return fmt.Errorf("get or create credential: %w", err)
	}

	// 原子 add-client:agent 端在 inboundsMu 内做 read-modify-write,自带幂等(已存在则 no-op)。
	return mutateInboundClient(ctx, rm, serverID, inboundTag, "add-client", credential)
}

// extractClientByEmail 在 inbound.settings 的 clients / users / accounts 数组里按 email 找现存 client,
// 命中返回其副本(浅拷贝),没有则 nil。用于"加 client 前先按 email 查、有就复用"的去重兜底。
func extractClientByEmail(settings map[string]interface{}, email string) map[string]interface{} {
	if settings == nil || email == "" {
		return nil
	}
	for _, key := range []string{"clients", "users", "accounts"} {
		arr, _ := settings[key].([]interface{})
		for _, c := range arr {
			cm, _ := c.(map[string]interface{})
			if cm == nil {
				continue
			}
			if e, _ := cm["email"].(string); e == email {
				cp := make(map[string]interface{}, len(cm))
				for k, v := range cm {
					cp[k] = v
				}
				return cp
			}
		}
	}
	return nil
}

// removeUserFromInbound 通过 agent 原子 remove-client 移除用户凭据。
// 主控不再持有 inbound 副本,所以也不存在并发解绑时彼此覆盖的可能。
func removeUserFromInbound(ctx context.Context, rm *RemoteManageHandler, cfg storage.UserInboundConfig) error {
	var savedCred map[string]interface{}
	if err := json.Unmarshal([]byte(cfg.CredentialJSON), &savedCred); err != nil || savedCred == nil {
		return fmt.Errorf("parse saved credential: %v", err)
	}
	return mutateInboundClient(ctx, rm, cfg.ServerID, cfg.InboundTag, "remove-client", savedCred)
}

// shadowsocksKeyLength 根据 SS method 返回 password 应有的字节数（base64 解码后）。
func shadowsocksKeyLength(method string) int {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "2022-blake3-aes-128-gcm":
		return 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32
	}
	// 老 SS 算法对 key 长度宽松,16 字节够大多数场景。
	return 16
}

// generateCredential 生成单用户在指定 inbound 上的认证凭据。
// shadowsocks 协议要求 password 与 method 的 key length 严格匹配,否则 xray reload 会失败。
// SS2022 :
//
//	2022-blake3-aes-128-gcm           → 16 bytes (base64 24 chars)
//	2022-blake3-aes-256-gcm           → 32 bytes
//	2022-blake3-chacha20-poly1305     → 32 bytes
//
// 老 SS / 非 2022 method → 任意长度都接受,默认给 16 bytes 即可。
//
// email 强制使用 `<username>__<inboundTag>` 格式,保证同一 user 在同一 server 多 inbound 时
// 每条 client 的 email 唯一 — Xray stats 才能按 inbound 拆开 per-user 流量,前端 drilldown
// 无需"多 inbound 平均分"近似。反查走 ResolveUsernameByEmail 的 `__` split 规则,
// 跟 routed 子账户 `<username>__<id>__<label>` 命名兼容(都取首段当 username)。
func generateCredential(protocol string, user storage.User, method, inboundTag string) (map[string]interface{}, string, error) {
	cred := make(map[string]interface{})
	email := user.Username + "__" + inboundTag

	switch strings.ToLower(protocol) {
	case "vless", "vmess":
		id := uuid.New().String()
		cred["id"] = id
		cred["email"] = email
		cred["level"] = 0
	case "trojan":
		cred["password"] = uuid.New().String()
		cred["email"] = email
		cred["level"] = 0
	case "anytls":
		cred["password"] = uuid.New().String()
		cred["email"] = email
		cred["level"] = 0
	case "snell":
		// Snell v4/v5 多用户 = 每用户独立 psk(逐 PSK 试解);version/obfs 由 inbound(users[0])决定。
		// v6(共享 psk + clientId)需 version 感知,由 inbound 创建时处理,此处按 v4/v5 生成 psk。
		cred["psk"] = uuid.New().String()
		cred["email"] = email
		cred["level"] = 0
	case "mieru":
		// mieru 多用户 = 每用户 username(取面板用户名,inbound 内唯一)+ 独立 password。
		// 服务端按 username 派生 userTag 定位用户;username+password 派生加密密钥。
		cred["username"] = user.Username
		cred["password"] = uuid.New().String()
		cred["email"] = email
		cred["level"] = 0
	case "hysteria":
		// HY2 客户端凭据:auth(密码) + email(用于 per-user 流量统计,接入套餐限额)。
		cred["auth"] = uuid.New().String()
		cred["email"] = email
		cred["level"] = 0
	case "shadowsocks":
		keyLen := shadowsocksKeyLength(method)
		key := make([]byte, keyLen)
		rand.Read(key)
		cred["password"] = base64.StdEncoding.EncodeToString(key)
		cred["email"] = email
		cred["level"] = 0
	case "socks", "http":
		cred["user"] = user.Username
		cred["pass"] = uuid.New().String()[:16]
	default:
		return nil, "", fmt.Errorf("unsupported protocol: %s", protocol)
	}

	credJSON, _ := json.Marshal(cred)
	return cred, string(credJSON), nil
}

// filterCredentials 从凭据列表中移除匹配的凭据
func filterCredentials(items []interface{}, savedCred map[string]interface{}, protocol string) []interface{} {
	var result []interface{}
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			result = append(result, item)
			continue
		}
		if matchCredential(m, savedCred, protocol) {
			continue
		}
		result = append(result, item)
	}
	return result
}

func matchCredential(a, b map[string]interface{}, protocol string) bool {
	switch strings.ToLower(protocol) {
	case "vless", "vmess":
		return fmt.Sprint(a["id"]) == fmt.Sprint(b["id"])
	case "trojan", "anytls":
		return fmt.Sprint(a["password"]) == fmt.Sprint(b["password"])
	case "snell":
		return fmt.Sprint(a["psk"]) == fmt.Sprint(b["psk"])
	case "mieru":
		return fmt.Sprint(a["username"]) == fmt.Sprint(b["username"])
	case "hysteria":
		return fmt.Sprint(a["auth"]) == fmt.Sprint(b["auth"])
	case "shadowsocks":
		return fmt.Sprint(a["password"]) == fmt.Sprint(b["password"])
	case "socks", "http":
		return fmt.Sprint(a["user"]) == fmt.Sprint(b["user"])
	}
	return false
}
