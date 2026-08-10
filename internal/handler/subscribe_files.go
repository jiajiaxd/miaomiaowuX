package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/logger"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"miaomiaowux/internal/storage"
	"miaomiaowux/internal/validator"

	"gopkg.in/yaml.v3"
)

type subscribeFilesHandler struct {
	repo *storage.TrafficRepository
}

// 返回一个仅用于管理订阅文件的处理程序。
func NewSubscribeFilesHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("subscribe files handler requires repository")
	}

	return &subscribeFilesHandler{
		repo: repo,
	}
}

func (h *subscribeFilesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/subscribe-files")
	path = strings.Trim(path, "/")

	switch {
	case path == "" && r.Method == http.MethodGet:
		h.handleList(w, r)
	case path == "" && r.Method == http.MethodPost:
		h.handleCreate(w, r)
	case path == "reorder" && r.Method == http.MethodPut:
		h.handleReorder(w, r)
	case path == "traffic" && r.Method == http.MethodGet:
		h.handleTraffic(w, r)
	case path == "import" && r.Method == http.MethodPost:
		h.handleImport(w, r)
	case path == "upload" && r.Method == http.MethodPost:
		h.handleUpload(w, r)
	case path == "create-from-config" && r.Method == http.MethodPost:
		h.handleCreateFromConfig(w, r)
	case strings.HasSuffix(path, "/users") && r.Method == http.MethodGet:
		// GET /api/admin/subscribe-files/{id}/users — 列出该订阅分配给哪些用户(同步自 mmw v0.7.3)
		idStr := strings.TrimSuffix(path, "/users")
		h.handleGetSubscriptionUsers(w, r, idStr)
	case strings.HasSuffix(path, "/content") && r.Method == http.MethodGet:
		// GET /api/admin/subscribe-files/{文件名}/内容
		filename := strings.TrimSuffix(path, "/content")
		h.handleGetContent(w, r, filename)
	case strings.HasSuffix(path, "/content") && r.Method == http.MethodPut:
		// PUT /api/admin/subscribe-files/{文件名}/内容
		filename := strings.TrimSuffix(path, "/content")
		h.handleUpdateContent(w, r, filename)
	case path != "" && path != "import" && path != "upload" && path != "create-from-config" && (r.Method == http.MethodPut || r.Method == http.MethodPatch):
		h.handleUpdate(w, r, path)
	case path != "" && path != "import" && path != "upload" && path != "create-from-config" && r.Method == http.MethodDelete:
		h.handleDelete(w, r, path)
	default:
		allowed := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
		methodNotAllowed(w, allowed...)
	}
}

func (h *subscribeFilesHandler) handleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	files, err := h.repo.ListSubscribeFiles(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 数据隔离:
	//   - 普通用户:只看自己创建的
	//   - admin:查看全部订阅,前端可按 created_by 筛选,便于代用户排错和管理。
	username := auth.UsernameFromContext(ctx)
	isAdmin := userIsAdmin(ctx, h.repo, username)
	if !isAdmin {
		filtered := make([]storage.SubscribeFile, 0, len(files))
		for _, f := range files {
			if f.CreatedBy == username {
				filtered = append(filtered, f)
			}
		}
		files = filtered
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"files": h.convertSubscribeFilesWithVersions(ctx, files),
	})
}

var errSubscribeFilenameTaken = errors.New("文件名已被其他用户占用")

// sanitizeSubscribeFilename 校验订阅文件名安全并补全扩展名。
// 防路径穿越:必须是纯基名(不含路径分隔符 / 反斜杠 / .. / 控制字符),否则拒绝;
// 统一补 .yaml/.yml 扩展。所有把 filename 拼进 subscribes/<filename> 的入口都必须先过它。
func sanitizeSubscribeFilename(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("文件名不能为空")
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") || name != filepath.Base(name) {
		return "", errors.New("文件名非法:不能包含路径分隔符或 ..")
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			return "", errors.New("文件名含非法控制字符")
		}
	}
	ext := filepath.Ext(name)
	if ext != ".yaml" && ext != ".yml" {
		name += ".yaml"
	}
	return name, nil
}

// ensureFilenameWritable 供**新建订阅**的三条路径(create / import / upload)调用:
// 目标 filename 只要已被任何一条订阅占用就拒绝。写盘(WriteFile subscribes/<filename>)前必须调用。
//
// 早期这里只拦「他人占用」,同用户或 admin 重名直接放行。但 subscribe_files.filename
// 没有唯一约束,放行的结果是**两条独立的订阅记录指向磁盘上同一个文件** ——
// 编辑其中一条的内容,另一条跟着变(表现为"两个订阅内容一致")。
// 一份物理文件不该被两条订阅共享,所以这里不再区分属主。
//
// 与 handleUpdate 改名时的判定对齐:那边按 `existingFile.ID != id` 比对,本来就是对的;
// 新建没有自身 ID,占用即冲突。
func (h *subscribeFilesHandler) ensureFilenameWritable(ctx context.Context, filename, username string) error {
	existing, err := h.repo.GetSubscribeFileByFilename(ctx, filename)
	if err != nil {
		if errors.Is(err, storage.ErrSubscribeFileNotFound) {
			return nil // 无人占用
		}
		return err
	}
	// 占用者名字带进错误里,否则用户只看到"已被占用"却不知道是哪条订阅,无从改起。
	if existing.CreatedBy != username && !userIsAdmin(ctx, h.repo, username) {
		return errSubscribeFilenameTaken
	}
	return fmt.Errorf("文件名 %s 已被订阅「%s」使用,请换一个文件名", filename, existing.Name)
}

func subscribeFileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (h *subscribeFilesHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req subscribeFileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}

	if req.Name == "" {
		writeBadRequest(w, "订阅名称是必填项")
		return
	}
	if req.URL == "" {
		writeBadRequest(w, "链接地址是必填项")
		return
	}
	if req.Type == "" {
		writeBadRequest(w, "类型是必填项")
		return
	}
	if req.Filename == "" {
		writeBadRequest(w, "文件名是必填项")
		return
	}

	username := auth.UsernameFromContext(r.Context())
	if req.TemplateFilename != "" && !canUserViewRuleTemplate(r.Context(), h.repo, username, req.TemplateFilename) {
		writeError(w, http.StatusForbidden, errors.New("无权使用该模板"))
		return
	}

	// 安全:校验文件名(防路径穿越)+ 统一扩展名。
	sanitizedName, serr := sanitizeSubscribeFilename(req.Filename)
	if serr != nil {
		writeBadRequest(w, serr.Error())
		return
	}
	req.Filename = sanitizedName

	// 跨用户占用防护:filename 已被他人订阅占用则拒绝(防后续 update-content 覆盖他人物理文件)。
	if err := h.ensureFilenameWritable(r.Context(), req.Filename, username); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}

	// 配额校验:普通用户创建订阅受全局配额限制(admin 不限)。
	if err := checkUserQuota(r.Context(), h.repo, username, "subscribe"); err != nil {
		writeError(w, http.StatusForbidden, err)
		return
	}

	file := storage.SubscribeFile{
		Name:                      req.Name,
		Description:               req.Description,
		URL:                       req.URL,
		Type:                      req.Type,
		Filename:                  req.Filename,
		TemplateFilename:          req.TemplateFilename,
		SelectedTags:              req.SelectedTags,
		SelectedNodeIDs:           req.SelectedNodeIDs,
		SelectedCustomRuleIDs:     req.SelectedCustomRuleIDs,
		SelectedOverrideScriptIDs: req.SelectedOverrideScriptIDs,
		StatsServerIDs:            req.StatsServerIDs,
		TrafficLimit:              req.TrafficLimit,
		CreatedBy:                 username,
	}
	if req.RawOutput != nil {
		file.RawOutput = *req.RawOutput
	}
	if req.SortOrder != nil {
		file.SortOrder = *req.SortOrder
	}
	if req.CustomShortCode != nil {
		file.CustomShortCode = *req.CustomShortCode
	}

	created, err := h.repo.CreateSubscribeFile(r.Context(), file)
	if err != nil {
		if errors.Is(err, storage.ErrCustomShortCodeExists) {
			writeError(w, http.StatusConflict, err)
			return
		}
		if errors.Is(err, storage.ErrSubscribeFileExists) {
			writeError(w, http.StatusConflict, errors.New("订阅名称已存在"))
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// 不要为基于 URL 的订阅自动应用自定义规则
	// 它们将在首次获取订阅时应用

	respondJSON(w, http.StatusCreated, map[string]any{
		"file": convertSubscribeFile(created),
	})
}

func (h *subscribeFilesHandler) handleImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		URL         string `json:"url"`
		Filename    string `json:"filename"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}

	if req.URL == "" {
		writeBadRequest(w, "订阅URL是必填项")
		return
	}
	if req.Name == "" {
		writeBadRequest(w, "订阅名称是必填项")
		return
	}

	// SSRF 防护:仅允许 http/https;抓取时校验实际连接的 IP,拒绝内网/云元数据地址。
	// 否则任意登录用户都能让主控 GET http://127.0.0.1:PORT/... 或 169.254.169.254 拿内网内容/云凭据。
	if err := validateFetchURL(req.URL); err != nil {
		writeBadRequest(w, err.Error())
		return
	}

	// 创建 SSRF 安全的 HTTP 客户端并获取订阅内容
	client := newSSRFSafeHTTPClient(30 * time.Second)

	httpReq, err := http.NewRequest("GET", req.URL, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("无效的订阅URL"))
		return
	}

	// 添加User-Agent头
	httpReq.Header.Set("User-Agent", "clash-meta/2.4.0")

	resp, err := client.Do(httpReq)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("无法获取订阅内容: "+err.Error()))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadRequest, errors.New("订阅服务器返回错误状态"))
		return
	}

	// 读取响应内容(限制大小,防超大响应 OOM)
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBodyBytes))
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("读取订阅内容失败"))
		return
	}

	// 验证YAML格式
	var yamlCheck map[string]any
	if err := yaml.Unmarshal(body, &yamlCheck); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("订阅内容不是有效的YAML格式"))
		return
	}

	// 从content-disposition获取文件名
	filename := req.Filename
	if filename == "" {
		contentDisposition := resp.Header.Get("Content-Disposition")
		if contentDisposition != "" {
			filename = parseFilenameFromContentDisposition(contentDisposition)
		}
		if filename == "" {
			filename = fmt.Sprintf("subscription_%d.yaml", time.Now().Unix())
		}
	}

	// 安全:校验文件名(防路径穿越)+ 统一扩展名
	sanitizedName, serr := sanitizeSubscribeFilename(filename)
	if serr != nil {
		writeBadRequest(w, serr.Error())
		return
	}
	filename = sanitizedName

	username := auth.UsernameFromContext(r.Context())

	// 跨用户覆盖防护:filename 已被他人订阅占用则拒绝(写盘前)。
	if err := h.ensureFilenameWritable(r.Context(), filename, username); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}

	// 配额校验:普通用户创建订阅受全局配额限制(admin 不限)。(写盘前校验,失败无需回滚文件)
	if err := checkUserQuota(r.Context(), h.repo, username, "subscribe"); err != nil {
		writeError(w, http.StatusForbidden, err)
		return
	}

	// 保存文件到subscribes目录
	subscribesDir := "subscribes"
	if err := os.MkdirAll(subscribesDir, 0755); err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("创建订阅目录失败"))
		return
	}

	filePath := filepath.Join(subscribesDir, filename)
	fileExisted := subscribeFileExists(filePath)
	if err := os.WriteFile(filePath, body, 0644); err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("保存订阅文件失败"))
		return
	}

	// 保存到数据库
	file := storage.SubscribeFile{
		Name:        req.Name,
		Description: req.Description,
		URL:         req.URL,
		Type:        storage.SubscribeTypeImport,
		Filename:    filename,
		CreatedBy:   username,
	}

	created, err := h.repo.CreateSubscribeFile(r.Context(), file)
	if err != nil {
		// 数据库保存失败:仅删除本次新建的文件,不动已存在文件(避免误删)
		if !fileExisted {
			_ = os.Remove(filePath)
		}
		if errors.Is(err, storage.ErrCustomShortCodeExists) {
			writeError(w, http.StatusConflict, err)
			return
		}
		if errors.Is(err, storage.ErrSubscribeFileExists) {
			writeError(w, http.StatusConflict, errors.New("订阅名称已存在"))
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// 不要对导入的文件自动应用自定义规则
	// 如果需要，用户可以手动启用自动同步

	respondJSON(w, http.StatusCreated, map[string]any{
		"file": convertSubscribeFile(created),
	})
}

func (h *subscribeFilesHandler) handleUpload(w http.ResponseWriter, r *http.Request) {
	// 解析multipart form
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 详见上下文
		writeBadRequest(w, "解析表单失败")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeBadRequest(w, "文件上传失败")
		return
	}
	defer file.Close()

	name := r.FormValue("name")
	if name == "" {
		name = strings.TrimSuffix(header.Filename, filepath.Ext(header.Filename))
	}

	description := r.FormValue("description")
	filename := r.FormValue("filename")
	if filename == "" {
		filename = header.Filename
	}

	// 安全:校验文件名(防路径穿越)+ 统一扩展名
	sanitizedName, serr := sanitizeSubscribeFilename(filename)
	if serr != nil {
		writeBadRequest(w, serr.Error())
		return
	}
	filename = sanitizedName

	// 读取并验证YAML格式
	content, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("读取文件失败"))
		return
	}

	var yamlCheck map[string]any
	if err := yaml.Unmarshal(content, &yamlCheck); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("文件不是有效的YAML格式"))
		return
	}

	username := auth.UsernameFromContext(r.Context())

	// 跨用户覆盖防护:filename 已被他人订阅占用则拒绝(写盘前)。
	if err := h.ensureFilenameWritable(r.Context(), filename, username); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}

	// 配额校验:普通用户创建订阅受全局配额限制(admin 不限)。(写盘前校验,失败无需回滚文件)
	if err := checkUserQuota(r.Context(), h.repo, username, "subscribe"); err != nil {
		writeError(w, http.StatusForbidden, err)
		return
	}

	// 保存文件到subscribes目录
	subscribesDir := "subscribes"
	if err := os.MkdirAll(subscribesDir, 0755); err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("创建订阅目录失败"))
		return
	}

	filePath := filepath.Join(subscribesDir, filename)
	fileExisted := subscribeFileExists(filePath)
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("保存订阅文件失败"))
		return
	}

	// 保存到数据库
	subscribeFile := storage.SubscribeFile{
		Name:        name,
		Description: description,
		URL:         "", // 上传的文件没有URL
		Type:        storage.SubscribeTypeUpload,
		Filename:    filename,
		CreatedBy:   username,
	}

	created, err := h.repo.CreateSubscribeFile(r.Context(), subscribeFile)
	if err != nil {
		// 数据库保存失败:仅删除本次新建的文件,不动已存在文件(避免误删)
		if !fileExisted {
			_ = os.Remove(filePath)
		}
		if errors.Is(err, storage.ErrCustomShortCodeExists) {
			writeError(w, http.StatusConflict, err)
			return
		}
		if errors.Is(err, storage.ErrSubscribeFileExists) {
			writeError(w, http.StatusConflict, errors.New("订阅名称已存在"))
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// 不要对上传的文件自动应用自定义规则
	// 如果需要，用户可以手动启用自动同步

	respondJSON(w, http.StatusCreated, map[string]any{
		"file": convertSubscribeFile(created),
	})
}

func (h *subscribeFilesHandler) handleUpdate(w http.ResponseWriter, r *http.Request, idSegment string) {
	id, err := strconv.ParseInt(idSegment, 10, 64)
	if err != nil || id <= 0 {
		writeBadRequest(w, "无效的订阅ID")
		return
	}

	existing, err := h.repo.GetSubscribeFileByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrSubscribeFileNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 所有权校验:普通用户只能改自己创建的订阅。
	uname := auth.UsernameFromContext(r.Context())
	isAdmin := userIsAdmin(r.Context(), h.repo, uname)
	if !isAdmin && existing.CreatedBy != uname {
		writeError(w, http.StatusNotFound, storage.ErrSubscribeFileNotFound)
		return
	}

	var req subscribeFileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}

	// 短码编辑只允许管理员:普通用户即使是订阅创建者,也不能改 custom_short_code(短码归全局命名空间,必须管理)。
	// CustomShortCode 是 *string:nil = 前端没传(内联更新模板/标签等场景),不要碰短码;
	// 非 nil + 值变化 = 用户主动改 → 需要管理员权限。
	if !isAdmin && req.CustomShortCode != nil && *req.CustomShortCode != existing.CustomShortCode {
		writeError(w, http.StatusForbidden, errors.New("只有管理员可以编辑短码"))
		return
	}
	if req.TemplateFilename != "" && !canUserViewRuleTemplate(r.Context(), h.repo, uname, req.TemplateFilename) {
		writeError(w, http.StatusForbidden, errors.New("无权使用该模板"))
		return
	}

	// 更新字段
	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.Description != "" {
		existing.Description = req.Description
	}
	if req.URL != "" {
		existing.URL = req.URL
	}
	if req.Type != "" {
		existing.Type = req.Type
	}
	// 更新 auto_sync_custom_rules（如果提供）
	wasAutoSyncEnabled := existing.AutoSyncCustomRules
	if req.AutoSyncCustomRules != nil {
		existing.AutoSyncCustomRules = *req.AutoSyncCustomRules
	}
	existing.TemplateFilename = req.TemplateFilename
	if req.SelectedTags != nil {
		existing.SelectedTags = req.SelectedTags
	}
	if req.SelectedNodeIDs != nil {
		existing.SelectedNodeIDs = req.SelectedNodeIDs
	}
	if req.SelectedCustomRuleIDs != nil {
		existing.SelectedCustomRuleIDs = req.SelectedCustomRuleIDs
	}
	if req.SelectedOverrideScriptIDs != nil {
		existing.SelectedOverrideScriptIDs = req.SelectedOverrideScriptIDs
	}
	existing.StatsServerIDs = req.StatsServerIDs
	existing.TrafficLimit = req.TrafficLimit
	// 仅当前端显式传了 custom_short_code 才覆盖(同上,nil = 内联更新场景,保留原值)
	if req.CustomShortCode != nil {
		existing.CustomShortCode = *req.CustomShortCode
	}
	if req.RawOutput != nil {
		existing.RawOutput = *req.RawOutput
	}
	if req.SortOrder != nil {
		existing.SortOrder = *req.SortOrder
	}

	// 处理文件名更新
	oldFilename := existing.Filename
	needRenameFile := false
	if req.Filename != "" && req.Filename != existing.Filename {
		// 安全:校验新文件名(防路径穿越)+ 统一扩展名
		sanitizedName, serr := sanitizeSubscribeFilename(req.Filename)
		if serr != nil {
			writeError(w, http.StatusBadRequest, serr)
			return
		}
		req.Filename = sanitizedName

		// 检查新文件名是否已被其他订阅使用
		if existingFile, err := h.repo.GetSubscribeFileByFilename(r.Context(), req.Filename); err == nil && existingFile.ID != id {
			writeError(w, http.StatusConflict, errors.New("文件名已被其他订阅使用"))
			return
		}

		existing.Filename = req.Filename
		needRenameFile = true
	}

	updated, err := h.repo.UpdateSubscribeFile(r.Context(), existing)
	if err != nil {
		if errors.Is(err, storage.ErrCustomShortCodeExists) {
			writeError(w, http.StatusConflict, err)
			return
		}
		if errors.Is(err, storage.ErrSubscribeFileExists) {
			writeError(w, http.StatusConflict, errors.New("订阅名称已存在"))
			return
		}
		if errors.Is(err, storage.ErrSubscribeFileNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// 如果文件名发生变化，重命名物理文件
	if needRenameFile {
		oldPath := filepath.Join("subscribes", oldFilename)
		newPath := filepath.Join("subscribes", req.Filename)

		// 检查旧文件是否存在
		if _, err := os.Stat(oldPath); err == nil {
			// 重命名文件
			if err := os.Rename(oldPath, newPath); err != nil {
				// 重命名失败，回滚数据库更新
				existing.Filename = oldFilename
				_, _ = h.repo.UpdateSubscribeFile(r.Context(), existing)
				writeError(w, http.StatusInternalServerError, errors.New("重命名文件失败: "+err.Error()))
				return
			}
		}
		// 如果旧文件不存在，只更新数据库记录，不报错
	}

	// 如果 auto_sync 刚刚启用（从 false 更改为 true），则触发立即同步
	if !wasAutoSyncEnabled && updated.AutoSyncCustomRules {
		go func() {
			addedGroups, err := syncCustomRulesToFile(context.Background(), h.repo, updated)
			if err != nil {
				logger.Info("[AutoSync] 同步自定义规则失败", "filename", updated.Filename, "id", updated.ID, "error", err)
			} else {
				logger.Info("[AutoSync] 同步自定义规则成功", "filename", updated.Filename, "id", updated.ID)
				if len(addedGroups) > 0 {
					logger.Info("[AutoSync] 添加的代理组", "groups", addedGroups)
				}
			}
		}()
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"file": convertSubscribeFile(updated),
	})
}

func (h *subscribeFilesHandler) handleDelete(w http.ResponseWriter, r *http.Request, idSegment string) {
	id, err := strconv.ParseInt(idSegment, 10, 64)
	if err != nil || id <= 0 {
		writeBadRequest(w, "无效的订阅ID")
		return
	}

	// 获取文件信息以便删除物理文件
	file, err := h.repo.GetSubscribeFileByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrSubscribeFileNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 所有权校验:普通用户只能删自己创建的订阅。
	if uname := auth.UsernameFromContext(r.Context()); !userIsAdmin(r.Context(), h.repo, uname) && file.CreatedBy != uname {
		writeError(w, http.StatusNotFound, storage.ErrSubscribeFileNotFound)
		return
	}

	// 删除数据库记录
	if err := h.repo.DeleteSubscribeFile(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrSubscribeFileNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 删除物理文件
	filePath := filepath.Join("subscribes", file.Filename)
	_ = os.Remove(filePath) // 忽略错误，即使文件不存在也继续

	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *subscribeFilesHandler) handleReorder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}
	if len(req.IDs) == 0 {
		writeBadRequest(w, "排序列表不能为空")
		return
	}

	if err := h.repo.ReorderSubscribeFiles(r.Context(), req.IDs); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "reordered"})
}

func (h *subscribeFilesHandler) handleTraffic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	files, err := h.repo.ListSubscribeFiles(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 普通用户(开了"订阅管理"权限后能进来):流量列必须显示套餐口径,
	// 跟 /api/traffic/summary 上的"流量信息"页保持一致 —— 否则下面那条
	// GetAllRemoteServersTrafficTotals 路径会把全平台所有用户的 inbound 流量
	// 全聚合返回,与该用户毫无关系。
	username := auth.UsernameFromContext(ctx)
	if !userIsAdmin(ctx, h.repo, username) {
		h.handleTrafficForUser(ctx, w, username, files)
		return
	}

	allNodes, err := h.repo.ListAllNodes(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	allExternalSubs, _ := h.repo.ListAllExternalSubscriptions(ctx)
	extSubByName := make(map[string]storage.ExternalSubscription, len(allExternalSubs))
	for _, s := range allExternalSubs {
		extSubByName[s.Name] = s
	}

	type trafficItem struct {
		Used  int64 `json:"used"`
		Limit int64 `json:"limit"`
	}
	result := make(map[int64]trafficItem, len(files))

	now := time.Now()
	for _, f := range files {
		nodes := allNodes
		if len(f.SelectedTags) > 0 {
			tagsMap := make(map[string]bool, len(f.SelectedTags))
			for _, t := range f.SelectedTags {
				tagsMap[t] = true
			}
			filtered := make([]storage.Node, 0)
			for _, n := range allNodes {
				if n.HasAnyTag(tagsMap) {
					filtered = append(filtered, n)
				}
			}
			nodes = filtered
		}

		// 收集外部订阅名(用于把订阅源自带的 used/total 也算进去 — 与服务器流量并列)
		extSubNames := make(map[string]bool)
		for _, n := range nodes {
			if n.Tag != "" && n.Tag != "手动输入" {
				extSubNames[n.Tag] = true
			}
		}

		// 服务器流量范围:
		//   stats_server_ids 非空 → 仅统计选中的服务器
		//   stats_server_ids 空(默认)→ 统计全部服务器
		var serverScopeIDs []int64
		if strings.TrimSpace(f.StatsServerIDs) != "" {
			for _, s := range strings.Split(f.StatsServerIDs, ",") {
				if id, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil && id > 0 {
					serverScopeIDs = append(serverScopeIDs, id)
				}
			}
		}

		var totalUsed, totalLimit int64
		if len(serverScopeIDs) > 0 {
			limit, used, _ := h.repo.GetRemoteServerTrafficTotals(ctx, serverScopeIDs)
			totalUsed += used
			totalLimit += limit
		} else {
			limit, used, _ := h.repo.GetAllRemoteServersTrafficTotals(ctx)
			totalUsed += used
			totalLimit += limit
		}

		for name := range extSubNames {
			sub, ok := extSubByName[name]
			if !ok {
				continue
			}
			if sub.Expire != nil && sub.Expire.Before(now) {
				continue
			}
			totalLimit += sub.Total
			switch sub.TrafficMode {
			case "download":
				totalUsed += sub.Download
			case "upload":
				totalUsed += sub.Upload
			default:
				totalUsed += sub.Upload + sub.Download
			}
		}

		// 仅当订阅自带 traffic_limit > 0 时才作为"用户显式覆盖"使用;
		// nil / 0 都视作"跟随服务器算出的 totalLimit",避免前端 inline payload 把 0 持久化后覆盖掉服务器额度。
		if f.TrafficLimit != nil && *f.TrafficLimit > 0 {
			totalLimit = int64(*f.TrafficLimit * 1024 * 1024 * 1024)
		}
		result[f.ID] = trafficItem{Used: totalUsed, Limit: totalLimit}
	}

	respondJSON(w, http.StatusOK, map[string]any{"traffic": result})
}

// handleTrafficForUser 给单个普通用户返回订阅流量:对该用户名下每个订阅文件
// 都填同一组 {used, limit} = 用户套餐口径,跟 /api/traffic/summary 完全一致。
// 没绑套餐的用户:返回 0/0(前端会显示无限制/未消耗,行为与流量信息页一致)。
func (h *subscribeFilesHandler) handleTrafficForUser(ctx context.Context, w http.ResponseWriter, username string, files []storage.SubscribeFile) {
	type trafficItem struct {
		Used  int64 `json:"used"`
		Limit int64 `json:"limit"`
	}
	result := make(map[int64]trafficItem, len(files))

	var used, limit int64
	if username != "" {
		if user, err := h.repo.GetUser(ctx, username); err == nil && user.PackageID > 0 {
			if pkg, perr := h.repo.GetPackage(ctx, user.PackageID); perr == nil {
				// 有效上限 = 用户级覆写 ?? 套餐流量,与 enforcer 断流口径一致。
				limit = resolveTrafficLimitBytes(&user, pkg)
				// 计费流量:倍率已在采集时折算,拿到即最终值。
				if billable, terr := h.repo.GetUserBillableTraffic(ctx, username); terr == nil {
					used = billable
				}
			}
		}
	}

	for _, f := range files {
		if f.CreatedBy != username {
			continue
		}
		// 订阅自定义限额覆盖套餐限额(管理员路径的同款语义)
		fileLimit := limit
		if f.TrafficLimit != nil {
			fileLimit = int64(*f.TrafficLimit * 1024 * 1024 * 1024)
		}
		result[f.ID] = trafficItem{Used: used, Limit: fileLimit}
	}

	respondJSON(w, http.StatusOK, map[string]any{"traffic": result})
}

// parseFilenameFromContentDisposition 从Content-Disposition头解析文件名
// 支持格式: attachment;filename*=UTF-8”%E6%B3%A1%E6%B3%A1Dog
func parseFilenameFromContentDisposition(header string) string {
	// 查找 filename*= 部分
	if idx := strings.Index(header, "filename*="); idx != -1 {
		// 提取等号后的内容
		value := header[idx+10:]
		// 查找两个单引号后的内容
		if idx2 := strings.LastIndex(value, "''"); idx2 != -1 {
			encoded := value[idx2+2:]
			// URL解码
			if decoded, err := url.QueryUnescape(encoded); err == nil {
				return decoded
			}
		}
	}

	// 如果没有filename*=，尝试filename=
	if idx := strings.Index(header, "filename="); idx != -1 {
		value := header[idx+9:]
		value = strings.Trim(value, `"`)
		if idx2 := strings.IndexAny(value, ";,"); idx2 != -1 {
			value = value[:idx2]
		}
		return strings.TrimSpace(value)
	}

	return ""
}

type subscribeFileRequest struct {
	Name                      string   `json:"name"`
	Description               string   `json:"description"`
	URL                       string   `json:"url"`
	Type                      string   `json:"type"`
	Filename                  string   `json:"filename"`
	AutoSyncCustomRules       *bool    `json:"auto_sync_custom_rules,omitempty"`
	TemplateFilename          string   `json:"template_filename"`
	SelectedTags              []string `json:"selected_tags"`
	SelectedNodeIDs           []int64  `json:"selected_node_ids"`
	SelectedCustomRuleIDs     []int64  `json:"selected_custom_rule_ids"`
	SelectedOverrideScriptIDs []int64  `json:"selected_override_script_ids"`
	StatsServerIDs            string   `json:"stats_server_ids"`
	TrafficLimit              *float64 `json:"traffic_limit"`
	// 必须用指针以区分"前端没传"vs"前端想清空":
	// 内联更新(只发 template_filename)时 CustomShortCode 字段缺省,
	// 旧 string 零值会被误判为"想把短码清空"→ 触发"只有管理员可以编辑短码"。
	CustomShortCode *string `json:"custom_short_code,omitempty"`
	RawOutput       *bool   `json:"raw_output,omitempty"`
	SortOrder       *int    `json:"sort_order,omitempty"`
}

type subscribeFileDTO struct {
	ID                        int64     `json:"id"`
	Name                      string    `json:"name"`
	Description               string    `json:"description"`
	Type                      string    `json:"type"`
	Filename                  string    `json:"filename"`
	FileShortCode             string    `json:"file_short_code"`
	CustomShortCode           string    `json:"custom_short_code"`
	AutoSyncCustomRules       bool      `json:"auto_sync_custom_rules"`
	TemplateFilename          string    `json:"template_filename"`
	SelectedTags              []string  `json:"selected_tags"`
	SelectedNodeIDs           []int64   `json:"selected_node_ids"`
	SelectedCustomRuleIDs     []int64   `json:"selected_custom_rule_ids"`
	SelectedOverrideScriptIDs []int64   `json:"selected_override_script_ids"`
	StatsServerIDs            string    `json:"stats_server_ids"`
	TrafficLimit              *float64  `json:"traffic_limit"`
	SortOrder                 int       `json:"sort_order"`
	RawOutput                 bool      `json:"raw_output"`
	CreatedBy                 string    `json:"created_by"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
	LatestVersion             int64     `json:"latest_version,omitempty"`
}

func convertSubscribeFile(file storage.SubscribeFile) subscribeFileDTO {
	// nil → 空数组,避免 JSON 序列化成 null 让前端 .map / .has 走错分支
	tags := file.SelectedTags
	if tags == nil {
		tags = []string{}
	}
	nodeIDs := file.SelectedNodeIDs
	if nodeIDs == nil {
		nodeIDs = []int64{}
	}
	ruleIDs := file.SelectedCustomRuleIDs
	if ruleIDs == nil {
		ruleIDs = []int64{}
	}
	scriptIDs := file.SelectedOverrideScriptIDs
	if scriptIDs == nil {
		scriptIDs = []int64{}
	}
	return subscribeFileDTO{
		ID:                        file.ID,
		Name:                      file.Name,
		Description:               file.Description,
		Type:                      file.Type,
		Filename:                  file.Filename,
		FileShortCode:             file.FileShortCode,
		CustomShortCode:           file.CustomShortCode,
		AutoSyncCustomRules:       file.AutoSyncCustomRules,
		TemplateFilename:          file.TemplateFilename,
		SelectedTags:              tags,
		SelectedNodeIDs:           nodeIDs,
		SelectedCustomRuleIDs:     ruleIDs,
		SelectedOverrideScriptIDs: scriptIDs,
		StatsServerIDs:            file.StatsServerIDs,
		TrafficLimit:              file.TrafficLimit,
		SortOrder:                 file.SortOrder,
		RawOutput:                 file.RawOutput,
		CreatedBy:                 file.CreatedBy,
		CreatedAt:                 file.CreatedAt,
		UpdatedAt:                 file.UpdatedAt,
	}
}

func convertSubscribeFiles(files []storage.SubscribeFile) []subscribeFileDTO {
	result := make([]subscribeFileDTO, 0, len(files))
	for _, file := range files {
		result = append(result, convertSubscribeFile(file))
	}
	return result
}

func (h *subscribeFilesHandler) convertSubscribeFilesWithVersions(ctx context.Context, files []storage.SubscribeFile) []subscribeFileDTO {
	result := make([]subscribeFileDTO, 0, len(files))
	for _, file := range files {
		dto := convertSubscribeFile(file)

		// 获取最新版本号
		if versions, err := h.repo.ListRuleVersions(ctx, file.Filename, 1); err == nil && len(versions) > 0 {
			dto.LatestVersion = versions[0].Version
		}

		result = append(result, dto)
	}
	return result
}

// 保存生成的配置为订阅文件
func (h *subscribeFilesHandler) handleCreateFromConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Filename    string `json:"filename"`
		Content     string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}

	if req.Name == "" {
		writeBadRequest(w, "订阅名称是必填项")
		return
	}
	if req.Content == "" {
		writeBadRequest(w, "配置内容不能为空")
		return
	}

	// 获取当前用户名和设置，判断是否需要校验
	username := auth.UsernameFromContext(r.Context())
	shouldValidate := true // 默认进行校验
	if username != "" {
		// 获取用户设置
		settings, err := h.repo.GetUserSettings(r.Context(), username)
		if err == nil {
			// 只有在使用新模板系统时才进行校验
			shouldValidate = settings.UseNewTemplateSystem
			logger.Info("[创建订阅文件] 用户设置", "username", username, "use_new_template_system", settings.UseNewTemplateSystem, "should_validate", shouldValidate)
		} else if !errors.Is(err, storage.ErrUserSettingsNotFound) {
			logger.Info("[创建订阅文件] 获取用户设置失败，使用默认行为(进行校验)", "username", username, "error", err)
		}
	}

	// 设置默认文件名
	filename := req.Filename
	if filename == "" {
		filename = req.Name
	}

	// 确保文件名有.yaml或.yml扩展名
	ext := filepath.Ext(filename)
	if ext != ".yaml" && ext != ".yml" {
		filename = filename + ".yaml"
	}

	// 验证YAML格式，使用Node API保持顺序和格式
	var rootNode yaml.Node
	if err := yaml.Unmarshal([]byte(req.Content), &rootNode); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("配置内容不是有效的YAML格式"))
		return
	}

	// 只有在使用新模板系统时才进行配置校验
	if shouldValidate {
		// 校验配置内容
		var configMap map[string]interface{}
		var tempBuf bytes.Buffer
		tempEncoder := yaml.NewEncoder(&tempBuf)
		tempEncoder.SetIndent(2)
		if err := tempEncoder.Encode(&rootNode); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("编码配置用于校验失败"))
			return
		}
		if err := yaml.Unmarshal(tempBuf.Bytes(), &configMap); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("解析配置用于校验失败"))
			return
		}

		validationResult := validator.ValidateClashConfig(configMap)
		if !validationResult.Valid {
			logger.Info("[创建订阅文件] [配置校验] 校验失败", "filename", filename)
			var errorMessages []string
			for _, issue := range validationResult.Issues {
				if issue.Level == validator.ErrorLevel {
					errorMsg := issue.Message
					if issue.Location != "" {
						errorMsg = fmt.Sprintf("%s (位置: %s)", errorMsg, issue.Location)
					}
					errorMessages = append(errorMessages, errorMsg)
					logger.Info("[创建订阅文件] [配置校验] 错误", "message", errorMsg)
				}
			}
			writeError(w, http.StatusBadRequest, errors.New("配置校验失败: "+strings.Join(errorMessages, "; ")))
			return
		}

		// 如果有自动修复，使用修复后的配置
		if validationResult.FixedConfig != nil {
			fixedYAML, err := yaml.Marshal(validationResult.FixedConfig)
			if err != nil {
				writeError(w, http.StatusInternalServerError, errors.New("序列化修复配置失败"))
				return
			}
			if err := yaml.Unmarshal(fixedYAML, &rootNode); err != nil {
				writeError(w, http.StatusInternalServerError, errors.New("解析修复配置失败"))
				return
			}

			// 记录自动修复的警告
			for _, issue := range validationResult.Issues {
				if issue.Level == validator.WarningLevel && issue.AutoFixed {
					logger.Info("[创建订阅文件] [配置校验] 警告(已修复)", "message", issue.Message, "location", issue.Location)
				}
			}
		}
	} else {
		logger.Info("[创建订阅文件] 使用旧模板系统，跳过配置校验", "filename", filename)
	}

	// 修复short-id字段，确保使用双引号
	// 修复ShortIdStyleInNode(&rootNode)

	// 重新序列化YAML，保持原有顺序和格式
	reserializedContent, err := MarshalYAMLWithIndent(&rootNode)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("处理YAML内容失败"))
		return
	}

	// 修复表情符号/反斜杠转义
	fixedContent := RemoveUnicodeEscapeQuotes(string(reserializedContent))

	// 保存文件到subscribes目录
	subscribesDir := "subscribes"
	if err := os.MkdirAll(subscribesDir, 0755); err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("创建订阅目录失败"))
		return
	}

	filePath := filepath.Join(subscribesDir, filename)
	if err := os.WriteFile(filePath, []byte(fixedContent), 0644); err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("保存订阅文件失败"))
		return
	}

	// 配额校验:普通用户创建订阅受全局配额限制(admin 不限)。
	if err := checkUserQuota(r.Context(), h.repo, username, "subscribe"); err != nil {
		_ = os.Remove(filePath)
		writeError(w, http.StatusForbidden, err)
		return
	}

	// 保存到数据库
	file := storage.SubscribeFile{
		Name:        req.Name,
		Description: req.Description,
		URL:         "",
		Type:        storage.SubscribeTypeCreate,
		Filename:    filename,
		CreatedBy:   username,
	}

	created, err := h.repo.CreateSubscribeFile(r.Context(), file)
	if err != nil {
		// 如果数据库保存失败，删除已保存的文件
		_ = os.Remove(filePath)
		if errors.Is(err, storage.ErrCustomShortCodeExists) {
			writeError(w, http.StatusConflict, err)
			return
		}
		if errors.Is(err, storage.ErrSubscribeFileExists) {
			writeError(w, http.StatusConflict, errors.New("订阅名称已存在"))
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// 初始化自定义规则应用记录以防止首次修改时出现重复
	h.initializeCustomRuleApplications(r.Context(), created.ID)

	respondJSON(w, http.StatusCreated, map[string]any{
		"file": convertSubscribeFile(created),
	})
}

// 获取订阅文件内容
func (h *subscribeFilesHandler) handleGetContent(w http.ResponseWriter, r *http.Request, filename string) {
	if filename == "" {
		writeBadRequest(w, "文件名不能为空")
		return
	}

	// 验证文件名
	filename, err := url.QueryUnescape(filename)
	if err != nil {
		writeBadRequest(w, "无效的文件名")
		return
	}

	// 检查文件是否存在于数据库
	sf, err := h.repo.GetSubscribeFileByFilename(r.Context(), filename)
	if err != nil {
		if errors.Is(err, storage.ErrSubscribeFileNotFound) {
			writeError(w, http.StatusNotFound, errors.New("订阅文件不存在"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 所有权校验:普通用户只能看自己创建的订阅内容。
	if uname := auth.UsernameFromContext(r.Context()); !userIsAdmin(r.Context(), h.repo, uname) && sf.CreatedBy != uname {
		writeError(w, http.StatusNotFound, errors.New("订阅文件不存在"))
		return
	}

	// 读取文件内容
	filePath := filepath.Join("subscribes", filename)
	content, err := os.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, errors.New("文件不存在"))
			return
		}
		writeError(w, http.StatusInternalServerError, errors.New("读取文件失败"))
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"content": string(content),
	})
}

// 更新订阅文件内容
func (h *subscribeFilesHandler) handleUpdateContent(w http.ResponseWriter, r *http.Request, filename string) {
	if filename == "" {
		writeBadRequest(w, "文件名不能为空")
		return
	}

	// 验证文件名
	filename, err := url.QueryUnescape(filename)
	if err != nil {
		writeBadRequest(w, "无效的文件名")
		return
	}

	// 检查文件是否存在于数据库
	subscribeFile, err := h.repo.GetSubscribeFileByFilename(r.Context(), filename)
	if err != nil {
		if errors.Is(err, storage.ErrSubscribeFileNotFound) {
			writeError(w, http.StatusNotFound, errors.New("订阅文件不存在"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 所有权校验:普通用户只能改自己创建的订阅内容。
	if uname := auth.UsernameFromContext(r.Context()); !userIsAdmin(r.Context(), h.repo, uname) && subscribeFile.CreatedBy != uname {
		writeError(w, http.StatusNotFound, errors.New("订阅文件不存在"))
		return
	}

	// 解析请求体
	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}

	if req.Content == "" {
		writeBadRequest(w, "内容不能为空")
		return
	}

	// 验证YAML格式，使用 Node API 保持顺序
	var rootNode yaml.Node
	if err := yaml.Unmarshal([]byte(req.Content), &rootNode); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("内容不是有效的YAML格式: "+err.Error()))
		return
	}

	// 转换为 map 进行校验；可安全修复的问题由后端兜底处理，避免旧前端或直接 API 调用无法保存。
	var yamlCheck map[string]any
	if err := yaml.Unmarshal([]byte(req.Content), &yamlCheck); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("内容不是有效的YAML格式: "+err.Error()))
		return
	}

	// 校验配置内容
	validationResult := validator.ValidateClashConfig(yamlCheck)
	if !validationResult.Valid {
		logger.Info("[更新订阅文件] [配置校验] 校验失败", "filename", filename)
		var errorMessages []string
		for _, issue := range validationResult.Issues {
			if issue.Level == validator.ErrorLevel {
				errorMsg := issue.Message
				if issue.Location != "" {
					errorMsg = fmt.Sprintf("%s (位��: %s)", errorMsg, issue.Location)
				}
				errorMessages = append(errorMessages, errorMsg)
				logger.Info("[更新订阅文件] [配置校验] 错误", "message", errorMsg)
			}
		}
		writeError(w, http.StatusBadRequest, errors.New("配置校验失败: "+strings.Join(errorMessages, "; ")))
		return
	}

	// 没有修复时保留用户原始排版；发生修复时保存校验器产出的可用配置。
	contentToSave := RemoveUnicodeEscapeQuotes(req.Content)
	if validationResult.FixedConfig != nil {
		fixedYAML, marshalErr := yaml.Marshal(validationResult.FixedConfig)
		if marshalErr != nil {
			writeError(w, http.StatusInternalServerError, errors.New("序列化自动修复后的配置失败"))
			return
		}
		contentToSave = RemoveUnicodeEscapeQuotes(string(fixedYAML))
	}

	// 记录警告信息（如果有）
	for _, issue := range validationResult.Issues {
		if issue.Level == validator.WarningLevel {
			logger.Info("[更新订阅文件] [配置校验] 警告(前端已修复)", "message", issue.Message, "location", issue.Location)
		}
	}

	// 保存文件
	filePath := filepath.Join("subscribes", filename)
	if err := os.WriteFile(filePath, []byte(contentToSave), 0644); err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("保存文件失败"))
		return
	}

	// 保存版本记录(author = 当前调用者,而非硬编码 "admin")
	author := auth.UsernameFromContext(r.Context())
	if author == "" {
		author = "admin"
	}
	version, err := h.repo.SaveRuleVersion(r.Context(), filename, contentToSave, author)
	if err != nil {
		// 版本保存失败不影响文件保存，只记录错误
		writeError(w, http.StatusInternalServerError, errors.New("保存版本记录失败"))
		return
	}

	// 更新数据库中的updated_at字段
	subscribeFile.UpdatedAt = time.Now()
	_, err = h.repo.UpdateSubscribeFile(r.Context(), subscribeFile)
	if err != nil {
		// 更新时间戳失败不影响文件保存，只记录错误
		writeError(w, http.StatusInternalServerError, errors.New("更新订阅信息失败"))
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"status":        "updated",
		"version":       version,
		"auto_repaired": validationResult.FixedConfig != nil,
	})
}

// initializeCustomRuleApplications 记录新创建的订阅文件的初始自定义规则应用程序状态。
// 当从内容中已包含自定义规则的生成器页面创建文件时，会调用此方法。
// 我们只记录应用程序状态，而不重新应用规则（这会重复它们）。
func (h *subscribeFilesHandler) initializeCustomRuleApplications(ctx context.Context, fileID int64) {
	// 获取所有已启用的自定义规则以记录其当前状态
	rules, err := h.repo.ListEnabledCustomRules(ctx, "")
	if err != nil {
		logger.Info("[Subscribe] 获取自定义规则失败", "error", err)
		return
	}

	if len(rules) == 0 {
		return
	}

	// 记录每个规则的当前状态而不修改文件
	for _, rule := range rules {
		// 计算内容哈希以跟踪未来的变化
		hash := sha256.Sum256([]byte(rule.Content))
		contentHash := hex.EncodeToString(hash[:])

		// 解析规则内容以提取应用的实际规则/提供程序
		// 这必须与 applyRulesRule 和 applyRuleProvidersRule 中使用的格式匹配
		var appliedContent string
		if rule.Type == "rules" {
			// 解析规则内容，得到规则数组
			var newRules []interface{}

			// 尝试首先解析为地图（使用“rules:”键）
			var parsedAsMap map[string]interface{}
			if err := yaml.Unmarshal([]byte(rule.Content), &parsedAsMap); err == nil {
				if rulesValue, hasRulesKey := parsedAsMap["rules"]; hasRulesKey {
					if rulesArray, ok := rulesValue.([]interface{}); ok {
						newRules = rulesArray
					}
				}
			}

			// 尝试解析为 YAML 数组
			if len(newRules) == 0 {
				if err := yaml.Unmarshal([]byte(rule.Content), &newRules); err != nil {
					// 解析为纯文本
					lines := strings.Split(rule.Content, "\n")
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if line != "" && !strings.HasPrefix(line, "#") {
							newRules = append(newRules, line)
						}
					}
				}
			}

			// 序列化为 JSON 格式（与 applyRulesRule 相同）
			if len(newRules) > 0 {
				appliedJSON, _ := json.Marshal(newRules)
				appliedContent = string(appliedJSON)
			}
		} else if rule.Type == "rule-providers" {
			// 解析规则提供者内容
			var parsedContent map[string]interface{}
			if err := yaml.Unmarshal([]byte(rule.Content), &parsedContent); err == nil {
				var providersMap map[string]interface{}
				if providersValue, hasProvidersKey := parsedContent["rule-providers"]; hasProvidersKey {
					if pm, ok := providersValue.(map[string]interface{}); ok {
						providersMap = pm
					}
				} else {
					providersMap = parsedContent
				}

				// 序列化为JSON格式
				if len(providersMap) > 0 {
					appliedJSON, _ := json.Marshal(providersMap)
					appliedContent = string(appliedJSON)
				}
			}
		} else if rule.Type == "dns" {
			// 对于 DNS 规则，我们不跟踪应用的内容
			appliedContent = ""
		}

		app := &storage.CustomRuleApplication{
			SubscribeFileID: fileID,
			CustomRuleID:    rule.ID,
			RuleType:        rule.Type,
			RuleMode:        rule.Mode,
			AppliedContent:  appliedContent,
			ContentHash:     contentHash,
		}

		if err := h.repo.UpsertCustomRuleApplication(ctx, app); err != nil {
			logger.Info("[Subscribe] 记录自定义规则应用失败", "rule_id", rule.ID, "error", err)
		}
	}

	logger.Info("[Subscribe] 记录自定义规则应用状态完成", "rule_count", len(rules), "file_id", fileID)
}

// handleGetSubscriptionUsers GET /api/admin/subscribe-files/{id}/users
// 返回该订阅文件分配给哪些用户 + 各自的 user_short_code / custom_user_short_code(同步自 mmw v0.7.3)
func (h *subscribeFilesHandler) handleGetSubscriptionUsers(w http.ResponseWriter, r *http.Request, idStr string) {
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeBadRequest(w, "invalid subscription file ID")
		return
	}

	users, err := h.repo.GetUsersBySubscriptionID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if users == nil {
		users = []storage.UserShortCodeInfo{}
	}

	respondJSON(w, http.StatusOK, map[string]any{"users": users})
}
