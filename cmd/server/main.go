package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // 嵌入时区库,LoadLocation 不依赖系统 zoneinfo(纠正缺 /etc/localtime 的机器)

	"miaomiaowux/internal/agentlog"
	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/captcha"
	"miaomiaowux/internal/child"
	"miaomiaowux/internal/ddns"
	"miaomiaowux/internal/event"
	"miaomiaowux/internal/handler"
	"miaomiaowux/internal/license"
	"miaomiaowux/internal/logger"
	mcpserver "miaomiaowux/internal/mcp"
	"miaomiaowux/internal/notify"
	"miaomiaowux/internal/patches"
	"miaomiaowux/internal/proxygroups"
	"miaomiaowux/internal/securechan"
	"miaomiaowux/internal/storage"
	"miaomiaowux/internal/taskrun"
	inttgbot "miaomiaowux/internal/tgbot"
	"miaomiaowux/internal/traffic"
	"miaomiaowux/internal/version"
	"miaomiaowux/internal/web"
	ruletemplates "miaomiaowux/rule_templates"
	"miaomiaowux/subscribes"

	"gopkg.in/yaml.v3"
)

// ServerConfig表示配置文件结构
type ServerConfig struct {
	Mode           string `yaml:"mode"`            // "主控"或"远程"
	MasterServer   string `yaml:"master_server"`   // 主服务器 URL（用于远程模式）
	RemoteToken    string `yaml:"remote_token"`    // 用于远程服务器身份验证的令牌
	ConnectionMode string `yaml:"connection_mode"` // "websocket"、"http"、"pull"、"auto"
	Port           string `yaml:"port"`            // 服务器端口
	ChildAPIToken  string `yaml:"child_api_token"` // 用于子 API 身份验证的令牌
}

// 从 YAML 文件加载配置
func loadConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config ServerConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// initTimezone 兜底进程时区。Go 按 TZ 环境变量、其次 /etc/localtime 解析 time.Local;
// 部分精简 VPS / 容器的 /etc/localtime 缺失或损坏时会静默回退 UTC,导致按本地 HH:MM 调度的
// 「每日流量通知」等功能整体偏移(主机是 CST 时差 8 小时),日志时间戳也会错。
// 这里仅在 time.Local 落到 UTC 且用户未显式设置 TZ 时,用 /etc/timezone 纠正。
func initTimezone() {
	if zone := time.Now().Location().String(); zone != "UTC" && zone != "" {
		logger.Info("本地时区", "zone", zone)
		return
	}
	// 已落到 UTC。用户显式设了 TZ(含 TZ=UTC)就尊重其选择,不再纠正。
	if _, explicit := os.LookupEnv("TZ"); explicit {
		logger.Info("本地时区", "zone", "UTC", "source", "TZ")
		return
	}
	// TZ 未设且 time.Local=UTC,极可能是 /etc/localtime 缺失,用 /etc/timezone 兜底。
	if data, err := os.ReadFile("/etc/timezone"); err == nil {
		if name := strings.TrimSpace(string(data)); name != "" && name != "UTC" {
			if loc, err := time.LoadLocation(name); err == nil {
				time.Local = loc
				logger.Info("本地时区已按 /etc/timezone 纠正", "zone", name)
				return
			}
		}
	}
	logger.Warn("无法确定本地时区,按 UTC 运行;每日通知等按本地时间的功能会偏移,请设置环境变量 TZ(如 TZ=Asia/Shanghai)")
}

// resolveRuntimeDataDir uses known persistent paths before considering the
// process working directory. Some upgraded systemd units have an incorrect
// WorkingDirectory, but the real database remains /etc/mmwx/data/mmwx.db.
func resolveRuntimeDataDir() string {
	if configured := strings.TrimSpace(os.Getenv("MMWX_DATA_DIR")); configured != "" {
		if absolute, err := filepath.Abs(configured); err == nil {
			return absolute
		}
		return filepath.Clean(configured)
	}
	for _, knownDir := range []string{"/etc/mmwx/data", "/app/data"} {
		for _, marker := range []string{"mmwx.db", storage.DatabaseConfigFilename, "mmwx_master.key"} {
			if _, statErr := os.Stat(filepath.Join(knownDir, marker)); statErr == nil {
				return knownDir
			}
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "data"
	}
	return filepath.Join(cwd, "data")
}

func main() {
	// 初始化logger
	logger.Init()
	initTimezone()
	logger.Info("喵喵屋服务器启动中", "version", version.Version)

	// 启动日志清理任务（每天凌晨3点清理7天前的日志）
	go startLogCleanup()

	// 解析命令行标志
	configPath := flag.String("c", "", "Path to configuration file")
	flag.Parse()

	// 从文件加载配置（如果指定）
	var config *ServerConfig
	if *configPath != "" {
		var err error
		config, err = loadConfig(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config file: %v", err)
		}
		log.Printf("Loaded configuration from %s", *configPath)
	}

	// Resolve an absolute persistent path so a systemd WorkingDirectory change
	// cannot silently create and select a nested empty database.
	dataDir := resolveRuntimeDataDir()
	databaseConfig, databaseConfigPath, err := storage.LoadDatabaseConfig(dataDir)
	if err != nil {
		logger.Error("数据库配置加载失败", "path", databaseConfigPath, "error", err)
		os.Exit(1)
	}
	var repo *storage.TrafficRepository
	var recoveredFromBackup bool
	if databaseConfig.Driver == "sqlite" {
		databaseBackupPath := databaseConfig.Path + ".backup"
		repo, recoveredFromBackup, err = storage.OpenTrafficRepositoryWithRecovery(databaseConfig.Path, databaseBackupPath)
	} else {
		repo, err = storage.NewTrafficRepositoryFromConfig(databaseConfig)
	}
	if err != nil {
		// PostgreSQL 恢复采用新库切换。若新库在重启后无法打开，使用切换前
		// 留下的配置自动回退，避免主控因一次失败恢复永久无法启动。
		rollbackConfig, rollbackErr := storage.LoadDatabaseRestoreRollback(dataDir)
		if databaseConfig.Driver == "postgres" && rollbackErr == nil {
			logger.Warn("恢复后的 PostgreSQL 无法启动，正在自动切回原数据库", "database", databaseConfig.Database, "error", err)
			if saveErr := storage.SaveDatabaseConfig(dataDir, rollbackConfig); saveErr == nil {
				repo, err = storage.NewTrafficRepositoryFromConfig(rollbackConfig)
				databaseConfig = rollbackConfig
			}
		}
		if err != nil {
			logger.Error("数据库初始化失败", "driver", databaseConfig.Driver, "error", err)
			os.Exit(1)
		}
	}
	if clearErr := storage.ClearDatabaseRestoreRollback(dataDir); clearErr != nil {
		logger.Warn("清理数据库恢复回滚标记失败", "error", clearErr)
	}
	databaseTarget := databaseConfig.Database
	if databaseConfig.Driver == "sqlite" {
		databaseTarget = databaseConfig.Path
		if absolutePath, absErr := filepath.Abs(databaseConfig.Path); absErr == nil {
			databaseTarget = absolutePath
		}
	}
	logger.Info("数据库连接成功", "driver", databaseConfig.Driver, "config", databaseConfigPath, "database", databaseTarget)
	if recoveredFromBackup {
		logger.Warn("主数据库损坏或无法启动，已使用最近的每小时备份恢复；故障数据库及 WAL/SHM 已归档到 data/database-recovery-*，请检查磁盘和文件系统")
	}
	defer repo.Close()

	// 定时任务运行记录器(P3)。高频 collector 的成功按 5min 节流(否则 speed 3s/次会写爆表),
	// 其余低频任务每次都记。失败永远记。各任务通过 taskrun.Record 全局调用,无需改构造函数。
	taskrun.Init(taskrun.New(repo, map[string]time.Duration{
		"traffic_collector":   5 * time.Minute,
		"speed_collector":     5 * time.Minute,
		"probe_quality_alert": 5 * time.Minute,
	}))
	go startTaskRunCleanup(context.Background(), repo)

	addr := getAddr(config, repo)

	masterIdentity, err := securechan.LoadOrGenerate(filepath.Join(dataDir, "mmwx_master.key"))
	if err != nil {
		logger.Error("加密密钥初始化失败", "error", err)
		os.Exit(1)
	}
	logger.Info("主控加密公钥已加载", "public_key", masterIdentity.PublicKeyBase64())

	cryptoConfig := handler.NewCryptoConfig(masterIdentity, securechan.NewSessionCache(1*time.Hour))

	licenseManager := license.NewManager(repo, license.GetMachineID())
	// 注入 usage 来源,让心跳把"本机当前 used_servers/nodes/users" 上报给 license 服务器。
	licenseManager.SetUsageReporter(repo)
	licenseManager.Start(context.Background())
	defer licenseManager.Stop()

	authManager, err := auth.NewManager(repo)
	if err != nil {
		logger.Error("认证管理器加载失败", "error", err)
		os.Exit(1)
	}

	tokenStore := auth.NewTokenStore(24 * time.Hour)
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		tokenStore.SetSecret(jwtSecret)
		logger.Info("JWT_SECRET 已配置，会话令牌将使用 HMAC 签名")
	}

	// 从数据库加载持久会话
	ctx := context.Background()
	sessions, err := repo.LoadSessions(ctx)
	if err != nil {
		logger.Warn("从数据库加载会话失败", "error", err)
	} else {
		for _, session := range sessions {
			tokenStore.LoadSession(session.Token, session.Username, session.ExpiresAt)
		}
		logger.Info("会话加载完成", "count", len(sessions))
	}

	// 周期清理内存中过期 token(防 tokens map 因未被 Lookup 的过期项缓慢泄漏)
	go tokenStore.StartCleanup(ctx, 10*time.Minute)

	// 从数据库中清理过期会话
	if err := repo.CleanupExpiredSessions(ctx); err != nil {
		logger.Warn("清理过期会话失败", "error", err)
	}

	subscribeDir := filepath.Join("subscribes")
	if err := subscribes.Ensure(subscribeDir); err != nil {
		logger.Error("订阅文件准备失败", "error", err)
		os.Exit(1)
	}

	ruleTemplatesDir := filepath.Join("rule_templates")
	if err := ruletemplates.Ensure(ruleTemplatesDir); err != nil {
		logger.Error("规则模板文件准备失败", "error", err)
		os.Exit(1)
	}

	// rule_templates 补丁:Ensure 不覆盖已存在文件(保护用户自定义),
	// 但对历史已知错误的 dns 块(语义比对,顺序无关)做一次精准替换。详见 internal/patches 包注释。
	if patched, err := patches.ApplyDNSPatches(ruleTemplatesDir); err != nil {
		logger.Warn("DNS 模板补丁应用过程出错(不影响启动)", "error", err)
	} else if patched > 0 {
		logger.Info("DNS 模板补丁已应用", "count", patched)
	}

	// 初始化代理组配置 Store（纯内存存储）
	// 优先从系统配置的远程地址拉取，失败时使用空配置
	var proxyGroupsStore *proxygroups.Store

	// 获取系统配置中的远程地址
	systemConfig, err := repo.GetSystemConfig(ctx)
	if err != nil {
		logger.Warn("加载系统配置失败", "error", err)
	}

	agentlog.SetEnabled(systemConfig.AgentLogEnabled)

	handler.InitNotifier(notify.Config{
		Enabled:                   systemConfig.NotifyEnabled,
		BotToken:                  systemConfig.TelegramBotToken,
		ChatID:                    systemConfig.TelegramChatID,
		NotifyLogin:               systemConfig.NotifyLogin,
		NotifySubscribeFetch:      systemConfig.NotifySubscribeFetch,
		NotifyDailyTraffic:        systemConfig.NotifyDailyTraffic,
		NotifyServerOffline:       systemConfig.NotifyServerOffline,
		NotifyServerOnline:        systemConfig.NotifyServerOnline,
		NotifyTrafficThreshold:    systemConfig.NotifyTrafficThreshold,
		DailyTrafficTime:          systemConfig.NotifyDailyTrafficTime,
		TrafficThresholdPercent:   systemConfig.NotifyTrafficThresholdPercent,
		NotifyTrafficThreshold80:  systemConfig.NotifyTrafficThreshold80,
		NotifyOverLimit:           systemConfig.NotifyOverLimit,
		NotifyPackageExpiring:     systemConfig.NotifyPackageExpiring,
		PackageExpiringDaysAhead:  systemConfig.NotifyPackageExpiringDays,
		NotifyPackageExpired:      systemConfig.NotifyPackageExpired,
		NotifyUserRegistered:      systemConfig.NotifyUserRegistered,
		NotifyTelegramBound:       systemConfig.NotifyTelegramBound,
		NotifyCertResult:          systemConfig.NotifyCertResult,
		NotifyAgentLongOffline:    systemConfig.NotifyAgentLongOffline,
		AgentLongOfflineMinutes:   systemConfig.NotifyAgentLongOfflineMinutes,
		NotifyDeviceLimitExceeded: systemConfig.NotifyDeviceLimitExceeded,
		NotifyProbeQuality:        true,
	})

	// TG bot 已拆为独立项目 ../mmwX-tgbot,通过 /api/admin/tgbot/* HTTP 调主控。
	// 主控仅保留 admin REST handler + 邀请码 web UI + storage 字段 + notify 裸 HTTP 通知。
	tgbotAPIHandler := handler.NewTGBotAPIHandler(repo)
	// TG 邀请码注册也要受许可证用户数配额限制(此前这条路径完全绕过配额)
	tgbotAPIHandler.SetLicenseManager(licenseManager)

	// 从远程拉取配置
	data, resolvedURL, fetchErr := proxygroups.FetchConfig(systemConfig.ProxyGroupsSourceURL)
	if fetchErr != nil {
		logger.Warn("拉取代理组配置失败", "error", fetchErr)
		// 远程拉取失败时使用空配置初始化
		proxyGroupsStore, err = proxygroups.NewStore([]byte("[]"), "empty-fallback")
		if err != nil {
			logger.Error("创建代理组存储失败", "error", err)
			os.Exit(1)
		}
		logger.Info("代理组存储已使用空配置初始化", "reason", "远程拉取失败")
	} else {
		// 远程拉取成功
		proxyGroupsStore, err = proxygroups.NewStore(data, resolvedURL)
		if err != nil {
			logger.Error("代理组配置无效", "source", resolvedURL, "error", err)
			os.Exit(1)
		}
		logger.Info("代理组配置加载成功", "source", resolvedURL)
	}

	syncSubscribeFilesToDatabase(repo, subscribeDir)

	trafficHandler := handler.NewTrafficSummaryHandler(repo)
	packageSubscribeHandler := handler.NewPackageSubscribeHandler(repo)
	userRepo := auth.NewRepositoryAdapter(repo)

	mux := http.NewServeMux()
	mux.Handle("/api/setup/status", handler.NewSetupStatusHandler(repo))
	mux.Handle("/api/setup/init", handler.NewInitialSetupHandler(repo, dataDir))
	mux.Handle("/api/setup/verify-domain", handler.NewVerifyDomainHandler())
	mux.Handle("/api/setup/restore-backup", handler.NewSetupRestoreBackupHandler(repo, dataDir))

	// 从 system_settings 读 3 个安全限流器的自定义阈值(KV 缺失 → fallback hardcoded 默认值)。
	// 同一份配置后面给 brute_force + subscription_rate 构造时复用。
	secCfg := handler.LoadSecuritySettings(context.Background(), repo)
	handler.SetBlockUnknownSubscriptionUA(secCfg.BlockUnknownSubUA)
	loginRateLimiter := handler.NewLoginRateLimiterWithConfig(
		secCfg.LoginRateMaxAttempts, secCfg.LoginRateWindowMinutes, secCfg.LoginRateLockMinutes,
	)
	loginRateLimiter.SetSkipLocalIP(secCfg.SkipLocalIP)
	twoFactorStore := auth.NewTwoFactorPendingStore(5 * time.Minute)
	turnstileVerifier := captcha.New(repo)

	// 公开端点:登录页前端拉这个拿 site_key 决定是否渲染 widget(在 auth 之前必须可访问)。
	// 两 key 都空时 enabled=false → 前端不渲染、后端 Verify 直接放行,无侵入降级。
	mux.HandleFunc("/api/captcha/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled":  turnstileVerifier.Enabled(r.Context()),
			"site_key": turnstileVerifier.SiteKey(r.Context()),
		})
	})

	mux.Handle("/api/login", handler.NewLoginHandler(authManager, tokenStore, repo, loginRateLimiter, twoFactorStore, turnstileVerifier))
	mux.Handle("/api/login/2fa", handler.NewTwoFactorLoginHandler(tokenStore, repo, twoFactorStore))
	mux.Handle("/api/login/recovery", handler.NewRecoveryLoginHandler(tokenStore, repo, twoFactorStore))

	// 仅限管理端点
	mux.Handle("/api/admin/credentials", auth.RequireAdmin(tokenStore, userRepo, handler.NewCredentialsHandler(authManager, tokenStore)))

	// TG bot 相关 API(单前缀,handler 内部按 path 分发):
	//   - invites CRUD(admin web UI 用)
	//   - bind/unbind/user-by-tg/user-summary/user-subscriptions/user-nodes(独立 mmwX-tgbot 用)
	mux.Handle("/api/admin/tgbot/", auth.RequireAdmin(tokenStore, userRepo, tgbotAPIHandler))
	mux.Handle("/api/admin/users", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserListHandler(repo)))
	userCreateHandler := handler.NewUserCreateHandler(repo)
	userCreateHandler.SetLicenseManager(licenseManager)
	mux.Handle("/api/admin/users/create", auth.RequireAdmin(tokenStore, userRepo, userCreateHandler))
	// /api/admin/users/delete 依赖 remoteManageHandler + limiterPusher 做 xray client 清理，注册下移到 ~line 348 之后
	// /api/admin/users/status (启用/禁用) 同样依赖 remoteManageHandler + limiterPusher,见同区
	mux.Handle("/api/admin/users/reset-password", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserResetPasswordHandler(repo)))
	mux.Handle("/api/admin/users/remark", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserRemarkHandler(repo)))
	mux.Handle("/api/admin/users/short-code", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserShortCodeHandler(repo)))
	mux.Handle("/api/admin/users/update-email", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserUpdateEmailHandler(repo)))
	mux.Handle("/api/admin/users/subaccounts", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserSubaccountsHandler(repo)))
	mux.Handle("/api/admin/users/", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserSubscriptionsHandler(repo)))
	mux.Handle("/api/admin/subscriptions", auth.RequireAdmin(tokenStore, userRepo, handler.NewSubscriptionAdminHandler(subscribeDir, repo)))
	mux.Handle("/api/admin/subscriptions/", auth.RequireAdmin(tokenStore, userRepo, handler.NewSubscriptionAdminHandler(subscribeDir, repo)))
	mux.Handle("/api/admin/subscribe-files", auth.RequireToken(tokenStore, userRepo, handler.NewSubscribeFilesHandler(repo)))
	mux.Handle("/api/admin/subscribe-files/", auth.RequireToken(tokenStore, userRepo, handler.NewSubscribeFilesHandler(repo)))
	mux.Handle("/api/admin/rules/", auth.RequireAdmin(tokenStore, userRepo, http.StripPrefix("/api/admin/rules/", handler.NewRuleEditorHandler(subscribeDir, repo))))
	mux.Handle("/api/admin/rule-templates", auth.RequireToken(tokenStore, userRepo, handler.NewRuleTemplatesHandler(repo)))
	mux.Handle("/api/admin/rule-templates/", auth.RequireToken(tokenStore, userRepo, handler.NewRuleTemplatesHandler(repo)))
	// 在remoteManageHandler之后注册的节点处理程序（见下文）
	mux.Handle("/api/admin/sync-external-subscriptions", auth.RequireAdmin(tokenStore, userRepo, handler.NewSyncExternalSubscriptionsHandler(repo, subscribeDir)))
	mux.Handle("/api/admin/sync-external-subscription", auth.RequireAdmin(tokenStore, userRepo, handler.NewSyncSingleExternalSubscriptionHandler(repo, subscribeDir)))
	// 同步 handler 本身按 context username 限定范围(syncExternalSubscriptionsManual 只同步本人订阅),
	// 普通用户也应能同步自己导入的外部订阅。新增 user 路由(RequireToken)避免普通用户撞 RequireAdmin 的 403;
	// admin 路由保留兼容旧前端。
	mux.Handle("/api/user/sync-external-subscriptions", auth.RequireToken(tokenStore, userRepo, handler.NewSyncExternalSubscriptionsHandler(repo, subscribeDir)))
	mux.Handle("/api/user/sync-external-subscription", auth.RequireToken(tokenStore, userRepo, handler.NewSyncSingleExternalSubscriptionHandler(repo, subscribeDir)))
	mux.Handle("/api/user/sync-external-subscriptions/confirm", auth.RequireToken(tokenStore, userRepo, handler.NewConfirmExternalSyncHandler(repo)))
	mux.Handle("/api/admin/rules/latest", auth.RequireAdmin(tokenStore, userRepo, handler.NewRuleMetadataHandler(subscribeDir, repo)))
	mux.Handle("/api/admin/routing-rule-presets", auth.RequireAdmin(tokenStore, userRepo, handler.NewRoutingRulePresetsHandler(repo)))
	mux.Handle("/api/admin/custom-rules", auth.RequireToken(tokenStore, userRepo, handler.NewCustomRulesHandler(repo)))
	mux.Handle("/api/admin/custom-rules/", auth.RequireToken(tokenStore, userRepo, handler.NewCustomRuleHandler(repo)))
	mux.Handle("/api/admin/apply-custom-rules", auth.RequireToken(tokenStore, userRepo, handler.NewApplyCustomRulesHandler(repo)))
	mux.Handle("/api/admin/override-scripts", auth.RequireToken(tokenStore, userRepo, handler.NewOverrideScriptsHandler(repo)))
	mux.Handle("/api/admin/override-scripts/", auth.RequireToken(tokenStore, userRepo, handler.NewOverrideScriptsHandler(repo)))
	mux.Handle("/api/admin/templates", auth.RequireToken(tokenStore, userRepo, handler.NewTemplatesHandler(repo)))
	mux.Handle("/api/admin/templates/", auth.RequireToken(tokenStore, userRepo, handler.NewTemplateHandler(repo)))
	mux.Handle("/api/admin/templates/convert", auth.RequireToken(tokenStore, userRepo, handler.NewTemplateConvertHandler()))
	mux.Handle("/api/admin/templates/fetch-source", auth.RequireToken(tokenStore, userRepo, handler.NewTemplateFetchSourceHandler()))
	mux.Handle("/api/admin/backup/download", auth.RequireAdmin(tokenStore, userRepo, handler.NewBackupDownloadHandler(repo, dataDir)))
	mux.Handle("/api/admin/backup/restore", auth.RequireAdmin(tokenStore, userRepo, handler.NewBackupRestoreHandler(repo, dataDir)))
	mux.Handle("/api/admin/update/check", auth.RequireAdmin(tokenStore, userRepo, handler.NewUpdateCheckHandler()))
	mux.Handle("/api/admin/update/apply", auth.RequireAdmin(tokenStore, userRepo, handler.NewUpdateApplyHandler()))
	mux.Handle("/api/admin/update/apply-sse", auth.RequireAdmin(tokenStore, userRepo, handler.NewUpdateApplySSEHandler()))
	mux.Handle("/api/admin/proxy-groups/sync", auth.RequireAdmin(tokenStore, userRepo, handler.NewProxyGroupsSyncHandler(repo, proxyGroupsStore)))

	// Template V3 端点（仅限管理员）
	templateV3Handler := handler.NewTemplateV3Handler(repo)
	mux.Handle("/api/admin/template-v3", auth.RequireToken(tokenStore, userRepo, templateV3Handler))
	mux.Handle("/api/admin/template-v3/", auth.RequireToken(tokenStore, userRepo, templateV3Handler))

	// 包管理端点（仅限管理员）— list/create 不依赖 limiterPusher;delete 需解绑用户,延后到 remoteManageHandler/limiterPusher 创建后注册
	mux.Handle("/api/admin/packages", auth.RequireAdmin(tokenStore, userRepo, handler.NewPackageListHandler(repo)))
	packageCreateHandler := handler.NewPackageCreateHandler(repo)
	packageCreateHandler.SetLicenseManager(licenseManager)
	mux.Handle("/api/admin/packages/create", auth.RequireAdmin(tokenStore, userRepo, packageCreateHandler))

	// 用户端点（所有经过身份验证的用户）
	mux.Handle("/api/proxy-groups", auth.RequireToken(tokenStore, userRepo, handler.NewProxyGroupsHandler(proxyGroupsStore)))
	mux.Handle("/api/user/2fa/status", auth.RequireToken(tokenStore, userRepo, handler.NewTwoFactorStatusHandler(repo)))
	mux.Handle("/api/user/2fa/setup", auth.RequireToken(tokenStore, userRepo, handler.NewTwoFactorSetupHandler(authManager, repo)))
	mux.Handle("/api/user/2fa/verify-setup", auth.RequireToken(tokenStore, userRepo, handler.NewTwoFactorVerifySetupHandler(repo)))
	mux.Handle("/api/user/2fa/disable", auth.RequireToken(tokenStore, userRepo, handler.NewTwoFactorDisableHandler(authManager, repo)))
	mux.Handle("/api/user/password", auth.RequireToken(tokenStore, userRepo, handler.NewPasswordHandler(authManager)))
	mux.Handle("/api/user/profile", auth.RequireToken(tokenStore, userRepo, handler.NewProfileHandler(repo)))
	mux.Handle("/api/user/telegram-binding", auth.RequireToken(tokenStore, userRepo, handler.NewTelegramBindingHandler(repo)))
	mux.Handle("/api/user/settings", auth.RequireToken(tokenStore, userRepo, handler.NewUserSettingsHandler(repo, tokenStore)))
	mux.Handle("/api/user/config", auth.RequireToken(tokenStore, userRepo, handler.NewUserConfigHandler(repo)))
	mux.Handle("/api/user/default-template", auth.RequireToken(tokenStore, userRepo, handler.NewUserDefaultTemplateHandler(repo)))
	mux.Handle("/api/user/token", auth.RequireToken(tokenStore, userRepo, handler.NewUserTokenHandler(repo)))
	// 代理集合(Clash proxy-provider)配置 — 用户自己 CRUD;handler 内做 username 隔离
	mux.Handle("/api/user/proxy-provider-configs", auth.RequireToken(tokenStore, userRepo, handler.NewProxyProviderConfigsHandler(repo)))
	// 每用户 API 令牌(供 MCP / 程序化访问);明文仅创建时返回一次
	mux.Handle("/api/user/api-tokens", auth.RequireToken(tokenStore, userRepo, handler.NewUserAPITokensHandler(repo)))
	mux.Handle("/api/user/api-tokens/", auth.RequireToken(tokenStore, userRepo, handler.NewUserAPITokensHandler(repo)))
	mux.Handle("/api/user/external-subscriptions", auth.RequireToken(tokenStore, userRepo, handler.NewExternalSubscriptionsHandler(repo)))
	mux.Handle("/api/user/external-subscriptions/delete", auth.RequireToken(tokenStore, userRepo, handler.NewDeleteExternalSubscriptionHandler(repo)))
	mux.Handle("/api/user/external-subscriptions/nodes", auth.RequireToken(tokenStore, userRepo, handler.NewExternalSubscriptionNodesHandler(repo)))
	mux.Handle("/api/user/external-subscriptions/check-filter", auth.RequireToken(tokenStore, userRepo, handler.NewExternalSubscriptionCheckFilterHandler(repo)))
	// Debug日志相关endpoint
	mux.Handle("/api/user/debug/", auth.RequireToken(tokenStore, userRepo, handler.NewDebugHandler(repo)))

	mux.Handle("/api/traffic/summary", auth.RequireToken(tokenStore, userRepo, trafficHandler))
	mux.Handle("/api/traffic/summary/aggregated", auth.RequireToken(tokenStore, userRepo, trafficHandler))
	mux.Handle("/api/subscriptions", auth.RequireToken(tokenStore, userRepo, handler.NewSubscriptionListHandler(repo)))
	mux.Handle("/api/user/package-subscribe", auth.RequireToken(tokenStore, userRepo, packageSubscribeHandler))
	mux.Handle("/api/dns/resolve", auth.RequireToken(tokenStore, userRepo, handler.NewDNSHandler()))
	mux.Handle("/api/subscribe-files", auth.RequireToken(tokenStore, userRepo, handler.NewSubscribeFilesListHandler(repo)))
	mux.Handle("/api/clash/subscribe", handler.NewSubscriptionEndpoint(tokenStore, repo, subscribeDir))

	// Xray 管理端点（经过身份验证的用户）
	xrayHandler := handler.NewXrayHandler(repo)
	mux.Handle("/api/xray/outbound/add", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(xrayHandler.AddOutbound)))
	mux.Handle("/api/xray/outbound/remove", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(xrayHandler.RemoveOutbound)))
	mux.Handle("/api/xray/outbound/list", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(xrayHandler.ListOutbounds)))
	mux.Handle("/api/xray/stats", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(xrayHandler.GetStats)))
	mux.Handle("/api/xray/stats/system", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(xrayHandler.GetSystemStats)))

	// 流量收集器（早期创建，以便可以与处理程序共享）
	trafficCollector := traffic.NewCollector(repo)
	// 主控本机自采间隔跟随「上报间隔」(dashboard_refresh_interval_ms,会同步给所有 agent),
	// 与 agent 保持一致;未设置时用默认 5000ms。speed 仍用 speed_collect_interval。
	reportMs := 5000
	if val, _ := repo.GetSystemSetting(context.Background(), "dashboard_refresh_interval_ms"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n >= 1000 && n <= 60000 {
			reportMs = n
		}
	}
	trafficCollector.SetInterval(time.Duration(reportMs) * time.Millisecond)
	if systemConfig.SpeedCollectInterval > 0 {
		trafficCollector.SetSpeedInterval(time.Duration(systemConfig.SpeedCollectInterval) * time.Second)
	}

	// Xray 服务器处理程序（远程服务器管理复用）
	xrayServerHandler := handler.NewXrayServerHandler(repo, trafficCollector, cryptoConfig)

	// 面向浏览器的实时数据推送 WS(替代前端高频轮询):RequireToken 认(支持 ?token= query 参数),
	// hub 内按 admin/user 角色区分推送内容。数据源复用 xrayServerHandler.BuildRemoteServersList。
	dashboardWSHub := handler.NewDashboardWSHub(repo, xrayServerHandler, getAllowedOrigins())
	mux.Handle("/api/ws/dashboard", auth.RequireToken(tokenStore, userRepo, dashboardWSHub))

	// 远程服务器管理端点（仅限管理员）
	mux.Handle("/api/admin/remote-servers", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayServerHandler.ListRemoteServers)))
	mux.Handle("/api/admin/remote-servers/create", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayServerHandler.CreateRemoteServer)))
	mux.Handle("/api/admin/remote-servers/reveal-token", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayServerHandler.RevealServerToken)))
	// 接入分享服务器(消费方)
	mux.Handle("/api/admin/remote-servers/add-shared", auth.RequireAdmin(tokenStore, userRepo, handler.NewAddSharedServerHandler(repo)))
	mux.Handle("/api/admin/remote-servers/update", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayServerHandler.UpdateRemoteServer)))
	mux.Handle("/api/admin/remote-servers/reorder", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayServerHandler.ReorderRemoteServers)))
	mux.Handle("/api/admin/remote-servers/traffic-stats-selection", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayServerHandler.SetTrafficStatsServers)))
	mux.Handle("/api/admin/remote-servers/delete", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayServerHandler.DeleteRemoteServer)))
	mux.Handle("/api/admin/remote-servers/sync-node-address", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayServerHandler.SyncNodeAddress)))

	// 远程服务器公共端点（无管理员身份验证，基于令牌）
	mux.Handle("/api/remote/heartbeat", http.HandlerFunc(xrayServerHandler.RemoteHeartbeat))
	mux.Handle("/api/remote/token/refresh", http.HandlerFunc(xrayServerHandler.RefreshRemoteToken))
	mux.Handle("/api/remote/install.sh", http.HandlerFunc(xrayServerHandler.GetRemoteInstallScript))

	// 流量采集与统计
	trafficApiHandler := handler.NewTrafficHandler(repo, trafficCollector)
	remoteTrafficHandler := handler.NewRemoteTrafficHandler(repo, trafficCollector, cryptoConfig)
	mux.Handle("/api/admin/traffic", auth.RequireAdmin(tokenStore, userRepo, trafficApiHandler))
	mux.Handle("/api/admin/traffic/", auth.RequireAdmin(tokenStore, userRepo, trafficApiHandler))
	mux.Handle("/api/remote/traffic", remoteTrafficHandler)
	// 把 traffic 汇总/明细 handler 注入实时 WS hub,快照复用其 JSON 输出(traffic-summary + admin-traffic)。
	dashboardWSHub.SetTrafficHandlers(trafficHandler, trafficApiHandler)

	// 远程速度处理程序（来自子服务器的 HTTP 推送）
	remoteSpeedHandler := handler.NewRemoteSpeedHandler(repo, cryptoConfig)
	mux.Handle("/api/remote/speed", remoteSpeedHandler)

	// 远程服务器的 WebSocket 处理程序
	remoteWSHandler := handler.NewRemoteWSHandler(repo, trafficCollector)
	// WS 在线判断注入 collector:WS 连着的服务器 traffic/speed 走 WS 推送,collector 不再 HTTP 拉取
	// (消除 auto 模式 agent 进 stealth 后 collector 疯狂 refused 刷屏 + 拖住 WAL)
	trafficCollector.SetWSChecker(remoteWSHandler.IsConnected)
	remoteWSHandler.SetCrypto(cryptoConfig)
	mux.Handle("/api/remote/ws", remoteWSHandler)

	// 限速配置推送器
	limiterPusher := handler.NewLimiterConfigPusher(repo, remoteWSHandler)
	limiterPusher.SetLicenseManager(licenseManager)
	remoteWSHandler.SetLimiterPusher(limiterPusher)
	remoteWSHandler.SetLicenseManager(licenseManager)
	// license 从失效恢复为有效时,主动重推所有 embedded 服务器的限速(失效期被 gate 漏下发的补上)。
	licenseManager.SetOnRecover(func() {
		limiterPusher.PushToAllEmbeddedServers(context.Background())
	})
	// license「服务器配额」变化(到期/降级/恢复)时,重算 per-server xray 授权并下发给在线 agent:
	// 超额服务器停 xray、拿到名额的启 xray。
	licenseManager.SetOnQuotaChange(func() {
		remoteWSHandler.ReconcileServerQuota(context.Background())
	})
	// PRO 特性丢失(降级/到期/解绑)时撤销已下发到 agent 的配置。
	// 与 SetOnRecover 成对:恢复时补推,丢失时清零。agent 侧限速是内存态,
	// 只"停止下发"不会让存量限速失效 —— 必须主动推一份清零配置覆盖掉。
	licenseManager.SetOnFeatureLost(func(feature string) {
		if feature == "limiter" {
			limiterPusher.RevokeAllEmbeddedServers(context.Background())
		}
	})
	// 5min 定期兜底:即便漏了某次事件触发(如下发时 agent 恰好离线),也能在下个周期把
	// 授权重新对齐(agent 侧幂等,值没变不会反复启停 xray)。
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			remoteWSHandler.ReconcileServerQuota(context.Background())
		}
	}()
	xrayServerHandler.SetLimiterPusher(limiterPusher)
	xrayServerHandler.SetLicenseManager(licenseManager)

	// 远程服务器管理代理（将命令转发到子服务器）
	remoteManageHandler := handler.NewRemoteManageHandler(repo, remoteWSHandler)
	remoteManageHandler.SetSubscribeDir(subscribeDir)
	remoteWSHandler.SetServerAddressChangeCallback(remoteManageHandler.SyncServerAddressChange)
	remoteManageHandler.SetCrypto(cryptoConfig)
	remoteManageHandler.SetLicenseManager(licenseManager) // syncInboundsToNodes 路径里 license budget 检查需要
	// inbound cache: 套餐绑/换绑时 in-memory 算 cred 用,从 xray config snapshot 派生。
	inboundCache := handler.NewInboundCache()
	remoteManageHandler.SetInboundCache(inboundCache)
	// 启动时预热(异步,不阻塞 main):从 DB current snapshot 把每台 server 的 inbound 索引拉进 cache。
	// 新 agent 第一次连上来前,套餐绑套餐如果选了这个 server 的 inbound,有 DB snapshot 就立即 cache hit。
	go func() {
		ctx := context.Background()
		servers, err := repo.ListRemoteServers(ctx)
		if err != nil {
			log.Printf("[InboundCache] warmup list servers failed: %v", err)
			return
		}
		for _, s := range servers {
			inboundCache.WarmupFromDB(ctx, repo, s.ID)
		}
		log.Printf("[InboundCache] warmup done for %d servers", len(servers))
	}()
	// agent 重连后校正 embedded→external 漂移(license 恢复后自动把卡在 external 的 agent 拉回 embedded)。
	remoteWSHandler.SetXrayModeCorrectCallback(remoteManageHandler.CorrectXrayModeDrift)
	xrayServerHandler.SetRemoteManager(remoteManageHandler)
	xrayServerHandler.SetWSHandler(remoteWSHandler)

	// DDNS 管理器:agent 心跳触发 IPChanged 时同步 pull_address 域名的 A/AAAA 记录到新 IP。
	// reconciler 跑后台 5min ticker 兜底失败重试(IPChanged 已消费 → 后续心跳 IP 不变就不会再触发,
	// 没 reconciler 的话 DDNS 失败就永远卡住)。
	ddnsManager := ddns.NewManager(repo)
	go ddnsManager.StartReconciler(context.Background())
	remoteWSHandler.SetDDNSManager(ddnsManager)
	xrayServerHandler.SetDDNSManager(ddnsManager)
	// 状态查询(前端 Tooltip 用) + 手动同步(前端"立即重试"按钮),都走子路径 /api/admin/servers/{id}/ddns-*
	ddnsAdminHandler := handler.NewDDNSAdminHandler(repo, ddnsManager)
	mux.Handle("/api/admin/servers/", auth.RequireAdmin(tokenStore, userRepo, ddnsAdminHandler))

	// 一次性老格式凭据 email 迁移(ae60947 漏回填存量)。
	// 启动延迟 60s — 等 agent WS 重连。失败的行下次启动重试,全部成功才写 done 标记。
	handler.NewCredentialEmailMigrator(repo, remoteManageHandler).Start(context.Background(), 60*time.Second)

	// 一次性补写 user_inbound_configs 孤儿 — collector 有 (server, email) 流量但表里
	// 没该用户的 inbound 持有记录,导致 /api/admin/traffic/user-nodes & node-users 反查空。
	// 只补 role=user 的真实付费用户,admin 自用走 handler fallback,不污染本表。
	// 延迟 90s — 比 CredentialEmailMigrator(60s)晚跑,确保它先把老 email 迁完再补剩下的。
	handler.NewOrphanInboundConfigBackfiller(repo).Start(context.Background(), 90*time.Second)

	// 启动 5 分钟后先修复一次,之后每天 03:30 清理孤儿/重复 xray client 与失效子账户。
	// 触发场景:用户删除时 server 离线 → push remove 失败 → db 已清但 xray config 仍残留。
	handler.NewOrphanXrayClientCleaner(repo, remoteManageHandler).Start(context.Background())

	// 凌晨 04:00(排在上面的清理之后)扫一次,补回「DB 登记了绑定但 agent xray 上没有」的 client。
	// 触发场景:入站删除后用同 tag 重建 → agent 侧空入站 + DB 孤儿凭据 → 订阅发出的 UUID
	// 在 xray 里不存在(TCPing 通但连不上);以及 agent 重装 / 配置回滚等漂移。
	// 与上面的 cleaner 方向相反、互补;补发用 DB 原凭据,订阅 UUID 不变。
	handler.NewInboundClientReconciler(repo, remoteManageHandler).Start(context.Background())

	// 启动后补全存量 TLS 节点的服务端证书 SHA-256，随后每天刷新一次以跟进证书续期。
	// 每次运行写入 task_runs，可在日志管理 → 定时任务中查看详情。
	handler.NewNodeTLSFingerprintBackfiller(repo).Start(context.Background(), 2*time.Minute)

	// 依赖 limiterPusher 的端点
	packageUpdateHandler := handler.NewPackageUpdateHandler(repo, remoteManageHandler, limiterPusher)
	packageUpdateHandler.SetLicenseManager(licenseManager)
	mux.Handle("/api/admin/packages/update", auth.RequireAdmin(tokenStore, userRepo, packageUpdateHandler))
	packageAssignHandler := handler.NewPackageAssignHandler(repo, remoteManageHandler, limiterPusher)
	tgbotAPIHandler.SetPackageAssign(packageAssignHandler) // 让 TGBOT 注册/兑换的套餐走同一套下发
	renewalService := handler.NewRenewalService(repo, packageAssignHandler)
	tgbotAPIHandler.SetRenewalService(renewalService)
	mux.Handle("/api/admin/packages/assign", auth.RequireAdmin(tokenStore, userRepo, packageAssignHandler))
	// 快捷续期:复用 packageAssignHandler 的 AssignAndProvision(samePackage 快路径),只延长 package_end_date
	mux.Handle("/api/admin/users/extend", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserExtendHandler(packageAssignHandler)))
	mux.Handle("/api/admin/packages/unassign", auth.RequireAdmin(tokenStore, userRepo, handler.NewPackageUnassignHandler(repo, remoteManageHandler, limiterPusher)))
	// 删除套餐:解绑所有绑定用户(移除入站凭据/清 package_id/删套餐订阅)后再删,故依赖 remoteManageHandler/limiterPusher
	mux.Handle("/api/admin/packages/", auth.RequireAdmin(tokenStore, userRepo, handler.NewPackageDeleteHandler(repo, remoteManageHandler, limiterPusher)))
	// 服务器分享(PRO):拥有方生成/管理分享令牌
	mux.Handle("/api/admin/server-share/", auth.RequireAdmin(tokenStore, userRepo, handler.NewServerShareHandler(repo, licenseManager, remoteManageHandler)))
	// 自定义品牌(PRO):管理员设置站点标题/左上角标题/logo;是否生效由 license.FeatureCustomBranding 门控。
	brandingHandler := handler.NewBrandingHandler(repo, licenseManager)
	mux.Handle("/api/admin/system-settings/branding", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(brandingHandler.Admin)))
	mux.Handle("/api/admin/system-settings/branding/logo", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(brandingHandler.UploadLogo)))
	// 公开读取(无鉴权:登录页也要能拿品牌);门控在 handler 内 —— 无 PRO 一律返回空/404。
	mux.HandleFunc("/api/branding", brandingHandler.PublicGet)
	mux.HandleFunc("/api/branding/logo", brandingHandler.ServeLogo)
	speedTesterWS := handler.NewSpeedTesterWSHandler(repo)
	speedTesterWS.SetLicenseManager(licenseManager)
	mux.Handle("/api/speedtest/tester/ws", speedTesterWS) // 家用测速端反向连入(token 认证,无 JWT)
	speedTestHandler := handler.NewSpeedTestHandler(repo, licenseManager)
	speedTestHandler.SetTesterWS(speedTesterWS)
	mux.Handle("/api/admin/speedtest/", auth.RequireAdmin(tokenStore, userRepo, speedTestHandler))
	// Tunnel(dokodemo 转发入站)聚合管理:跨所有远程/分享服务器列出 protocol==tunnel 入站,供节点管理「Tunnel 管理」弹窗使用
	mux.Handle("/api/admin/tunnels", auth.RequireAdmin(tokenStore, userRepo, handler.NewTunnelsHandler(repo, remoteManageHandler)))
	// 链式端口转发编排:选有序多台服务器建 N 条首尾相接的单跳 tunnel。
	mux.Handle("/api/admin/tunnel-chains", auth.RequireAdmin(tokenStore, userRepo, handler.NewTunnelChainHandler(repo, remoteManageHandler)))
	// 联邦入口(分享令牌鉴权,供其他主控间接管理被分享服务器)
	federationHandler := handler.NewFederationHandler(repo, remoteManageHandler, licenseManager)
	mux.Handle("/api/federation/manage", federationHandler)
	mux.Handle("/api/federation/server-info", federationHandler)
	mux.Handle("/api/admin/users/limits", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserLimitsHandler(repo, limiterPusher, licenseManager)))
	mux.Handle("/api/admin/users/node-limits", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserNodeLimitsHandler(repo, limiterPusher, licenseManager)))
	mux.Handle("/api/admin/users/traffic-limit", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserTrafficLimitHandler(repo)))
	mux.Handle("/api/admin/users/delete", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserDeleteHandler(repo, remoteManageHandler, limiterPusher)))
	mux.Handle("/api/admin/users/status", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserStatusHandler(repo, remoteManageHandler, limiterPusher, tokenStore)))
	mux.Handle("/api/admin/users/reset-xray-credentials", auth.RequireAdmin(tokenStore, userRepo, handler.NewAdminXrayCredentialResetHandler(repo, remoteManageHandler)))
	mux.Handle("/api/admin/users/repair-node-credentials", auth.RequireAdmin(tokenStore, userRepo, handler.NewAdminNodeCredentialRepairHandler(repo)))

	// 用户节点管理（普通用户查看套餐节点、管理自己的出站）
	userNodesHandler := handler.NewUserNodesHandler(repo, remoteManageHandler)
	mux.Handle("/api/user/nodes", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(userNodesHandler.HandleListNodes)))
	mux.Handle("/api/user/nodes/outbound", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(userNodesHandler.HandleOutbound)))
	mux.Handle("/api/user/nodes/outbounds", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(userNodesHandler.HandleListOutbounds)))

	// 注册节点处理程序（需要remoteManageHandler进行远程入站清理）
	mux.Handle("/api/admin/nodes", auth.RequireToken(tokenStore, userRepo, handler.NewNodesHandler(repo, subscribeDir, remoteManageHandler, licenseManager)))
	mux.Handle("/api/admin/nodes/", auth.RequireToken(tokenStore, userRepo, handler.NewNodesHandler(repo, subscribeDir, remoteManageHandler, licenseManager)))
	// URI 管理:每个用户 × 其可见节点 的成品分享 URI(后端 substore 生成),仅管理员可用
	mux.Handle("/api/admin/node-uris", auth.RequireAdmin(tokenStore, userRepo, handler.NewNodeURIsHandler(repo)))

	// 路由出站(routed node)管理:给物理节点挂多个虚拟出站节点
	routedOutboundHandler := handler.NewRoutedOutboundHandler(repo, remoteManageHandler)
	routedOutboundHandler.SetLicenseManager(licenseManager) // 这里是 license max_nodes 唯一生效点
	mux.Handle("/api/admin/routed-outbound", auth.RequireAdmin(tokenStore, userRepo, routedOutboundHandler))
	// 用户私有路由出站(routed_owner='user'):普通用户为自己创建/删除/查询专属出站
	mux.Handle("/api/user/routed-outbound", auth.RequireToken(tokenStore, userRepo, handler.NewUserRoutedOutboundHandler(repo, remoteManageHandler)))

	// 从妙妙屋(mmw)迁移工具
	migrateHandler := handler.NewMigrateHandler(repo, remoteManageHandler)
	mux.Handle("/api/admin/migrate/fetch-mmw-backup", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(migrateHandler.FetchMmwBackup)))
	mux.Handle("/api/admin/migrate/upload-mmw-backup", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(migrateHandler.UploadMmwBackup)))
	mux.Handle("/api/admin/migrate/import-mmw", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(migrateHandler.ImportMmw)))
	mux.Handle("/api/admin/migrate/distinct-node-servers", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(migrateHandler.DistinctNodeServers)))
	mux.Handle("/api/admin/migrate/patch-client-emails", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(migrateHandler.PatchClientEmails)))
	mux.Handle("/api/admin/migrate/takeover-external-xray", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(migrateHandler.TakeoverExternalXray)))

	// 初始化事件系统以进行入站同步
	eventBus := event.GetBus()
	nodeSyncListener := event.NewNodeSyncListener(repo, remoteManageHandler.InboundToClashProxyByServerID)
	eventBus.Subscribe(event.EventInboundAdded, nodeSyncListener)
	eventBus.Subscribe(event.EventInboundRemoved, nodeSyncListener)
	eventBus.Subscribe(event.EventInboundUpdated, nodeSyncListener)
	log.Println("[Event] Inbound event listeners registered")

	mux.Handle("/api/admin/remote/services/status", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleServicesStatus)))
	mux.Handle("/api/admin/remote/services/control", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleServiceControl)))
	mux.Handle("/api/admin/remote/xray/install", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXrayInstall)))
	mux.Handle("/api/admin/remote/xray/remove", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXrayRemove)))
	mux.Handle("/api/admin/remote/xray/config", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXrayConfig)))
	mux.Handle("/api/admin/remote/xray/test-config", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXrayTestConfig)))
	mux.Handle("/api/admin/remote/xray/config/files", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXrayConfigFiles)))
	mux.Handle("/api/admin/remote/nginx/install", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleNginxInstall)))
	mux.Handle("/api/admin/remote/nginx/remove", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleNginxRemove)))
	// Cloudflare WARP — 每个 agent 各自注册 + 注入 warp-v4 / warp-v6 双 outbound
	mux.Handle("/api/admin/remote/warp/install", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleWarpInstall)))
	mux.Handle("/api/admin/remote/warp/status", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleWarpStatus)))
	mux.Handle("/api/admin/remote/warp/license", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleWarpLicense)))
	mux.Handle("/api/admin/remote/warp/remove", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleWarpRemove)))
	// SSE 流安装/删除
	mux.Handle("/api/admin/remote/xray/install-stream", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXrayInstallStream)))
	mux.Handle("/api/admin/remote/xray/remove-stream", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXrayRemoveStream)))
	mux.Handle("/api/admin/remote/nginx/install-stream", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleNginxInstallStream)))
	mux.Handle("/api/admin/remote/nginx/remove-stream", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleNginxRemoveStream)))
	mux.Handle("/api/admin/remote/agent/upgrade-stream", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleAgentUpgradeStream)))
	mux.Handle("/api/admin/remote/agent/uninstall-stream", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleAgentUninstallStream)))
	mux.Handle("/api/admin/remote/agent/version-info", auth.RequireAdmin(tokenStore, userRepo, handler.NewAgentVersionHandler(remoteManageHandler, repo)))
	mux.Handle("/api/admin/remote/nginx/config", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleNginxConfig)))
	mux.Handle("/api/admin/remote/nginx/config/files", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleNginxConfigFiles)))
	mux.Handle("/api/admin/remote/nginx/servers-list", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleNginxServersList)))
	mux.Handle("/api/admin/remote/nginx/websites", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleNginxWebsites)))
	mux.Handle("/api/admin/remote/system/info", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleSystemInfo)))
	// 出站 sendThrough 用:列服务器网卡地址。server_id 省略=主控本机。
	mux.Handle("/api/admin/server-nics", auth.RequireAdmin(tokenStore, userRepo, handler.NewServerNICsHandler(remoteManageHandler)))
	// 远程服务器Xray入站/出站/路由管理
	mux.Handle("/api/admin/remote/inbounds", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleInbounds)))
	mux.Handle("/api/admin/remote/outbounds", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleOutbounds)))
	mux.Handle("/api/admin/remote/routing", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleRouting)))
	mux.Handle("/api/admin/remote/scan", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleScan)))
	mux.Handle("/api/admin/remote/xray/system-config", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXraySystemConfig)))
	mux.Handle("/api/admin/remote/reality-domains", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleRealityDomains)))
	mux.Handle("/api/admin/remote/reality-domains/custom", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleAddCustomRealityDomain)))
	mux.Handle("/api/admin/remote/reality-domains/custom/delete", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleDeleteCustomRealityDomain)))
	mux.Handle("/api/admin/remote/reality-domains/blocked", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleListBlockedRealityDomains)))
	mux.Handle("/api/admin/remote/reality-domains/blocked/restore", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleRestoreRealityDomain)))
	// reality 域名共享池(PRO)
	mux.Handle("/api/admin/remote/reality-domains/share", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleRealityShareStatus)))
	mux.Handle("/api/admin/remote/reality-domains/share/toggle", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleRealityShareToggle)))
	mux.Handle("/api/admin/remote/reality-domains/share/sync", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleRealityShareSync)))
	mux.Handle("/api/admin/remote/reality-domains/share/withdraw", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleRealityShareWithdraw)))
	mux.Handle("/api/admin/remote/setup-ssl", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleSetupSSL)))
	mux.Handle("/api/admin/remote/deploy-steal-self", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleDeployStealSelfConfig)))
	mux.Handle("/api/admin/remote/sync-nodes", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleSyncInboundsToNodes)))
	mux.Handle("/api/admin/remote/switch-steal-mode", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleSwitchStealMode)))
	mux.Handle("/api/admin/remote/website/add", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleAddWebsite)))
	mux.Handle("/api/admin/remote/website/validate", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleValidateSite)))
	mux.Handle("/api/admin/remote/user-speeds", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleUserSpeeds)))
	// 令牌重置端点
	// xray 配置 snapshot / 跑路恢复 / 历史回滚
	xraySnapshotHandler := handler.NewXraySnapshotHandler(repo, remoteManageHandler)
	mux.Handle("/api/admin/xray-snapshots/", auth.RequireAdmin(tokenStore, userRepo, xraySnapshotHandler))
	// 慢通道:把 services/status + recovery-status handler + WS handler 注入实时 hub(主控定时查在线服务器状态,消 N+1)。
	dashboardWSHub.SetStatusHandlers(http.HandlerFunc(remoteManageHandler.HandleServicesStatus), xraySnapshotHandler, remoteWSHandler)

	mux.Handle("/api/admin/remote-servers/reset-server-token", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleResetServerToken)))
	mux.Handle("/api/admin/remote-servers/reset-agent-token", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleResetAgentToken)))
	mux.Handle("/api/admin/remote-servers/reset-all-tokens", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleResetAllTokens)))

	// TCPing 端点
	// tcping 连通性测试无数据修改，开放给普通用户（节点管理页的延迟测试按钮）
	mux.Handle("/api/admin/tcping", auth.RequireToken(tokenStore, userRepo, handler.NewTCPingHandler()))
	mux.Handle("/api/admin/tcping/batch", auth.RequireToken(tokenStore, userRepo, handler.NewTCPingBatchHandler()))
	// 从**指定远程服务器**发起 tcping(上面两个是从主控本机发起的,回答的是不同问题)
	mux.Handle("/api/admin/remote/tcping", auth.RequireAdmin(tokenStore, userRepo, handler.NewServerTCPingHandler(remoteManageHandler)))
	// 「A 能否连到 B」:自动挑 B 上确定在监听的端口探测(链式隧道建链前逐跳预检用)
	mux.Handle("/api/admin/remote/reachable", auth.RequireAdmin(tokenStore, userRepo, handler.NewServerReachabilityHandler(remoteManageHandler, repo)))

	// 子服务器模式配置
	// 确定我们是否处于儿童/远程模式：
	// 1. 配置文件设置了remote_token，或者
	// 2.环境变量MMWX_MODE=child
	var childClient *child.Client
	isChildMode := false
	var masterURL, masterToken, connectionMode, childAPIToken string

	// 首先检查配置文件
	if config != nil && config.RemoteToken != "" {
		isChildMode = true
		masterURL = config.MasterServer
		masterToken = config.RemoteToken
		connectionMode = config.ConnectionMode
		childAPIToken = config.ChildAPIToken
		log.Printf("[Child Mode] Detected from config file (remote_token present)")
	}

	// 环境变量可以覆盖或补充配置
	if os.Getenv("MMWX_MODE") == "child" {
		isChildMode = true
	}
	if envMasterURL := os.Getenv("MMWX_MASTER_URL"); envMasterURL != "" {
		masterURL = envMasterURL
	}
	if envMasterToken := os.Getenv("MMWX_MASTER_TOKEN"); envMasterToken != "" {
		masterToken = envMasterToken
	}
	if envConnectionMode := os.Getenv("MMWX_CONNECTION_MODE"); envConnectionMode != "" {
		connectionMode = envConnectionMode
	}
	if envChildAPIToken := os.Getenv("MMWX_CHILD_API_TOKEN"); envChildAPIToken != "" {
		childAPIToken = envChildAPIToken
	}

	// 默认连接模式 - 使用"auto"进行自动回退（websocket -> http -> pull）
	if connectionMode == "" {
		connectionMode = "auto"
	}

	if isChildMode {
		if masterURL != "" && masterToken != "" {
			childConfig := child.Config{
				MasterURL:             masterURL,
				Token:                 masterToken,
				ConnectionMode:        connectionMode,
				TrafficReportInterval: time.Duration(systemConfig.TrafficCollectInterval) * time.Second,
				SpeedReportInterval:   time.Duration(systemConfig.SpeedCollectInterval) * time.Second,
				HeartbeatInterval:     time.Duration(systemConfig.HeartbeatInterval) * time.Second,
			}
			childClient = child.NewClient(childConfig, trafficCollector, repo)
			log.Printf("[Child Mode] Configured: master=%s, mode=%s", masterURL, connectionMode)
		} else {
			log.Printf("[Child Mode] Warning: master_server or remote_token not set")
		}

		// 为pull模式注册子 API
		if childClient != nil {
			childAPIHandler := handler.NewChildAPIHandler(childClient, childAPIToken)
			mux.Handle("/api/child/traffic", childAPIHandler)
			mux.Handle("/api/child/speed", http.HandlerFunc(childAPIHandler.ServeSpeedHTTP))
			log.Printf("[Child Mode] Child API registered at /api/child/traffic and /api/child/speed")
		}

		// 注册子管理API（用于主机远程控制）
		childManageHandler := handler.NewChildManageHandler(masterToken)

		// 启动时检查并补全 Xray 配置
		go func() {
			// 延迟 2 秒，等待服务稳定
			time.Sleep(2 * time.Second)
			result := childManageHandler.EnsureXrayConfig()
			if result.Modified {
				log.Printf("[Child Mode] Xray config auto-completed: added %v", result.AddedSections)
				// 尝试重启 Xray 使配置生效
				cmd := exec.Command("systemctl", "restart", "xray")
				if err := cmd.Run(); err != nil {
					log.Printf("[Child Mode] Failed to restart xray: %v", err)
				} else {
					log.Printf("[Child Mode] Xray restarted after config update")
				}
			} else if result.Error != "" {
				log.Printf("[Child Mode] Xray config check: %s", result.Error)
			} else {
				log.Printf("[Child Mode] Xray config OK, no changes needed")
			}
		}()

		mux.Handle("/api/child/services/status", http.HandlerFunc(childManageHandler.HandleServicesStatus))
		mux.Handle("/api/child/services/control", http.HandlerFunc(childManageHandler.HandleServiceControl))
		mux.Handle("/api/child/xray/install", http.HandlerFunc(childManageHandler.HandleXrayInstall))
		mux.Handle("/api/child/xray/remove", http.HandlerFunc(childManageHandler.HandleXrayRemove))
		mux.Handle("/api/child/xray/config", http.HandlerFunc(childManageHandler.HandleXrayConfig))
		mux.Handle("/api/child/xray/config/files", http.HandlerFunc(childManageHandler.HandleXrayConfigFiles))
		mux.Handle("/api/child/xray/system-config", http.HandlerFunc(childManageHandler.HandleXraySystemConfig))
		mux.Handle("/api/child/nginx/install", http.HandlerFunc(childManageHandler.HandleNginxInstall))
		mux.Handle("/api/child/nginx/remove", http.HandlerFunc(childManageHandler.HandleNginxRemove))
		mux.Handle("/api/child/nginx/config", http.HandlerFunc(childManageHandler.HandleNginxConfig))
		mux.Handle("/api/child/nginx/config/files", http.HandlerFunc(childManageHandler.HandleNginxConfigFiles))
		mux.Handle("/api/child/system/info", http.HandlerFunc(childManageHandler.HandleSystemInfo))
		mux.Handle("/api/child/system/nics", http.HandlerFunc(childManageHandler.HandleSystemNICs))
		// X射线入站/出站/路由管理
		mux.Handle("/api/child/inbounds", http.HandlerFunc(childManageHandler.HandleInbounds))
		mux.Handle("/api/child/outbounds", http.HandlerFunc(childManageHandler.HandleOutbounds))
		mux.Handle("/api/child/routing", http.HandlerFunc(childManageHandler.HandleRouting))
		mux.Handle("/api/child/scan", http.HandlerFunc(childManageHandler.HandleScan))
		mux.Handle("/api/child/domains/latency", http.HandlerFunc(childManageHandler.HandleDomainLatencyProbe))
		log.Printf("[Child Mode] Management API registered at /api/child/*")
	}

	// Xray 示例 API（仅限管理员）
	xrayExamplesHandler := handler.NewXrayExamplesHandler("Xray-examples")
	mux.Handle("/api/admin/xray-examples", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayExamplesHandler.HandleGetProtocolCombinations)))

	// Xray 密钥生成 API（仅限管理员）
	xrayKeyGenHandler := handler.NewXrayKeyGeneratorHandler()
	mux.Handle("/api/admin/xray/generate-keys", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayKeyGenHandler.GenerateKeys)))
	mux.Handle("/api/admin/xray/generate-x25519", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayKeyGenHandler.GenerateX25519)))

	// 高层 inbound 构建器:吃高层意图拼出完整入站(供 MCP/自动化,无需复刻前端配置逻辑)
	buildInboundHandler := handler.NewBuildInboundHandler()
	mux.Handle("/api/admin/xray/build-inbound", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(buildInboundHandler.HandleBuildInbound)))

	// 系统设置 API（仅限管理员）
	systemSettingsHandler := handler.NewSystemSettingsHandler(repo, cryptoConfig)
	databaseSettingsHandler := handler.NewDatabaseSettingsHandler(repo, dataDir)
	mux.Handle("/api/admin/database/status", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(databaseSettingsHandler.Status)))
	mux.Handle("/api/admin/database/migration-progress", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(databaseSettingsHandler.MigrationProgress)))
	mux.Handle("/api/admin/database/test", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(databaseSettingsHandler.Test)))
	mux.Handle("/api/admin/database/migrate", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(databaseSettingsHandler.Migrate)))
	systemSettingsHandler.SetCollector(trafficCollector)
	systemSettingsHandler.SetWSHandler(remoteWSHandler)
	systemSettingsHandler.SetOnMasterURLChanged(remoteManageHandler.BroadcastMasterURLUpdate)
	// 启动时加载加密设置
	if encVal, _ := repo.GetSystemSetting(context.Background(), "require_encryption"); encVal == "true" {
		cryptoConfig.SetRequireEncryption(true)
	}
	// 启动时把 DB 里的默认主题注入到下发的 index.html(无 cookie 的用户首屏据此套主题,无闪烁)
	if theme, _ := repo.GetSystemSetting(context.Background(), handler.DefaultThemeKey); theme != "" {
		web.SetDefaultTheme(theme)
	}
	// 更新走 CDN 加速开关:默认开启(域名写死在代码);DB 里显式存 "0"/"false" 才关闭 → 回退直连 GitHub
	if v, _ := repo.GetSystemSetting(context.Background(), handler.UpdateCDNEnabledKey); v == "0" || v == "false" {
		handler.SetUpdateCDNEnabled(false)
	}
	// 日志管理(admin):系统日志(主控自身 mmwx.log)只读查询。定时/agent 日志端点见后续注册。
	mux.Handle("/api/admin/logs/system", auth.RequireAdmin(tokenStore, userRepo, handler.NewSystemLogHandler(repo)))
	// 安全日志:探测/封禁事件流 + 当前封禁列表 + 手动封禁/解封。子路径 events / bans / bans/{ip}。
	securityLogHandler := handler.NewSecurityLogHandler(repo)
	mux.Handle("/api/admin/security/", auth.RequireAdmin(tokenStore, userRepo, securityLogHandler))
	// 定时任务运行记录:runs(列表,后端分页) / types(下拉筛选清单)。
	returnRouteTester := handler.NewReturnRouteTester(repo, remoteManageHandler)
	taskLogHandler := handler.NewTaskLogHandler(repo, returnRouteTester)
	mux.Handle("/api/admin/tasks/", auth.RequireAdmin(tokenStore, userRepo, taskLogHandler))
	// Agent 日志:转发到指定 agent 拉取远程机器日志(agent 自身/xray/nginx)。旧版 agent 降级提示。
	mux.Handle("/api/admin/logs/agent", auth.RequireAdmin(tokenStore, userRepo, handler.NewAgentLogHandler(remoteManageHandler)))
	// 日志文件管理:主控自身的日志目录,以及转发到 agent 的同名能力。
	mux.Handle("/api/admin/logs/files", auth.RequireAdmin(tokenStore, userRepo, handler.NewLogFilesHandler()))
	mux.Handle("/api/admin/logs/agent/files", auth.RequireAdmin(tokenStore, userRepo, handler.NewAgentLogFilesHandler(remoteManageHandler)))
	// 自定义安全阈值(登录/暴力防护/订阅频率)— 写入后 handler 内部热更新 3 个 limiter 单例,无需重启
	mux.Handle("/api/admin/security-settings", auth.RequireAdmin(tokenStore, userRepo, handler.NewSecuritySettingsHandler(repo)))
	tgBotManager := inttgbot.NewManager(repo, tokenStore, mux)
	mux.Handle("/api/user/renewal-request", auth.RequireToken(tokenStore, userRepo, handler.NewUserRenewalHandler(renewalService, tgBotManager)))
	remoteManageHandler.SetOnMasterMigrated(func(ctx context.Context, _ string) {
		if err := tgBotManager.Restart(ctx); err != nil {
			logger.Error("主控迁移后重启 TGBot 失败", "error", err.Error())
		}
	})
	mux.Handle("/api/admin/system-settings/tgbot", auth.RequireAdmin(tokenStore, userRepo, handler.NewTGBotSettingsHandler(tgBotManager)))
	mux.HandleFunc("/tg-app", tgBotManager.ServeWebApp)
	mux.HandleFunc("/api/tg-webapp/", tgBotManager.ServeWebApp)
	// Turnstile 配置自测:前端 widget 验完拿 token,后端用 DB 已存 secret 调 cloudflare siteverify,
	// 返回详细 error_codes 供前端诊断"两 key 配错 / 域名没白名单 / 网络不通"等场景。
	mux.Handle("/api/admin/security-settings/turnstile/test", auth.RequireAdmin(tokenStore, userRepo, handler.NewTurnstileTestHandler(turnstileVerifier)))
	mux.Handle("/api/admin/system-settings/api-token", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(systemSettingsHandler.GetAPIToken)))
	mux.Handle("/api/admin/system-settings/api-token/regenerate", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(systemSettingsHandler.RegenerateAPIToken)))
	mux.Handle("/api/admin/system-settings/master-url", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetMasterURL(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetMasterURL(w, r)
			// Mini App 地址由主控公网地址派生；地址修改后刷新 Telegram 菜单按钮。
			go func() {
				if err := tgBotManager.Restart(context.Background()); err != nil {
					logger.Error("主控地址变更后重启 TGBot 失败", "error", err.Error())
				}
			}()
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/admin/system-settings/master-migration", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleMasterMigration)))
	mux.Handle("/api/admin/system-settings/external-https", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetExternalHTTPS(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetExternalHTTPS(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/admin/system-settings/redeem-template", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetRedeemTemplate(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetRedeemTemplate(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	// 自定义登录页壁纸:管理员读写 + 公开读取(登录页未鉴权时读)
	mux.Handle("/api/admin/system-settings/login-wallpaper", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetLoginWallpaper(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetLoginWallpaper(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.HandleFunc("/api/public/login-wallpaper", systemSettingsHandler.GetLoginWallpaperPublic)
	// 登录页展示许可证称号:免鉴权,仅 name/display_name/valid(见 handler 注释)
	mux.Handle("/api/public/license-badge", handler.NewLicenseBadgePublicHandler(repo, licenseManager))
	mux.Handle("/api/admin/system-settings/license-badge", auth.RequireAdmin(tokenStore, userRepo, handler.NewLicenseBadgeDisplayHandler(repo)))

	// 真探针数据的内存 ring(cpu/mem/disk/ping,来自 agent 上报)。查询热路径不建时序表，
	// 仅将紧凑的 24 小时 ring 定时落盘，避免主控重启后曲线清空。
	// 单例:读侧给 ProbePublicHandler,写侧 P3 注入 remoteWSHandler。
	// capN=1440(1 分钟间隔约 1 天窗口):伪装页延迟折线图/24 小时色块条据此回溯。
	// 内存量级:1440 点 × 16B × 目标数(≤30) × 服务器数,几十台机也就几 MB,可接受。
	probeMetricsStore := handler.NewProbeMetricsStore(1440)
	probeQualityAlertScheduler := handler.NewProbeQualityAlertScheduler(repo, probeMetricsStore)
	remoteWSHandler.SetProbeStore(probeMetricsStore)   // 写侧:接收 agent 上报的 sysmetrics/latency
	federationHandler.SetProbeStore(probeMetricsStore) // 拥有方 server-info 透传 cpu/mem/disk 给消费方探针
	// HTTP/pull 模式的 agent 没有 WS 连接,探针指标只能从 /api/remote/traffic 这条 POST 进来;
	// 采集开关也只能搭该请求的响应车下发。两者都注入后,两种连接模式的探针数据才一致。
	remoteTrafficHandler.SetProbeStore(probeMetricsStore)
	remoteTrafficHandler.SetWSHandler(remoteWSHandler)
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			probeMetricsStore.Evict(25 * time.Hour) // 保留完整 24h 历史，超窗服务器才清理
		}
	}()

	// 公开端点:伪装探针的只读服务器状态(无鉴权)。伪装关闭时返回 {enabled:false},开启时只吐白名单字段。
	// 走明文(前端 shouldEncrypt 已放行 /api/public/);此处 remoteWSHandler 已构造(见上文)。
	probePublicHandler := handler.NewProbePublicHandler(repo, remoteWSHandler, probeMetricsStore)
	probePublicHandler.SetLicenseManager(licenseManager)
	mux.Handle("/api/public/probe-servers", handler.RequireProbeExternalAccess(repo, probePublicHandler))
	// WS 推送版:一次计算广播给所有访客,替代每客户端 5 秒一次的 HTTP 轮询。
	// 前端优先连它,连不上(反代没配 upgrade / 连接数超限)自动回落上面的 HTTP 端点。
	mux.Handle("/api/public/probe-ws", handler.RequireProbeExternalAccess(repo, handler.NewProbeWSHandler(probePublicHandler)))
	// 延迟弹窗按需拉的详细曲线(单服务器单目标),与列表端点分开:列表 5 秒轮询,给粗粒度小 payload。
	mux.Handle("/api/public/probe-series", handler.RequireProbeExternalAccess(repo, handler.NewProbeSeriesHandler(repo, probeMetricsStore)))

	// CDN 省市 ping 目标列表(管理员配置伪装探针 ping 时勾选)。代理+缓存 lf3-ips.zstaticcdn.com,防 SSRF。
	mux.Handle("/api/admin/probe/regions", auth.RequireAdmin(tokenStore, userRepo, handler.NewProbeCDNProxyHandler(repo)))

	// 伪装探针配置(开关 + 标题 + 展示的服务器 + 是否显名)
	mux.Handle("/api/admin/system-settings/probe-disguise", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetProbeDisguise(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetProbeDisguise(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	// 默认主题(flat / pixel):PUT 保存后重读并同步注入到 index.html,让新用户首屏立即用新默认
	mux.Handle("/api/admin/system-settings/default-theme", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetDefaultTheme(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetDefaultTheme(w, r)
			if theme, _ := repo.GetSystemSetting(r.Context(), handler.DefaultThemeKey); theme != "" {
				web.SetDefaultTheme(theme)
			}
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	// 更新走 CDN 加速开关(admin GET 回显 / PUT 切换)。CDN 域名写死在代码,默认开启,关闭则回退直连 GitHub。
	mux.Handle("/api/admin/system-settings/update-cdn", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetUpdateCDNStatus(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetUpdateCDNStatus(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	// 公告系统:模板配置(admin GET/PUT)、公告实例 CRUD(admin)、生效公告(登录可读)
	announcementHandler := handler.NewAnnouncementHandler(repo, licenseManager)
	mux.Handle("/api/admin/system-settings/announcements", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			announcementHandler.GetConfig(w, r)
		case http.MethodPut:
			announcementHandler.SetConfig(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/admin/announcements", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(announcementHandler.ServeAdmin)))
	mux.Handle("/api/admin/announcements/blocked-nodes", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(announcementHandler.GetBlockedNodes)))
	mux.Handle("/api/announcements/active", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(announcementHandler.GetActive)))
	// 节点被墙自动探测循环。探测源是**家用测速端**(部署在国内家庭网络)——
	// 机房 agent / 主控本机都探不准被墙,会把落地节点误判成被墙。
	handler.StartReachabilityScheduler(context.Background(), repo, speedTesterWS, announcementHandler)
	// 从旧版本升上来、还没重新配探测源的实例会静默停用被墙探测,启动时明确告警一次。
	announcementHandler.WarnLegacyProbeSource(context.Background())

	mux.Handle("/api/admin/system-settings/short-link", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetShortLinkEnabled(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetShortLinkEnabled(w, r)
		default:
			http.Error(w, "��法不允许", http.StatusMethodNotAllowed)
		}
	})))
	// 节点名称倍率前缀(开关 + 左右分隔符)
	mux.Handle("/api/admin/system-settings/node-name-multiplier-prefix", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetNodeNameMultiplierPrefix(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetNodeNameMultiplierPrefix(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/admin/system-settings/intervals", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetIntervals(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetIntervals(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	// 公开:所有登录用户可拿前端 dashboard 刷新间隔(默认 5000ms,admin 可在系统设置改)
	mux.Handle("/api/system-config/refetch-interval", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(systemSettingsHandler.GetPublicIntervals)))
	// admin:写前端 dashboard 刷新间隔,clamp [1000, 60000] ms
	mux.Handle("/api/admin/system-settings/dashboard-refresh", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(systemSettingsHandler.SetDashboardRefresh)))

	// 用户权限 / 配额(全局策略)
	userPermsHandler := handler.NewUserPermissionsHandler(repo)
	mux.Handle("/api/admin/system-settings/user-permissions", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			userPermsHandler.AdminGet(w, r)
		case http.MethodPut, http.MethodPost:
			userPermsHandler.AdminSet(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	// 普通用户拿自己适用的可见页面 + 配额 + 已用量
	mux.Handle("/api/user/permissions", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(userPermsHandler.UserGet)))
	mux.Handle("/api/admin/system-settings/agent-log", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetAgentLogEnabled(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetAgentLogEnabled(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))

	mux.Handle("/api/admin/system-settings/override-scripts", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetOverrideScriptsEnabled(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetOverrideScriptsEnabled(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))

	mux.Handle("/api/admin/system-settings/subscription-output-format", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetSubscriptionOutputFormat(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetSubscriptionOutputFormat(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))

	mux.Handle("/api/admin/system-settings/silent-mode", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetSilentMode(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetSilentMode(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/admin/system-settings/require-encryption", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetRequireEncryption(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetRequireEncryption(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/admin/system-settings/miaomiaowu-features", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetMiaomiaowuFeaturesEnabled(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetMiaomiaowuFeaturesEnabled(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/admin/system-settings/default-template", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetDefaultTemplate(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetDefaultTemplate(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))

	// 许可证 API
	licenseHandler := handler.NewLicenseHandler(repo, licenseManager)
	mux.Handle("/api/admin/license/status", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(licenseHandler.GetStatus)))
	mux.Handle("/api/admin/license/usage", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(licenseHandler.GetUsage)))
	mux.Handle("/api/admin/license/settings", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			licenseHandler.GetSettings(w, r)
		case http.MethodPut:
			licenseHandler.UpdateSettings(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/user/license/status", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(licenseHandler.UserGetStatus)))

	// 通知配置 API（仅限管理员）
	notifyConfigHandler := handler.NewNotifyConfigHandler(repo)
	mux.Handle("/api/admin/notify-config", auth.RequireAdmin(tokenStore, userRepo, notifyConfigHandler))
	mux.Handle("/api/admin/notify-config/test", auth.RequireAdmin(tokenStore, userRepo, notifyConfigHandler))
	mux.Handle("/api/admin/notify-config/preview", auth.RequireAdmin(tokenStore, userRepo, notifyConfigHandler))

	// 证书管理 API（仅限管理员）
	certHandler := handler.NewCertificateHandler(repo, remoteWSHandler)
	certHandler.SetOnMasterURLChanged(remoteManageHandler.BroadcastMasterURLUpdate)
	certHandler.SetRemoteManage(remoteManageHandler) // 联邦服务器证书下发走拥有方主控
	remoteManageHandler.SetCertificateHandler(certHandler)
	// agent 重连先同步实际 Xray 配置快照，再按快照补发其中引用的主控托管证书。
	remoteWSHandler.SetXrayConfigSyncCallback(func(ctx context.Context, serverID int64, prevStatus string) {
		// 离线期间错过的服务器 IP 变更必须先修到 Agent 配置，再读取快照；
		// 否则 pending_recovery 会保存带旧 IP 的配置，用户恢复时又把旧地址写回来。
		remoteManageHandler.SyncPendingOutboundAddressChanges(ctx, serverID)
		remoteManageHandler.SyncXrayConfigOnReconnect(ctx, serverID, prevStatus)
		certHandler.SyncManagedXrayCertificatesOnReconnect(ctx, serverID)
	})
	remoteManageHandler.SetStealSelfDeployer(remoteManageHandler.DeployStealSelfConfig)
	remoteWSHandler.SetScanResultHandler(remoteManageHandler.HandleScanResult)
	remoteWSHandler.SetStealSelfDeployer(remoteManageHandler.DeployStealSelfConfig)
	remoteWSHandler.SetMasterURLSyncCallback(remoteManageHandler.SyncMasterURLOnReconnect)
	mux.Handle("/api/admin/certificates", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.ListCertificates)))
	mux.Handle("/api/admin/certificates/valid", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.ListValidCertificates)))
	mux.Handle("/api/admin/certificates/self-signed", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.GenerateSelfSignedCert)))
	mux.Handle("/api/admin/certificates/create", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.CreateCertificate)))
	mux.Handle("/api/admin/certificates/renew", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.RenewCertificate)))
	mux.Handle("/api/admin/certificates/auto-renew", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.SetAutoRenew)))
	mux.Handle("/api/admin/certificates/auto-deploy", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.SetAutoDeploy)))
	mux.Handle("/api/admin/certificates/deploy", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.DeployCertificate)))
	mux.Handle("/api/admin/certificates/upload", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.UploadCertificate)))
	mux.Handle("/api/admin/certificates/download", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.DownloadCertificate)))
	mux.Handle("/api/admin/certificates/delete", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.DeleteCertificate)))
	mux.Handle("/api/admin/certificates/", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.GetCertificate)))
	mux.Handle("/api/admin/master-cert-status", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.GetMasterCertStatus)))
	mux.Handle("/api/admin/deploy-master-cert", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.DeployMasterCert)))
	mux.Handle("/api/admin/enable-https", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.EnableHTTPS)))

	// DNS 提供商管理 API（仅限管理员）
	mux.Handle("/api/admin/dns-providers", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.ListDNSProviders)))
	mux.Handle("/api/admin/dns-providers/create", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.CreateDNSProvider)))
	mux.Handle("/api/admin/dns-providers/", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			certHandler.UpdateDNSProvider(w, r)
		case http.MethodDelete:
			certHandler.DeleteDNSProvider(w, r)
		default:
			http.NotFound(w, r)
		}
	})))

	// 创建订阅处理程序（在端点和短链接之间共享）
	subscriptionHandler := handler.NewSubscriptionHandlerConcrete(repo, subscribeDir)

	// 短链接重置端点。
	//
	// 曾经挂在 RequireToken 下、且前端「个人设置」里给每个用户都放了按钮 —— 但
	// ResetAllSubscriptionShortURLs 是 `SELECT id FROM subscribe_files` 全表重置、
	// handler 取了 username 却根本不用,任何一个普通用户点一下就会把**全系统所有人**的
	// 订阅短链接冲掉。现已收归管理员;自定义短码请走订阅管理里的按文件设置入口。
	mux.Handle("/api/user/short-link", auth.RequireAdmin(tokenStore, userRepo, handler.NewShortLinkResetHandler(repo)))
	mux.Handle("/api/user/custom-short-code", auth.RequireToken(tokenStore, userRepo, handler.NewUserCustomShortCodeSelfHandler(repo)))

	// 临时订阅端点
	// 中间件:RequireToken(非 admin 也能进 handler),handler 内按"妙妙屋功能 → 节点管理"开关决定是否放行。
	// 路径保留 /api/admin/ 前缀以避免破坏既有前端调用;实际权限语义由 handler 控制。
	mux.Handle("/api/admin/temp-subscription", auth.RequireToken(tokenStore, userRepo, handler.NewTempSubscriptionHandler(repo)))
	tempSubAccessHandler := handler.NewTempSubscriptionAccessHandler()

	// 短链接和 Web 应用程序的组合处理程序
	// 这会捕获任何 6 字符路径（如 /AbC123）并将它们路由到短链接处理程序
	// /t/{id} 路径路由到临时订阅处理程序
	// 所有其他路径都转到 Web 处理程序
	shortLinkHandler := handler.NewShortLinkHandler(repo, subscriptionHandler, packageSubscribeHandler)
	// 暴力防护 / 订阅频率限制 用前面 LoadSecuritySettings 拿到的同一份 secCfg 构造,
	// system_settings 里有自定义阈值就用它们,没有就 fallback 到 hardcoded 默认值(24h/24h/30 次/2h)。
	bruteForceProtector := handler.NewBruteForceProtectorWithConfig(
		secCfg.BruteForceEnabled, secCfg.BruteForceMaxFailures,
		secCfg.BruteForceWindowMinutes, secCfg.BruteForceBlockMinutes,
	)
	bruteForceProtector.SetSkipLocalIP(secCfg.SkipLocalIP)
	// 持久化:注入 repo → 封禁/探测事件双写 DB;启动回填 → 永久封禁跨重启生效;后台清理 → 修内存泄漏
	bruteForceProtector.SetRepo(repo)
	bruteForceProtector.RestoreFromDB(context.Background())
	go bruteForceProtector.StartCleanup(context.Background())
	subRateLimiter := handler.NewSubscriptionRateLimiterWithConfig(
		secCfg.SubRateEnabled, secCfg.SubRateLimit, secCfg.SubRateWindowMinutes,
	)
	subRateLimiter.SetSkipLocalIP(secCfg.SkipLocalIP)
	go subRateLimiter.StartCleanup(context.Background())

	// 自定义静态资源目录 data/public/(Docker 下随 data 卷持久化、二进制下就是工作目录旁)。
	// 前端 dist 是编译进二进制的只读 embed.FS,用户无法往里放图片;这是唯一能在 Docker/二进制
	// 部署里放自定义壁纸等图片的位置:把图片丢进 data/public/,再在设置里引用 /public/xxx.jpg。
	// ServeMux 里 "/public/" 比 "/" 更具体 → 优先命中,不会被 SPA 兜底吞掉。
	publicDir := filepath.Join(dataDir, "public")
	_ = os.MkdirAll(publicDir, 0755)
	mux.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir(publicDir))))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.Trim(r.URL.Path, "/")
		clientIP := handler.GetClientIP(r)

		isTempSub := strings.HasPrefix(path, "t/") && len(path) == 10

		// 暴力探测封禁检查：仅对 /x/ 短链探测路径生效(失败计数也只来自 /x/ 与临时订阅)。
		// SPA 路由(/nodes、/users 等单段 alphanumeric)、静态资源、临时订阅一律放行,
		// 否则被封 IP 连前端 UI 都无法加载(SPA 路由与短码长得一样,不能一并拦截)。
		if strings.HasPrefix(path, "x/") && bruteForceProtector.IsBlocked(clientIP, r.URL.Path) {
			http.NotFound(w, r)
			return
		}

		isSubscriptionFetch := isTempSub ||
			(strings.HasPrefix(path, "x/") && len(path) > 2 && isAlphanumeric(path[2:]))
		if isSubscriptionFetch && !subRateLimiter.Allow(clientIP) {
			http.Error(w, "请求过于频繁，请稍后再试", http.StatusTooManyRequests)
			return
		}

		// 检查这是否是临时订阅访问（以"t/"开头，后跟 8 个十六进制字符）
		if isTempSub {
			rec := &handler.StatusRecorder{ResponseWriter: w, StatusCode: 200}
			tempSubAccessHandler.ServeHTTP(rec, r)
			if rec.StatusCode == http.StatusNotFound || rec.StatusCode == http.StatusForbidden {
				bruteForceProtector.RecordFailure(clientIP, r.URL.Path)
			}
			return
		}
		// 可变长度短链接匹配（/x/{fileCode}{userCode} 格式）
		if strings.HasPrefix(path, "x/") {
			code := path[2:]
			if len(code) >= 2 && isAlphanumeric(code) {
				if shortLinkHandler.TryServe(w, r) {
					return
				}
				bruteForceProtector.RecordFailure(clientIP, r.URL.Path)
				http.NotFound(w, r)
				return
			}
		}

		// 否则，传递给 Web 处理程序
		web.Handler().ServeHTTP(w, r)
	})

	// 嵌入式 MCP server(streamable-HTTP):供 OpenClaw 等 agent 运维。鉴权在工具调用时按 API 令牌经 mux 复用现有链。
	mux.Handle("/mcp", mcpserver.NewHandler(mux))

	// E2E 加密通道 — 复用 internal/securechan(X25519 + AES-256-GCM + 滑动窗口防重放)
	// 接到前端 user-facing API。客户端不发 X-Secure-Channel header 时透传,完全向后兼容。
	secureChannelHandler := handler.NewUserSecureChannelHandler()
	mux.Handle("/api/securechan/handshake", http.HandlerFunc(secureChannelHandler.Handshake))

	silentModeManager := handler.NewSilentModeManager(repo, tokenStore)
	// 中间件顺序:SecureChannelMiddleware 必须在 silentMode/CORS 之**内**(更靠近 mux),
	// 因为它会替换 request.Body 与 response body,外层 CORS/silentMode 只需看请求 path/header 即可。
	handlerWithSecureChannel := secureChannelHandler.SecureChannelMiddleware(mux)
	handlerWithSilentMode := silentModeManager.Middleware(handlerWithSecureChannel)

	allowedOrigins := getAllowedOrigins()
	handlerWithCORS := withCORS(handlerWithSilentMode, allowedOrigins)
	// HTTPS 启用后,应用层拦截非合法 Host 的请求(IP+端口直连等)→ 308 重定向到正确域名。
	// 跟 bind host 解耦,Docker / 跨机反代 / 裸机都能正确工作。详见 host_enforcement.go。
	handlerWithHostEnforce := handler.EnforceHTTPSHost(handlerWithCORS, repo)

	srv := &http.Server{
		Addr:              addr,
		Handler:           handlerWithHostEnforce,
		ReadHeaderTimeout: 5 * time.Second,
	}

	collectorCtx, stopCollector := context.WithCancel(context.Background())
	handler.StartProbeMetricsPersistence(collectorCtx, probeMetricsStore, filepath.Join(dataDir, "probe-metrics.json"))
	returnRouteTester.Start(collectorCtx)
	returnRouteTester.LogTargets()
	if err := tgBotManager.Restart(collectorCtx); err != nil {
		logger.Error("内置 TGBot 启动失败", "error", err.Error())
	}
	defer tgBotManager.Stop()

	trafficCollector.OnServerOffline = handler.SendServerOfflineNotification
	// 启动 Xray 流量收集器（每 1 分钟）
	go trafficCollector.Start(collectorCtx)
	go probeQualityAlertScheduler.Start(collectorCtx)
	// 启动拉模式服务器的速度收集（每 3 秒）
	go trafficCollector.StartSpeedCollection(collectorCtx)
	// 启动每日快照和清理任务
	go startDailySnapshotTask(collectorCtx, trafficHandler, trafficCollector)
	go startTrafficSnapshotBackfillTask(collectorCtx, repo)
	go startTrafficLedgerAuditTask(collectorCtx, repo)
	// WAL 巡检:每 5 分钟 wal_checkpoint(TRUNCATE),把 -wal 抽干并截断,防止长跑容器里 mmwx.db-wal 无界膨胀。
	go startWALCheckpointTask(collectorCtx, repo)
	// 每分钟检查数据库健康；一旦损坏或底层 I/O 失败，停止所有后台采集/写入任务并只告警一次。
	go startDatabaseHealthTask(collectorCtx, repo, stopCollector)
	// 一次性补:上一轮已切到 traffic_source='system' 但 daily snapshot baseline 缺失的 server。
	// 行数 < 7 视为"切换时漏迁移"(覆盖本周维度);ON CONFLICT 覆盖,重启重跑也安全。
	// 新装的 system server 跑 7 天后自然有 ≥7 行,不会被误触发。
	go backfillSystemSnapshotsForSwitchedServers(collectorCtx, repo)
	// 启动流量超限检查（每 2 分钟）
	trafficEnforcer := handler.NewTrafficLimitEnforcer(repo, remoteManageHandler, limiterPusher)
	go trafficEnforcer.Start(collectorCtx, time.Duration(systemConfig.TrafficCheckInterval)*time.Second)
	// 启动 WebSocket 陈旧连接清理
	remoteWSHandler.StartCleanupLoop(collectorCtx, 1*time.Minute)
	// 启动通知调度器
	go handler.StartNotifyScheduler(collectorCtx, repo)
	go handler.StartServerProviderSync(collectorCtx, repo, licenseManager)
	handler.FinishPendingMasterHTTPSRecovery(collectorCtx, repo)
	recoveryPort := "12889"
	if config != nil && config.Port != "" {
		recoveryPort = config.Port
	} else if envPort := os.Getenv("PORT"); envPort != "" {
		recoveryPort = envPort
	}
	go handler.NewMasterHTTPSRecoveryMonitor(repo, recoveryPort, handler.SignalGracefulRestart).Start(collectorCtx)

	// 一次性数据迁移:给老 routed 节点补 creator 的 user_subaccounts 行 — 让 admin 自己用 routed 节点的
	// 流量能走 user_subaccounts 命中而不依赖 ResolveUsernameByEmail 的 _admin__ 反查 fallback。
	// 幂等:NOT EXISTS 保护重启不重复写。新建节点已在 routed_outbound.create 同步处理,这里只补历史欠账。
	if n, err := repo.BackfillRoutedCreatorSubaccounts(context.Background()); err != nil {
		log.Printf("[Startup] BackfillRoutedCreatorSubaccounts failed: %v", err)
	} else if n > 0 {
		log.Printf("[Startup] BackfillRoutedCreatorSubaccounts: filled %d creator subaccount row(s) for legacy routed nodes", n)
	}

	// 一次性补:历史 bug 导致「套餐开了按月重置但用户行 is_reset=0」的存量用户从未重置。按套餐刷回。
	// 幂等:只改 is_reset=0 且套餐要求重置的行;下次启动这些行已 is_reset=1,不再命中。
	if n, err := repo.BackfillUserResetFromPackage(context.Background()); err != nil {
		log.Printf("[Startup] BackfillUserResetFromPackage failed: %v", err)
	} else if n > 0 {
		log.Printf("[Startup] BackfillUserResetFromPackage: enabled monthly reset for %d user(s) per their package", n)
	}

	// 一次性数据迁移:清掉旧"new<last 启发式重启检测"误判累加的 total_* 脏数据。
	// 新算法用 agent 上报的 xray_boot_time 作权威重启信号,total_* 从下一轮 collector tick
	// 起按真重启累加。详见 internal/storage/traffic.go:ResetTrafficTotalsForXrayBootTimeMigration。
	// flag = traffic_total_reset_v2_done,system_settings 表里防重复。
	if n, alreadyDone, err := repo.ResetTrafficTotalsForXrayBootTimeMigration(context.Background()); err != nil {
		log.Printf("[Startup] ResetTrafficTotalsForXrayBootTimeMigration failed: %v", err)
	} else if alreadyDone {
		log.Printf("[Startup] ResetTrafficTotalsForXrayBootTimeMigration: already done, skip")
	} else {
		log.Printf("[Startup] ResetTrafficTotalsForXrayBootTimeMigration: reset done, %d rows affected (3 tables)", n)
	}

	// 一次性回填:collector 从"读时乘倍率"切到"采集时计价"。用当前倍率把存量裸量换算成
	// weighted_*,并写入采集时归因的 attributed_username → 上线读数与切换前等价(零行为变化),
	// 从下一个 tick 起改倍率不再追溯重算历史。
	// flag = weighted_traffic_backfill_done。**二次回填会覆盖已累积的加权历史,故 flag 与数据同事务**。
	if n, alreadyDone, err := repo.BackfillWeightedTraffic(context.Background()); err != nil {
		log.Printf("[Startup] BackfillWeightedTraffic failed: %v", err)
	} else if alreadyDone {
		log.Printf("[Startup] BackfillWeightedTraffic: already done, skip")
	} else {
		log.Printf("[Startup] BackfillWeightedTraffic: backfilled %d user_email_traffic row(s)", n)
	}

	// 修复上面那次回填留下的坏数据:服务器已被删除时,旧版 Classify 返回空归因,
	// attributed_username 被写成空串、套餐 oneway/twoway 倍率一并丢失(twoway 用户计费腰斩)。
	// 归因层已修,但存量行不会自愈,这里把"没有归属"的行重算一遍。
	// 只碰无归属的行 —— 不整表重跑,避免用今天的倍率改写已正确的历史。
	// flag = weighted_attrib_repair_v1_done。
	if n, alreadyDone, err := repo.RepairWeightedAttribution(context.Background()); err != nil {
		log.Printf("[Startup] RepairWeightedAttribution failed: %v", err)
	} else if alreadyDone {
		log.Printf("[Startup] RepairWeightedAttribution: already done, skip")
	} else if n > 0 {
		log.Printf("[Startup] RepairWeightedAttribution: repaired %d row(s) that lost user attribution; "+
			"注意:均分分母 bug 造成的权重偏小无法自动识别,如需彻底纠正请手动整表重跑", n)
	} else {
		log.Printf("[Startup] RepairWeightedAttribution: nothing to repair")
	}

	// 紧急修复:reset migration 把 node_traffic.uplink/downlink 改成了 last_*(很小),snapshot
	// baseline 还是历史累计 → 服务器视图算"已用 = current - snapshot"全负数 → clamp 0 → "流量丢失"。
	// 真正修复:从 node_traffic_snapshots 反推恢复 node_traffic 到 reset 前的累计值。
	// 取每个 (server, tag) 历史 snapshot 中 (uplink+downlink) 最大值,绕开 today snapshot 被
	// reset 后写入的污染数据。详见 internal/storage/traffic.go:RestoreNodeTrafficFromSnapshots。
	if n, alreadyDone, err := repo.RestoreNodeTrafficFromSnapshots(context.Background()); err != nil {
		log.Printf("[Startup] RestoreNodeTrafficFromSnapshots failed: %v", err)
	} else if alreadyDone {
		log.Printf("[Startup] RestoreNodeTrafficFromSnapshots: already done, skip")
	} else {
		log.Printf("[Startup] RestoreNodeTrafficFromSnapshots: restored %d node_traffic row(s) from snapshots", n)
	}
	// 同款,对 user_traffic 表
	if n, alreadyDone, err := repo.RestoreUserTrafficFromSnapshots(context.Background()); err != nil {
		log.Printf("[Startup] RestoreUserTrafficFromSnapshots failed: %v", err)
	} else if alreadyDone {
		log.Printf("[Startup] RestoreUserTrafficFromSnapshots: already done, skip")
	} else {
		log.Printf("[Startup] RestoreUserTrafficFromSnapshots: restored %d user_traffic row(s) from snapshots", n)
	}

	// 清掉 reset 前用户用 admin UI "重置流量"留下的负偏移 — reset migration 已经做过等效操作,
	// 负偏移叠加只会让"已用 = (current+offset) - snapshot" 算成大负数 → clamp 0,显示假象。
	// 正偏移保留(用户记账累计的语义,有保留价值)。
	if n, alreadyDone, err := repo.ClearNegativeTrafficUsedOffsetsAfterReset(context.Background()); err != nil {
		log.Printf("[Startup] ClearNegativeTrafficUsedOffsetsAfterReset failed: %v", err)
	} else if alreadyDone {
		log.Printf("[Startup] ClearNegativeTrafficUsedOffsetsAfterReset: already done, skip")
	} else {
		log.Printf("[Startup] ClearNegativeTrafficUsedOffsetsAfterReset: cleared %d server(s) with negative offset", n)
	}
	// 启动分享服务器(联邦)状态/流量轮询（每 30 秒从拥有方拉取）
	handler.SetFederationLicense(licenseManager)
	go handler.StartFederationPoller(collectorCtx, repo, probeMetricsStore)
	// 启动证书自动续订检查程序（每 24 小时检查一次是否有 30 天内过期的证书）
	certHandler.StartRenewalChecker(collectorCtx)
	// TODO: 启动远程服务器离线检测任务（功能尚未实现）
	// 开始离线检测任务（collectorCtx，repo）

	// 如果处于子模式，则启动子客户端
	if childClient != nil {
		childClient.Start(collectorCtx)
		log.Printf("[Child Mode] Client started")
	}

	// 在启动时打印 API token
	apiToken, err := repo.GetAPIToken(context.Background())
	if err != nil {
		log.Printf("警告: 获取 API token 失败: %v", err)
	} else {
		log.Printf("=================================================")
		log.Printf("API Token: %s", apiToken)
		log.Printf("在请求头 MM-Authorization 中使用此 token 可无需认证访问 API")
		log.Printf("=================================================")
	}

	go func() {
		logger.Info("妙妙屋 HTTP 服务器启动", "version", version.Version, "address", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP服务器运行失败", "error", err)
			os.Exit(1)
		}
	}()

	waitForShutdown(srv, stopCollector)
}

func getAddr(config *ServerConfig, repo *storage.TrafficRepository) string {
	port := "12889"
	if config != nil && config.Port != "" {
		port = config.Port
	} else if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	// 默认绑 0.0.0.0,兼容裸机、Docker 与跨机反代。BIND_HOST 可显式覆盖默认值；
	// 系统设置中的“关闭公网访问”具有更高优先级，开启后强制仅监听本机回环地址。
	host := "0.0.0.0"
	if v := strings.TrimSpace(os.Getenv("BIND_HOST")); v != "" {
		host = v
	}
	if repo != nil {
		forcePublic, _ := repo.GetSystemSetting(context.Background(), "master_force_public_http")
		localOnly, err := repo.GetSystemSetting(context.Background(), "master_local_only")
		if err != nil {
			log.Printf("[Main] Failed to read master access setting, using %s: %v", host, err)
		} else if localOnly == "1" && handler.IsDockerEnvironment() {
			log.Printf("[Main] Docker environment ignores master_local_only; use Docker port publishing or host firewall instead")
			_ = repo.SetSystemSetting(context.Background(), "master_local_only", "0")
			host = "0.0.0.0"
		} else if localOnly == "1" && forcePublic != "1" {
			host = "127.0.0.1"
		} else if forcePublic == "1" {
			host = "0.0.0.0"
		}
	}
	log.Printf("[Main] HTTP server binding to %s:%s", host, port)
	return host + ":" + port
}

// 检查字符串是否仅包含字母数字字符
func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func waitForShutdown(srv *http.Server, cancels ...context.CancelFunc) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	logger.Info("收到关闭信号，开始优雅关闭")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 停止所有后台任务
	for _, cancelFunc := range cancels {
		if cancelFunc != nil {
			cancelFunc()
		}
	}

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("优雅关闭失败", "error", err)
	} else {
		logger.Info("服务器已安全关闭")
	}
}

// backfillSystemSnapshotsForSwitchedServers 为早期已切换到 system source、但缺少历史
// system snapshot 的服务器补基线。这里只允许插入缺失快照，禁止修改 system cycle 和
// traffic_used_offset；后两者是实时记账状态，数据库迁移后覆写会造成服务器流量归零。
//
// 启动后 30s 延迟跑,避开启动峰值;失败只 log,不阻塞主控。
func backfillSystemSnapshotsForSwitchedServers(ctx context.Context, repo *storage.TrafficRepository) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}

	scanCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// marker 检查 — 已跑过就跳过,保护用户手动校准不被覆盖
	if val, err := repo.GetSystemSetting(scanCtx, storage.SystemTrafficSnapshotBackfillMarker); err == nil && val != "" {
		log.Printf("[Backfill SystemSnap] one-time resync already done at %s, skip", val)
		return
	}

	servers, err := repo.ListRemoteServers(scanCtx)
	if err != nil {
		log.Printf("[Backfill SystemSnap] list remote servers failed: %v", err)
		return
	}

	backfilled := int64(0)
	for _, s := range servers {
		if s.TrafficSource != "system" {
			continue
		}
		inserted, err := repo.BackfillMissingServerSystemTrafficSnapshots(scanCtx, s.ID)
		if err != nil {
			log.Printf("[Backfill SystemSnap] backfill server %d (%s) failed: %v", s.ID, s.Name, err)
			continue
		}
		backfilled += inserted
		if inserted > 0 {
			log.Printf("[Backfill SystemSnap] server %d (%s) added %d missing snapshot(s); live cycle and offset preserved", s.ID, s.Name, inserted)
		}
	}
	if backfilled > 0 {
		log.Printf("[Backfill SystemSnap] safe one-time backfill done: added %d snapshot(s)", backfilled)
	}

	// 写 marker — 即便没 migrate 任何 server(全是 xray source)也写,避免每次启动重复扫
	if err := repo.SetSystemSetting(scanCtx, storage.SystemTrafficSnapshotBackfillMarker, time.Now().UTC().Format(time.RFC3339)); err != nil {
		log.Printf("[Backfill SystemSnap] write marker failed: %v", err)
	}
}

// 创建每日快照并清理旧数据
// startWALCheckpointTask 每 5 分钟做一次 wal_checkpoint(TRUNCATE):把 WAL 已提交帧写回主库并截断 -wal 文件。
// SQLite 默认 PASSIVE 自动 checkpoint 在持续并发读下常抽不干、且从不截断文件;配合 DSN 里的 journal_size_limit,
// 这个巡检保证长跑容器里 mmwx.db-wal 不会无界膨胀。TRUNCATE 会等 reader(有 5s busy_timeout),
// 偶发 SQLITE_BUSY 属正常,下一轮再来,非致命。
func startWALCheckpointTask(ctx context.Context, repo *storage.TrafficRepository) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if truncated, remaining, err := repo.CheckpointBestEffort(); err != nil {
				log.Printf("[WAL] periodic checkpoint failed: %v", err)
			} else if !truncated {
				// TRUNCATE 抢不到窗口(有长读/写事务持 WAL mark)已降级 PASSIVE 尽力抽干,-wal 不会无界
				log.Printf("[WAL] checkpoint 未能截断(WAL 仍剩 %d 帧,已降级 PASSIVE 尽力抽干,不影响可用)", remaining)
			}
		}
	}
}

func startDatabaseHealthTask(ctx context.Context, repo *storage.TrafficRepository, stopBackgroundTasks context.CancelFunc) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	unhealthy := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := repo.QuickCheck(checkCtx)
			cancel()
			if err != nil {
				unhealthy = true
				// 查询超时、database is locked、短暂 I/O 错误不等于数据库已损坏。
				// 旧逻辑遇到一次临时错误就取消共享 context，流量重置等任务会永久停止且无法自愈。
				if isDefiniteDatabaseCorruption(err) {
					logger.Error("数据库确认损坏，已停止后台数据库写入任务；请检查磁盘并重启以触发备份恢复", "error", err)
					stopBackgroundTasks()
					return
				}
				logger.Warn("数据库健康检查暂时失败，将继续重试；后台任务未停止", "error", err)
				continue
			}
			if unhealthy {
				logger.Info("数据库健康检查已恢复")
				unhealthy = false
			}
		}
	}
}

func isDefiniteDatabaseCorruption(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"database disk image is malformed",
		"file is not a database",
		"sqlite_corrupt",
		"sqlite_notadb",
		"quick_check failed:",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

func startDailySnapshotTask(ctx context.Context, trafficHandler *handler.TrafficSummaryHandler, trafficCollector *traffic.Collector) {
	if trafficHandler == nil {
		return
	}

	// 带重试的流量收集函数
	runWithRetry := func() error {
		logger.Info("[流量收集器] 开始每日流量收集", "start_time", time.Now().Format("2006-01-02 15:04:05"))

		retryDelay := 30 * time.Second
		snapshotDone := false

		for attempt := 1; ; attempt++ {
			runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := trafficHandler.RecordDailyUsage(runCtx)
			cancel()

			// Snapshot collection is independent from the aggregate summary. A
			// temporary summary failure must never suppress the period baselines.
			var snapshotErr error
			if trafficCollector != nil && !snapshotDone {
				snapCtx, snapCancel := context.WithTimeout(ctx, 60*time.Second)
				snapshotErr = trafficCollector.CreateDailySnapshots(snapCtx)
				snapCancel()
				snapshotDone = snapshotErr == nil
			}
			if err == nil && snapshotErr == nil {
				logger.Info("[流量收集器] 每日流量收集成功")
				return nil
			}
			if snapshotErr != nil {
				logger.Error("[流量收集器] 节点/用户快照保存失败", "error", snapshotErr)
				err = errors.Join(err, snapshotErr)
			}

			logger.Warn("[流量收集器] 每日快照尚未完整落库，将持续重试", "attempt", attempt, "error", err)
			logger.Info("[流量收集器] 准备重试", "delay", retryDelay)
			select {
			case <-ctx.Done():
				logger.Info("[流量收集器] 重试已取消（服务器关闭）")
				return ctx.Err()
			case <-time.After(retryDelay):
			}
			// Permanent outages should not create a tight loop. Retry quickly at
			// first, then cap at five minutes until the database recovers.
			if retryDelay < 5*time.Minute {
				retryDelay *= 2
				if retryDelay > 5*time.Minute {
					retryDelay = 5 * time.Minute
				}
			}
		}
	}

	// 启动后不立即跑,改为等到下一个 00:00:00 触发第一次,之后每 24h 一次。
	// 用户需求:每日流量记录在 0 点产生,而不是服务器启动时刻。
	now := time.Now()
	nextMidnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Add(24 * time.Hour)
	firstDelay := time.Until(nextMidnight)
	logger.Info("[流量收集器] 定时调度器已启动", "first_run_at", nextMidnight.Format("2006-01-02 15:04:05"), "interval", "24小时")

	recorded := func() {
		taskrun.Record(ctx, "daily_snapshot", func() (string, error) {
			// 必须把错误透传给 taskrun,否则 task_runs 里这个任务永远是 ok,
			// 失败只在日志里,DB 中零痕迹 —— 整个 taskrun 机制对它形同虚设。
			return "", runWithRetry()
		})
	}

	firstTimer := time.NewTimer(firstDelay)
	select {
	case <-ctx.Done():
		firstTimer.Stop()
		logger.Info("[流量收集器] 定时调度器已停止")
		return
	case <-firstTimer.C:
		recorded()
	}

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("[流量收集器] 定时调度器已停止")
			return
		case <-ticker.C:
			recorded()
		}
	}
}

func startTrafficLedgerAuditTask(ctx context.Context, repo *storage.TrafficRepository) {
	if repo == nil {
		return
	}
	run := func() {
		taskrun.Record(ctx, "traffic_ledger_audit", func() (string, error) {
			checkCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			return repo.AuditDailyTrafficLedger(checkCtx, time.Now())
		})
	}
	// Give collectors one minute to establish their first baselines.
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
		run()
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func startTrafficSnapshotBackfillTask(ctx context.Context, repo *storage.TrafficRepository) {
	if repo == nil {
		return
	}
	// Let the HTTP service and collectors finish starting first. The migration
	// reads only immutable dates before the live ledger boundary and retries
	// until its transaction and completion marker commit together.
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	for {
		var result storage.TrafficDailyBackfillResult
		var migrationErr error
		taskrun.Record(ctx, "traffic_snapshot_backfill", func() (string, error) {
			migrationCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
			defer cancel()
			result, migrationErr = repo.BackfillDailyTrafficLedgerFromSnapshots(migrationCtx)
			return result.String(), migrationErr
		})
		if migrationErr == nil && result.AlreadyDone {
			return
		}
		if migrationErr == nil {
			logger.Info("[流量账本迁移] 历史快照迁移完成", "result", result.String())
			return
		}
		logger.Error("[流量账本迁移] 历史快照迁移失败，将自动重试", "error", migrationErr)
		retry := time.NewTimer(5 * time.Minute)
		select {
		case <-ctx.Done():
			retry.Stop()
			return
		case <-retry.C:
		}
	}
}

// syncSubscribeFilesToDatabase 扫描订阅目录并确保
// 每个 YAML 文件在 subscribe_files 表中都有相应的记录。
// 这有助于从旧版本升级时向后兼容。
func syncSubscribeFilesToDatabase(repo *storage.TrafficRepository, subscribeDir string) {
	if repo == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 读取订阅目录中的所有文件
	entries, err := os.ReadDir(subscribeDir)
	if err != nil {
		logger.Warn("读取订阅目录失败", "dir", subscribeDir, "error", err)
		return
	}

	synced := 0
	for _, entry := range entries {
		// 跳过目录和非 YAML 文件
		if entry.IsDir() {
			continue
		}
		filename := entry.Name()
		if filepath.Ext(filename) != ".yaml" && filepath.Ext(filename) != ".yml" {
			continue
		}

		// 跳过 .keep.yaml 占位符文件
		if filename == ".keep.yaml" {
			continue
		}

		// 检查该文件是否已有数据库记录
		if _, err := repo.GetSubscribeFileByFilename(ctx, filename); err == nil {
			// 文件已存在于数据库中，跳过
			continue
		} else if !errors.Is(err, storage.ErrSubscribeFileNotFound) {
			logger.Warn("检查订阅文件失败", "filename", filename, "error", err)
			continue
		}

		// 数据库中不存在文件，创建一条新记录
		// 使用不带扩展名的文件名作为名称
		name := filename[:len(filename)-len(filepath.Ext(filename))]

		file := storage.SubscribeFile{
			Name:        name,
			Description: "自动同步的订阅文件",
			URL:         "",                          // 没有旧文件的 URL
			Type:        storage.SubscribeTypeUpload, // 标记为上传类型
			Filename:    filename,
		}

		if _, err := repo.CreateSubscribeFile(ctx, file); err != nil {
			logger.Warn("同步订阅文件到数据库失败", "filename", filename, "error", err)
			continue
		}

		synced++
	}

	if synced > 0 {
		logger.Info("订阅文件同步完成", "count", synced)
	}
}

// 启动日志清理任务
func startLogCleanup() {
	logManager := logger.NewLogManager("data/logs")

	// 一轮清理：debug 日志(log_*, 7天) + lumberjack 主日志(mmwx*, 兜底保留最新2个)
	runCleanup := func() {
		if err := logManager.CleanupOldLogs(); err != nil {
			logger.Error("[日志清理] 清理 debug 日志失败", "error", err)
		}
		if err := logManager.EnforceMaxFiles("mmwx", 2); err != nil {
			logger.Error("[日志清理] 清理主日志失败", "error", err)
		}
	}

	// 启动时立即清理一次
	runCleanup()

	// 兜底巡检(主轮转由 lumberjack 负责,这里 10 分钟扫一次)
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	logger.Info("[日志清理] 定时清理任务已启动", "interval", "10分钟", "debug_max_age", "7天", "main_keep", 2)

	for range ticker.C {
		runCleanup()
	}
}

const taskRunRetention = 7 * 24 * time.Hour

// startTaskRunCleanup 只保留最近七天的定时任务运行记录。
// 启动时立即清理，之后每小时巡检，避免长期运行时 task_runs 持续增长。
func startTaskRunCleanup(ctx context.Context, repo *storage.TrafficRepository) {
	cleanup := func() {
		deleted, err := repo.DeleteOldTaskRuns(ctx, time.Now().Add(-taskRunRetention))
		if err != nil {
			logger.Error("[定时任务日志] 清理过期记录失败", "error", err)
			return
		}
		if deleted > 0 {
			logger.Info("[定时任务日志] 已清理七天前的记录", "count", deleted)
		}
	}
	cleanup()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanup()
		}
	}
}
