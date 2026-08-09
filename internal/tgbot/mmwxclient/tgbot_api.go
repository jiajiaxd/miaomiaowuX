package mmwxclient

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// BindRequest 给 /api/admin/tgbot/bind 的入参。kind=new 时 Username 必填,kind=bind 时不要传 username。
type BindRequest struct {
	Code           string `json:"code"`
	TelegramID     int64  `json:"telegram_id"`
	TelegramHandle string `json:"telegram_handle,omitempty"`
	Username       string `json:"username,omitempty"`
	Email          string `json:"email,omitempty"`
	Password       string `json:"password,omitempty"`
}

// BindResponse 主控 /bind 返回。kind=new 时 InitialPassword 非空,Package 非 nil。
type BindResponse struct {
	Success         bool           `json:"success"`
	Username        string         `json:"username"`
	Kind            string         `json:"kind"`
	InitialPassword string         `json:"initial_password,omitempty"`
	Package         map[string]any `json:"package,omitempty"`
}

func (c *Client) Bind(ctx context.Context, req BindRequest) (*BindResponse, error) {
	var out BindResponse
	if err := c.post(ctx, "/api/admin/tgbot/bind", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RedeemResult 已绑用户续期结果。
type RedeemResult struct {
	Success     bool   `json:"success"`
	Username    string `json:"username"`
	PackageName string `json:"package_name"`
	EndDate     string `json:"end_date"`
}

type RenewalRequest struct {
	RequestToken    string `json:"request_token,omitempty"`
	Username        string `json:"username"`
	TelegramID      int64  `json:"telegram_id,omitempty"`
	PackageName     string `json:"package_name"`
	PreviousEndDate string `json:"previous_end_date,omitempty"`
	RenewDays       int    `json:"renew_days"`
	Source          string `json:"source"`
	Status          string `json:"status"`
	NewEndDate      string `json:"new_end_date,omitempty"`
	ErrorMessage    string `json:"error_message,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
	ReviewedAt      string `json:"reviewed_at,omitempty"`
}

type ServerRenewalResult struct {
	Processed  bool   `json:"processed"`
	ServerName string `json:"server_name"`
	ExpiresAt  string `json:"expires_at"`
}

func (c *Client) ConfirmServerRenewed(ctx context.Context, serverID int64, expectedDate string) (*ServerRenewalResult, error) {
	var out ServerRenewalResult
	if err := c.post(ctx, "/api/admin/tgbot/server-renewed", map[string]any{
		"server_id": serverID, "expected_date": expectedDate,
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) RenewalRequestHistory(ctx context.Context, tgID int64) ([]RenewalRequest, error) {
	var out struct {
		Requests []RenewalRequest `json:"requests"`
	}
	q := url.Values{"telegram_id": []string{strconv.FormatInt(tgID, 10)}}
	if err := c.get(ctx, "/api/admin/tgbot/renewal-request/status", q, &out); err != nil {
		return nil, err
	}
	return out.Requests, nil
}

func (c *Client) CreateRenewalRequest(ctx context.Context, tgID int64, passphrase string) (*RenewalRequest, error) {
	var out struct {
		Request RenewalRequest `json:"request"`
	}
	if err := c.post(ctx, "/api/admin/tgbot/renewal-request", map[string]any{"telegram_id": tgID, "passphrase": passphrase}, &out); err != nil {
		return nil, err
	}
	return &out.Request, nil
}

func (c *Client) RenewalRequestStatus(ctx context.Context, tgID int64) (*RenewalRequest, error) {
	var out struct {
		Request *RenewalRequest `json:"request"`
	}
	q := url.Values{"telegram_id": []string{strconv.FormatInt(tgID, 10)}}
	if err := c.get(ctx, "/api/admin/tgbot/renewal-request/status", q, &out); err != nil {
		return nil, err
	}
	return out.Request, nil
}

func (c *Client) ReviewRenewalRequest(ctx context.Context, token string, adminTGID int64, approve bool) (*RenewalRequest, bool, error) {
	action := "reject"
	if approve {
		action = "approve"
	}
	var out struct {
		Request   RenewalRequest `json:"request"`
		Processed bool           `json:"processed"`
	}
	if err := c.post(ctx, "/api/admin/tgbot/renewal-request/"+action, map[string]any{"token": token, "admin_telegram_id": adminTGID}, &out); err != nil {
		return nil, false, err
	}
	return &out.Request, out.Processed, nil
}

func (c *Client) FailRenewalRequest(ctx context.Context, token, detail string) error {
	return c.post(ctx, "/api/admin/tgbot/renewal-request/fail", map[string]any{"token": token, "error": detail}, nil)
}

// Redeem 已绑用户用兑换码续期(只延长到期时间)。
func (c *Client) Redeem(ctx context.Context, code string, tgID int64) (*RedeemResult, error) {
	var out RedeemResult
	if err := c.post(ctx, "/api/admin/tgbot/redeem",
		map[string]any{"code": code, "telegram_id": tgID}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// BindAdmin 把 TG 自动绑到主控管理员账号(Mini App:管理员未绑定时自动绑)。返回管理员用户名。
func (c *Client) BindAdmin(ctx context.Context, tgID int64, handle string) (string, error) {
	var out struct {
		Success  bool   `json:"success"`
		Username string `json:"username"`
	}
	if err := c.post(ctx, "/api/admin/tgbot/bind-admin",
		map[string]any{"telegram_id": tgID, "telegram_handle": handle}, &out); err != nil {
		return "", err
	}
	return out.Username, nil
}

func (c *Client) Unbind(ctx context.Context, tgID int64) (string, error) {
	var out struct {
		Success  bool   `json:"success"`
		Username string `json:"username"`
	}
	if err := c.post(ctx, "/api/admin/tgbot/unbind", map[string]any{"telegram_id": tgID}, &out); err != nil {
		return "", err
	}
	return out.Username, nil
}

type UserByTG struct {
	Success        bool   `json:"success"`
	Bound          bool   `json:"bound"`
	Username       string `json:"username,omitempty"`
	Role           string `json:"role,omitempty"`
	IsActive       bool   `json:"is_active,omitempty"`
	IsPrimaryAdmin bool   `json:"is_primary_admin,omitempty"`
	NotifyEnabled  bool   `json:"notify_enabled,omitempty"`
}

func (c *Client) UserByTG(ctx context.Context, tgID int64) (*UserByTG, error) {
	var out UserByTG
	q := url.Values{"tg_id": []string{strconv.FormatInt(tgID, 10)}}
	if err := c.get(ctx, "/api/admin/tgbot/user-by-tg", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UserSummary 主控 /user-summary 返回(松散字段,bot 渲染时灵活取)。
type UserSummary struct {
	Success        bool            `json:"success"`
	Username       string          `json:"username"`
	Role           string          `json:"role"`
	IsActive       bool            `json:"is_active"`
	Email          string          `json:"email"`
	Package        map[string]any  `json:"package,omitempty"`
	PackageEndDate string          `json:"package_end_date,omitempty"`
	Traffic        TrafficCounters `json:"traffic"`
}

type TrafficCounters struct {
	CycleUplink   int64 `json:"cycle_uplink"`
	CycleDownlink int64 `json:"cycle_downlink"`
	TotalUplink   int64 `json:"total_uplink"`
	TotalDownlink int64 `json:"total_downlink"`
}

func (c *Client) UserSummary(ctx context.Context, username string) (*UserSummary, error) {
	var out UserSummary
	q := url.Values{"username": []string{username}}
	if err := c.get(ctx, "/api/admin/tgbot/user-summary", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type Subscription struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	FileShortCode   string `json:"file_short_code"`
	CustomShortCode string `json:"custom_short_code"`
	CombinedCode    string `json:"combined_code"`
}

type UserSubscriptionsResp struct {
	Success       bool           `json:"success"`
	UserShortCode string         `json:"user_short_code"`
	Subscriptions []Subscription `json:"subscriptions"`
	// DefaultSubscription 套餐默认订阅(用户有套餐时即有,无需分配 subscribe_file)。
	DefaultSubscription *Subscription `json:"default_subscription,omitempty"`
}

func (c *Client) UserSubscriptions(ctx context.Context, username string) (*UserSubscriptionsResp, error) {
	var out UserSubscriptionsResp
	q := url.Values{"username": []string{username}}
	if err := c.get(ctx, "/api/admin/tgbot/user-subscriptions", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type NodeInfo struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Protocol     string `json:"protocol"`
	ServerName   string `json:"server_name"`
	ServerStatus string `json:"server_status"`
	ServerOnline bool   `json:"server_online"`
	InboundTag   string `json:"inbound_tag"`
	NodeType     string `json:"node_type"`
	Enabled      bool   `json:"enabled"`
}

type UserNodesResp struct {
	Success bool       `json:"success"`
	Nodes   []NodeInfo `json:"nodes"`
}

func (c *Client) UserNodes(ctx context.Context, username string) (*UserNodesResp, error) {
	var out UserNodesResp
	q := url.Values{"username": []string{username}}
	if err := c.get(ctx, "/api/admin/tgbot/user-nodes", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AdminSubview 管理员账号的「系统订阅列表第一个订阅」+ 其节点(名/协议/状态)。
type AdminSubview struct {
	Subscription *Subscription `json:"subscription"`
	Nodes        []struct {
		NodeID   int64  `json:"node_id"`
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
		Status   string `json:"status"`
	} `json:"nodes"`
}

// GetAdminSubview 取管理员的订阅视图(无套餐管理员在 Mini App 用第一个订阅)。
func (c *Client) GetAdminSubview(ctx context.Context, username string) (*AdminSubview, error) {
	var out AdminSubview
	q := url.Values{"username": []string{username}}
	if err := c.get(ctx, "/api/admin/tgbot/admin-subview", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AdminNodeTrafficItem 管理员视角下单个节点的全局流量。
type AdminNodeTrafficItem struct {
	NodeID   int64  `json:"node_id"`
	NodeName string `json:"node_name"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
}

// AdminMonthlyNodeTraffic 返回本月第一天至今的所有节点流量汇总。
func (c *Client) AdminMonthlyNodeTraffic(ctx context.Context) ([]AdminNodeTrafficItem, error) {
	var out struct {
		Items []AdminNodeTrafficItem `json:"items"`
	}
	monthStart := time.Now().Format("2006-01") + "-01"
	q := url.Values{"date": []string{monthStart}}
	if err := c.get(ctx, "/api/admin/traffic/node-totals", q, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// RemoteServerStatus 是管理员状态页需要的最小服务器信息。
type RemoteServerStatus struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	XrayRunning bool   `json:"xray_running"`
}

// RemoteServers 返回主控管理的全部服务器，不按订阅或套餐过滤。
func (c *Client) RemoteServers(ctx context.Context) ([]RemoteServerStatus, error) {
	var out struct {
		Servers []RemoteServerStatus `json:"servers"`
	}
	if err := c.get(ctx, "/api/admin/remote-servers", nil, &out); err != nil {
		return nil, err
	}
	return out.Servers, nil
}

// ControlXray 复用主控服务管理的控制接口。start 会走主控现有的冲突恢复逻辑，
// stop 则直接转发给 Agent；调用者必须已经完成 Mini App 管理员身份校验。
func (c *Client) ControlXray(ctx context.Context, serverID int64, action string) error {
	q := url.Values{"server_id": []string{strconv.FormatInt(serverID, 10)}}
	return c.post(ctx, "/api/admin/remote/services/control?"+q.Encode(), map[string]any{
		"service": "xray",
		"action":  action,
	}, nil)
}

// NodeTrafficItem 用户在单个节点的已用流量(本周期)。
type NodeTrafficItem struct {
	NodeID   int64  `json:"node_id"`
	NodeName string `json:"node_name"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
}

// UserNodeTraffic 取用户各节点已用流量。注意端点在 /api/admin/traffic/user-nodes
// (非 tgbot 子域),鉴权同为 RequireAdmin,故 bot 的 admin token 可用。
func (c *Client) UserNodeTraffic(ctx context.Context, username string) ([]NodeTrafficItem, error) {
	var out struct {
		Items []NodeTrafficItem `json:"items"`
	}
	q := url.Values{"username": []string{username}}
	if err := c.get(ctx, "/api/admin/traffic/user-nodes", q, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// DailyUsage 套餐周期内某一天的用量(GB)。
type DailyUsage struct {
	Date   string  `json:"date"`
	UsedGB float64 `json:"used_gb"`
}

// UserDailyTraffic 取用户套餐周期内每日用量(用于首页流量曲线)。
func (c *Client) UserDailyTraffic(ctx context.Context, username string) ([]DailyUsage, error) {
	var out struct {
		History []DailyUsage `json:"history"`
	}
	q := url.Values{"username": []string{username}}
	if err := c.get(ctx, "/api/admin/tgbot/user-daily-traffic", q, &out); err != nil {
		return nil, err
	}
	return out.History, nil
}

// ============ 邀请码(admin 命令 /admin_invite 用) ============

type Invite struct {
	Code         string `json:"code"`
	Kind         string `json:"kind"`
	BindUsername string `json:"bind_username,omitempty"`
	CreatedBy    string `json:"created_by"`
	PackageID    *int64 `json:"package_id,omitempty"`
	MaxUses      int    `json:"max_uses"`
	UsedCount    int    `json:"used_count"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	Revoked      bool   `json:"revoked"`
	Remark       string `json:"remark,omitempty"`
	Usable       bool   `json:"usable"`
}

func (c *Client) ListInvites(ctx context.Context, limit int) ([]Invite, error) {
	var out struct {
		Success bool     `json:"success"`
		Items   []Invite `json:"items"`
	}
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if err := c.get(ctx, "/api/admin/tgbot/invites", q, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *Client) RevokeInvite(ctx context.Context, code string) error {
	return c.post(ctx, "/api/admin/tgbot/invites/revoke", map[string]any{"code": code}, nil)
}

// DeleteInvite 硬删除邀请码(仅限已不可用的)。
func (c *Client) DeleteInvite(ctx context.Context, code string) error {
	return c.post(ctx, "/api/admin/tgbot/invites/delete", map[string]any{"code": code}, nil)
}

// CreateInviteRequest 给 POST /api/admin/tgbot/invites。
// kind=new 时 PackageID/DurationMonths 有意义;kind=bind 时 BindUsername 必填。
// DurationMonths>0:注册账号有效期 = now + N 月,且 N>1 时主控自动开按月续期。
type CreateInviteRequest struct {
	Kind           string `json:"kind"`
	BindUsername   string `json:"bind_username,omitempty"`
	PackageID      *int64 `json:"package_id,omitempty"`
	MaxUses        int    `json:"max_uses,omitempty"`
	DurationMonths int    `json:"duration_months,omitempty"`
	Remark         string `json:"remark,omitempty"`
}

// CreateInvite 创建邀请码,返回生成的 code。
func (c *Client) CreateInvite(ctx context.Context, req CreateInviteRequest) (string, error) {
	var out struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := c.post(ctx, "/api/admin/tgbot/invites", req, &out); err != nil {
		return "", err
	}
	return out.Code, nil
}

// ============ 套餐(创建邀请码时按钮选套餐用)============

// Package 主控 /api/admin/packages 返回的套餐(只取 bot 渲染需要的字段)。
type Package struct {
	ID             int64   `json:"id"`
	Name           string  `json:"name"`
	TrafficLimitGB float64 `json:"traffic_limit_gb"`
	CycleDays      int     `json:"cycle_days"`
}

// ListPackages 列出所有套餐模板。注意端点在 /api/admin/packages(非 tgbot 子域),
// 但鉴权中间件与 tgbot 同为 RequireAdmin,故同一 admin token 可用。
func (c *Client) ListPackages(ctx context.Context) ([]Package, error) {
	var out struct {
		Packages []Package `json:"packages"`
	}
	if err := c.get(ctx, "/api/admin/packages", nil, &out); err != nil {
		return nil, err
	}
	return out.Packages, nil
}

// GetRedeemTemplate 取主控配置的兑换码复制文案模板(未配置时主控会返回内置默认模板)。
func (c *Client) GetRedeemTemplate(ctx context.Context) (string, error) {
	var out struct {
		RedeemTemplate string `json:"redeem_template"`
	}
	if err := c.get(ctx, "/api/admin/system-settings/redeem-template", nil, &out); err != nil {
		return "", err
	}
	return out.RedeemTemplate, nil
}

// ============ 用户自助通知 ============

// SetNotify 开关某 tg_id 的每日通知。
func (c *Client) SetNotify(ctx context.Context, tgID int64, enabled bool) error {
	return c.post(ctx, "/api/admin/tgbot/notify",
		map[string]any{"telegram_id": tgID, "enabled": enabled}, nil)
}

// NotifyUser 每日推送名单的一行(流量 + 到期)。
type NotifyUser struct {
	Username       string  `json:"username"`
	TelegramID     int64   `json:"telegram_id"`
	PackageName    string  `json:"package_name"`
	TrafficLimitGB float64 `json:"traffic_limit_gb"`
	CycleUplink    int64   `json:"cycle_uplink"`
	CycleDownlink  int64   `json:"cycle_downlink"`
	TotalUplink    int64   `json:"total_uplink"`
	TotalDownlink  int64   `json:"total_downlink"`
	PackageEndDate string  `json:"package_end_date"`
}

// NotifyDigest 拉取所有已开通知用户(供 bot 每日推送)。
func (c *Client) NotifyDigest(ctx context.Context) ([]NotifyUser, error) {
	var out struct {
		Users []NotifyUser `json:"users"`
	}
	if err := c.get(ctx, "/api/admin/tgbot/notify-digest", nil, &out); err != nil {
		return nil, err
	}
	return out.Users, nil
}

// ============ 公告 ============

// Announcement 公告实例。Recipients 仅 pending 接口返回(该公告的定向收件人 tg_id)。
type Announcement struct {
	ID         int64   `json:"id"`
	Type       string  `json:"type"`
	Title      string  `json:"title"`
	Body       string  `json:"body"`
	Recipients []int64 `json:"recipients,omitempty"`
}

// PendingAnnouncements 拉取待 bot 推送的公告,每条自带定向收件人(有套餐 + 节点相关的仅含该节点用户)。
func (c *Client) PendingAnnouncements(ctx context.Context) ([]Announcement, error) {
	var out struct {
		Announcements []Announcement `json:"announcements"`
	}
	if err := c.get(ctx, "/api/admin/tgbot/announcements/pending", nil, &out); err != nil {
		return nil, err
	}
	return out.Announcements, nil
}

// MarkAnnouncementDelivered 标记公告已由 bot 推送(避免重复发)。
func (c *Client) MarkAnnouncementDelivered(ctx context.Context, id int64) error {
	return c.post(ctx, "/api/admin/tgbot/announcements/delivered", map[string]any{"id": id}, nil)
}

// ActiveAnnouncements 拉取该用户当前应看到的生效公告(主控按套餐/节点归属定向过滤),供 Mini App 横幅。
func (c *Client) ActiveAnnouncements(ctx context.Context, username string) ([]Announcement, error) {
	q := url.Values{}
	q.Set("username", username)
	var out struct {
		Announcements []Announcement `json:"announcements"`
	}
	if err := c.get(ctx, "/api/admin/tgbot/announcements/active", q, &out); err != nil {
		return nil, err
	}
	return out.Announcements, nil
}

// PostAnnouncement 管理员经 bot 命令 / miniapp 发布一条公告。
func (c *Client) PostAnnouncement(ctx context.Context, title, body string) error {
	return c.post(ctx, "/api/admin/tgbot/announcements",
		map[string]any{"type": "general", "title": title, "body": body}, nil)
}

// ListAnnouncements 列出所有当前生效公告(管理员视角,不按用户过滤),供 Mini App 管理页。
func (c *Client) ListAnnouncements(ctx context.Context) ([]Announcement, error) {
	var out struct {
		Announcements []Announcement `json:"announcements"`
	}
	if err := c.get(ctx, "/api/admin/announcements", nil, &out); err != nil {
		return nil, err
	}
	return out.Announcements, nil
}

// DeleteAnnouncement 删除一条公告(Mini App 管理页)。
func (c *Client) DeleteAnnouncement(ctx context.Context, id int64) error {
	return c.doRequest(ctx, "DELETE", "/api/admin/announcements?id="+strconv.FormatInt(id, 10), nil, nil)
}

// ============ 管理员用户管理(miniapp:搜索 / 续期 / 改套餐)============

// AdminUser 主控 /api/admin/users 返回的用户(只取 miniapp 用户管理页需要的字段)。
type AdminUser struct {
	Username       string  `json:"username"`
	Nickname       string  `json:"nickname"`
	Role           string  `json:"role"`
	PackageID      *int64  `json:"package_id"`
	PackageName    string  `json:"package_name,omitempty"`
	PackageEndDate *string `json:"package_end_date,omitempty"`
	IsActive       bool    `json:"is_active"`
	TrafficUsed    int64   `json:"traffic_used,omitempty"`
	TrafficLimit   int64   `json:"traffic_limit,omitempty"`
	SpeedLimitMbps float64 `json:"speed_limit_mbps"`
}

// ListUsers 列出所有用户(返回全量,搜索在 miniapp 前端做)。端点 /api/admin/users 同为 RequireAdmin。
func (c *Client) ListUsers(ctx context.Context) ([]AdminUser, error) {
	var out struct {
		Users []AdminUser `json:"users"`
	}
	if err := c.get(ctx, "/api/admin/users", nil, &out); err != nil {
		return nil, err
	}
	return out.Users, nil
}

// ExtendUser 给已绑套餐的用户延长有效期 N 天(主控从当前到期日或今天往后延,只延期不重置流量)。
func (c *Client) ExtendUser(ctx context.Context, username string, days int) error {
	return c.post(ctx, "/api/admin/users/extend",
		map[string]any{"username": username, "days": days}, nil)
}

// AssignPackage 改用户套餐。不传 expire_date/is_reset/reset_day —— 主控按新套餐自身的 CycleDays/重置设置兜底
// (即改套餐 = 以新套餐重新起一个周期)。端点 /api/admin/packages/assign 同为 RequireAdmin。
func (c *Client) AssignPackage(ctx context.Context, username string, packageID int64) error {
	return c.post(ctx, "/api/admin/packages/assign",
		map[string]any{"username": username, "package_id": packageID}, nil)
}

// GetDefaultTheme 取主控「默认主题」系统设置(flat / pixel / anime)。端点 RequireAdmin,bot token 可访问。
// 供 Mini App 跟随主控主题使用;失败时上层自行退化为默认(pixel)。
func (c *Client) GetDefaultTheme(ctx context.Context) (string, error) {
	var out struct {
		DefaultTheme string `json:"default_theme"`
	}
	if err := c.get(ctx, "/api/admin/system-settings/default-theme", nil, &out); err != nil {
		return "", err
	}
	return out.DefaultTheme, nil
}

// Branding 仅包含 Mini App 需要的公开品牌字段。公开 branding 接口已经处理 PRO 门控。
type Branding struct {
	BrandTitle string `json:"brand_title"`
	LogoURL    string `json:"logo_url"`
}

// GetBranding 取主控当前生效的品牌；未配置或功能未生效时字段为空，由 Mini App 使用内置资源。
func (c *Client) GetBranding(ctx context.Context) (Branding, error) {
	var out struct {
		Branding Branding `json:"branding"`
	}
	if err := c.get(ctx, "/api/branding", nil, &out); err != nil {
		return Branding{}, err
	}
	out.Branding.BrandTitle = strings.TrimSpace(out.Branding.BrandTitle)
	out.Branding.LogoURL = strings.TrimSpace(out.Branding.LogoURL)
	return out.Branding, nil
}
