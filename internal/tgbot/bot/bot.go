// Package bot 命令路由 + 处理。HTTP 调用主控走 mmwxclient。
package bot

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"miaomiaowux/internal/tgbot/config"
	"miaomiaowux/internal/tgbot/mmwxclient"
)

type Service struct {
	mu          sync.Mutex
	cfg         config.Config
	client      *mmwxclient.Client
	b           *bot.Bot
	cancel      context.CancelFunc
	webHandler  http.Handler
	botUsername string // 由 getMe 获取,用于兑换码文案的 {机器人地址} = https://t.me/<botUsername>

	// Mini App 主题跟随主控「默认主题」的 60s 缓存(见 cachedDefaultTheme)
	themeMu  sync.Mutex
	themeVal string
	themeExp time.Time

	// Mini App 左上角标题和 Logo 跟随主控自定义品牌，缓存策略同主题。
	brandMu  sync.Mutex
	brandVal mmwxclient.Branding
	brandExp time.Time
}

// botURL 返回机器人的 t.me 链接;拿不到 username 时返回空串。
func (s *Service) botURL() string {
	if s.botUsername == "" {
		return ""
	}
	return "https://t.me/" + s.botUsername
}

// BotURL 返回 getMe 探测到的机器人公开地址。
func (s *Service) BotURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.botURL()
}

func New(cfg config.Config, client *mmwxclient.Client) *Service {
	s := &Service{cfg: cfg, client: client}
	s.webHandler = s.newWebAppHandler()
	return s
}

// isAdminTG is the single authorization source for TG administrative actions.
// The configured allowlist alone is not sufficient: IDs can be stale or can
// later register/bind to a normal account. Require the signed TG identity to be
// bound to an active master account whose current role is still admin.
func (s *Service) isAdminTG(ctx context.Context, tgID int64) bool {
	if tgID == 0 || !s.cfg.IsAdmin(tgID) {
		return false
	}
	info, err := s.client.UserByTG(ctx, tgID)
	return err == nil && info != nil && info.Bound && info.IsActive && info.IsPrimaryAdmin && info.Role == "admin"
}

func (s *Service) Start(parent context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := bot.New(s.cfg.TGBotToken, bot.WithDefaultHandler(s.defaultHandler))
	if err != nil {
		return err
	}
	registerCommands(b, s)

	ctx, cancel := context.WithCancel(parent)
	s.b = b
	s.cancel = cancel

	// 记录 bot 自己的 @username(用于兑换码文案的 {机器人地址})。失败不致命。
	if me, merr := b.GetMe(ctx); merr == nil && me != nil {
		s.botUsername = me.Username
	} else if merr != nil {
		log.Printf("[mmwX-tgbot] getMe failed (bot url placeholder will be empty): %v", merr)
	}

	s.setMyCommands(ctx, b)
	if err := s.setMenuButton(ctx, b); err != nil {
		cancel()
		s.b = nil
		s.cancel = nil
		return err
	}

	go func() {
		log.Printf("[mmwX-tgbot] long-poll started")
		b.Start(ctx)
		log.Printf("[mmwX-tgbot] long-poll stopped")
	}()
	go s.runDailyNotifier(ctx, b)
	go s.runAnnouncementBroadcaster(ctx, b)
	return nil
}

// setMenuButton 把主控内置的 Mini App 地址设为聊天菜单按钮。
func (s *Service) setMenuButton(ctx context.Context, b *bot.Bot) error {
	if s.cfg.WebAppURL == "" {
		return fmt.Errorf("Mini App 地址为空")
	}
	parsed, err := url.Parse(s.cfg.WebAppURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return fmt.Errorf("Mini App 地址必须是公网 HTTPS 地址，当前为 %q", s.cfg.WebAppURL)
	}
	ok, err := b.SetChatMenuButton(ctx, &bot.SetChatMenuButtonParams{
		MenuButton: &models.MenuButtonWebApp{
			Type:   models.MenuButtonTypeWebApp,
			Text:   "📊 我的面板",
			WebApp: models.WebAppInfo{URL: s.cfg.WebAppURL},
		},
	})
	if err != nil {
		return fmt.Errorf("Telegram 设置“我的面板”菜单失败: %w", err)
	}
	if !ok {
		return fmt.Errorf("Telegram 未接受“我的面板”菜单地址 %s", s.cfg.WebAppURL)
	}
	log.Printf("[mmwX-tgbot] chat menu updated: %s", s.cfg.WebAppURL)
	return nil
}

func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.b = nil
}

func (s *Service) ServeWebApp(w http.ResponseWriter, r *http.Request) {
	s.webHandler.ServeHTTP(w, r)
}
