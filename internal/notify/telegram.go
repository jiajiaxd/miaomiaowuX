package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const telegramAPIBase = "https://api.telegram.org/bot"

var httpClient = &http.Client{Timeout: 10 * time.Second}

func sendTelegram(ctx context.Context, botToken, chatID, text string, buttons []Button) error {
	if botToken == "" || chatID == "" {
		return fmt.Errorf("bot token or chat ID is empty")
	}

	endpoint := telegramAPIBase + botToken + "/sendMessage"
	params := url.Values{
		"chat_id":    {chatID},
		"text":       {text},
		"parse_mode": {"Markdown"},
	}
	if len(buttons) > 0 {
		rows := make([][]map[string]string, 0, len(buttons))
		for _, button := range buttons {
			if data := strings.TrimSpace(button.CallbackData); data != "" && len(data) <= 64 {
				rows = append(rows, []map[string]string{{"text": button.Text, "callback_data": data}})
				continue
			}
			u, err := url.Parse(strings.TrimSpace(button.URL))
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				continue
			}
			rows = append(rows, []map[string]string{{"text": button.Text, "url": u.String()}})
		}
		if len(rows) > 0 {
			markup, _ := json.Marshal(map[string]any{"inline_keyboard": rows})
			params.Set("reply_markup", string(markup))
		}
	}

	// 参数放进 POST body(而非 query string):否则 chat_id、通知正文(含用户名/IP)会进 URL,
	// 一旦请求失败,*url.Error 会把整条 URL 打进日志 → 泄漏 chat_id / 正文 / 用户 IP。
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		// *url.Error.Error() 会带完整请求 URL(URL path 里仍含 bot token)。脱敏后只保留操作名与
		// 底层原因(如 context canceled / connection refused),避免 token 落进日志。
		return fmt.Errorf("send telegram: %w", redactURLError(err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var result struct {
			OK          bool   `json:"ok"`
			Description string `json:"description"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&result)
		return fmt.Errorf("telegram API error (status %d): %s", resp.StatusCode, result.Description)
	}

	return nil
}

// redactURLError 把 *url.Error 里的敏感 URL 去掉。net/http 的传输错误是 *url.Error,
// 其 Error() 会拼上完整请求 URL(含 bot token,历史上还含 chat_id/正文/IP)。URL 对排障价值有限,
// 但会泄漏 token,故整体替换成固定主机名,只保留操作名(Post)与底层原因。非 *url.Error 原样返回。
func redactURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s https://api.telegram.org: %w", ue.Op, ue.Err)
	}
	return err
}

// markdownEscaper 转义 Telegram legacy Markdown 中会独立改变样式的字符。
// 普通成对方括号(如节点名 [GOMAMI])不是链接，不应转义：部分第三方客户端会把
// `\[` 的反斜杠原样显示。真正形如 [text](url) 的动态内容在函数中单独防护。
var markdownEscaper = strings.NewReplacer("_", "\\_", "*", "\\*", "`", "\\`")

// EscapeMarkdown 把用户名/服务器名等动态内容安全地嵌进带 *bold* / `code` 的消息模板。
// 未转义时,含下划线(或 * `)的用户名会让 TG 的 Markdown 解析失败 → 400 bad request。
func EscapeMarkdown(s string) string {
	if strings.Contains(s, "](") {
		s = strings.ReplaceAll(s, "[", "\\[")
	}
	return markdownEscaper.Replace(s)
}
