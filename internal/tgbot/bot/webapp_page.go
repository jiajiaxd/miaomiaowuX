package bot

import (
	"context"
	stdhtml "html"
	"net/http"
	"strings"
	"time"

	"miaomiaowux/internal/tgbot/mmwxclient"
)

// webAppPage 返回 Mini App 单页(自包含,引 Telegram WebApp SDK)。
// __DEVPREVIEW__ 注入:仅 webapp_dev_preview=true 时允许从 ?initData= 读取
// 真实 Telegram 签名串。无签名时不得回退为管理员。
// __THEME__ 注入:跟随主控「默认主题」,为特殊主题注入根 class(首屏即生效,无闪烁)。
func (s *Service) webAppPage(w http.ResponseWriter, r *http.Request) {
	// Do not let a CDN retain an old Mini App shell after authorization fixes.
	setWebAppPrivateHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	flag := "false"
	if s.cfg.WebAppDevPreview {
		flag = "true"
	}
	themeClass := ""
	switch s.cachedDefaultTheme(r.Context()) {
	case "anime":
		themeClass = "theme-anime"
	case "premium":
		themeClass = "theme-premium"
	}
	html := strings.ReplaceAll(webAppHTML, "__DEVPREVIEW__", flag)
	html = strings.ReplaceAll(html, "__THEME__", themeClass)
	branding := s.cachedBranding(r.Context())
	brandTitle := branding.BrandTitle
	brandHTML := `妙妙屋<span class="ax"><span class="ax-t">X</span><span class="ax-g" aria-hidden="true">X</span><span class="ax-p" aria-hidden="true"></span></span>`
	if brandTitle != "" {
		brandHTML = stdhtml.EscapeString(brandTitle)
	}
	html = strings.ReplaceAll(html, "__BRAND_TITLE__", brandHTML)
	logoURL := branding.LogoURL
	if logoURL == "" {
		logoURL = "/api/tg-webapp/logo-light"
	}
	html = strings.ReplaceAll(html, "__BRAND_LOGO__", stdhtml.EscapeString(logoURL))
	html = strings.ReplaceAll(html, "__CUSTOM_BRAND_LOGO__", stdhtml.EscapeString(branding.LogoURL))
	_, _ = w.Write([]byte(html))
}

func (s *Service) cachedBranding(ctx context.Context) mmwxclient.Branding {
	s.brandMu.Lock()
	if time.Now().Before(s.brandExp) {
		v := s.brandVal
		s.brandMu.Unlock()
		return v
	}
	s.brandMu.Unlock()

	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	v, err := s.client.GetBranding(cctx)
	if err != nil {
		s.brandMu.Lock()
		defer s.brandMu.Unlock()
		return s.brandVal
	}
	s.brandMu.Lock()
	s.brandVal = v
	s.brandExp = time.Now().Add(60 * time.Second)
	s.brandMu.Unlock()
	return v
}

// cachedDefaultTheme 取主控默认主题,带 60s 缓存 —— 避免每次开面板都打一次主控。
// 主控不可达时退化为上次缓存值(初始为空 = 默认外观),不阻塞页面渲染。
func (s *Service) cachedDefaultTheme(ctx context.Context) string {
	s.themeMu.Lock()
	if time.Now().Before(s.themeExp) {
		v := s.themeVal
		s.themeMu.Unlock()
		return v
	}
	s.themeMu.Unlock()

	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	v, err := s.client.GetDefaultTheme(cctx)
	if err != nil {
		s.themeMu.Lock()
		defer s.themeMu.Unlock()
		return s.themeVal
	}
	s.themeMu.Lock()
	s.themeVal = v
	s.themeExp = time.Now().Add(60 * time.Second)
	s.themeMu.Unlock()
	return v
}

// 主题取自 ../miaomiaowux/miaomiaowux-frontend/src/styles/theme.css:
// 品牌陶土橙 #d97757(暗色 #f18c6e),暖白底 / 深色 #10131c。logo 引主控 /images/。
const webAppHTML = `<!DOCTYPE html>
<html lang="zh" class="__THEME__">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>妙妙屋X · 我的面板</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<style>
:root{
 --brand:#d97757;--brand-soft:#fbe7da;--ok:#22c55e;--warn:#ef4444;--unknown:#a1a1aa;--radius:.625rem;
 --bg:#faf8f5;--text:#271610;--card:#ffffff;--muted:#816055;--border:rgba(137,110,96,.22);
}
html.dark{
 --brand:#f18c6e;--brand-soft:rgba(241,140,110,.16);
 --bg:#10131c;--text:#f9f4f1;--card:#1a1f2b;--muted:#cfb8af;--border:rgba(255,255,255,.08);
}
/* anime 主题(跟随主控「默认主题=anime」,由服务端注入 html.theme-anime):刻晴粉紫配色。
   覆盖 --brand 及派生色 + 动效 X 渐变。选择器特异性均高于基础规则,顺序也在其后,稳覆盖。 */
html.theme-anime{
 --brand:#8b5cf6;--brand-soft:#ede9fe;--radius:.75rem;
 --bg:#f3effb;--text:#241249;--card:#fcfbff;--muted:#7c6ba0;--border:rgba(139,92,246,.2);
}
html.dark.theme-anime{
 --brand:#a78bfa;--brand-soft:rgba(167,139,250,.18);
 --bg:#160f24;--text:#f2ecff;--card:#1e1633;--muted:#b9a8d8;--border:rgba(255,255,255,.09);
}
html.theme-anime .ax-t{background:linear-gradient(135deg,#8b5cf6 0%,#ec4899 20%,#a78bfa 40%,#8b5cf6 60%,#d946ef 80%,#8b5cf6 100%);background-size:300% 300%;-webkit-background-clip:text;background-clip:text;color:transparent}
html.theme-anime .ax-g{background:linear-gradient(135deg,#8b5cf6,#ec4899,#a78bfa,#8b5cf6);background-size:300% 300%;-webkit-background-clip:text;background-clip:text;color:transparent}
html.theme-anime .ax-p::before{color:#c084fc}
html.theme-anime .ax-p::after{color:#8b5cf6}
/* anime 紫白棋盘格背景(同款主控 body),header/nav/输入框仍是实色浮在格子上 */
html.theme-anime body{background-color:#faf8ff;background-image:repeating-conic-gradient(#f1ecfb 0 25%,#faf8ff 0 50%);background-size:88px 88px;background-attachment:fixed}
html.dark.theme-anime body{background-color:#120e22;background-image:repeating-conic-gradient(#171130 0 25%,#120e22 0 50%);background-size:88px 88px;background-attachment:fixed}
html.theme-premium{--brand:#d7a63d;--brand-soft:#292315;--bg:#080909;--text:#f4eedf;--card:#10110f;--muted:#a89f8b;--border:rgba(215,166,61,.32);color-scheme:dark}
html.theme-premium body{background-color:#080909;background-image:linear-gradient(rgba(215,166,61,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(215,166,61,.025) 1px,transparent 1px);background-size:32px 32px;background-attachment:fixed}
html.theme-premium .card{border-color:rgba(215,166,61,.32);border-radius:2px;background:#10110f;box-shadow:0 12px 32px -24px rgba(215,166,61,.65)}
html.theme-premium .ax-t,html.theme-premium .ax-g{background:linear-gradient(110deg,#8c5d17,#f2d78a 45%,#c78e24 70%,#fff1b9);-webkit-background-clip:text;background-clip:text;color:transparent}
/* anime 卡片:方角 + 蕾丝花纹内边框(照搬主控 .pixel-card::after)。
   ::after 用透明 border + border-image 画蕾丝;inset 4 + border 13 ≈ 17px,故内边距提到 18px 让内容避开花纹。 */
html.theme-anime .card{position:relative;border:none;border-radius:0;padding:18px 16px;box-shadow:0 4px 18px -6px rgba(139,92,246,.28)}
html.theme-anime .card::after{content:"";position:absolute;inset:4px;pointer-events:none;border:13px solid transparent;border-image:url(/api/tg-webapp/anime-lace.svg) 30 round}
*{box-sizing:border-box}html,body{margin:0}
body{font-family:'Inter',-apple-system,system-ui,"PingFang SC","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--text);padding-bottom:66px;}
header{position:sticky;top:0;z-index:10;background:var(--bg);border-bottom:1px solid var(--border);padding:10px 16px;display:flex;align-items:center;gap:10px;}
header .logo{height:26px;width:26px;display:block;flex:0 0 auto}
header .sub{font-size:11px;color:var(--muted);margin-left:auto}
.brand{font-size:18px;font-weight:700;display:inline-flex;align-items:baseline;line-height:1}
/* 特效 X(移植自 miaomiaowu-docs/src/components/animated-x.tsx) */
.ax{position:relative;display:inline-block;font-weight:800;margin-left:1px}
.ax-t{position:relative;z-index:10;background:linear-gradient(135deg,#f97316 0%,#ef4444 15%,#f59e0b 30%,#f97316 45%,#ec4899 60%,#f59e0b 75%,#f97316 90%,#ef4444 100%);background-size:300% 300%;-webkit-background-clip:text;background-clip:text;color:transparent;animation:axshift 3s ease-in-out infinite,axshimmer 2s ease-in-out infinite}
.ax-g{position:absolute;inset:0;z-index:0;opacity:.6;background:linear-gradient(135deg,#f97316,#ef4444,#f59e0b,#f97316);background-size:300% 300%;-webkit-background-clip:text;background-clip:text;color:transparent;animation:axshift 3s ease-in-out infinite,axglow 2s ease-in-out infinite}
.ax-p{position:absolute;inset:0;z-index:20;pointer-events:none}
.ax-p::before,.ax-p::after{content:'✦';position:absolute;font-size:.3em;animation:axspark 2.5s ease-in-out infinite}
.ax-p::before{top:-.2em;right:-.12em;color:#f59e0b;animation-delay:0s}
.ax-p::after{bottom:-.05em;left:-.12em;color:#f97316;animation-delay:1.2s}
@keyframes axshift{0%,100%{background-position:0% 50%}50%{background-position:100% 50%}}
@keyframes axshimmer{0%,100%{filter:brightness(1)}50%{filter:brightness(1.3)}}
@keyframes axglow{0%,100%{opacity:.3;filter:blur(8px)}50%{opacity:.7;filter:blur(12px)}}
@keyframes axspark{0%,100%{opacity:0;transform:scale(.5) rotate(0)}20%{opacity:1;transform:scale(1) rotate(90deg)}40%{opacity:0;transform:scale(.5) rotate(180deg)}}
main{padding:12px 14px}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px;margin-bottom:10px;}
.title{font-size:12px;color:var(--muted);margin:0 0 7px;letter-spacing:.3px;}
.row{display:flex;justify-content:space-between;align-items:center;margin:4px 0;font-size:15px;}
.big{font-size:22px;font-weight:700;line-height:1.1}
.bar{height:8px;border-radius:6px;background:var(--brand-soft);overflow:hidden;margin:8px 0 0;}
.bar>i{display:block;height:100%;background:var(--brand);}
.muted{color:var(--muted);font-size:13px}
.sub{display:flex;justify-content:space-between;align-items:center;gap:8px;margin:10px 0}
.sub .u{font-size:12px;color:var(--muted);word-break:break-all;flex:1}
.btn{background:var(--brand);color:#fff;border:0;border-radius:8px;padding:7px 13px;font-size:13px;white-space:nowrap}
.inp{width:100%;margin:6px 0;padding:11px 12px;font-size:15px;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--text);outline:none}
.inp:focus{border-color:var(--brand)}
.seg{display:flex;gap:6px;margin:6px 0}
.seg button{flex:1;padding:8px;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--text);font-size:13px}
.seg button.active{background:var(--brand);color:#fff;border-color:var(--brand)}
.badge{font-size:11px;background:var(--brand);color:#fff;border-radius:6px;padding:1px 6px;margin-left:6px}
.warn{color:var(--warn)}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px;vertical-align:middle}
.st{display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--border)}
.st:last-child{border-bottom:0}
.qm{display:inline-flex;width:9px;height:9px;margin-right:7px;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:var(--unknown)}
.stlabel{font-size:12px}
.xsw{position:relative;width:42px;height:24px;border:0;border-radius:999px;background:var(--unknown);padding:0;transition:background .2s;flex:0 0 auto}
.xsw::after{content:"";position:absolute;top:3px;left:3px;width:18px;height:18px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.25);transition:transform .2s}
.xsw.on{background:var(--ok)}
.xsw.on::after{transform:translateX(18px)}
.xsw:disabled{opacity:.45}
.xctl{display:flex;align-items:center;gap:9px}
#notice{text-align:center;color:var(--muted);padding:70px 24px;line-height:1.8}
.hide{display:none}
nav{position:fixed;left:0;right:0;bottom:0;display:flex;background:var(--card);border-top:1px solid var(--border);padding-bottom:env(safe-area-inset-bottom)}
nav button{flex:1;background:none;border:0;padding:8px 0 10px;color:var(--muted);display:flex;flex-direction:column;align-items:center;gap:3px;font-size:11px}
nav button.active{color:var(--brand)}
nav svg{width:22px;height:22px}
</style>
</head>
<body>
<header>
  <img id="logo" class="logo" src="__BRAND_LOGO__" data-custom="__CUSTOM_BRAND_LOGO__" alt="妙妙屋X">
  <span class="brand">__BRAND_TITLE__</span>
  <span class="sub">我的面板</span>
</header>
<div id="notice" class="hide">请在 Telegram 里通过机器人菜单按钮打开本页面。</div>
<main id="app" class="hide">
  <div id="view-home"></div>
  <div id="view-traffic" class="hide"></div>
  <div id="view-status" class="hide"></div>
  <div id="view-renewal" class="hide"></div>
  <div id="view-invites" class="hide"></div>
  <div id="view-users" class="hide"></div>
</main>
<nav id="nav" class="hide">
  <button data-v="home" class="active" onclick="__tab('home')">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 10l9-7 9 7v9a2 2 0 0 1-2 2h-4v-6H9v6H5a2 2 0 0 1-2-2z"/></svg>
    <span>主页</span>
  </button>
  <button data-v="traffic" onclick="__tab('traffic')">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19V5M4 19h16M8 19v-6M12 19V9M16 19v-9M20 19V7"/></svg>
    <span>流量</span>
  </button>
  <button data-v="status" onclick="__tab('status')">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3 8 4-16 3 8h4"/></svg>
    <span>状态</span>
  </button>
  <button id="nav-renewal" data-v="renewal" class="hide" onclick="__tab('renewal')">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 12a8 8 0 1 1-2.34-5.66"/><path d="M20 4v6h-6"/><path d="M12 8v4l3 2"/></svg>
    <span>续费</span>
  </button>
  <button id="nav-invites" data-v="invites" class="hide" onclick="__tab('invites')">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16v16H4z"/><path d="M4 9h16M9 4v5"/></svg>
    <span>兑换码</span>
  </button>
  <button id="nav-users" data-v="users" class="hide" onclick="__tab('users')">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>
    <span>用户</span>
  </button>
</nav>
<script>
var tg = window.Telegram && window.Telegram.WebApp;
function hb(n){n=Number(n)||0;if(n<1024)return n+" B";var u=["KB","MB","GB","TB"],i=-1;do{n/=1024;i++}while(n>=1024&&i<3);return n.toFixed(2)+" "+u[i];}
function esc(s){return String(s==null?"":s).replace(/[&<>]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;"}[c];});}
// toast:纯 DOM 提示,不依赖 Telegram showPopup(6.0 老客户端不支持会抛错)
function toast(msg){var t=document.getElementById("__toast");if(!t){t=document.createElement("div");t.id="__toast";t.style.cssText="position:fixed;left:50%;bottom:78px;transform:translateX(-50%);background:rgba(0,0,0,.82);color:#fff;padding:9px 16px;border-radius:10px;font-size:14px;z-index:999;opacity:0;transition:opacity .2s;pointer-events:none;max-width:80%;text-align:center";document.body.appendChild(t);}t.textContent=msg;t.style.opacity="1";clearTimeout(window.__tt);window.__tt=setTimeout(function(){t.style.opacity="0";},1600);}
// hap:震动反馈,带版本检查 + try/catch(6.1 以下不支持)
function hap(kind,style){try{if(tg&&tg.HapticFeedback&&tg.isVersionAtLeast&&tg.isVersionAtLeast("6.1")){if(kind==="notif")tg.HapticFeedback.notificationOccurred(style);else if(kind==="sel")tg.HapticFeedback.selectionChanged();else tg.HapticFeedback.impactOccurred(style||"light");}}catch(e){}}
// copyText:健壮复制(clipboard API + execCommand 兜底)
function copyText(u){try{if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(u);return;}}catch(e){}try{var ta=document.createElement("textarea");ta.value=u;ta.style.position="fixed";ta.style.opacity="0";document.body.appendChild(ta);ta.select();document.execCommand("copy");document.body.removeChild(ta);}catch(e){}}
function setScheme(){var dark=tg?(tg.colorScheme==="dark"):window.matchMedia&&window.matchMedia("(prefers-color-scheme:dark)").matches;
 document.documentElement.classList.toggle("dark",!!dark);
 var lg=document.getElementById("logo");if(lg&&!lg.getAttribute("data-custom"))lg.src=dark?"/api/tg-webapp/logo-dark":"/api/tg-webapp/logo-light";}
function copy(u){hap("impact","light");copyText(u);toast("已复制订阅链接");}
window.__copy=copy;
// 客户端选择(value=主控订阅 ?t= 参数,口径同妙妙屋X 前端)
var CLIENTS=[["auto","自动识别"],["clash","Clash / Mihomo"],["clashmeta","Clash.Meta"],["sing-box","sing-box"],["shadowrocket","Shadowrocket"],["surge","Surge"],["surgemac","Surge Mac"],["loon","Loon"],["stash","Stash"],["qx","QuantumultX"],["surfboard","Surfboard"],["v2ray","V2Ray"],["uri","通用 URI"]];
function subURL(i,base){var t=document.getElementById("cli-"+i).value;return base+(base.indexOf("?")>=0?"&":"?")+"t="+encodeURIComponent(t);}
function __subcopy(i,base){copy(subURL(i,base));}
window.__subcopy=__subcopy;
function __tab(v){hap("sel");
 ["home","traffic","status","renewal","invites","users"].forEach(function(x){document.getElementById("view-"+x).classList.toggle("hide",x!==v);});
 document.querySelectorAll("#nav button").forEach(function(b){b.classList.toggle("active",b.getAttribute("data-v")===v);});
 if(v==="invites"&&!window.__invLoaded){loadInvites();}
 if(v==="users"&&!window.__usersLoaded){loadUsers();}}
window.__tab=__tab;

function chart(hist){
 hist=(hist||[]).filter(function(d){return d&&d.date;});
 if(!hist.length)return '';
 var max=0;hist.forEach(function(d){if(d.used_gb>max)max=d.used_gb;});if(max<=0)max=1;
 var bw=Math.max(3,Math.floor((300-hist.length*2)/hist.length)),H=80,W=hist.length*(bw+2);
 var bars="";hist.forEach(function(d,i){var hh=Math.max(1,d.used_gb/max*H);bars+='<rect x="'+(i*(bw+2))+'" y="'+(H-hh)+'" width="'+bw+'" height="'+hh+'" rx="1" fill="var(--brand)"></rect>';});
 var total=hist.reduce(function(a,d){return a+(d.used_gb||0);},0);
 var h='<div class="card"><div class="title">每日流量(本周期)</div>';
 h+='<svg viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none" style="width:100%;height:80px">'+bars+'</svg>';
 h+='<div class="row"><span class="muted">'+esc(hist[0].date.slice(5))+' ~ '+esc(hist[hist.length-1].date.slice(5))+'</span><span class="muted">峰值 '+max.toFixed(2)+' GB · 累计 '+total.toFixed(2)+' GB</span></div></div>';
 return h;
}
function renderRegister(){
 var h='<div class="card"><div class="title">注册并绑定账号</div>';
 h+='<div class="muted" style="margin-bottom:10px">输入兑换码、设置用户名和密码,注册成功后自动绑定当前 Telegram。</div>';
 h+='<input id="r-code" class="inp" placeholder="兑换码" autocapitalize="characters">';
 h+='<input id="r-user" class="inp" placeholder="用户名(3-20 位,字母数字 _ -)">';
 h+='<input id="r-pwd" class="inp" type="password" placeholder="密码(6-64 位)">';
 h+='<div id="r-msg" class="warn" style="font-size:13px;min-height:18px;margin:4px 0"></div>';
 h+='<button class="btn" style="width:100%;padding:11px" onclick="__register(this)">注册并绑定</button>';
 h+='</div>';
 return h;
}
function renderRedeem(){
 var h='<div class="card"><div class="title">兑换码续期</div>';
 h+='<div style="display:flex;gap:8px"><input id="rd-code" class="inp" style="margin:0;flex:1" placeholder="输入兑换码" autocapitalize="characters">';
 h+='<button class="btn" onclick="__redeem(this)">兑换</button></div>';
 h+='<div id="rd-msg" style="font-size:13px;min-height:18px;margin:6px 0 0"></div>';
 h+='</div>';
 return h;
}
function renderRenewal(d){
 var r=d.renewal_request||{},pending=r.status==="pending"||r.status==="processing";
 var h='<div class="card"><div class="title">申请续费</div>';
 if(pending){h+='<div class="muted">续费申请审核中 · '+esc(r.package_name||"")+'</div></div>';return h;}
 if(r.status==="approved")h+='<div style="color:var(--ok);font-size:13px;margin-bottom:7px">上次申请已通过'+(r.new_end_date?' · 到期 '+esc(String(r.new_end_date).slice(0,10)):'')+'</div>';
 else if(r.status==="rejected")h+='<div class="warn" style="font-size:13px;margin-bottom:7px">上次申请未通过</div>';
 h+='<div style="display:flex;gap:8px"><input id="rn-pass" class="inp" style="margin:0;flex:1" maxlength="256" placeholder="输入续费口令">';
 h+='<button class="btn" onclick="__renew(this)">提交</button></div><div id="rn-msg" style="font-size:13px;min-height:18px;margin:6px 0 0"></div></div>';return h;
}
function __renew(btn){var el=document.getElementById("rn-pass"),pass=(el&&el.value||"").trim(),msg=document.getElementById("rn-msg");
 if(!pass){msg.className="warn";msg.textContent="请输入续费口令";return;}btn.disabled=true;btn.textContent="提交中...";
 fetch("/api/tg-webapp/renewal-request",{method:"POST",headers:{"Content-Type":"application/json","X-Telegram-Init-Data":window.__init},body:JSON.stringify({passphrase:pass})})
 .then(function(x){return x.json().then(function(j){return{ok:x.ok,j:j};});}).then(function(res){if(!res.ok)throw new Error(res.j.error||"提交失败");hap("notif","success");toast("已发送给管理员审核");load();})
 .catch(function(err){btn.disabled=false;btn.textContent="提交";msg.className="warn";msg.textContent=err.message||"提交失败";});}
window.__renew=__renew;

function renewalStatus(s){
 return {pending:["等待管理员确认","var(--brand)"],processing:["正在处理","var(--brand)"],approved:["续费成功","var(--ok)"],rejected:["申请未通过","var(--warn)"],failed:["处理失败","var(--warn)"]}[s]||[s||"未知","var(--unknown)"];
}
function shortDate(v){if(!v)return "--";var d=new Date(v);return isNaN(d.getTime())?String(v).slice(0,10):d.toLocaleString();}
function renderRenewalPage(d){
 var list=d.renewal_requests||[],h='<div class="card"><div class="title">套餐续费</div><div class="muted">使用续费口令申请管理员审核，或使用兑换码立即续期。</div></div>';
 h+=renderRenewal(d);h+=renderRedeem();
 h+='<div class="card"><div class="title">续费记录</div>';
 if(!list.length){h+='<div class="muted">暂无续费申请记录。</div></div>';return h;}
 list.forEach(function(r,i){var st=renewalStatus(r.status);if(i>0)h+='<div style="border-top:1px solid var(--border);margin:12px 0"></div>';
  h+='<div class="row" style="margin:0"><span style="font-weight:600">'+esc(r.package_name||"套餐续费")+'</span><span style="color:'+st[1]+'">'+st[0]+'</span></div>';
  h+='<div class="row" style="margin:6px 0 0"><span class="muted">申请时间</span><span class="muted">'+esc(shortDate(r.created_at))+'</span></div>';
  h+='<div class="row" style="margin:4px 0 0"><span class="muted">续费周期</span><span class="muted">'+esc(r.renew_days||0)+' 天</span></div>';
  if(r.previous_end_date)h+='<div class="row" style="margin:4px 0 0"><span class="muted">原到期时间</span><span class="muted">'+esc(String(r.previous_end_date).slice(0,10))+'</span></div>';
  if(r.new_end_date)h+='<div class="row" style="margin:4px 0 0"><span class="muted">新到期时间</span><span style="color:var(--ok)">'+esc(String(r.new_end_date).slice(0,10))+'</span></div>';
  if(r.error_message)h+='<div class="warn" style="font-size:12px;margin-top:6px">'+esc(r.error_message)+'</div>';
 });h+='</div>';return h;
}
function __redeem(btn){
 var code=(document.getElementById("rd-code").value||"").trim();
 var msg=document.getElementById("rd-msg");msg.className="";msg.style.color="var(--muted)";
 if(!code){msg.style.color="var(--warn)";msg.textContent="请输入兑换码";return;}
 btn.disabled=true;btn.textContent="兑换中...";
 fetch("/api/tg-webapp/redeem",{method:"POST",headers:{"Content-Type":"application/json","X-Telegram-Init-Data":window.__init},body:JSON.stringify({code:code})})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j};});})
  .then(function(res){btn.disabled=false;btn.textContent="兑换";
   if(!res.ok){msg.style.color="var(--warn)";msg.textContent=res.j.error||"兑换失败";return;}
   hap("notif","success");
   msg.style.color="var(--ok)";msg.textContent="续期成功,到期 "+(res.j.end_date||"");
   load();})
  .catch(function(){btn.disabled=false;btn.textContent="兑换";msg.style.color="var(--warn)";msg.textContent="网络错误";});
}
window.__redeem=__redeem;
function __register(btn){
 var code=(document.getElementById("r-code").value||"").trim();
 var user=(document.getElementById("r-user").value||"").trim();
 var pwd=(document.getElementById("r-pwd").value||"");
 var msg=document.getElementById("r-msg");
 if(!code||!user||!pwd){msg.textContent="请填写邀请码、用户名和密码";return;}
 if(!/^[a-zA-Z0-9_-]{3,20}$/.test(user)){msg.textContent="用户名格式不对(3-20 位 字母数字 _ -)";return;}
 if(pwd.length<6){msg.textContent="密码至少 6 位";return;}
 msg.textContent="";btn.disabled=true;btn.textContent="提交中...";
 fetch("/api/tg-webapp/register",{method:"POST",headers:{"Content-Type":"application/json","X-Telegram-Init-Data":window.__init},
  body:JSON.stringify({code:code,username:user,password:pwd})})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j};});})
  .then(function(res){
   if(!res.ok){msg.textContent=res.j.error||"注册失败";btn.disabled=false;btn.textContent="注册并绑定";return;}
   hap("notif","success");
   load();
  })
  .catch(function(){msg.textContent="网络错误,请重试";btn.disabled=false;btn.textContent="注册并绑定";});
}
window.__register=__register;
function renderAnnouncements(list){
 if(!list||!list.length)return "";
 var h="";
 list.forEach(function(an){
  // 被墙类用告警红,其它用品牌色左边框;标题可空
  var warn=(an.type==="node_blocked");
  h+='<div class="card" style="border-left:3px solid '+(warn?"var(--warn)":"var(--brand)")+'">';
  h+='<div class="title" style="color:'+(warn?"var(--warn)":"var(--brand)")+'">📢 '+(an.title?esc(an.title):"公告")+'</div>';
  h+='<div style="white-space:pre-wrap;line-height:1.6">'+esc(an.body||"")+'</div>';
  h+='</div>';
 });
 return h;
}
function renderHome(d){
 if(d.bound===false)return renderAnnouncements(d.announcements)+renderRegister();
 var h=renderAnnouncements(d.announcements),a=d.account||{};
 h+='<div class="card"><div class="row" style="margin:0"><span style="font-size:17px;font-weight:600">'+esc(a.username)+'</span><span class="muted">'+(a.role==="admin"?"管理员":"用户")+(a.is_active?"":" · 已停用")+'</span></div>';
 if(a.email)h+='<div class="muted" style="margin-top:3px">'+esc(a.email)+'</div>';
 h+='</div>';
 var t=d.traffic;
 if(t){
  var used=Number(t.cycle_used)||0,limit=(Number(t.limit_gb)||0)*1073741824,pct=limit>0?Math.min(100,used/limit*100):0;
  var dl=t.days_left!=null?Number(t.days_left):null;
  h+='<div class="card"><div class="title">流量 · '+esc(t.package_name||"未绑定套餐")+'</div>';
  h+='<div class="row" style="margin:0"><span class="big">'+hb(used)+'</span><span class="muted">'+(limit>0?"/ "+(t.limit_gb)+" GB":"")+'</span></div>';
  if(limit>0){
   h+='<div class="bar"><i style="width:'+pct.toFixed(1)+'%"></i></div>';
   h+='<div class="row" style="margin:6px 0 0"><span class="muted">已用 '+pct.toFixed(1)+'%</span>'+(dl!=null?'<span class="'+(dl<=7?"warn":"muted")+'">剩 '+dl+' 天</span>':'<span></span>')+'</div>';
  }
  h+='<div class="row" style="margin:4px 0 0"><span class="muted">累计</span><span class="muted">↑'+hb(t.total_up)+' ↓'+hb(t.total_down)+'</span></div>';
  h+='</div>';
 }
 var subs=d.subscriptions||[];
 h+='<div class="card"><div class="title">订阅链接</div>';
 if(!subs.length)h+='<div class="muted">暂无订阅,请联系管理员。</div>';
 subs.forEach(function(sf,i){
  if(i>0)h+='<div style="border-top:1px solid var(--border);margin:10px 0"></div>';
  h+='<div><span>'+esc(sf.name)+'</span>'+(sf["default"]?'<span class="badge">默认</span>':'')+'</div>';
  h+='<div style="display:flex;gap:6px;align-items:center;margin-top:8px">';
  h+='<select id="cli-'+i+'" class="inp" style="margin:0;flex:1;padding:9px">';
  CLIENTS.forEach(function(c){h+='<option value="'+c[0]+'">'+c[1]+'</option>';});
  h+='</select>';
  h+='<button class="btn" onclick="__subcopy('+i+',\''+esc(sf.url)+'\')">复制订阅</button>';
  h+='</div>';
 });
 h+='</div>';
 h+=chart(d.history);
 return h;
}
function renderTraffic(d){
 var nodes=d.nodes||[];
	if(d.is_admin)nodes=nodes.filter(function(n){return (n.used||0)>0;});
 nodes=nodes.slice().sort(function(x,y){return (y.used||0)-(x.used||0);});
 var total=nodes.reduce(function(a,n){return a+(n.used||0);},0);
 var title=d.traffic_period==="month"?"本月各节点流量":"各节点已用流量";
 var h='<div class="card"><div class="title">'+title+' · 合计 '+hb(total)+'</div>';
 if(!nodes.length)h+='<div class="muted">本周期暂无各节点流量数据。</div>';
 var max=0;nodes.forEach(function(n){if((n.used||0)>max)max=n.used;});if(max<=0)max=1;
 nodes.forEach(function(n){var pct=Math.max(2,(n.used||0)/max*100);
  h+='<div style="margin:11px 0"><div class="row" style="margin:0 0 5px"><span>'+esc(n.name)+'</span><span class="muted">'+hb(n.used)+'</span></div>';
  h+='<div class="bar" style="margin:0"><i style="width:'+pct+'%"></i></div></div>';});
 h+='</div>';
 return h;
}
function renderStatus(d){
 var ns=d.node_status||[];
 var on=ns.filter(function(n){return n.status==="online";}).length;
 var kind=d.status_kind==="server"?"服务器":"节点";
 var adminServers=d.is_admin&&d.status_kind==="server";
 var h='<div class="card"><div class="title">'+kind+'状态 · 在线 '+on+'/'+ns.length+'</div>';
 if(!ns.length)h+='<div class="muted">暂无'+kind+'。</div>';
 ns.forEach(function(n){var ic,lb,col;
  if(n.status==="online"){ic='<span class="dot" style="background:var(--ok)"></span>';lb="在线";col="var(--ok)";}
  else if(n.status==="unknown"){ic='<span class="qm">?</span>';lb="外部";col="var(--unknown)";}
  else{ic='<span class="dot" style="background:var(--warn)"></span>';lb="离线";col="var(--warn)";}
  h+='<div class="st"><span>'+ic+esc(n.name)+' <span class="muted">'+esc(n.protocol||"")+'</span></span>';
  if(adminServers){
   h+='<span class="xctl"><span class="stlabel" style="color:'+col+'">'+lb+'</span>';
   h+='<button class="xsw '+(n.xray_running?"on":"")+'" role="switch" aria-checked="'+(n.xray_running?"true":"false")+'" aria-label="'+esc(n.name)+' Xray '+(n.xray_running?"停止":"启动")+'" '+(n.status!=="online"?"disabled":"")+' onclick="__xrayToggle('+Number(n.id)+','+(n.xray_running?"true":"false")+',this)"></button></span>';
  }else h+='<span class="stlabel" style="color:'+col+'">'+lb+'</span>';
  h+='</div>';});
 h+='</div>';
 return h;
}
function __xrayToggle(id,running,btn){
 var action=running?"stop":"start",verb=running?"停止":"启动";
 if(!id||btn.disabled||!window.confirm("确定要"+verb+"这台服务器的 Xray 吗？"))return;
 btn.disabled=true;btn.style.opacity=".45";hap("impact","medium");
 fetch("/api/tg-webapp/admin/xray-control",{method:"POST",headers:{"Content-Type":"application/json","X-Telegram-Init-Data":window.__init},body:JSON.stringify({server_id:id,action:action})})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j};});})
  .then(function(res){
   if(!res.ok){throw new Error(res.j.error||verb+"失败");}
   hap("notif","success");
   btn.classList.toggle("on",!running);btn.setAttribute("aria-checked",!running?"true":"false");
   setTimeout(load,1500);
  })
  .catch(function(err){btn.disabled=false;btn.style.opacity="";hap("notif","error");window.alert(err.message||verb+"失败");});
}
window.__xrayToggle=__xrayToggle;
function render(d){
 document.getElementById("app").classList.remove("hide");
 // 第三方客户端可能复用同一 WebView；每次根据服务端响应重置角色菜单，
 // 避免上一个管理员会话的 DOM 状态残留给普通用户。
 document.getElementById("nav-invites").classList.add("hide");
 document.getElementById("nav-users").classList.add("hide");
 document.getElementById("nav-renewal").classList.add("hide");
 document.getElementById("view-home").innerHTML=renderHome(d);
 document.getElementById("view-traffic").innerHTML=renderTraffic(d);
 document.getElementById("view-status").innerHTML=renderStatus(d);
 document.getElementById("view-renewal").innerHTML=renderRenewalPage(d);
 if(d.bound!==false)document.getElementById("nav").classList.remove("hide");
 if(d.is_admin){document.getElementById("nav-invites").classList.remove("hide");document.getElementById("nav-users").classList.remove("hide");}
 else if(d.bound!==false){document.getElementById("nav-renewal").classList.remove("hide");}
}

// ===== 管理员:邀请码 =====
function invStatus(ic){if(ic.revoked)return["✗ 已撤销","var(--warn)"];if(!ic.usable)return["○ 已用尽/过期","var(--unknown)"];return["✓ 可用","var(--ok)"];}
function renderInvites(){
 var inv=window.__inv||{},pkgs=inv.packages||[],list=inv.invites||[];
 var h='<div class="card"><div class="title">发布公告</div>';
 h+='<input id="an-title" class="inp" placeholder="标题(可空,默认「公告」)">';
 h+='<textarea id="an-body" class="inp" rows="3" placeholder="公告内容 — 广播给所有绑定用户 + 显示在 Mini App"></textarea>';
 h+='<div id="an-msg" class="warn" style="font-size:13px;min-height:18px;margin:4px 0"></div>';
 h+='<button class="btn" style="width:100%;padding:11px" onclick="__postAnnounce(this)">发布公告</button>';
 h+='</div>';
 h+='<div class="card"><div class="title">当前生效公告</div><div id="announce-list"><div class="muted">加载中…</div></div></div>';
 h+='<div class="card"><div class="title">生成兑换码</div>';
 h+='<div class="muted" style="margin-bottom:4px">套餐</div>';
 h+='<select id="i-pkg" class="inp" style="margin-top:0">';
 h+='<option value="0">不绑套餐</option>';
 pkgs.forEach(function(p){h+='<option value="'+p.id+'">'+esc(p.name)+'('+(p.traffic_limit_gb)+'GB/'+(p.cycle_days)+'天)</option>';});
 h+='</select>';
 h+='<div class="muted" style="margin:10px 0 4px">有效期</div><div class="seg" id="i-dur">';
 [1,3,6,12].forEach(function(m,i){h+='<button class="'+(i==0?"active":"")+'" onclick="__durpick(this,'+m+')">'+(m==12?"1年":m+"月")+'</button>';});
 h+='</div>';
 h+='<div class="muted" style="margin:10px 0 4px">使用次数(>1 可多用户共用一个码)</div>';
 h+='<input id="i-max" class="inp" type="number" min="1" value="1" placeholder="使用次数">';
 h+='<div id="i-msg" class="warn" style="font-size:13px;min-height:18px;margin:4px 0"></div>';
 h+='<button class="btn" style="width:100%;padding:11px" onclick="__createInv(this)">生成兑换码</button>';
 h+='</div>';
 // list
 h+='<div class="card"><div class="title">兑换码('+list.length+')</div>';
 if(!list.length)h+='<div class="muted">暂无兑换码。</div>';
 list.forEach(function(ic){var st=invStatus(ic);
  h+='<div class="st"><div style="flex:1"><div style="font-family:monospace">'+esc(ic.code)+'</div>';
  h+='<div class="muted" style="font-size:12px">'+esc(st[0])+' · '+ic.used_count+'/'+ic.max_uses+'</div></div>';
  h+='<button class="btn" onclick="__copyInv(\''+esc(ic.code)+'\')">复制文案</button>';
  if(!ic.revoked)h+='<button class="btn" style="background:var(--warn)" onclick="__revokeInv(\''+esc(ic.code)+'\',this)">撤销</button>';
  else h+='<button class="btn" style="background:var(--unknown)" onclick="__deleteInv(\''+esc(ic.code)+'\',this)">删除</button>';
  h+='</div>';});
 h+='</div>';
 document.getElementById("view-invites").innerHTML=h;
 window.__dur=1;
 loadAnnouncements();
}
// 加载当前生效公告 → 渲染到 #announce-list(带删除按钮)
function loadAnnouncements(){
 var box=document.getElementById("announce-list"); if(!box)return;
 fetch("/api/tg-webapp/admin/announcements",{method:"POST",headers:{"Content-Type":"application/json","X-Telegram-Init-Data":window.__init},body:"{}"})
  .then(function(r){return r.json();})
  .then(function(j){
   var arr=(j&&j.announcements)||[];
   if(!arr.length){box.innerHTML='<div class="muted">暂无生效公告。</div>';return;}
   var h="";
   arr.forEach(function(a){
    h+='<div class="st"><div style="flex:1;min-width:0">';
    h+='<div style="font-weight:600">'+esc(a.title||"公告")+' <span class="muted" style="font-size:11px">'+esc(a.type||"")+'</span></div>';
    h+='<div class="muted" style="font-size:12px;white-space:pre-wrap;word-break:break-all">'+esc(a.body||"")+'</div></div>';
    h+='<button class="btn" style="background:var(--warn)" onclick="__delAnnounce('+a.id+',this)">删除</button></div>';
   });
   box.innerHTML=h;
  })
  .catch(function(){box.innerHTML='<div class="muted">加载失败。</div>';});
}
function __delAnnounce(id,btn){
 btn.disabled=true;btn.textContent="…";
 fetch("/api/tg-webapp/admin/announce-delete",{method:"POST",headers:{"Content-Type":"application/json","X-Telegram-Init-Data":window.__init},body:JSON.stringify({id:id})})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j};});})
  .then(function(res){if(!res.ok){btn.disabled=false;btn.textContent="删除";toast(res.j.error||"删除失败");return;}hap("notif","success");loadAnnouncements();})
  .catch(function(){btn.disabled=false;btn.textContent="删除";toast("网络错误");});
}
window.__delAnnounce=__delAnnounce;
function __durpick(btn,m){window.__dur=m;document.querySelectorAll("#i-dur button").forEach(function(b){b.classList.remove("active");});btn.classList.add("active");}
window.__durpick=__durpick;
// __copyInv:复制主控配置的注册文案(替换 {兑换码}/{主控域名}/{机器人地址});模板为空则只复制码。
// 用 split/join 兼容老 webview(无 replaceAll)。
function __copyInv(code){
 var inv=window.__inv||{},tpl=(inv.redeem_template||"").trim();
 var text=tpl?tpl.split("{兑换码}").join(code).split("{主控域名}").join(inv.master_url||"").split("{机器人地址}").join(inv.bot_url||""):code;
 hap("impact","light");copyText(text);toast(tpl?"文案已复制":"兑换码已复制");
}
window.__copyInv=__copyInv;
function __postAnnounce(btn){
 var msg=document.getElementById("an-msg");msg.textContent="";
 var title=document.getElementById("an-title").value.trim();
 var body=document.getElementById("an-body").value.trim();
 if(!body){msg.textContent="请输入公告内容";return;}
 btn.disabled=true;btn.textContent="发布中...";
 fetch("/api/tg-webapp/admin/announce",{method:"POST",headers:{"Content-Type":"application/json","X-Telegram-Init-Data":window.__init},body:JSON.stringify({title:title,body:body})})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j};});})
  .then(function(res){btn.disabled=false;btn.textContent="发布公告";
   if(!res.ok){msg.textContent=res.j.error||"发布失败";return;}
   hap("notif","success");document.getElementById("an-title").value="";document.getElementById("an-body").value="";toast("公告已发布");loadAnnouncements();})
  .catch(function(){btn.disabled=false;btn.textContent="发布公告";msg.textContent="网络错误";});
}
window.__postAnnounce=__postAnnounce;
function loadInvites(){
 document.getElementById("view-invites").innerHTML='<div class="card"><div class="muted">加载中...</div></div>';
 fetch("/api/tg-webapp/admin/invites",{method:"POST",headers:{"Content-Type":"application/json","X-Telegram-Init-Data":window.__init},body:"{}"})
  .then(function(r){if(!r.ok)throw new Error(r.status);return r.json();})
  .then(function(j){window.__inv=j;window.__invLoaded=true;renderInvites();})
  .catch(function(){document.getElementById("view-invites").innerHTML='<div class="card">加载失败。</div>';});
}
function __createInv(btn){
 var msg=document.getElementById("i-msg");msg.textContent="";
 var pkg=parseInt(document.getElementById("i-pkg").value,10)||0;
 var mu=parseInt(document.getElementById("i-max").value,10)||1;if(mu<1)mu=1;
 var body={package_id:pkg?pkg:null,duration_months:window.__dur||1,max_uses:mu};
 btn.disabled=true;btn.textContent="生成中...";
 fetch("/api/tg-webapp/admin/invite-create",{method:"POST",headers:{"Content-Type":"application/json","X-Telegram-Init-Data":window.__init},body:JSON.stringify(body)})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j};});})
  .then(function(res){btn.disabled=false;btn.textContent="生成兑换码";
   if(!res.ok){msg.textContent=res.j.error||"生成失败";return;}
   hap("notif","success");
   toast("已生成兑换码:"+res.j.code);
   loadInvites();})
  .catch(function(){btn.disabled=false;btn.textContent="生成兑换码";msg.textContent="网络错误";});
}
window.__createInv=__createInv;
function __revokeInv(code,btn){
 btn.disabled=true;btn.textContent="...";
 fetch("/api/tg-webapp/admin/invite-revoke",{method:"POST",headers:{"Content-Type":"application/json","X-Telegram-Init-Data":window.__init},body:JSON.stringify({code:code})})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j};});})
  .then(function(res){if(res.ok){hap("impact","medium");loadInvites();}else{btn.disabled=false;btn.textContent="撤销";toast(res.j.error||"撤销失败");}})
  .catch(function(){btn.disabled=false;btn.textContent="撤销";});
}
window.__revokeInv=__revokeInv;
function __deleteInv(code,btn){
 btn.disabled=true;btn.textContent="...";
 fetch("/api/tg-webapp/admin/invite-delete",{method:"POST",headers:{"Content-Type":"application/json","X-Telegram-Init-Data":window.__init},body:JSON.stringify({code:code})})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j};});})
  .then(function(res){if(res.ok){hap("impact","medium");toast("已删除");loadInvites();}else{btn.disabled=false;btn.textContent="删除";toast(res.j.error||"删除失败");}})
  .catch(function(){btn.disabled=false;btn.textContent="删除";});
}
window.__deleteInv=__deleteInv;
// ===== 管理员:用户管理(搜索 / 续期 / 改套餐)=====
function uDays(end){if(!end)return null;return Math.ceil((new Date(end+"T23:59:59").getTime()-Date.now())/86400000);}
function uBadge(end,hasPkg){if(!hasPkg)return '<span class="muted">未绑套餐</span>';var d=uDays(end);if(d===null)return '<span class="muted">无到期</span>';var col=d<0?"var(--unknown)":(d<7?"var(--warn)":"var(--ok)");return '<span style="color:'+col+'">'+(d<0?"已过期":("剩 "+d+" 天"))+'</span>';}
function renderUsers(){
 var h='<div class="card"><div class="title">用户管理</div>';
 h+='<input id="u-q" class="inp" style="margin-top:0" oninput="__filterUsers()" placeholder="搜索用户名 / 昵称 / 套餐">';
 h+='<div id="u-list" style="margin-top:8px"></div></div>';
 document.getElementById("view-users").innerHTML=h;
 renderUserList();
}
function renderUserList(){
 var data=window.__users||{},all=data.users||[],pkgs=data.packages||[];
 var qEl=document.getElementById("u-q"),q=(qEl?qEl.value:"").trim().toLowerCase();
 var list=all.filter(function(u){return u.role!=="admin";}).filter(function(u){
  if(!q)return true;
  return (u.username||"").toLowerCase().indexOf(q)>=0||(u.nickname||"").toLowerCase().indexOf(q)>=0||(u.package_name||"").toLowerCase().indexOf(q)>=0;});
 var h='';
 if(!list.length){document.getElementById("u-list").innerHTML='<div class="muted" style="padding:6px 0">无匹配用户。</div>';return;}
 list.forEach(function(u,i){var hasPkg=!!u.package_id;
  h+='<div class="st" style="flex-direction:column;align-items:stretch;gap:6px">';
  h+='<div style="display:flex;justify-content:space-between;gap:8px"><div style="min-width:0"><div style="font-weight:600">'+esc(u.username)+(u.nickname?' <span class="muted" style="font-weight:400">'+esc(u.nickname)+'</span>':'')+'</div><div class="muted" style="font-size:12px">'+esc(u.package_name||"未绑套餐")+(hasPkg?' · '+hb(u.traffic_used||0)+(u.traffic_limit?' / '+hb(u.traffic_limit):''):'')+'</div></div>';
  h+='<div style="text-align:right;font-size:12px;white-space:nowrap">'+uBadge(u.package_end_date,hasPkg)+(u.package_end_date?'<div class="muted">'+esc(u.package_end_date)+'</div>':'')+'</div></div>';
  if(hasPkg){h+='<div class="seg" style="margin-top:2px">';[30,60,90].forEach(function(dd){h+='<button onclick="__extendUser(\''+esc(u.username)+'\','+dd+',this)">+'+dd+'天</button>';});h+='</div>';}
  h+='<div style="display:flex;gap:6px"><select id="pk-'+i+'" class="inp" style="margin-top:0;flex:1">';
  pkgs.forEach(function(p){var sel=(u.package_id&&u.package_id==p.id)?" selected":"";h+='<option value="'+p.id+'"'+sel+'>'+esc(p.name)+'</option>';});
  h+='</select><button class="btn" onclick="__assignPkg(\''+esc(u.username)+'\','+i+',this)">'+(hasPkg?"改套餐":"绑定")+'</button></div>';
  h+='</div>';});
 document.getElementById("u-list").innerHTML=h;
}
function __filterUsers(){renderUserList();}
window.__filterUsers=__filterUsers;
function loadUsers(){
 document.getElementById("view-users").innerHTML='<div class="card"><div class="muted">加载中...</div></div>';
 fetch("/api/tg-webapp/admin/users",{method:"POST",headers:{"Content-Type":"application/json","X-Telegram-Init-Data":window.__init},body:"{}"})
  .then(function(r){if(!r.ok)throw new Error(r.status);return r.json();})
  .then(function(j){window.__users=j;window.__usersLoaded=true;renderUsers();})
  .catch(function(){document.getElementById("view-users").innerHTML='<div class="card">加载失败。</div>';});
}
function __extendUser(username,days,btn){
 btn.disabled=true;var old=btn.textContent;btn.textContent="...";
 fetch("/api/tg-webapp/admin/user-extend",{method:"POST",headers:{"Content-Type":"application/json","X-Telegram-Init-Data":window.__init},body:JSON.stringify({username:username,days:days})})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j};});})
  .then(function(res){btn.disabled=false;btn.textContent=old;
   if(!res.ok){toast(res.j.error||"续期失败");return;}
   hap("notif","success");toast("已为 "+username+" 续期 "+days+" 天");loadUsers();})
  .catch(function(){btn.disabled=false;btn.textContent=old;toast("网络错误");});
}
window.__extendUser=__extendUser;
function __assignPkg(username,i,btn){
 var sel=document.getElementById("pk-"+i);var pid=parseInt(sel?sel.value:"0",10)||0;
 if(pid<=0){toast("请选择套餐");return;}
 btn.disabled=true;var old=btn.textContent;btn.textContent="...";
 fetch("/api/tg-webapp/admin/user-assign",{method:"POST",headers:{"Content-Type":"application/json","X-Telegram-Init-Data":window.__init},body:JSON.stringify({username:username,package_id:pid})})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j};});})
  .then(function(res){btn.disabled=false;btn.textContent=old;
   if(!res.ok){toast(res.j.error||"修改失败");return;}
   hap("notif","success");toast("已修改 "+username+" 的套餐");loadUsers();})
  .catch(function(){btn.disabled=false;btn.textContent=old;toast("网络错误");});
}
window.__assignPkg=__assignPkg;
function load(){
 // The nonce and cache:no-store prevent a CDN rule that ignores the custom
 // Telegram header from reusing another visitor's identity response.
 fetch("/api/tg-webapp/me",{method:"POST",cache:"no-store",headers:{"Cache-Control":"no-cache","Content-Type":"application/json","X-Telegram-Init-Data":window.__init},body:"{}"})
  .then(function(r){if(!r.ok)throw new Error(r.status);return r.json();})
  .then(render)
  .catch(function(){document.getElementById("app").classList.remove("hide");document.getElementById("view-home").innerHTML='<div class="card">加载失败,请稍后重试。</div>';});
}
(function(){
 setScheme();
 if(tg&&tg.onEvent)tg.onEvent("themeChanged",setScheme);
 var initData=(tg&&tg.initData)?tg.initData:"";
 // 本地浏览器预览也必须显式传入 Telegram 签名的 ?initData=;
 // 不再使用可伪造的管理员哨兵值。
 if(!initData&&__DEVPREVIEW__){initData=new URLSearchParams(location.search).get("initData")||"";}
 if(!initData){document.getElementById("notice").classList.remove("hide");return;}
 window.__init=initData;
 if(tg){tg.ready();tg.expand();}
 load();
})();
</script>
</body>
</html>`
