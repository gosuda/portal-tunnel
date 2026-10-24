package gateway

import (
	"html"
	"io"
	"net/http"
	"strings"
)

// The sign-in pages share one shell, so every method looks like Portal and a new
// method adds a body and a script instead of new CSS. Everything is inline except
// the web fonts, which load from the CDN the relay frontend already uses; the
// content security policy admits that one font host and nothing else.
const signinContentSecurityPolicy = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
	"font-src https://fonts.bunny.net; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// signinShell holds the placeholders @@HOST@@ and @@FULLHOST@@ (the protected host,
// filled per request and HTML-escaped), @@BODY@@ and @@SCRIPT@@ (the per-screen
// parts, filled once at start).
const signinShell = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="light dark"><title>Sign in to continue</title><style>
@font-face{font-family:"Manrope";font-style:normal;font-weight:700;font-display:swap;src:url(https://fonts.bunny.net/manrope/files/manrope-latin-700-normal.woff2) format("woff2")}
@font-face{font-family:"Open Sans";font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.bunny.net/open-sans/files/open-sans-latin-400-normal.woff2) format("woff2")}
@font-face{font-family:"Open Sans";font-style:normal;font-weight:600;font-display:swap;src:url(https://fonts.bunny.net/open-sans/files/open-sans-latin-600-normal.woff2) format("woff2")}
@font-face{font-family:"Open Sans";font-style:normal;font-weight:700;font-display:swap;src:url(https://fonts.bunny.net/open-sans/files/open-sans-latin-700-normal.woff2) format("woff2")}
:root{--bg:#f3f5f8;--card:#ffffff;--fg:#1a222b;--muted:#657383;--border:#d9dfe5;--control:#86909b;--input:#eceff2;--primary:#009494;--action:#006e6f;--action-fg:#ffffff;--danger:#cc272e;--ok:#008a39;--dot:#00949424;--info-bg:#0094941f;--ok-bg:#008a391f;--danger-bg:#cc272e1a;color-scheme:light}
@supports (color:oklch(0% 0 0)){:root{--bg:oklch(97% 0.005 250);--card:oklch(100% 0 0);--fg:oklch(25% 0.02 250);--muted:oklch(55% 0.03 250);--border:oklch(90% 0.01 250);--control:oklch(65% 0.02 250);--input:oklch(95% 0.005 250);--primary:oklch(60% 0.11 195);--action:oklch(48% 0.1 195);--action-fg:oklch(100% 0 0);--danger:oklch(55% 0.2 25);--ok:oklch(55% 0.16 150);--dot:oklch(60% 0.11 195 / 0.14);--info-bg:oklch(60% 0.11 195 / 0.12);--ok-bg:oklch(55% 0.16 150 / 0.12);--danger-bg:oklch(55% 0.2 25 / 0.1)}}
@media (prefers-color-scheme:dark){:root{--bg:#0b0b0b;--card:#161616;--fg:#fff6f8;--muted:#9a8a8f;--border:#ffffff1a;--control:#6e6769;--input:#1f191a;--primary:#5ecbcb;--action:#5ecbcb;--action-fg:#030303;--danger:#ee343b;--ok:#55c975;--dot:#5ecbcb2e;--info-bg:#5ecbcb24;--ok-bg:#55c97524;--danger-bg:#ee343b24;color-scheme:dark}}
@media (prefers-color-scheme:dark){@supports (color:oklch(0% 0 0)){:root{--bg:oklch(15% 0 0);--card:oklch(20% 0 0);--fg:oklch(98% 0.01 0);--muted:oklch(65% 0.02 0);--border:oklch(100% 0 0 / 0.1);--control:oklch(52% 0.01 0);--input:oklch(22% 0.01 0);--primary:oklch(78% 0.1 195);--action:oklch(78% 0.1 195);--action-fg:oklch(10% 0 0);--danger:oklch(62% 0.22 25);--ok:oklch(75% 0.16 150);--dot:oklch(78% 0.1 195 / 0.18);--info-bg:oklch(78% 0.1 195 / 0.14);--ok-bg:oklch(75% 0.16 150 / 0.14);--danger-bg:oklch(62% 0.22 25 / 0.14)}}}
*{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 "Open Sans","Helvetica Neue",Arial,sans-serif;-webkit-text-size-adjust:100%}
[hidden]{display:none!important}
.page{position:relative;min-height:100vh;min-height:100dvh;overflow:hidden}
.grid{position:absolute;inset:0;width:100%;height:100%;pointer-events:none}
.col{position:relative;display:flex;flex-direction:column;gap:16px;width:100%;max-width:26rem;min-height:inherit;margin:0 auto;padding:20px max(16px,env(safe-area-inset-right,0px)) max(20px,env(safe-area-inset-bottom,0px)) max(16px,env(safe-area-inset-left,0px))}
.head{display:flex;align-items:center;gap:8px}
.mark{width:15px;height:24px;color:var(--primary);flex:none}
.word{font:700 17px/1 "Manrope","Open Sans","Helvetica Neue",Arial,sans-serif}
.card{display:grid;gap:14px;margin-block:auto;padding:22px 20px 20px;border:1px solid var(--border);border-radius:1rem;background:var(--card)}
.card>section{display:grid;gap:14px}
.host{display:flex;align-items:center;gap:6px;min-width:0;width:fit-content;max-width:100%;margin:0;padding:5px 9px;border:1px solid var(--border);border-radius:.5rem;background:var(--input);color:var(--muted);font:12px/1.4 ui-monospace,"SF Mono",Menlo,Consolas,monospace}
.host span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
svg.i{fill:none;stroke:currentColor;stroke-width:1.75;stroke-linecap:round;stroke-linejoin:round}
.host svg{width:14px;height:14px;flex:none}
.ico{display:grid;place-items:center;width:44px;height:44px;border-radius:50%}
.ico svg{width:22px;height:22px}
.ico.info{background:var(--info-bg);color:var(--primary)}
.ico.ok{background:var(--ok-bg);color:var(--ok)}
.ico.danger{background:var(--danger-bg);color:var(--danger)}
h1{margin:0;font:700 1.4rem/1.2 "Manrope","Open Sans","Helvetica Neue",Arial,sans-serif;letter-spacing:-.01em;text-wrap:balance}
h1:focus{outline:none}
.body{margin:0;color:var(--muted)}
.mono{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:.9em}
.who{display:grid;gap:2px;padding:10px 12px;border:1px solid var(--border);border-radius:.5rem;background:var(--input)}
.who small{font-size:.74rem;font-weight:600;color:var(--muted)}
.who b{font:600 .86rem ui-monospace,"SF Mono",Menlo,Consolas,monospace;overflow-wrap:anywhere}
.field{display:grid;gap:6px}
.field label{font-size:.82rem;font-weight:600}
textarea{width:100%;min-height:96px;padding:10px 12px;border:1px solid var(--control);border-radius:.5rem;background:var(--input);color:var(--fg);font:.9rem ui-monospace,"SF Mono",Menlo,Consolas,monospace;resize:vertical}
textarea::placeholder{color:var(--muted);opacity:1}
.err{display:flex;gap:6px;align-items:flex-start;margin:0;font-size:.86rem}
.err svg{width:16px;height:16px;margin-top:3px;flex:none;stroke:var(--danger);stroke-width:1.9}
.btn{width:100%;min-height:44px;padding:10px 14px;border:1px solid var(--action);border-radius:.5rem;background:var(--action);color:var(--action-fg);font:700 .95rem "Open Sans","Helvetica Neue",Arial,sans-serif;cursor:pointer}
.btn:disabled{opacity:.6;cursor:wait}
a.btn{display:flex;align-items:center;justify-content:center;text-decoration:none}
:focus-visible{outline:2px solid var(--primary);outline-offset:2px}
.foot{position:relative;text-align:center;font-size:.78rem;color:var(--muted)}
.spin svg{animation:spin 1s linear infinite;transform-origin:center}
@keyframes spin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.spin svg{animation:none}}
</style></head><body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
<symbol id="mark" viewBox="0 0 906.26 1457.543"><path fill="currentColor" d="M254.854 137.158c-34.46 84.407-88.363 149.39-110.934 245.675 90.926-187.569 308.397-483.654 554.729-348.685 135.487 74.216 194.878 270.78 206.058 467.566 21.924 385.996-190.977 853.604-467.585 943.057-174.879 56.543-307.375-86.447-364.527-198.115-176.498-344.82 2.041-910.077 182.259-1109.498zm198.13 7.918C202.61 280.257 4.622 968.542 207.322 1270.414c51.713 77.029 194.535 160.648 285.294 71.318-209.061 31.529-288.389-176.143-301.145-340.765 31.411 147.743 139.396 326.12 309.075 253.588 251.957-107.723 376.778-648.46 269.433-966.817 22.394 134.616 15.572 317.711-47.551 412.087 86.655-230.615 7.903-704.478-269.444-554.749z"/></symbol>
<symbol id="i-lock" viewBox="0 0 24 24"><rect x="5" y="10.5" width="14" height="9" rx="2"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/></symbol>
<symbol id="i-check" viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></symbol>
<symbol id="i-alert" viewBox="0 0 24 24"><path d="M12 8.5v4.5M12 16.5v.01"/><path d="M10.3 4.2 2.8 17.5a2 2 0 0 0 1.7 3h15a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0z"/></symbol>
<symbol id="i-wallet" viewBox="0 0 24 24"><path d="M4 7.5A2.5 2.5 0 0 1 6.5 5H18v3"/><rect x="3.5" y="8" width="17" height="11" rx="2"/><circle cx="16" cy="13.5" r="1"/></symbol>
<symbol id="i-spin" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5" opacity=".22"/><path d="M12 3.5a8.5 8.5 0 0 1 8.5 8.5"/></symbol>
<symbol id="i-clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/></symbol>
</svg>
<div class="page">
<svg class="grid" aria-hidden="true"><defs><pattern id="dots" width="18" height="18" patternUnits="userSpaceOnUse"><circle cx="2" cy="2" r="1.1" style="fill:var(--dot)"/></pattern></defs><rect width="100%" height="100%" fill="url(#dots)"/></svg>
<div class="col">
<header class="head"><svg class="mark" aria-hidden="true"><use href="#mark"/></svg><span class="word">Portal</span></header>
<main class="card" aria-live="polite">
<p class="host" title="@@FULLHOST@@"><svg class="i" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-lock"/></svg><span>@@HOST@@</span></p>
@@BODY@@
</main>
<footer class="foot">Protected by Portal</footer>
</div></div>
<script>
@@SCRIPT@@
</script></body></html>`

// signinScriptPrelude holds what every method shares: switching between the
// screens of a method, the post-login target check, and the request helper.
// The target check refuses control characters and backslashes because browsers
// drop tabs and newlines from URLs, so "/<TAB>/host" would become "//host".
const signinScriptPrelude = `const views=[...document.querySelectorAll('[data-view]')];
const show=(name)=>{let shown;views.forEach((v)=>{v.hidden=v.dataset.view!==name;if(!v.hidden)shown=v});const h=shown&&shown.querySelector('h1');if(h)h.focus({preventScroll:true})};
document.addEventListener('click',(e)=>{const b=e.target.closest('[data-go]');if(b)show(b.dataset.go)});
const next=()=>{const value=new URLSearchParams(location.search).get('next')||'/';return value.startsWith('/')&&!value.startsWith('//')&&!value.includes('\\')&&!/[\u0000-\u001f\u007f]/.test(value)?value:'/'};
const done=()=>{const target=next();document.querySelector('#dest').textContent=target;show('ok');location.assign(target)};
const fail=(message)=>{document.querySelector('#err-msg').textContent=message||'Check your connection and try again.';show('error')};
const post=async(path,body)=>{const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});let data={};try{data=await response.json()}catch(e){}return{status:response.status,ok:response.ok,data}};
`

// Screens every method ends in, after its own screens.
const signinCommonViews = `<section data-view="ok" hidden><div class="ico ok"><svg class="i" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-check"/></svg></div><h1 tabindex="-1">You are signed in</h1><p class="body">Taking you to <span class="mono" id="dest"></span>.</p></section>
<section data-view="error" hidden><div class="ico danger"><svg class="i" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-alert"/></svg></div><h1 tabindex="-1">Something went wrong</h1><p class="body" id="err-msg"></p><button type="button" class="btn" data-go="form">Try again</button></section>`

const signinCredentialBody = `<section data-view="form"><h1 tabindex="-1">Sign in to continue</h1><p class="body">Paste the access credential the owner of this app gave you.</p>
<div class="field"><label for="credential">Access credential</label><textarea id="credential" placeholder="pcred_…" spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
<p class="err" id="hint" role="alert" hidden><svg class="i" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-alert"/></svg><span>Paste the credential first.</span></p></div>
<button type="button" class="btn" id="signin">Sign in</button></section>
<section data-view="checking" hidden><div class="ico info spin"><svg class="i" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-spin"/></svg></div><h1 tabindex="-1">Checking your credential</h1><p class="body">This takes a moment.</p></section>
<section data-view="invalid" hidden><div class="ico danger"><svg class="i" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-alert"/></svg></div><h1 tabindex="-1">That credential did not work</h1><p class="body">It may have expired, or access may have been removed. Ask the owner of this app for a new link.</p><button type="button" class="btn" data-go="form">Try again</button></section>
` + signinCommonViews

const signinCredentialScript = `const input=document.querySelector('#credential'),hint=document.querySelector('#hint');
const redeem=async()=>{const credential=input.value.trim();hint.hidden=credential!=='';if(!credential){input.focus();return}show('checking');try{const r=await post('/_portal/auth/redeem',{credential});if(r.status===401){show('invalid');return}if(!r.ok){fail(r.data.error);return}done()}catch(e){fail()}};
document.querySelector('#signin').addEventListener('click',redeem);
const fragment=new URLSearchParams(location.hash.slice(1));if(fragment.has('credential')){input.value=fragment.get('credential');history.replaceState(null,'',location.pathname+location.search);redeem()}`

const signinWalletBody = `<section data-view="form"><h1 tabindex="-1">Connect your wallet</h1><p class="body">Sign a one-time message to show you own an allowed Ethereum address. It costs nothing.</p><button type="button" class="btn" data-connect>Connect wallet</button></section>
<section data-view="none" hidden><div class="ico danger"><svg class="i" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-wallet"/></svg></div><h1 tabindex="-1">No wallet found in this browser</h1><p class="body">Open this page in a browser that has an Ethereum wallet, such as the browser inside a wallet app.</p><button type="button" class="btn" data-connect>Try again</button></section>
<section data-view="signing" hidden><div class="ico info spin"><svg class="i" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-spin"/></svg></div><h1 tabindex="-1">Confirm in your wallet</h1><p class="body">Approve the signature request. You will not be charged.</p></section>
<section data-view="denied" hidden><div class="ico danger"><svg class="i" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-alert"/></svg></div><h1 tabindex="-1">This address is not allowed</h1><p class="body">Ask the owner of this app to add it, or connect a different wallet.</p><div class="who"><small>Connected address</small><b id="who"></b></div><button type="button" class="btn" data-connect="fresh">Connect a different wallet</button></section>
` + signinCommonViews

const signinWalletScript = `const short=(a)=>a.length>12?a.slice(0,6)+'\u2026'+a.slice(-4):a;
const connect=async(fresh)=>{if(!window.ethereum){show('none');return}show('signing');try{
if(fresh){try{await window.ethereum.request({method:'wallet_requestPermissions',params:[{eth_accounts:{}}]})}catch(e){}}
const accounts=await window.ethereum.request({method:'eth_requestAccounts'});const address=accounts&&accounts[0];if(!address)throw new Error('The wallet did not provide an account.');
const c=await post('/_portal/auth/challenge',{address});if(c.status===401){document.querySelector('#who').textContent=short(address);show('denied');return}if(!c.ok)throw new Error(c.data.error||'Could not create a sign-in challenge.');
const signature=await window.ethereum.request({method:'personal_sign',params:[c.data.message,address]});
const v=await post('/_portal/auth/verify',{challenge_id:c.data.challenge_id,message:c.data.message,signature});if(!v.ok)throw new Error(v.data.error||'The signature could not be verified.');done();
}catch(e){if(e&&e.code===4001){show('form');return}fail(e&&e.message)}};
document.addEventListener('click',(e)=>{const b=e.target.closest('[data-connect]');if(b)connect(b.dataset.connect==='fresh')});`

// An OIDC login leaves for the provider at once, so its only screens are the
// ways it can come back without a session. They are rendered by the server and
// need no script. @@ISSUER@@ is the provider's host, @@RETRY@@ the login link
// that keeps the visitor's target, and @@ACCOUNT@@ the account the provider
// signed in, in the form an allowlist entry takes.
const (
	signinOIDCExpiredBody = `<section><div class="ico info"><svg class="i" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-clock"/></svg></div><h1>Sign-in took too long</h1><p class="body">This sign-in expired, or a newer one was started in another tab. Start it again from here.</p><a class="btn" href="@@RETRY@@">Sign in again</a></section>`

	signinOIDCCanceledBody = `<section><div class="ico info"><svg class="i" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-alert"/></svg></div><h1>Sign-in was canceled</h1><p class="body"><span class="mono">@@ISSUER@@</span> did not finish signing you in. If you did not cancel, your account may not have access to this app; ask its owner.</p><a class="btn" href="@@RETRY@@">Sign in again</a></section>`

	signinOIDCDeniedBody = `<section><div class="ico danger"><svg class="i" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-alert"/></svg></div><h1>This account is not allowed</h1><p class="body">Ask the owner of this app to add it, or sign in with a different account. You may need to sign out of <span class="mono">@@ISSUER@@</span> first.</p><div class="who"><small>Signed in as</small><b>@@ACCOUNT@@</b></div><a class="btn" href="@@RETRY@@">Sign in again</a></section>`

	signinOIDCFailedBody = `<section><div class="ico danger"><svg class="i" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-alert"/></svg></div><h1>Sign-in could not be completed</h1><p class="body"><span class="mono">@@ISSUER@@</span> did not respond or could not finish the sign-in. Try again in a moment. If this keeps happening, tell the owner of this app.</p><a class="btn" href="@@RETRY@@">Try again</a></section>`
)

var (
	signinCredentialPage = newSigninPage(signinCredentialBody, signinScriptPrelude+signinCredentialScript)
	signinWalletPage     = newSigninPage(signinWalletBody, signinScriptPrelude+signinWalletScript)

	signinOIDCExpiredPage  = newSigninPage(signinOIDCExpiredBody, "")
	signinOIDCCanceledPage = newSigninPage(signinOIDCCanceledBody, "")
	signinOIDCDeniedPage   = newSigninPage(signinOIDCDeniedBody, "")
	signinOIDCFailedPage   = newSigninPage(signinOIDCFailedBody, "")
)

func newSigninPage(body, script string) string {
	return strings.NewReplacer("@@BODY@@", body, "@@SCRIPT@@", script).Replace(signinShell)
}

// setSigninHeaders marks a response as a sign-in page: never cached or sniffed,
// and held to the sign-in content policy.
func setSigninHeaders(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", signinContentSecurityPolicy)
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
}

// writeSigninPage renders a sign-in page for the host the visitor reached, with
// fields holding further placeholder and value pairs. The host and the values
// come from the request or the provider, so they are escaped, and all of them
// are filled in one pass so a value is never read as a placeholder.
func writeSigninPage(w io.Writer, page, host string, fields ...string) {
	host = strings.TrimSpace(host)
	pairs := append([]string{"@@HOST@@", displayHost(host), "@@FULLHOST@@", host}, fields...)
	for i := 1; i < len(pairs); i += 2 {
		pairs[i] = html.EscapeString(pairs[i])
	}
	_, _ = io.WriteString(w, strings.NewReplacer(pairs...).Replace(page))
}

// displayHost shortens the identity-bound first label of a canonical host, such
// as "home-ha-377e330d…4083d4.relay.example", to keep the host chip readable.
func displayHost(host string) string {
	label, rest, found := strings.Cut(host, ".")
	runes := []rune(label)
	if !found || len(runes) <= 24 {
		return host
	}
	return string(runes[:12]) + "\u2026" + string(runes[len(runes)-4:]) + "." + rest
}
