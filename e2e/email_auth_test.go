package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
)

type mailCatcher struct {
	addr  string
	mails chan caughtMail
}

type caughtMail struct {
	to   string
	data string
}

func startMailCatcher(t *testing.T) *mailCatcher {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for mail: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	catcher := &mailCatcher{addr: listener.Addr().String(), mails: make(chan caughtMail, 16)}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go catcher.serve(conn)
		}
	}()
	return catcher
}

func (c *mailCatcher) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	text := textproto.NewConn(conn)
	_ = text.PrintfLine("220 mail.test ESMTP")
	var mail caughtMail
	for {
		line, err := text.ReadLine()
		if err != nil {
			return
		}
		if c.handleMailLine(text, line, &mail) {
			return
		}
	}
}

func (c *mailCatcher) handleMailLine(text *textproto.Conn, line string, mail *caughtMail) bool {
	verb, arg, _ := strings.Cut(line, " ")
	switch strings.ToUpper(verb) {
	case "RCPT":
		mail.to = strings.TrimSuffix(strings.TrimPrefix(arg, "TO:<"), ">")
		_ = text.PrintfLine("250 OK")
	case "DATA":
		_ = text.PrintfLine("354 send it")
		data, err := text.ReadDotBytes()
		if err != nil {
			return true
		}
		mail.data = string(data)
		c.mails <- *mail
		_ = text.PrintfLine("250 OK")
	case "QUIT":
		_ = text.PrintfLine("221 bye")
		return true
	default:
		_ = text.PrintfLine("250 OK")
	}
	return false
}

func (c *mailCatcher) next(t *testing.T) caughtMail {
	t.Helper()
	select {
	case mail := <-c.mails:
		return mail
	case <-time.After(10 * time.Second):
		t.Fatal("no mail arrived")
		return caughtMail{}
	}
}

func (c *mailCatcher) expectNone(t *testing.T) {
	t.Helper()
	select {
	case mail := <-c.mails:
		t.Fatalf("unexpected mail to %s", mail.to)
	case <-time.After(300 * time.Millisecond):
	}
}

func (m caughtMail) link(t *testing.T) string {
	t.Helper()
	for line := range strings.Lines(m.data) {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "https://") && strings.Contains(line, "#email_token=") {
			return line
		}
	}
	t.Fatalf("mail has no sign-in link:\n%s", m.data)
	return ""
}

type browserPage struct {
	t         *testing.T
	commands  *os.File
	replies   *os.File
	reader    *bufio.Reader
	lastID    int
	sessionID string
}

func newCommandPipe(t *testing.T, what string) (*os.File, *os.File) {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("create %s pipe: %v", what, err)
	}
	return read, write
}

func runBrowserCommand(t *testing.T, browser string, commandRead, replyWrite *os.File) (<-chan struct{}, *browserTree) {
	t.Helper()
	cmd := exec.Command(browser,
		"--headless",
		"--disable-gpu",
		"--ignore-certificate-errors",
		"--no-sandbox",
		"--user-data-dir="+filepath.Join(t.TempDir(), "chrome"),
		"--remote-debugging-pipe",
		"about:blank",
	)
	cmd.ExtraFiles = []*os.File{commandRead, replyWrite}
	cmd.SysProcAttr = browserSysProcAttr()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start browser: %v", err)
	}
	_ = commandRead.Close()
	_ = replyWrite.Close()
	tree := newBrowserTree(cmd)
	browserDone := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(browserDone)
	}()
	return browserDone, tree
}

func launchBrowserProcess(t *testing.T, browser string) (*os.File, *os.File) {
	t.Helper()
	commandRead, commandWrite := newCommandPipe(t, "command")
	replyRead, replyWrite := newCommandPipe(t, "reply")
	t.Cleanup(func() {
		_ = commandWrite.Close()
		_ = replyRead.Close()
	})
	browserDone, tree := runBrowserCommand(t, browser, commandRead, replyWrite)
	t.Cleanup(func() { waitBrowserExit(t, browserDone, tree) })
	return commandWrite, replyRead
}

func startBrowserPage(t *testing.T, browser string) *browserPage {
	t.Helper()
	commands, replies := launchBrowserProcess(t, browser)
	page := &browserPage{t: t, commands: commands, replies: replies, reader: bufio.NewReader(replies)}
	var target struct {
		TargetID string `json:"targetId"`
	}
	if err := page.call("Target.createTarget", map[string]any{"url": "about:blank"}, &target); err != nil {
		t.Fatalf("create tab: %v", err)
	}
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := page.call("Target.attachToTarget", map[string]any{"targetId": target.TargetID, "flatten": true}, &attached); err != nil {
		t.Fatalf("attach to tab: %v", err)
	}
	page.sessionID = attached.SessionID
	return page
}

type browserCallReply struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func parseCallReply(raw []byte, id int) (browserCallReply, bool, error) {
	var reply browserCallReply
	if err := json.Unmarshal(bytes.TrimSuffix(raw, []byte{0}), &reply); err != nil {
		return reply, false, err
	}
	return reply, reply.ID == id, nil
}

func (p *browserPage) call(method string, params map[string]any, result any) error {
	p.lastID++
	command := map[string]any{"id": p.lastID, "method": method, "params": params}
	if p.sessionID != "" {
		command["sessionId"] = p.sessionID
	}
	data, err := json.Marshal(command)
	if err != nil {
		return err
	}
	if _, err := p.commands.Write(append(data, 0)); err != nil {
		return err
	}
	if err := p.replies.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	return p.awaitCallReply(method, result)
}

func (p *browserPage) awaitCallReply(method string, result any) error {
	for {
		raw, err := p.reader.ReadBytes(0)
		if err != nil {
			return fmt.Errorf("read %s reply: %w", method, err)
		}
		reply, matched, err := parseCallReply(raw, p.lastID)
		if err != nil {
			return err
		}
		if !matched {
			continue
		}
		if reply.Error != nil {
			return fmt.Errorf("browser call %s failed: %s", method, reply.Error.Message)
		}
		if result == nil {
			return nil
		}
		return json.Unmarshal(reply.Result, result)
	}
}

func (p *browserPage) open(address string) {
	p.t.Helper()
	for _, target := range []string{"about:blank", address} {
		if err := p.call("Page.navigate", map[string]any{"url": target}, nil); err != nil {
			p.t.Fatalf("open %s: %v", target, err)
		}
	}
}

func (p *browserPage) evaluate(expression string) bool {
	var evaluated struct {
		Result struct {
			Value any `json:"value"`
		} `json:"result"`
	}
	err := p.call("Runtime.evaluate", map[string]any{"expression": expression, "returnByValue": true}, &evaluated)
	return err == nil && evaluated.Result.Value == true
}

func (p *browserPage) text() string {
	var evaluated struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	_ = p.call("Runtime.evaluate", map[string]any{"expression": "document.body ? document.body.innerText : ''", "returnByValue": true}, &evaluated)
	return evaluated.Result.Value
}

func (p *browserPage) waitFor(what, expression string) {
	p.t.Helper()
	timeout := time.After(15 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for !p.evaluate(expression) {
		select {
		case <-tick.C:
		case <-timeout:
			p.t.Fatalf("page never showed %s; it says:\n%s", what, p.text())
		}
	}
}

func signinView(name string) string {
	return fmt.Sprintf(`!!document.querySelector('[data-view=%s]') && !document.querySelector('[data-view=%s]').hidden`, name, name)
}

func bootMailRelay(t *testing.T, ctx context.Context) (string, int) {
	t.Helper()
	port := harnessPort(t, "localhost")
	sniAddr := net.JoinHostPort("localhost", strconv.Itoa(port))
	relay, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     "https://" + sniAddr,
		StateDir:      t.TempDir(),
		SNIListenAddr: sniAddr,
		SNIPort:       port,
	})
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = relay.Shutdown(shutdownCtx)
		_ = relay.Wait()
	})
	return sniAddr, port
}

func trackMailTunnelRun(t *testing.T, ctx context.Context, cancel context.CancelFunc, expose *tunnel.Runtime) {
	t.Helper()
	runDone := make(chan error, 1)
	go func() { runDone <- expose.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = expose.Close()
		select {
		case err := <-runDone:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("run tunnel: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("tunnel did not stop")
		}
	})
}

func awaitMailLease(t *testing.T, ctx context.Context, expose *tunnel.Runtime) []sdk.RelayStatus {
	t.Helper()
	waitCtx, waitCancel := context.WithTimeout(ctx, 60*time.Second)
	defer waitCancel()
	ready, err := expose.Exposure.WaitReady(waitCtx)
	if err != nil {
		t.Fatalf("wait for lease: %v", err)
	}
	if len(ready) != 1 || ready[0].PublicURL == "" || ready[0].AliasURL == "" {
		t.Fatalf("relay status = %+v, want a public URL and an alias", ready)
	}
	return ready
}

func exposeMailTunnel(t *testing.T, ctx context.Context, cancel context.CancelFunc, sniAddr, target string, catcher *mailCatcher) (string, string) {
	t.Helper()
	expose, err := tunnel.Start(ctx, tunnel.Spec{
		Identity:  tunnel.IdentitySpec{Name: "mail", Path: filepath.Join(t.TempDir(), "identity.json")},
		Relays:    tunnel.RelaySpec{URLs: []string{"https://" + sniAddr}},
		Transport: tunnel.TransportSpec{Target: target},
		HTTP: &tunnel.HTTPConfig{Auth: &appauth.Config{
			Provider:        appauth.ProviderEmail,
			EmailList:       []string{"@example.com"},
			IdentityHeaders: true,
			EmailConfig:     appauth.EmailConfig{SMTPAddr: catcher.addr, SMTPFrom: "Portal <login@portal.test>"},
		}},
	})
	if err != nil {
		t.Fatalf("start tunnel: %v", err)
	}
	trackMailTunnelRun(t, ctx, cancel, expose)
	ready := awaitMailLease(t, ctx, expose)
	return strings.TrimSuffix(ready[0].PublicURL, "/"), strings.TrimSuffix(ready[0].AliasURL, "/")
}

func driveBrowserSignin(t *testing.T, page *browserPage, publicURL string, catcher *mailCatcher) string {
	t.Helper()
	page.open(publicURL + "/inbox")
	page.waitFor("the email form", signinView("form"))
	page.evaluate(`document.querySelector('#email').value='alice@example.com';document.querySelector('#email-form').requestSubmit();true`)
	page.waitFor("the sent screen", signinView("sent"))
	mail := catcher.next(t)
	if mail.to != "alice@example.com" {
		t.Fatalf("mail to %q", mail.to)
	}
	link := mail.link(t)
	if !strings.HasPrefix(link, publicURL+"/") {
		t.Fatalf("link %q is not for %s", link, publicURL)
	}
	return link
}

func confirmSigninLink(t *testing.T, page *browserPage, link string) {
	t.Helper()
	page.open(link)
	page.waitFor("the confirm screen", signinView("confirm"))
	if !page.evaluate(`location.hash === ''`) {
		t.Fatal("the token stayed in the address")
	}

	page.open(link)
	page.waitFor("the confirm screen", signinView("confirm"))
	page.evaluate(`document.querySelector('#redeem').click();true`)
	page.waitFor("the application", `document.body.innerText.includes('signed in as alice@example.com at /inbox')`)

	page.open(link)
	page.waitFor("the confirm screen", signinView("confirm"))
	page.evaluate(`document.querySelector('#redeem').click();true`)
	page.waitFor("the used-link screen", signinView("invalid"))
}

func requestEmailLink(t *testing.T, ctx context.Context, client *http.Client, publicURL, host, email string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, publicURL+"/_portal/auth/email/request", strings.NewReader(`{"email":"`+email+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	req.Header.Set("Origin", "https://"+host)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("request a link at %s: %v", host, err)
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func assertForeignHostRejected(t *testing.T, ctx context.Context, client *http.Client, publicURL string, port int, catcher *mailCatcher) {
	t.Helper()
	if code := requestEmailLink(t, ctx, client, publicURL, "attacker.localhost:"+strconv.Itoa(port), "bob@example.com"); code != http.StatusMisdirectedRequest {
		t.Fatalf("request at a foreign host = %d, want 421", code)
	}
	catcher.expectNone(t)
}

func assertAliasEmailFlow(t *testing.T, ctx context.Context, client *http.Client, publicURL, aliasURL string, catcher *mailCatcher) {
	t.Helper()
	alias, err := url.Parse(aliasURL)
	if err != nil {
		t.Fatal(err)
	}
	if code := requestEmailLink(t, ctx, client, publicURL, alias.Host, "bob@example.com"); code != http.StatusAccepted {
		t.Fatalf("request at the alias = %d, want 202", code)
	}
	if link := catcher.next(t).link(t); !strings.HasPrefix(link, aliasURL+"/") {
		t.Fatalf("link %q is not for the alias %s", link, aliasURL)
	}

	const burst = 24
	codes := make(chan int, burst)
	for range burst {
		go func() { codes <- requestEmailLink(t, ctx, client, publicURL, alias.Host, "nobody@elsewhere.test") }()
	}
	for range burst {
		if code := <-codes; code != http.StatusAccepted {
			t.Errorf("request at the alias during a burst = %d, want 202", code)
		}
	}
	catcher.expectNone(t)
}

func TestEmailSignInInARealBrowser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the debugging pipe needs inherited descriptors")
	}
	browser := requireBrowser(t)
	catcher := startMailCatcher(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "signed in as "+r.Header.Get(types.HeaderPortalUser)+" at "+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sniAddr, port := bootMailRelay(t, ctx)
	publicURL, aliasURL := exposeMailTunnel(t, ctx, cancel, sniAddr, strings.TrimPrefix(upstream.URL, "http://"), catcher)

	page := startBrowserPage(t, browser)
	link := driveBrowserSignin(t, page, publicURL, catcher)
	confirmSigninLink(t, page, link)

	canonical, err := url.Parse(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: canonical.Hostname(), MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, sniAddr)
		},
	}}
	assertForeignHostRejected(t, ctx, client, publicURL, port, catcher)
	assertAliasEmailFlow(t, ctx, client, publicURL, aliasURL, catcher)
}
