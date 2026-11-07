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
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// mailCatcher is the smallest SMTP server a tunnel can send through: it answers
// on a loopback address, where no TLS is required, and keeps each mail.
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
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "RCPT":
			mail.to = strings.TrimSuffix(strings.TrimPrefix(arg, "TO:<"), ">")
			_ = text.PrintfLine("250 OK")
		case "DATA":
			_ = text.PrintfLine("354 send it")
			data, err := text.ReadDotBytes()
			if err != nil {
				return
			}
			mail.data = string(data)
			c.mails <- mail
			_ = text.PrintfLine("250 OK")
		case "QUIT":
			_ = text.PrintfLine("221 bye")
			return
		default:
			_ = text.PrintfLine("250 OK")
		}
	}
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

// link reads the sign-in link out of a mail.
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

// browserPage drives one Chrome tab over --remote-debugging-pipe: Chrome reads
// commands from descriptor 3 and writes replies to descriptor 4, each ending in
// a NUL, so no WebSocket client is needed.
type browserPage struct {
	t         *testing.T
	commands  *os.File
	replies   *os.File
	reader    *bufio.Reader
	lastID    int
	sessionID string
}

func startBrowserPage(t *testing.T, browser string) *browserPage {
	t.Helper()
	commandRead, commandWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("create command pipe: %v", err)
	}
	replyRead, replyWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("create reply pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = commandWrite.Close()
		_ = replyRead.Close()
	})
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
	t.Cleanup(func() { waitBrowserExit(t, browserDone, tree) })

	page := &browserPage{t: t, commands: commandWrite, replies: replyRead, reader: bufio.NewReader(replyRead)}
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
	for {
		raw, err := p.reader.ReadBytes(0)
		if err != nil {
			return fmt.Errorf("read %s reply: %w", method, err)
		}
		var reply struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(bytes.TrimSuffix(raw, []byte{0}), &reply); err != nil {
			return err
		}
		if reply.ID != p.lastID {
			continue
		}
		if reply.Error != nil {
			return fmt.Errorf("%s: %s", method, reply.Error.Message)
		}
		if result == nil {
			return nil
		}
		return json.Unmarshal(reply.Result, result)
	}
}

// open loads a URL in the tab. The blank page first makes a link that differs
// from the current address only in its fragment a real load.
func (p *browserPage) open(address string) {
	p.t.Helper()
	for _, target := range []string{"about:blank", address} {
		if err := p.call("Page.navigate", map[string]any{"url": target}, nil); err != nil {
			p.t.Fatalf("open %s: %v", target, err)
		}
	}
}

// evaluate runs an expression in the page and reports whether it is true. A page
// that is still loading has no answer yet.
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

// The whole of an email sign-in, through a real relay, a real tunnel and a real
// browser, which also enforces the page's CSP. A browser that only opens the
// link and runs the page, as a mail scanner can, leaves it usable; the visitor's
// click signs in; and the link then works no more. The mail is only ever for a
// host of this tunnel, whichever host the request names.
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

	expose, err := tunnel.Start(ctx, tunnel.Spec{
		Identity:  tunnel.IdentitySpec{Name: "mail", Path: filepath.Join(t.TempDir(), "identity.json")},
		Relays:    tunnel.RelaySpec{URLs: []string{"https://" + sniAddr}},
		Transport: tunnel.TransportSpec{Target: strings.TrimPrefix(upstream.URL, "http://")},
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
	waitCtx, waitCancel := context.WithTimeout(ctx, 60*time.Second)
	defer waitCancel()
	ready, err := expose.Exposure.WaitReady(waitCtx)
	if err != nil {
		t.Fatalf("wait for lease: %v", err)
	}
	if len(ready) != 1 || ready[0].PublicURL == "" || ready[0].AliasURL == "" {
		t.Fatalf("relay status = %+v, want a public URL and an alias", ready)
	}
	publicURL := strings.TrimSuffix(ready[0].PublicURL, "/")
	aliasURL := strings.TrimSuffix(ready[0].AliasURL, "/")

	page := startBrowserPage(t, browser)

	// A visitor without a session lands on the form and asks for a link.
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

	// A scanner opens the link and runs the page, and clicks nothing. The script
	// has run once the confirm screen shows; a page that spent the token on load
	// would never show it.
	page.open(link)
	page.waitFor("the confirm screen", signinView("confirm"))
	if !page.evaluate(`location.hash === ''`) {
		t.Fatal("the token stayed in the address")
	}

	// The visitor opens the same link and clicks, and lands where they were going.
	page.open(link)
	page.waitFor("the confirm screen", signinView("confirm"))
	page.evaluate(`document.querySelector('#redeem').click();true`)
	page.waitFor("the application", `document.body.innerText.includes('signed in as alice@example.com at /inbox')`)

	// The link has been used.
	page.open(link)
	page.waitFor("the confirm screen", signinView("confirm"))
	page.evaluate(`document.querySelector('#redeem').click();true`)
	page.waitFor("the used-link screen", signinView("invalid"))

	// A request names its own Host. The alias of this tunnel is a host of the
	// tunnel, so its link is for the alias. Any other is refused, and no mail goes
	// out, because the link would carry the token to whoever answers there.
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
	ask := func(host, email string) int {
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
	if code := ask("attacker.localhost:"+strconv.Itoa(port), "bob@example.com"); code != http.StatusMisdirectedRequest {
		t.Fatalf("request at a foreign host = %d, want 421", code)
	}
	catcher.expectNone(t)
	alias, err := url.Parse(aliasURL)
	if err != nil {
		t.Fatal(err)
	}
	if code := ask(alias.Host, "bob@example.com"); code != http.StatusAccepted {
		t.Fatalf("request at the alias = %d, want 202", code)
	}
	if link := catcher.next(t).link(t); !strings.HasPrefix(link, aliasURL+"/") {
		t.Fatalf("link %q is not for the alias %s", link, aliasURL)
	}

	// Each visitor connection takes an idle reverse session, so a burst makes the
	// relay report connecting while it is serving that very burst. The tunnel
	// still holds the alias, so nobody on the short URL may be refused.
	const burst = 24
	codes := make(chan int, burst)
	for range burst {
		go func() { codes <- ask(alias.Host, "nobody@elsewhere.test") }()
	}
	for range burst {
		if code := <-codes; code != http.StatusAccepted {
			t.Errorf("request at the alias during a burst = %d, want 202", code)
		}
	}
	catcher.expectNone(t)
}
