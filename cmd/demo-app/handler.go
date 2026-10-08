package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"time"

	"golang.org/x/net/websocket"

	"github.com/gosuda/portal-tunnel/v2/sdk"
)

//go:embed static
var staticFiles embed.FS

func newHandler() http.Handler {
	staticFS, _ := fs.Sub(staticFiles, "static")

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(staticFS)))
	mux.HandleFunc("/api/ping", handlePing)
	mux.Handle("/ws", websocket.Handler(handleWebSocket))
	mux.HandleFunc("/api/test-cookies", handleCookies)

	return mux
}

func handlePing(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"message": "pong",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func handleWebSocket(conn *websocket.Conn) {
	defer conn.Close()
	for {
		var msg string
		if err := websocket.Message.Receive(conn, &msg); err != nil {
			return
		}
		if err := websocket.Message.Send(conn, "echo: "+msg); err != nil {
			return
		}
	}
}

func handleCookies(w http.ResponseWriter, r *http.Request) {
	secure := r != nil && r.TLS != nil

	for _, cookie := range []*http.Cookie{
		{Name: "session_id", Value: "abc123", Path: "/", MaxAge: 3600, Secure: secure},
		{Name: "auth_token", Value: "secret456", Path: "/", MaxAge: 3600, Secure: secure},
		{Name: "csrf_token", Value: "xyz789", Path: "/", MaxAge: 3600, Secure: secure},
		{Name: "user_pref", Value: "dark_mode", Path: "/", MaxAge: 86400, Secure: secure},
	} {
		http.SetCookie(w, cookie)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"message": "4 cookies set: session_id, auth_token, csrf_token, user_pref",
	})
}

func newUDPInfoHandler(exposure *sdk.Exposure) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		udpRelays, _ := exposure.WaitDatagramReady(r.Context())
		udpAddrs := make([]string, 0, len(udpRelays))
		for _, relay := range udpRelays {
			udpAddrs = append(udpAddrs, relay.UDPAddr)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message":   "demo-udp is running",
			"udp_addrs": udpAddrs,
		})
	})
	return mux
}
