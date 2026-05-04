package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

var thumbnailHTTPClient = utils.NewHTTPClient(utils.WithHTTPTimeout(5 * time.Second))

const (
	thumbnailViewportWidth  = 1280
	thumbnailViewportHeight = 720
	thumbnailJPEGQuality    = 80
	thumbnailMaxBytes       = 256 << 10 // 256KB
	thumbnailCooldown       = 30 * time.Second
	thumbnailPageTimeout    = 15 * time.Second
	thumbnailQueueSize      = 32
	thumbnailContentType    = "image/jpeg"
)

type thumbnailEntry struct {
	data      []byte
	fetchedAt time.Time
}

type thumbnailService struct {
	mu               sync.RWMutex
	cache            map[string]*thumbnailEntry
	pending          map[string]bool
	queue            chan string
	headlessShellURL string
	done             chan struct{}
}

func newThumbnailService(headlessShellURL string) *thumbnailService {
	headlessShellURL = strings.TrimSpace(headlessShellURL)
	if headlessShellURL == "" {
		return nil
	}
	service := &thumbnailService{
		cache:            make(map[string]*thumbnailEntry),
		pending:          make(map[string]bool),
		queue:            make(chan string, thumbnailQueueSize),
		headlessShellURL: headlessShellURL,
		done:             make(chan struct{}),
	}
	go service.worker()
	return service
}

func (s *thumbnailService) worker() {
	for hostname := range s.queue {
		_, _ = s.captureAndStore(hostname)
		s.mu.Lock()
		delete(s.pending, hostname)
		s.mu.Unlock()
	}
	close(s.done)
}

func (s *thumbnailService) get(hostname string) ([]byte, string, bool) {
	if s == nil {
		return nil, "", false
	}
	s.mu.RLock()
	entry, ok := s.cache[hostname]
	s.mu.RUnlock()
	if !ok || len(entry.data) == 0 {
		return nil, "", false
	}
	return entry.data, thumbnailContentType, true
}

func (s *thumbnailService) load(hostname string) ([]byte, string, error) {
	if data, contentType, ok := s.get(hostname); ok {
		return data, contentType, nil
	}
	data, err := s.captureAndStore(hostname)
	if err != nil {
		return nil, "", err
	}
	return data, thumbnailContentType, nil
}

func (s *thumbnailService) triggerAsync(hostname string) {
	if s == nil || hostname == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, ok := s.cache[hostname]; ok {
		if len(entry.data) > 0 || time.Since(entry.fetchedAt) < thumbnailCooldown {
			return
		}
	}
	if s.pending[hostname] {
		return
	}

	s.pending[hostname] = true
	select {
	case s.queue <- hostname:
	default:
		delete(s.pending, hostname)
	}
}

func (s *thumbnailService) captureAndStore(hostname string) ([]byte, error) {
	store := func(data []byte) {
		s.mu.Lock()
		s.cache[hostname] = &thumbnailEntry{data: data, fetchedAt: time.Now()}
		s.mu.Unlock()
	}

	data, err := s.screenshot(hostname)
	if err != nil {
		log.Warn().Err(err).Str("hostname", hostname).Msg("thumbnail capture failed")
		store(nil)
		return nil, err
	}
	if len(data) > thumbnailMaxBytes {
		err = fmt.Errorf("thumbnail too large: %d bytes", len(data))
		log.Warn().Err(err).Str("hostname", hostname).Int("size", len(data)).Msg("thumbnail capture failed")
		store(nil)
		return nil, err
	}

	store(data)
	log.Info().Str("hostname", hostname).Int("size", len(data)).Msg("thumbnail captured")
	return data, nil
}

func (s *thumbnailService) resolveCDPWebSocketURL() (string, error) {
	parsed, err := url.Parse(s.headlessShellURL)
	if err != nil {
		return "", fmt.Errorf("parse headless shell URL: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf("http://%s/json/version", parsed.Host), nil)
	if err != nil {
		return "", fmt.Errorf("build /json/version request: %w", err)
	}
	req.Host = "127.0.0.1" // headless-shell rejects non-IP Host headers

	resp, err := thumbnailHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("query /json/version: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("read /json/version: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("/json/version status %d: %s", resp.StatusCode, body)
	}

	var info struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("decode /json/version: %w", err)
	}
	if info.WebSocketDebuggerURL == "" {
		return "", fmt.Errorf("/json/version: empty webSocketDebuggerUrl")
	}

	wsURL, err := url.Parse(info.WebSocketDebuggerURL)
	if err != nil {
		return "", fmt.Errorf("parse debugger URL: %w", err)
	}
	wsURL.Host = parsed.Host // headless-shell returns 0.0.0.0 internally
	return wsURL.String(), nil
}

func (s *thumbnailService) screenshot(hostname string) ([]byte, error) {
	cdpURL, err := s.resolveCDPWebSocketURL()
	if err != nil {
		return nil, err
	}

	browser := rod.New().ControlURL(cdpURL)
	if err := browser.Connect(); err != nil {
		return nil, err
	}

	incognito, err := browser.Incognito()
	if err != nil {
		return nil, err
	}
	defer incognito.Close()

	page, err := incognito.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return nil, err
	}
	defer page.Close()

	_ = page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{
		Width:  thumbnailViewportWidth,
		Height: thumbnailViewportHeight,
	})
	_ = browser.IgnoreCertErrors(true)

	if err := page.Navigate("https://" + hostname); err != nil {
		return nil, err
	}
	if err := page.Timeout(thumbnailPageTimeout).WaitLoad(); err != nil {
		return nil, err
	}
	time.Sleep(1 * time.Second)

	quality := thumbnailJPEGQuality
	return page.Screenshot(false, &proto.PageCaptureScreenshot{
		Format:  proto.PageCaptureScreenshotFormatJpeg,
		Quality: &quality,
	})
}

func (s *thumbnailService) remove(hostname string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.cache, hostname)
	delete(s.pending, hostname)
	s.mu.Unlock()
}

func (s *thumbnailService) close() {
	if s == nil {
		return
	}
	close(s.queue)
	<-s.done
	s.mu.Lock()
	s.cache = make(map[string]*thumbnailEntry)
	s.pending = make(map[string]bool)
	s.mu.Unlock()
}
