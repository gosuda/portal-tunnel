// Package thumbnail reads the image a tunnel's target application advertises,
// so a service does not have to be described twice: once to the app and once on
// the command line.
//
// This is metadata construction, not part of the tunnelling contract, so it
// lives here rather than in the SDK. The SDK receives a resolved
// types.LeaseMetadata and stays agnostic about how metadata.thumbnail was
// chosen; that keeps HTML fetching and parsing out of its public surface, and
// keeps this an explicit CLI action against the target the operator just named
// rather than a general-purpose capability every SDK consumer inherits.
package thumbnail

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/html"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	// Short on purpose: this runs before the tunnel is announced, and a card
	// image must not hold startup open while a target that is not listening yet
	// times out.
	fetchTimeout  = 3 * time.Second
	htmlReadLimit = 512 << 10
)

// Resolve returns the thumbnail a lease should carry.
//
// An explicit value always wins, and without the opt-in the target is not
// contacted at all. Both halves are the contract with whoever runs this: they
// named a specific image, or they asked for none of this.
//
// It never fails. What was found, or why nothing was, goes to the log so the
// chosen value is visible rather than guessed at.
func Resolve(ctx context.Context, declared, targetAddr string, fromTarget bool) string {
	if strings.TrimSpace(declared) != "" || !fromTarget {
		return declared
	}

	found, err := FromTarget(ctx, targetAddr)
	switch {
	case err != nil:
		log.Info().Err(err).Str("target", targetAddr).
			Msg("could not read a thumbnail from the target; pass --thumbnail to set one")
		return ""
	case found == "":
		log.Info().Str("target", targetAddr).
			Msg("target advertises no absolute og:image, twitter:image or icon URL; leaving the thumbnail empty")
		return ""
	}
	log.Info().Str("thumbnail", found).Str("target", targetAddr).
		Msg("using the image the target advertises as the lease thumbnail")
	return found
}

// FromTarget asks the target application which image represents it and returns
// that as an absolute URL, or an empty string when it advertises none.
//
// Only absolute http(s) URLs are taken. The Open Graph protocol calls for one,
// metadata.thumbnail is an absolute URL by contract, and accepting a relative
// reference would mean resolving it against the hostname some relay will serve
// the lease at -- coupling a card image to relay selection for a value the app
// was supposed to state outright.
//
// targetAddr must be the bare host:port the tunnel dials, and only "/" on it is
// ever requested.
func FromTarget(ctx context.Context, targetAddr string) (string, error) {
	targetAddr, err := dialTarget(targetAddr)
	if err != nil {
		return "", err
	}

	pageURL := &url.URL{Scheme: "http", Host: targetAddr, Path: "/"}
	refs, err := declaredImageRefs(ctx, pageURL)
	if err != nil {
		return "", err
	}

	for _, ref := range refs {
		if absolute := absoluteImageURL(ref); absolute != "" {
			return absolute, nil
		}
	}
	return "", nil
}

// dialTarget accepts only what the tunnel itself dials. A URL would turn "read
// the target's front page" into "fetch any path on any host", which is a
// different capability and not one this needs.
func dialTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("no target address")
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", fmt.Errorf("target %q is not a host:port address: %w", raw, err)
	}
	if host == "" || port == "" {
		return "", fmt.Errorf("target %q is not a host:port address", raw)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("target %q has a non-numeric port", raw)
	}
	// Rebuilt from the validated parts rather than reusing the input, so the
	// request URL cannot carry a path, query or credentials.
	return net.JoinHostPort(host, port), nil
}

// absoluteImageURL returns ref when it is already an absolute http(s) URL.
//
// data: and javascript: parse as absolute too, so the scheme is checked rather
// than assumed: this value ends up in an <img src> on the dashboard.
func absoluteImageURL(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	parsed, err := url.Parse(ref)
	if err != nil || !parsed.IsAbs() {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	return parsed.String()
}

func declaredImageRefs(ctx context.Context, pageURL *url.URL) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/html")

	client := utils.NewHTTPClient(utils.WithHTTPTimeout(fetchTimeout))
	// The target's front page is the whole request. A redirect would send this
	// somewhere the operator did not name, so it is returned as a response and
	// rejected by the status check below rather than followed.
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("target returned %d", resp.StatusCode)
	}

	return parseDeclaredImageRefs(io.LimitReader(resp.Body, htmlReadLimit)), nil
}

// parseDeclaredImageRefs collects image references in preference order:
// og:image, then twitter:image, then apple-touch-icon.
func parseDeclaredImageRefs(r io.Reader) []string {
	var og, twitter, icons []string

	tokenizer := html.NewTokenizer(r)
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			return append(append(og, twitter...), icons...)
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			switch token.Data {
			case "meta":
				var property, name, content string
				for _, attr := range token.Attr {
					switch strings.ToLower(attr.Key) {
					case "property":
						property = strings.ToLower(attr.Val)
					case "name":
						name = strings.ToLower(attr.Val)
					case "content":
						content = attr.Val
					}
				}
				if content == "" {
					continue
				}
				switch {
				case property == "og:image", property == "og:image:secure_url":
					og = append(og, content)
				case name == "twitter:image", name == "twitter:image:src":
					twitter = append(twitter, content)
				}
			case "link":
				var rel, href string
				for _, attr := range token.Attr {
					switch strings.ToLower(attr.Key) {
					case "rel":
						rel = strings.ToLower(attr.Val)
					case "href":
						href = attr.Val
					}
				}
				if href == "" {
					continue
				}
				for _, value := range strings.Fields(rel) {
					if value == "apple-touch-icon" || value == "apple-touch-icon-precomposed" || value == "icon" {
						icons = append(icons, href)
						break
					}
				}
			case "body":
				// Everything worth reading lives in the head.
				return append(append(og, twitter...), icons...)
			}
		}
	}
}
