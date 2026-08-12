package sdk

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/html"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Reading the thumbnail here rather than on the relay is deliberate. The relay
// would have to fetch a page it does not control, follow its redirects, and
// proxy back whatever came out — an SSRF surface and a cache, added for a card
// image. This client already talks to the target as its whole purpose, and the
// target belongs to whoever runs it, so asking it what image it advertises adds
// no reachability that the tunnel does not already have.

const (
	// Short on purpose: this runs before the tunnel is announced, and a card
	// image must not hold startup open while a target that is not listening yet
	// times out.
	thumbnailFetchTimeout  = 3 * time.Second
	thumbnailHTMLReadLimit = 512 << 10
)

// resolveMetadataThumbnail returns the thumbnail the lease should carry.
//
// An explicit value always wins, and without the opt-in the target is never
// contacted. Both halves of that are the contract with whoever runs this: they
// asked for a specific image, or they asked for none of this at all.
func resolveMetadataThumbnail(ctx context.Context, cfg ExposeConfig, targetAddr, name string, relayURLs []string) string {
	declared := cfg.Metadata.Thumbnail
	if strings.TrimSpace(declared) != "" || !cfg.ThumbnailFromTarget {
		return declared
	}
	return discoverThumbnailForExposure(ctx, targetAddr, name, relayURLs)
}

// discoverThumbnailForExposure resolves the hostname this exposure will answer
// at, then asks the target what image it advertises. It never fails: what it
// found, or why it found nothing, goes to the log so the chosen value is
// visible rather than guessed at.
func discoverThumbnailForExposure(ctx context.Context, targetAddr, name string, relayURLs []string) string {
	publicHostname := ""
	if len(relayURLs) > 0 {
		// The first relay anchors a relative reference. A lease answers at one
		// hostname per relay while metadata carries a single value, and an app
		// that declares an absolute URL — which Open Graph asks for — is
		// unaffected either way.
		if host, err := utils.LeaseHostname(name, utils.PortalRootHost(relayURLs[0])); err == nil {
			publicHostname = host
		}
	}

	thumbnail, err := DiscoverThumbnail(ctx, targetAddr, publicHostname)
	switch {
	case err != nil:
		log.Info().Err(err).Str("target", targetAddr).
			Msg("could not read a thumbnail from the target; pass --thumbnail to set one")
		return ""
	case thumbnail == "":
		log.Info().Str("target", targetAddr).
			Msg("target advertises no og:image, twitter:image or icon; leaving the thumbnail empty")
		return ""
	}
	log.Info().Str("thumbnail", thumbnail).Str("target", targetAddr).
		Msg("using the image the target advertises as the lease thumbnail")
	return thumbnail
}

// DiscoverThumbnail asks the target application which image represents it and
// returns that as an absolute URL, or an empty string when it advertises none.
//
// publicHostname is the lease hostname this exposure will be reachable at. It
// is only consulted for a relative reference: the Open Graph protocol calls for
// an absolute URL, but declaring "/og.png" is common, and the file is served
// through the tunnel like every other path.
//
// Callers should treat any error as "no thumbnail". A card image is not worth
// failing a tunnel over.
func DiscoverThumbnail(ctx context.Context, targetAddr, publicHostname string) (string, error) {
	targetAddr = strings.TrimSpace(targetAddr)
	if targetAddr == "" {
		return "", fmt.Errorf("no target address")
	}

	pageURL := &url.URL{Scheme: "http", Host: targetAddr, Path: "/"}
	refs, err := declaredImageRefs(ctx, pageURL)
	if err != nil {
		return "", err
	}

	base := (*url.URL)(nil)
	if publicHostname = utils.NormalizeHostname(publicHostname); publicHostname != "" {
		base = &url.URL{Scheme: "https", Host: publicHostname, Path: "/"}
	}

	for _, ref := range refs {
		resolved := resolveThumbnailRef(ref, base)
		if resolved != "" {
			return resolved, nil
		}
	}
	return "", nil
}

// resolveThumbnailRef turns one declared reference into an absolute http(s)
// URL, or returns empty when it cannot be used.
//
// metadata.thumbnail is an absolute URL by contract — the dashboard's own
// tunnel command builder rejects anything else — so a value that cannot be made
// absolute is dropped rather than stored and left to render as a broken image.
func resolveThumbnailRef(ref string, base *url.URL) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	parsed, err := url.Parse(ref)
	if err != nil {
		return ""
	}

	if parsed.IsAbs() {
		// data: and javascript: parse as absolute too, so the scheme is checked
		// rather than assumed.
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return ""
		}
		return parsed.String()
	}

	// Relative, and nothing to resolve it against: the target's own address is
	// loopback and would be useless to a browser elsewhere.
	if base == nil {
		return ""
	}
	return base.ResolveReference(parsed).String()
}

func declaredImageRefs(ctx context.Context, pageURL *url.URL) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/html")

	client := utils.NewHTTPClient(utils.WithHTTPTimeout(thumbnailFetchTimeout))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("target returned %d", resp.StatusCode)
	}

	return parseDeclaredImageRefs(io.LimitReader(resp.Body, thumbnailHTMLReadLimit)), nil
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
