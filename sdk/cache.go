package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/internal/cachemanifest"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func (l *listener) staticCacheHTTPClient() *http.Client {
	client := l.api.httpClient()
	if client == nil {
		return nil
	}
	// Cache data and the lease token belong only to the configured relay.
	// Apply the same redirect boundary to probing, upload, and invalidation.
	cacheClient := *client
	cacheClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &cacheClient
}

func (l *listener) runStaticCache(ctx context.Context) {
	l.api.mu.RLock()
	limits := l.api.cache
	l.api.mu.RUnlock()
	if limits == nil {
		log.Info().Str("relay_url", l.api.relayURL.String()).Msg("relay cache unavailable; serving through the origin tunnel")
		return
	}
	relay := l.api.relayURL.String()
	l.cache.subscribe(relay, limits)
	defer l.cache.subscribe(relay, nil)
	for {
		snapshot, changed := l.cache.current()
		var syncErr error
		if snapshot != nil {
			syncErr = l.syncStaticCache(ctx, *limits, snapshot)
		}
		if syncErr != nil && ctx.Err() == nil {
			log.Warn().Err(syncErr).Str("relay_url", relay).Msg("static cache population skipped; origin tunnel remains available")
			lease, ok := l.leaseSnapshot()
			client := l.staticCacheHTTPClient()
			if ok && client != nil {
				headers := http.Header{types.HeaderAccessToken: []string{lease.accessToken}}
				_ = utils.HTTPDoAPIPath(ctx, client, l.api.relayURL, http.MethodDelete, types.PathSDKCache, nil, headers, nil)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		}
	}
}

func (l *listener) syncStaticCache(ctx context.Context, limits types.StaticCacheLimits, snapshot *staticSnapshot) error {
	if snapshot.err != nil {
		return snapshot.err
	}
	client := l.staticCacheHTTPClient()
	if client == nil {
		return errors.New("cache API transport is unavailable")
	}
	manifest := snapshot.manifest
	if _, _, err := cachemanifest.Digest(manifest, limits.MaxObjectSize, limits.MaxExposureBytes); err != nil {
		return err
	}
	root, err := os.OpenRoot(snapshot.root)
	if err != nil {
		return err
	}
	defer root.Close()
	lease, ok := l.leaseSnapshot()
	if !ok {
		return errors.New("cache origin lease is unavailable")
	}
	headers := http.Header{types.HeaderAccessToken: []string{lease.accessToken}}
	var status types.StaticCacheStatus
	if err := utils.HTTPDoAPIPath(ctx, client, l.api.relayURL, http.MethodPost, types.PathSDKCache, manifest, headers, &status); err != nil {
		return err
	}
	if status.Present {
		return nil
	}
	reader, writer := io.Pipe()
	parts := multipart.NewWriter(writer)
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, utils.ResolveAPIURL(l.api.relayURL, types.PathSDKCache).String(), reader)
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return err
	}
	request.Header.Set("Content-Type", parts.FormDataContentType())
	request.Header.Set(types.HeaderAccessToken, lease.accessToken)
	finished := make(chan error, 1)
	go func() {
		err := func() error {
			part, err := parts.CreateFormField("manifest")
			if err != nil {
				return err
			}
			if err := json.NewEncoder(part).Encode(manifest); err != nil {
				return err
			}
			for _, object := range manifest.Files {
				if err := ctx.Err(); err != nil {
					return err
				}
				part, err := parts.CreateFormField("object")
				if err != nil {
					return err
				}
				input, err := root.Open(object.Path)
				if err != nil {
					return err
				}
				info, statErr := input.Stat()
				if statErr != nil || !info.Mode().IsRegular() || info.Size() != object.Size {
					_ = input.Close()
					return errors.New("static cache source changed during upload")
				}
				_, copyErr := io.CopyN(part, input, object.Size)
				closeErr := input.Close()
				if err := errors.Join(copyErr, closeErr); err != nil {
					return err
				}
			}
			return parts.Close()
		}()
		_ = writer.CloseWithError(err)
		finished <- err
	}()
	response, requestErr := client.Do(request)
	_ = reader.CloseWithError(requestErr)
	writeErr := <-finished
	if requestErr != nil {
		return requestErr
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return utils.DecodeAPIRequestError(response)
	}
	if writeErr != nil {
		return writeErr
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, types.StaticCacheManifestLimit))
	return err
}
