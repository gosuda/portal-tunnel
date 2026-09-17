package cache

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Syncer subscribes one relay to an exposure's shared static source. A single
// caller advances Next and supplies current transport/credentials to Sync.
type Syncer struct {
	source   *Source
	relayURL url.URL
	limits   types.StaticCacheLimits
	snapshot *sourceSnapshot
}

// Subscribe includes the relay's advertised limits in source discovery. A new
// subscriber reuses the current generation if one is already available.
func (s *Source) Subscribe(relayURL url.URL, limits types.StaticCacheLimits) *Syncer {
	s.mu.Lock()
	s.limits[relayURL.String()] = limits
	wake := s.snapshot == nil || s.snapshot.err != nil
	s.mu.Unlock()
	if wake {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
	return &Syncer{source: s, relayURL: relayURL, limits: limits}
}

// Close removes the relay from source discovery. Cancel Next/Sync and wait for
// them to return before closing the subscription.
func (s *Syncer) Close() {
	s.source.mu.Lock()
	delete(s.source.limits, s.relayURL.String())
	s.source.mu.Unlock()
}

// Next waits for a new shared generation. Credentials are deliberately supplied
// afterward, so a lease renewed while waiting cannot leave Sync with an old token.
func (s *Syncer) Next(ctx context.Context) bool {
	for ctx.Err() == nil {
		snapshot, changed := s.source.current()
		if snapshot != nil && snapshot != s.snapshot {
			s.snapshot = snapshot
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-s.source.done:
			return false
		case <-changed:
		}
	}
	return false
}

// Sync checks/uploads the generation selected by Next, invalidating stale relay
// content on failure. All requests reject redirects; client itself is unchanged.
func (s *Syncer) Sync(ctx context.Context, client *http.Client, accessToken string) error {
	if client == nil {
		return errors.New("cache API transport is unavailable")
	}
	if accessToken == "" {
		return errors.New("cache origin lease is unavailable")
	}
	cacheClient := *client
	cacheClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	err := s.syncSnapshot(ctx, &cacheClient, accessToken)
	if err != nil && ctx.Err() == nil {
		headers := http.Header{types.HeaderAccessToken: []string{accessToken}}
		_ = utils.HTTPDoAPIPath(ctx, &cacheClient, &s.relayURL, http.MethodDelete, types.PathSDKCache, nil, headers, nil)
	}
	return err
}

func (s *Syncer) syncSnapshot(ctx context.Context, client *http.Client, accessToken string) error {
	snapshot := s.snapshot
	if snapshot == nil {
		return errors.New("cache source generation is unavailable")
	}
	if snapshot.err != nil {
		return snapshot.err
	}
	manifest := snapshot.manifest
	if _, _, err := manifestDigest(manifest, s.limits.MaxObjectSize, s.limits.MaxExposureBytes); err != nil {
		return err
	}
	root, err := os.OpenRoot(snapshot.root)
	if err != nil {
		return err
	}
	defer root.Close()
	headers := http.Header{types.HeaderAccessToken: []string{accessToken}}
	var status types.StaticCacheStatus
	if err := utils.HTTPDoAPIPath(ctx, client, &s.relayURL, http.MethodPost, types.PathSDKCache, manifest, headers, &status); err != nil {
		return err
	}
	if status.Present {
		return nil
	}
	reader, writer := io.Pipe()
	parts := multipart.NewWriter(writer)
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, utils.ResolveAPIURL(&s.relayURL, types.PathSDKCache).String(), reader)
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return err
	}
	request.Header.Set("Content-Type", parts.FormDataContentType())
	request.Header.Set(types.HeaderAccessToken, accessToken)
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
