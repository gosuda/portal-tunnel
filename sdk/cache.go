package sdk

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type staticCacheSource struct {
	root, index string
	ttl         time.Duration
}

func (l *listener) runStaticCache(ctx context.Context) {
	l.api.mu.RLock()
	limits := l.api.cache
	l.api.mu.RUnlock()
	if limits == nil {
		log.Info().Str("relay_url", l.api.relayURL.String()).Msg("relay cache unavailable; serving through the origin tunnel")
		return
	}
	for {
		if err := l.syncStaticCache(ctx, *limits); err != nil && ctx.Err() == nil {
			log.Warn().Err(err).Str("relay_url", l.api.relayURL.String()).Msg("static cache population skipped; origin tunnel remains available")
			if lease, ok := l.leaseSnapshot(); ok {
				headers := http.Header{types.HeaderAccessToken: []string{lease.accessToken}}
				_ = utils.HTTPDoAPIPath(ctx, l.api.httpClient(), l.api.relayURL, http.MethodDelete, types.PathSDKCache, nil, headers, nil)
			}
		}
		if !utils.SleepOrDone(ctx, 30*time.Second) {
			return
		}
	}
}

func (l *listener) syncStaticCache(ctx context.Context, limits types.StaticCacheLimits) error {
	client := l.api.httpClient()
	if client == nil {
		return errors.New("cache API transport is unavailable")
	}
	root, err := os.OpenRoot(l.cache.root)
	if err != nil {
		return err
	}
	defer root.Close()
	manifest := types.StaticCacheManifest{Index: l.cache.index}
	var total int64
	err = fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("cache source %q is not a regular file", path)
		}
		if len(manifest.Files) >= types.StaticCacheMaxFiles {
			return errors.New("too many static cache files")
		}
		file, err := root.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > limits.MaxObjectSize || info.Size() > limits.MaxExposureBytes-total {
			return fmt.Errorf("cache source %q exceeds relay limits or is not a regular file", path)
		}
		hash := sha256.New()
		if _, err := io.CopyN(hash, file, info.Size()); err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, types.StaticCacheFile{Path: path, Size: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil))})
		total += info.Size()
		return nil
	})
	if err != nil {
		return err
	}
	slices.SortFunc(manifest.Files, func(a, b types.StaticCacheFile) int { return cmp.Compare(a.Path, b.Path) })
	if _, _, err := utils.StaticCacheDigest(manifest, limits.MaxObjectSize, limits.MaxExposureBytes); err != nil {
		return err
	}
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
