// Package zonecache provides the candidate-domain cache that the ACME DNS
// providers use to remember which provider zone hosts each domain.
package zonecache

import (
	"maps"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Cache maps candidate domains to provider zone identifiers. Empty keys and
// values are never stored and count as absent on lookup. A nil or zero Cache
// misses every lookup and drops updates. A Cache is safe for concurrent use.
type Cache struct {
	zones *utils.Snapshot[map[string]string]
}

// New returns an empty Cache.
func New() *Cache {
	return &Cache{zones: utils.NewSnapshot(map[string]string{}, maps.Clone[map[string]string])}
}

// Candidates normalizes domain and returns it together with its parent-domain
// candidates, ordered from the full name down to the base domain
// ("A.B.Example.COM." yields "a.b.example.com", "b.example.com", "example.com").
func Candidates(domain string) (string, []string) {
	domain = utils.NormalizeHostname(domain)
	return domain, utils.DomainCandidates(domain)
}

// Lookup returns the zone identifier stored for the first candidate that has
// one, along with the candidate domain it is stored under.
func (c *Cache) Lookup(candidates []string) (value, key string, ok bool) {
	if c == nil {
		return "", "", false
	}
	zones := c.zones.Load()
	for _, candidate := range candidates {
		if value := zones[candidate]; value != "" {
			return value, candidate, true
		}
	}
	return "", "", false
}

// Set stores value under the normalized domain.
func (c *Cache) Set(domain, value string) {
	if c == nil {
		return
	}
	key := utils.NormalizeHostname(domain)
	if key == "" || value == "" {
		return
	}
	c.zones.UpdateCopy(func(zones *map[string]string) {
		if *zones == nil {
			*zones = make(map[string]string)
		}
		(*zones)[key] = value
	})
}

// Merge stores every entry in a single update, following the same key and
// value rules as Set.
func (c *Cache) Merge(entries map[string]string) {
	if c == nil || len(entries) == 0 {
		return
	}
	c.zones.UpdateCopy(func(zones *map[string]string) {
		if *zones == nil {
			*zones = make(map[string]string)
		}
		for domain, value := range entries {
			if key := utils.NormalizeHostname(domain); key != "" && value != "" {
				(*zones)[key] = value
			}
		}
	})
}
