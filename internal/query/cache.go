package query

import (
	"crypto/sha256"
	"sync"
)

// CachedCatalog remembers analyses by a hash of the text. Applications repeat a
// few statements, and PostgreSQL parsing through WebAssembly costs milliseconds,
// so this is what keeps a busy log from outrunning the collector. Hashing the key
// also means no query text stays in memory.
type CachedCatalog struct {
	catalog  *Catalog
	capacity int

	mu      sync.Mutex
	entries map[[sha256.Size]byte]Analysis
}

// NewCachedCatalog wraps catalog; capacity bounds memory.
func NewCachedCatalog(catalog *Catalog, capacity int) *CachedCatalog {
	return &CachedCatalog{catalog: catalog, capacity: capacity, entries: make(map[[sha256.Size]byte]Analysis)}
}

// Analyze returns the cached result or computes it. A full cache is simply
// cleared: an occasional miss costs far less than tracking recency per statement.
func (c *CachedCatalog) Analyze(text string) Analysis {
	key := sha256.Sum256([]byte(text))
	c.mu.Lock()
	defer c.mu.Unlock()
	if analysis, found := c.entries[key]; found {
		return analysis
	}
	analysis := c.catalog.Analyze(text)
	if len(c.entries) >= c.capacity {
		clear(c.entries)
	}
	c.entries[key] = analysis
	return analysis
}
