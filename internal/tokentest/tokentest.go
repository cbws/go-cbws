// Package tokentest provides a token source whose fetches a test controls
// and an in-memory token cache, for tests of the code that waits on them.
package tokentest

import (
	"fmt"
	"sync"
	"time"

	"go.cbws.cloud/sdk/oauth2/tokencache"
	"golang.org/x/oauth2"
)

// GatedSource issues a numbered bearer token per fetch, valid for an hour
// of wall-clock time. Every fetch waits until Open is called, so a test can
// hold one in progress for as long as it needs.
type GatedSource struct {
	gate chan struct{}
	once sync.Once

	mu    sync.Mutex
	calls int
}

// NewGatedSource returns a GatedSource whose fetches wait until Open.
func NewGatedSource() *GatedSource {
	return &GatedSource{gate: make(chan struct{})}
}

// Token implements oauth2.TokenSource.
func (s *GatedSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	s.calls++
	n := s.calls
	s.mu.Unlock()

	<-s.gate

	return &oauth2.Token{
		AccessToken: fmt.Sprintf("token-%d", n),
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}, nil
}

// Open lets every fetch, in progress or later, complete.
func (s *GatedSource) Open() {
	s.once.Do(func() { close(s.gate) })
}

// Calls reports how many fetches have started.
func (s *GatedSource) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.calls
}

// MemoryCache is a tokencache.Cache kept in a map.
type MemoryCache struct {
	mu      sync.Mutex
	entries map[string]*oauth2.Token
}

// NewMemoryCache returns an empty MemoryCache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{entries: map[string]*oauth2.Token{}}
}

// Load implements tokencache.Cache.
func (c *MemoryCache) Load(id string) (*oauth2.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	token, ok := c.entries[id]
	if !ok {
		return nil, tokencache.ErrMiss
	}

	return token, nil
}

// Store implements tokencache.Cache.
func (c *MemoryCache) Store(id string, token *oauth2.Token) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[id] = token

	return nil
}

// AccessTokens returns the access token of every entry, in no particular
// order.
func (c *MemoryCache) AccessTokens() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	tokens := make([]string, 0, len(c.entries))
	for _, token := range c.entries {
		tokens = append(tokens, token.AccessToken)
	}

	return tokens
}
