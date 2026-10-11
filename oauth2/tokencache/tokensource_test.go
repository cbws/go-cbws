package tokencache

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// now is the instant the tests reason from, so an expiry is a statement
// about a token rather than a race with the clock. It is taken from the wall
// clock once rather than fixed, because a token this package obtained itself
// is judged by oauth2.Token.Valid, which reads the wall clock: against a
// fixed instant every such token is expired once that instant has passed.
var now = time.Now().UTC().Truncate(time.Second)

func at(offset time.Duration) time.Time { return now.Add(offset) }

// countingSource issues a fresh token per call and records how often it was
// asked, which is the thing every test here is really measuring.
type countingSource struct {
	mu     sync.Mutex
	calls  int
	expiry time.Duration
	err    error
}

func (s *countingSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err != nil {
		return nil, s.err
	}

	s.calls++

	expiry := s.expiry
	if expiry == 0 {
		expiry = time.Hour
	}

	return &oauth2.Token{
		AccessToken: fmt.Sprintf("at-%d", s.calls),
		TokenType:   "Bearer",
		Expiry:      at(expiry),
	}, nil
}

func (s *countingSource) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.calls
}

// memoryCache is the reference Cache: the smallest thing satisfying the
// interface, so the tests exercise the decorator rather than a fixture.
type memoryCache struct {
	mu      sync.Mutex
	entries map[string]*oauth2.Token
	loads   int
	stores  int
	loadErr error
	saveErr error
}

func newMemoryCache() *memoryCache {
	return &memoryCache{entries: map[string]*oauth2.Token{}}
}

func (c *memoryCache) Load(id string) (*oauth2.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loads++

	if c.loadErr != nil {
		return nil, c.loadErr
	}

	token, ok := c.entries[id]
	if !ok {
		return nil, ErrMiss
	}

	return token, nil
}

func (c *memoryCache) Store(id string, token *oauth2.Token) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stores++

	if c.saveErr != nil {
		return c.saveErr
	}

	c.entries[id] = token

	return nil
}

func (c *memoryCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.entries)
}

func testKey() Key {
	return Key{Issuer: "https://accounts.cbws.cloud/oauth2/token", Subject: "sa-client-id"}
}

func quiet() Option {
	return WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// newSource builds a decorator over inner with the test clock pinned, so
// expiry is decided by the fixture rather than by how long the test took.
func newSource(t *testing.T, inner oauth2.TokenSource, cache Cache, options ...Option) oauth2.TokenSource {
	t.Helper()

	// Each test gets its own key, so the process-wide refresh lock and the
	// shared cache cannot leak between them.
	key := testKey()
	key.Subject = t.Name()

	options = append([]Option{withClock(func() time.Time { return now }), quiet()}, options...)

	source, err := NewTokenSource(inner, cache, key, options...)
	if err != nil {
		t.Fatalf("NewTokenSource: %+v", err)
	}

	return source
}

// TestCacheMissFetchesAndStores is the first call: nothing cached, so the
// wrapped source is asked and the answer is kept.
func TestCacheMissFetchesAndStores(t *testing.T) {
	inner := &countingSource{}
	cache := newMemoryCache()

	token, err := newSource(t, inner, cache).Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}

	if token.AccessToken != "at-1" {
		t.Errorf("access token = %q, want at-1", token.AccessToken)
	}
	if inner.count() != 1 {
		t.Errorf("wrapped source called %d times, want 1", inner.count())
	}
	if cache.len() != 1 {
		t.Errorf("cache holds %d entries, want 1", cache.len())
	}
}

// TestCacheHitSkipsTheWrappedSource is the point of the package: a second
// process, standing in as a second source over the same cache, must not go
// back to the authorization server.
func TestCacheHitSkipsTheWrappedSource(t *testing.T) {
	inner := &countingSource{}
	cache := newMemoryCache()

	first := newSource(t, inner, cache)
	if _, err := first.Token(); err != nil {
		t.Fatalf("first Token: %+v", err)
	}

	// A separate source over the same cache and key: another process.
	second := newSource(t, inner, cache)

	token, err := second.Token()
	if err != nil {
		t.Fatalf("second Token: %+v", err)
	}

	if token.AccessToken != "at-1" {
		t.Errorf("access token = %q, want the cached at-1", token.AccessToken)
	}
	if got := inner.count(); got != 1 {
		t.Errorf("wrapped source called %d times, want 1", got)
	}
}

// TestRepeatedCallsUseTheInMemoryCopy: a cache hit still costs a read, and
// a source asked many times in one process should not pay it every time.
func TestRepeatedCallsUseTheInMemoryCopy(t *testing.T) {
	inner := &countingSource{}
	cache := newMemoryCache()
	source := newSource(t, inner, cache)

	for i := range 5 {
		if _, err := source.Token(); err != nil {
			t.Fatalf("Token call %d: %+v", i, err)
		}
	}

	if got := inner.count(); got != 1 {
		t.Errorf("wrapped source called %d times, want 1", got)
	}
	if cache.loads > 1 {
		t.Errorf("cache read %d times, want at most 1 after the first call", cache.loads)
	}
}

// TestExpiryAndSkew fixes what counts as still usable. The skew is the
// margin a token has to clear, so a token expiring inside it is a miss even
// though it has not expired.
func TestExpiryAndSkew(t *testing.T) {
	tests := []struct {
		name    string
		expiry  time.Time
		skew    time.Duration
		wantHit bool
	}{
		{name: "comfortably valid", expiry: at(time.Hour), skew: DefaultSkew, wantHit: true},
		{name: "just outside the skew", expiry: at(DefaultSkew + time.Second), skew: DefaultSkew, wantHit: true},
		{name: "exactly at the skew", expiry: at(DefaultSkew), skew: DefaultSkew},
		{name: "inside the skew", expiry: at(time.Second), skew: DefaultSkew},
		{name: "expired", expiry: at(-time.Hour), skew: DefaultSkew},
		{name: "no expiry at all", skew: DefaultSkew},
		{name: "a zero skew still rejects an expired token", expiry: at(-time.Second)},
		{name: "a zero skew accepts a token about to expire", expiry: at(time.Second), wantHit: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inner := &countingSource{}
			cache := newMemoryCache()
			source := newSource(t, inner, cache, WithSkew(test.skew))

			id := sourceID(t, source)
			cache.entries[id] = &oauth2.Token{AccessToken: "at-cached", TokenType: "Bearer", Expiry: test.expiry}

			token, err := source.Token()
			if err != nil {
				t.Fatalf("Token: %+v", err)
			}

			cached := token.AccessToken == "at-cached"
			if cached != test.wantHit {
				t.Errorf("served %q, want a cache hit = %v", token.AccessToken, test.wantHit)
			}

			wantCalls := 1
			if test.wantHit {
				wantCalls = 0
			}
			if got := inner.count(); got != wantCalls {
				t.Errorf("wrapped source called %d times, want %d", got, wantCalls)
			}
		})
	}
}

// TestNearExpiryEntryIsReplaced: a stale entry must not merely be skipped,
// it has to be overwritten, or every later process pays the same miss.
func TestNearExpiryEntryIsReplaced(t *testing.T) {
	inner := &countingSource{}
	cache := newMemoryCache()
	source := newSource(t, inner, cache)

	id := sourceID(t, source)
	cache.entries[id] = &oauth2.Token{AccessToken: "at-stale", TokenType: "Bearer", Expiry: at(time.Second)}

	if _, err := source.Token(); err != nil {
		t.Fatalf("Token: %+v", err)
	}

	if got := cache.entries[id].AccessToken; got != "at-1" {
		t.Errorf("cached token = %q, want the fresh at-1 to have replaced the stale entry", got)
	}
}

// TestMalformedEntryIsAMiss: a Cache reporting something other than ErrMiss
// must not fail the call. An entry that cannot be read and one that is not
// there call for the same thing.
func TestMalformedEntryIsAMiss(t *testing.T) {
	inner := &countingSource{}
	cache := newMemoryCache()
	cache.loadErr = errors.New("entry is not valid JSON")

	token, err := newSource(t, inner, cache).Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if token.AccessToken != "at-1" {
		t.Errorf("access token = %q, want a freshly fetched at-1", token.AccessToken)
	}
}

// TestStoreFailureStillServesTheToken pins the documented policy: a cache
// that cannot be written costs the next process a fetch and nothing else,
// so it must never fail a call this one could serve. This is deliberately
// the opposite of the refresh-token store, where a failed write leaves a
// spent token behind.
func TestStoreFailureStillServesTheToken(t *testing.T) {
	inner := &countingSource{}
	cache := newMemoryCache()
	cache.saveErr = errors.New("read-only file system")

	token, err := newSource(t, inner, cache).Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if token.AccessToken != "at-1" {
		t.Errorf("access token = %q, want at-1", token.AccessToken)
	}
}

// TestWrappedSourceFailurePropagates: the cache has nothing to offer when
// the source behind it cannot produce a token.
func TestWrappedSourceFailurePropagates(t *testing.T) {
	want := errors.New("the authorization server said no")
	inner := &countingSource{err: want}

	_, err := newSource(t, inner, newMemoryCache()).Token()
	if !errors.Is(err, want) {
		t.Errorf("error = %v, want %v", err, want)
	}
}

// TestConcurrentCallersShareOneSource: callers of one source are
// serialized by it, so a burst of goroutines behind a single source fetches
// once.
func TestConcurrentCallersShareOneSource(t *testing.T) {
	inner := &countingSource{}
	source := newSource(t, inner, newMemoryCache())

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if _, err := source.Token(); err != nil {
				t.Errorf("Token: %+v", err)
			}
		}()
	}
	wg.Wait()

	if got := inner.count(); got != 1 {
		t.Errorf("wrapped source called %d times, want exactly 1", got)
	}
}

// TestSeparateSourcesMayEachFetch is the trade written down: nothing
// coalesces two sources over one key, because doing so means holding a lock
// across the wrapped source and that is what lets a nested wrapper wait on
// its own caller. The duplicate is harmless; the entry they converge on is
// the point.
func TestSeparateSourcesMayEachFetch(t *testing.T) {
	inner := &countingSource{}
	cache := newMemoryCache()

	sources := make([]oauth2.TokenSource, 4)
	for i := range sources {
		sources[i] = newSource(t, inner, cache)
	}

	var wg sync.WaitGroup
	for _, source := range sources {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if _, err := source.Token(); err != nil {
				t.Errorf("Token: %+v", err)
			}
		}()
	}
	wg.Wait()

	if got := cache.len(); got != 1 {
		t.Errorf("cache holds %d entries, want the sources to have converged on one", got)
	}

	// And once the entry is there, a later source reads it rather than
	// fetching, which is the reuse this package is for.
	before := inner.count()
	if _, err := newSource(t, inner, cache).Token(); err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if got := inner.count(); got != before {
		t.Errorf("a later source fetched again, want it served from the cache")
	}
}

// sourceID digs out the identifier a source stores under, so a test can
// plant an entry where that source will look for it.
func sourceID(t *testing.T, source oauth2.TokenSource) string {
	t.Helper()

	cached, ok := source.(*TokenSource)
	if !ok {
		t.Fatalf("source is %T, want *TokenSource", source)
	}

	return cached.id
}

// TestOnlyTheBearerCredentialIsCached: a source may return a token
// carrying a refresh token and whatever else the authorization server
// sent. This cache is for access tokens, and a long-lived credential
// copied in here would sit outside the store that owns it.
func TestOnlyTheBearerCredentialIsCached(t *testing.T) {
	full := &oauth2.Token{
		AccessToken:  "at-1",
		TokenType:    "Bearer",
		RefreshToken: "rt-secret",
		Expiry:       at(time.Hour),
	}
	full = full.WithExtra(map[string]any{"id_token": "id-secret"})

	cache := newMemoryCache()
	source := newSource(t, oauth2.StaticTokenSource(full), cache)

	served, err := source.Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}

	// The caller keeps everything the source produced.
	if served.RefreshToken != "rt-secret" {
		t.Errorf("caller was served refresh token %q, want it passed through", served.RefreshToken)
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	for id, cached := range cache.entries {
		if cached.RefreshToken != "" {
			t.Errorf("entry %s holds a refresh token", id)
		}
		if cached.Extra("id_token") != nil {
			t.Errorf("entry %s holds the id token", id)
		}
		if cached.AccessToken != "at-1" || cached.Expiry != full.Expiry {
			t.Errorf("entry %s = %+v, want the bearer credential and its expiry", id, cached)
		}
	}
}

// TestATokenAlreadyInsideTheSkewIsNotCached: the source behind this one
// refreshes on a narrower margin than the skew, so it can return something
// it considers current and this considers spent. Storing that would fill
// the cache with entries every later reader rejects.
func TestATokenAlreadyInsideTheSkewIsNotCached(t *testing.T) {
	nearly := &oauth2.Token{AccessToken: "at-nearly", TokenType: "Bearer", Expiry: at(5 * time.Second)}

	cache := newMemoryCache()
	source := newSource(t, oauth2.StaticTokenSource(nearly), cache)

	// The caller is still served: it is the best token available, and
	// failing would be worse than handing over one that is still valid.
	served, err := source.Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if served.AccessToken != "at-nearly" {
		t.Errorf("caller was served %q, want at-nearly", served.AccessToken)
	}

	if got := cache.len(); got != 0 {
		t.Errorf("cache holds %d entries, want none for a token inside the skew", got)
	}
}

// TestTokenTypeIsChecked: an entry naming a scheme CBWS does not issue is
// a miss rather than something to present. An empty type is Bearer by
// oauth2's own default, and the comparison ignores case because the
// spelling on the wire varies.
func TestTokenTypeIsChecked(t *testing.T) {
	for _, test := range []struct {
		name      string
		tokenType string
		wantHit   bool
	}{
		{name: "Bearer", tokenType: "Bearer", wantHit: true},
		{name: "lower case bearer", tokenType: "bearer", wantHit: true},
		{name: "shouting", tokenType: "BEARER", wantHit: true},
		{name: "empty defaults to Bearer", wantHit: true},
		{name: "MAC", tokenType: "mac"},
		{name: "nonsense", tokenType: "not-a-scheme"},
	} {
		t.Run(test.name, func(t *testing.T) {
			inner := &countingSource{}
			cache := newMemoryCache()
			source := newSource(t, inner, cache)

			cache.entries[sourceID(t, source)] = &oauth2.Token{
				AccessToken: "at-cached",
				TokenType:   test.tokenType,
				Expiry:      at(time.Hour),
			}

			token, err := source.Token()
			if err != nil {
				t.Fatalf("Token: %+v", err)
			}

			if hit := token.AccessToken == "at-cached"; hit != test.wantHit {
				t.Errorf("served %q, want a cache hit = %v", token.AccessToken, test.wantHit)
			}
		})
	}
}

// TestWrappingThroughAConcealingDecorator is the deadlock regression. An
// outer source that held a lock shared with the inner one would wait on
// itself here, and no inspection of the wrapped source could have seen it
// coming: ReuseTokenSource hides what it wraps, as any decorator may.
func TestWrappingThroughAConcealingDecorator(t *testing.T) {
	cache := newMemoryCache()
	key := Key{Issuer: "https://accounts.cbws.cloud/oauth2/token", Subject: t.Name()}

	inner, err := NewTokenSource(&countingSource{}, cache, key, quiet())
	if err != nil {
		t.Fatalf("NewTokenSource: %+v", err)
	}

	// The same key again, with the cached source hidden behind a decorator.
	outer, err := NewTokenSource(oauth2.ReuseTokenSource(nil, inner), cache, key, quiet())
	if err != nil {
		t.Fatalf("NewTokenSource: %+v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)

		if _, err := outer.Token(); err != nil {
			t.Errorf("Token: %+v", err)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Token deadlocked waiting on a lock its own caller holds")
	}
}

// TestEachWrapUsesWhatItWasGiven: a source is never folded into an
// existing one, so a second wrap cannot silently keep the first one's
// cache or options while appearing to take new ones.
func TestEachWrapUsesWhatItWasGiven(t *testing.T) {
	first, second := newMemoryCache(), newMemoryCache()
	key := Key{Issuer: "https://accounts.cbws.cloud/oauth2/token", Subject: t.Name()}

	inner, err := NewTokenSource(&countingSource{}, first, key, quiet())
	if err != nil {
		t.Fatalf("NewTokenSource: %+v", err)
	}

	outer, err := NewTokenSource(inner, second, key, quiet(), WithSkew(time.Minute))
	if err != nil {
		t.Fatalf("NewTokenSource: %+v", err)
	}

	wrapper, ok := outer.(*TokenSource)
	if !ok {
		t.Fatalf("outer is %T, want *TokenSource", outer)
	}
	if wrapper.cache != Cache(second) {
		t.Error("the second wrap kept the first one's cache")
	}
	if wrapper.skew != time.Minute {
		t.Errorf("skew = %v, want the option applied to the second wrap", wrapper.skew)
	}

	if _, err := outer.Token(); err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if second.len() != 1 {
		t.Errorf("the cache passed to the second wrap holds %d entries, want 1", second.len())
	}
}

// TestACacheHitIsNarrowedToo: writes go through accessOnly, but this
// package owns the boundary in both directions and cannot assume every
// Cache enforced it. An entry written by an older version, another
// implementation or a hand edit may hold more than a bearer credential.
func TestACacheHitIsNarrowedToo(t *testing.T) {
	inner := &countingSource{}
	cache := newMemoryCache()
	source := newSource(t, inner, cache)
	id := sourceID(t, source)

	overfull := &oauth2.Token{
		AccessToken:  "at-cached",
		TokenType:    "Bearer",
		RefreshToken: "rt-secret",
		Expiry:       at(time.Hour),
	}
	cache.entries[id] = overfull.WithExtra(map[string]any{"id_token": "id-secret"})

	served, err := source.Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}

	if served.AccessToken != "at-cached" {
		t.Fatalf("served %q, want the cached at-cached", served.AccessToken)
	}
	if served.RefreshToken != "" {
		t.Errorf("caller was handed refresh token %q out of the cache", served.RefreshToken)
	}
	if served.Extra("id_token") != nil {
		t.Error("caller was handed an id token out of the cache")
	}

	// The source keeps the narrowed token, not the entry as found.
	if held := source.(*TokenSource).token; held.RefreshToken != "" {
		t.Errorf("the source retained refresh token %q in memory", held.RefreshToken)
	}

	// And the surplus stops sitting in storage rather than merely stopping
	// at this boundary.
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if got := cache.entries[id].RefreshToken; got != "" {
		t.Errorf("the entry still holds refresh token %q, want it narrowed in place", got)
	}
}

// TestAFreshTokenWithoutExpiryIsReused: the strict rule is for entries
// read back from storage. A token this process just obtained is judged the
// way every other oauth2 source judges one, or a source returning no
// expiry would be called again on every single request.
func TestAFreshTokenWithoutExpiryIsReused(t *testing.T) {
	undated := &oauth2.Token{AccessToken: "at-undated", TokenType: "Bearer"}

	inner := &countingSource{}
	cache := newMemoryCache()

	source := newSource(t, countedStatic{inner: inner, token: undated}, cache)

	for i := range 5 {
		token, err := source.Token()
		if err != nil {
			t.Fatalf("Token %d: %+v", i, err)
		}
		if token.AccessToken != "at-undated" {
			t.Fatalf("Token %d served %q, want at-undated", i, token.AccessToken)
		}
	}

	if got := inner.count(); got != 1 {
		t.Errorf("wrapped source called %d times, want it asked once", got)
	}

	// It is still never written: nothing about a stored entry would say
	// how old it is, so one that never expires could be served forever.
	if got := cache.len(); got != 0 {
		t.Errorf("cache holds %d entries, want a token with no expiry left out", got)
	}
}

// countedStatic returns a fixed token while recording the calls through
// the counter it is given.
type countedStatic struct {
	inner *countingSource
	token *oauth2.Token
}

func (c countedStatic) Token() (*oauth2.Token, error) {
	if _, err := c.inner.Token(); err != nil {
		return nil, err
	}

	return c.token, nil
}

// TestANilEntryIsAMiss: a Cache reporting neither a token nor an error is
// not something any implementation should do, but it must not become a nil
// dereference here.
func TestANilEntryIsAMiss(t *testing.T) {
	inner := &countingSource{}

	token, err := newSource(t, inner, nilEntryCache{}).Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if token.AccessToken != "at-1" {
		t.Errorf("served %q, want a freshly fetched at-1", token.AccessToken)
	}
}

// TestNarrowingAnEntryInPlaceIsBestEffort: failing to rewrite an over-full
// entry still leaves a usable token that has been narrowed at this
// boundary, which is the part that protects the caller.
func TestNarrowingAnEntryInPlaceIsBestEffort(t *testing.T) {
	inner := &countingSource{}
	cache := newMemoryCache()
	source := newSource(t, inner, cache)

	cache.entries[sourceID(t, source)] = &oauth2.Token{
		AccessToken:  "at-cached",
		TokenType:    "Bearer",
		RefreshToken: "rt-secret",
		Expiry:       at(time.Hour),
	}
	cache.saveErr = errors.New("read-only file system")

	token, err := source.Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if token.AccessToken != "at-cached" {
		t.Errorf("served %q, want the cached at-cached", token.AccessToken)
	}
	if token.RefreshToken != "" {
		t.Errorf("caller was handed refresh token %q despite the rewrite failing", token.RefreshToken)
	}
	if got := inner.count(); got != 0 {
		t.Errorf("wrapped source called %d times, want the entry still served", got)
	}
}

// nilEntryCache reports neither a token nor an error.
type nilEntryCache struct{}

func (nilEntryCache) Load(string) (*oauth2.Token, error) { return nil, nil }
func (nilEntryCache) Store(string, *oauth2.Token) error  { return nil }

// TestNestedWrappersDoNotDeadlock is the regression for a lock held across
// the wrapped source. The previous shape passed only because the fake cache
// had no locking to hold, which is why this one uses a cache that locks for
// real, both with the inner source in plain sight and hidden behind a
// decorator.
func TestNestedWrappersDoNotDeadlock(t *testing.T) {
	for _, test := range []struct {
		name    string
		conceal func(oauth2.TokenSource) oauth2.TokenSource
	}{
		{name: "directly nested", conceal: func(s oauth2.TokenSource) oauth2.TokenSource { return s }},
		{name: "behind a decorator", conceal: func(s oauth2.TokenSource) oauth2.TokenSource {
			return oauth2.ReuseTokenSource(nil, s)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache := newSerializingCache()
			key := Key{Issuer: "https://accounts.cbws.cloud/oauth2/token", Subject: t.Name()}

			inner, err := NewTokenSource(&countingSource{}, cache, key, quiet())
			if err != nil {
				t.Fatalf("NewTokenSource: %+v", err)
			}

			outer, err := NewTokenSource(test.conceal(inner), cache, key, quiet())
			if err != nil {
				t.Fatalf("NewTokenSource: %+v", err)
			}

			done := make(chan struct{})
			go func() {
				defer close(done)

				if _, err := outer.Token(); err != nil {
					t.Errorf("Token: %+v", err)
				}
			}()

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Token deadlocked waiting on a lock its own caller holds")
			}

			if cache.overlapped() {
				t.Error("a cache operation began while another was still in flight, so something is held across the wrapped source")
			}
		})
	}
}

// serializingCache serializes its own operations, as any implementation
// backed by a file or a shared store would, and reports when an operation
// began while another was still in flight.
//
// That report is the real assertion. A wrapper that held a cache lock
// across the source it wraps would have the nested wrapper enter while the
// outer one was still inside, which on a genuine implementation is a
// deadlock rather than a failed test. Trying the lock rather than taking it
// turns that hang into something a test can state.
type serializingCache struct {
	memoryCache

	exclusive sync.Mutex

	reentryMu sync.Mutex
	reentered bool
}

func newSerializingCache() *serializingCache {
	return &serializingCache{memoryCache: memoryCache{entries: map[string]*oauth2.Token{}}}
}

func (c *serializingCache) enter() func() {
	if !c.exclusive.TryLock() {
		c.reentryMu.Lock()
		c.reentered = true
		c.reentryMu.Unlock()

		c.exclusive.Lock()
	}

	return c.exclusive.Unlock
}

func (c *serializingCache) Load(id string) (*oauth2.Token, error) {
	defer c.enter()()

	return c.memoryCache.Load(id)
}

func (c *serializingCache) Store(id string, token *oauth2.Token) error {
	defer c.enter()()

	return c.memoryCache.Store(id, token)
}

func (c *serializingCache) overlapped() bool {
	c.reentryMu.Lock()
	defer c.reentryMu.Unlock()

	return c.reentered
}

// TestACachedTokenKeepsTheConfiguredSkew: an entry is accepted because it
// clears the skew, and time passing does not make it clear it again. Left
// to oauth2's own ten second margin, a token taken at thirty-one seconds
// would go on being served from memory down to ten.
//
// The assertion in the middle asks oauth2.Token.Valid, which reads the wall
// clock whatever this source is told the time is, so only the injected
// clock is moved: what changes between the two calls is the source's view
// of the time and nothing else.
func TestACachedTokenKeepsTheConfiguredSkew(t *testing.T) {
	inner := &countingSource{}
	cache := newMemoryCache()

	clock := now

	source, err := NewTokenSource(inner, cache, Key{Issuer: "i", Subject: t.Name()},
		withClock(func() time.Time { return clock }), quiet())
	if err != nil {
		t.Fatalf("NewTokenSource: %+v", err)
	}

	cached := source.(*TokenSource)
	cache.entries[cached.id] = &oauth2.Token{
		AccessToken: "at-cached",
		TokenType:   "Bearer",
		Expiry:      at(DefaultSkew + time.Second),
	}

	token, err := source.Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if token.AccessToken != "at-cached" {
		t.Fatalf("served %q, want the cached at-cached", token.AccessToken)
	}

	// Two seconds on, the entry is inside the skew. It is still valid by
	// oauth2's reckoning, which is exactly the gap being closed.
	clock = clock.Add(2 * time.Second)
	if !cached.token.Valid() {
		t.Fatal("the fixture no longer exercises the gap: the token has expired outright")
	}

	token, err = source.Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if token.AccessToken != "at-1" {
		t.Errorf("served %q, want a fresh token once the cached one entered the skew", token.AccessToken)
	}
}

// TestAnEntryHoldingOnlyAnIdTokenIsNarrowedInStorage: the rewrite used to
// trigger on a refresh token alone, so an entry whose only surplus was an
// id token stayed over-full at rest.
func TestAnEntryHoldingOnlyAnIdTokenIsNarrowedInStorage(t *testing.T) {
	inner := &countingSource{}
	cache := newMemoryCache()
	source := newSource(t, inner, cache)
	id := sourceID(t, source)

	entry := &oauth2.Token{AccessToken: "at-cached", TokenType: "Bearer", Expiry: at(time.Hour)}
	cache.entries[id] = entry.WithExtra(map[string]any{"id_token": "id-secret"})

	token, err := source.Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if token.Extra("id_token") != nil {
		t.Error("caller was handed an id token")
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.entries[id].Extra("id_token") != nil {
		t.Error("the entry still holds an id token, want it narrowed in place")
	}
}

// TestAnUnusableOverFullEntryIsStillCleaned: an entry that has expired or
// cannot be presented still has the credential in it, and it is the entry
// most likely to sit there untouched, since nothing overwrites it until a
// fetch succeeds. Narrowing it has to happen before it is judged.
func TestAnUnusableOverFullEntryIsStillCleaned(t *testing.T) {
	failure := errors.New("the authorization server is unreachable")
	cache := newMemoryCache()
	source := newSource(t, &countingSource{err: failure}, cache)
	id := sourceID(t, source)

	expired := &oauth2.Token{AccessToken: "at-expired", TokenType: "Bearer", Expiry: at(-time.Hour)}
	cache.entries[id] = expired.WithExtra(map[string]any{"id_token": "id-secret"})

	// The caller hears about the source it could not reach, unchanged.
	if _, err := source.Token(); !errors.Is(err, failure) {
		t.Fatalf("error = %v, want %v", err, failure)
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	entry, ok := cache.entries[id]
	if !ok {
		t.Fatal("the entry disappeared, want it narrowed rather than dropped")
	}
	if entry.Extra("id_token") != nil {
		t.Error("the entry still holds an id token, want it cleaned even though it could not be served")
	}
}

// TestAnUnusableEntryThatIsAlreadyNarrowIsLeftAlone: cleaning is for
// entries holding more than they should, not a write on every miss.
func TestAnUnusableEntryThatIsAlreadyNarrowIsLeftAlone(t *testing.T) {
	inner := &countingSource{}
	cache := newMemoryCache()
	source := newSource(t, inner, cache)
	id := sourceID(t, source)

	cache.entries[id] = &oauth2.Token{AccessToken: "at-expired", TokenType: "Bearer", Expiry: at(-time.Hour)}
	before := cache.stores

	if _, err := source.Token(); err != nil {
		t.Fatalf("Token: %+v", err)
	}

	// One write, for the token that replaced it, and none for cleaning.
	if got := cache.stores - before; got != 1 {
		t.Errorf("cache written %d times, want only the replacement", got)
	}
}
