package tokencache

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// contextSource stands in for a source that holds and renews its own token:
// it answers every call with whatever token it currently holds and records
// the context each call came with. While blocked, a call waits for its
// context to end.
type contextSource struct {
	mu      sync.Mutex
	calls   int
	token   *oauth2.Token
	blocked bool
	lastCtx context.Context
}

func (s *contextSource) Token() (*oauth2.Token, error) {
	return s.TokenContext(context.Background())
}

func (s *contextSource) TokenContext(ctx context.Context) (*oauth2.Token, error) {
	s.mu.Lock()
	s.calls++
	s.lastCtx = ctx
	token, blocked := s.token, s.blocked
	s.mu.Unlock()

	if blocked {
		<-ctx.Done()

		return nil, ctx.Err()
	}

	return token, nil
}

func (s *contextSource) hold(token *oauth2.Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = token
}

func (s *contextSource) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.calls
}

func bearer(accessToken string, expiry time.Duration) *oauth2.Token {
	return &oauth2.Token{AccessToken: accessToken, TokenType: "Bearer", Expiry: at(expiry)}
}

func tokenContext(t *testing.T, source oauth2.TokenSource, ctx context.Context) (*oauth2.Token, error) {
	t.Helper()

	contextual, ok := source.(interface {
		TokenContext(context.Context) (*oauth2.Token, error)
	})
	if !ok {
		t.Fatalf("%T has no TokenContext", source)
	}

	return contextual.TokenContext(ctx)
}

// TestAContextSourceIsAskedOnEveryCall: a wrapped source that renews its
// own token only does so when it is asked, so once this process has a token
// of its own every call goes to that source, and a renewed token it answers
// with is served and stored.
func TestAContextSourceIsAskedOnEveryCall(t *testing.T) {
	inner := &contextSource{token: bearer("at-1", time.Hour)}
	cache := newMemoryCache()
	source := newSource(t, inner, cache)

	for i := range 3 {
		token, err := source.Token()
		if err != nil {
			t.Fatalf("Token call %d: %+v", i, err)
		}
		if token.AccessToken != "at-1" {
			t.Errorf("call %d: access token = %q, want at-1", i, token.AccessToken)
		}
	}
	if got := inner.count(); got != 3 {
		t.Errorf("wrapped source called %d times, want every call passed to it", got)
	}
	if cache.stores != 1 {
		t.Errorf("cache written %d times, want once for an unchanged token", cache.stores)
	}

	inner.hold(bearer("at-2", 2*time.Hour))

	token, err := source.Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if token.AccessToken != "at-2" {
		t.Errorf("access token = %q, want the renewed at-2", token.AccessToken)
	}
	if stored := cache.entries[sourceID(t, source)]; stored == nil || stored.AccessToken != "at-2" {
		t.Errorf("cache holds %v, want the renewed at-2", stored)
	}
}

// TestACachedTokenIsServedWithoutAskingAContextSource: a token read back
// from the cache keeps its skew rule, and is served from memory while it
// clears the skew, since the wrapped source has never seen it.
func TestACachedTokenIsServedWithoutAskingAContextSource(t *testing.T) {
	cache := newMemoryCache()
	inner := &contextSource{token: bearer("at-fresh", time.Hour)}
	source := newSource(t, inner, cache, WithSkew(time.Minute))
	cache.entries[sourceID(t, source)] = bearer("at-cached", 2*time.Minute)

	for i := range 3 {
		token, err := source.Token()
		if err != nil {
			t.Fatalf("Token call %d: %+v", i, err)
		}
		if token.AccessToken != "at-cached" {
			t.Errorf("call %d: access token = %q, want at-cached", i, token.AccessToken)
		}
	}
	if got := inner.count(); got != 0 {
		t.Errorf("wrapped source called %d times, want the cached token served", got)
	}
	if cache.loads != 1 {
		t.Errorf("cache read %d times, want once", cache.loads)
	}

	// The same entry inside the skew is spent, so the wrapped source is
	// asked instead.
	cache.entries[sourceID(t, source)] = bearer("at-cached", 30*time.Second)
	other := newSource(t, inner, cache, WithSkew(time.Minute))
	token, err := other.Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if token.AccessToken != "at-fresh" {
		t.Errorf("access token = %q, want at-fresh from the wrapped source", token.AccessToken)
	}
}

// TestTokenContextReachesAContextSource: the caller's context is what the
// wrapped source waits on, and nothing here is held while it does, so a
// second caller with its own deadline is not stuck behind the first.
func TestTokenContextReachesAContextSource(t *testing.T) {
	inner := &contextSource{blocked: true}
	source := newSource(t, inner, newMemoryCache())

	type key struct{}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), key{}, "caller"), 100*time.Millisecond)
	defer cancel()

	errs := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := tokenContext(t, source, ctx)
			errs <- err
		}()
	}

	for range 2 {
		select {
		case err := <-errs:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("TokenContext error = %v, want the context's deadline", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a caller went on waiting after its context ended")
		}
	}

	inner.mu.Lock()
	got := inner.lastCtx.Value(key{})
	inner.mu.Unlock()
	if got != "caller" {
		t.Errorf("wrapped source was asked on a context without the caller's value")
	}
}

// TestAnOvertakenAnswerDoesNotReplaceANewerToken: an answer that expires
// before the token already held came back after a renewal overtook it, and
// storing it would put the older token back in the cache.
func TestAnOvertakenAnswerDoesNotReplaceANewerToken(t *testing.T) {
	inner := &contextSource{token: bearer("at-2", 2*time.Hour)}
	cache := newMemoryCache()
	source := newSource(t, inner, cache)

	if _, err := source.Token(); err != nil {
		t.Fatalf("Token: %+v", err)
	}

	inner.hold(bearer("at-1", time.Hour))
	if _, err := source.Token(); err != nil {
		t.Fatalf("Token: %+v", err)
	}

	if stored := cache.entries[sourceID(t, source)]; stored == nil || stored.AccessToken != "at-2" {
		t.Errorf("cache holds %v, want the newer at-2 kept", stored)
	}
}

// TestAPlainSourceIsNotAskedWhileItsTokenIsValid: a wrapped source that
// takes no context is answered from the token held here, as before.
func TestAPlainSourceIsNotAskedWhileItsTokenIsValid(t *testing.T) {
	inner := &countingSource{}
	source := newSource(t, inner, newMemoryCache())

	for i := range 3 {
		if _, err := tokenContext(t, source, context.Background()); err != nil {
			t.Fatalf("TokenContext call %d: %+v", i, err)
		}
	}

	if got := inner.count(); got != 1 {
		t.Errorf("wrapped source called %d times, want 1", got)
	}
}
