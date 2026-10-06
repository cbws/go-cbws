package refresh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

var start = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeSource issues numbered tokens that live for lifetime on the test's
// clock. While held, fetches wait for release; err makes them fail; repeat
// makes them hand back the previous token, as a source answering from its own
// cache does.
type fakeSource struct {
	clock    *fakeClock
	lifetime time.Duration

	mu       sync.Mutex
	calls    int
	held     chan struct{}
	err      error
	repeat   bool
	nothing  bool
	noExpiry bool
	last     *oauth2.Token
}

func (f *fakeSource) Token() (*oauth2.Token, error) {
	f.mu.Lock()
	f.calls++
	n, held := f.calls, f.held
	f.mu.Unlock()

	if held != nil {
		<-held
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.err != nil:
		return nil, f.err
	case f.nothing:
		return nil, nil
	case f.repeat && f.last != nil:
		return f.last, nil
	}
	token := &oauth2.Token{AccessToken: fmt.Sprintf("token-%d", n), TokenType: "Bearer"}
	if !f.noExpiry {
		token.Expiry = f.clock.now().Add(f.lifetime)
	}
	f.last = token

	return token, nil
}

func (f *fakeSource) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.calls
}

func (f *fakeSource) hold() (release func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	held := make(chan struct{})
	f.held = held

	return func() {
		f.mu.Lock()
		f.held = nil
		f.mu.Unlock()
		close(held)
	}
}

func (f *fakeSource) set(apply func(*fakeSource)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	apply(f)
}

func newSource(t *testing.T, lifetime time.Duration) (*TokenSource, *fakeSource, *fakeClock) {
	t.Helper()

	clock := &fakeClock{t: start}
	inner := &fakeSource{clock: clock, lifetime: lifetime}
	source := NewTokenSource(inner, withClock(clock.now), WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))

	return source, inner, clock
}

func token(t *testing.T, s *TokenSource) string {
	t.Helper()

	token, err := s.Token()
	require.NoError(t, err)

	return token.AccessToken
}

func TestTokenSource_ServesTheHeldTokenFromMemory(t *testing.T) {
	s, inner, clock := newSource(t, time.Hour)

	assert.Equal(t, "token-1", token(t, s))
	clock.advance(50 * time.Minute)
	assert.Equal(t, "token-1", token(t, s))

	assert.Equal(t, 1, inner.callCount())
}

func TestTokenSource_ConcurrentCallersShareOneFetch(t *testing.T) {
	s, inner, _ := newSource(t, time.Hour)
	release := inner.hold()

	var wg sync.WaitGroup
	tokens := make([]string, 10)
	for i := range tokens {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := s.Token()
			assert.NoError(t, err)
			tokens[i] = token.AccessToken
		}()
	}
	require.Eventually(t, func() bool { return inner.callCount() == 1 }, time.Second, time.Millisecond)
	release()
	wg.Wait()

	assert.Equal(t, 1, inner.callCount())
	for _, token := range tokens {
		assert.Equal(t, "token-1", token)
	}
}

// In the last fifteenth of the lifetime a call answers at once with the held
// token and starts one background fetch, whose token replaces it.
func TestTokenSource_RefreshesAheadInTheBackground(t *testing.T) {
	s, inner, clock := newSource(t, time.Hour)
	token(t, s)
	clock.advance(56*time.Minute + time.Second)
	release := inner.hold()

	for range 5 {
		assert.Equal(t, "token-1", token(t, s))
	}
	require.Eventually(t, func() bool { return inner.callCount() == 2 }, time.Second, time.Millisecond)
	release()
	s.fetches.Wait()

	assert.Equal(t, 2, inner.callCount())
	assert.Equal(t, "token-2", token(t, s))
}

func TestTokenSource_DoesNotRefreshBeforeTheWindow(t *testing.T) {
	s, inner, clock := newSource(t, time.Hour)
	token(t, s)
	clock.advance(55 * time.Minute)

	token(t, s)
	s.fetches.Wait()

	assert.Equal(t, 1, inner.callCount())
}

// A failed background fetch leaves the held token served, retried no more
// often than RetryAfter. Inside the minimum validity the caller waits for a
// fetch and gets its outcome.
func TestTokenSource_FailedRefreshKeepsServingUntilTheMinimum(t *testing.T) {
	s, inner, clock := newSource(t, time.Hour)
	token(t, s)
	inner.set(func(f *fakeSource) { f.err = errors.New("issuer is down") })
	clock.advance(57 * time.Minute)

	assert.Equal(t, "token-1", token(t, s))
	s.fetches.Wait()
	clock.advance(5 * time.Second)
	assert.Equal(t, "token-1", token(t, s))
	s.fetches.Wait()
	assert.Equal(t, 2, inner.callCount(), "no retry within RetryAfter")

	clock.advance(5 * time.Second)
	token(t, s)
	s.fetches.Wait()
	assert.Equal(t, 3, inner.callCount(), "retried after RetryAfter")

	clock.advance(3*time.Minute - 15*time.Second) // ten seconds left
	_, err := s.Token()
	assert.EqualError(t, err, "issuer is down")

	inner.set(func(f *fakeSource) { f.err = nil })
	assert.Equal(t, "token-5", token(t, s))
}

// A source that answers from a cache of its own hands back the token already
// held when asked too early. That backs off like a failure instead of being
// asked again on every call.
func TestTokenSource_ANoNewerTokenBacksOff(t *testing.T) {
	s, inner, clock := newSource(t, time.Hour)
	token(t, s)
	inner.set(func(f *fakeSource) { f.repeat = true })
	clock.advance(57 * time.Minute)

	for range 5 {
		assert.Equal(t, "token-1", token(t, s))
		s.fetches.Wait()
	}
	assert.Equal(t, 2, inner.callCount())

	clock.advance(DefaultRetryAfter)
	token(t, s)
	s.fetches.Wait()
	assert.Equal(t, 3, inner.callCount())
}

func TestTokenSource_NeverServesInsideTheMinimumValidity(t *testing.T) {
	s, inner, clock := newSource(t, time.Hour)
	token(t, s)
	inner.set(func(f *fakeSource) { f.err = errors.New("refresh fails") })
	clock.advance(57 * time.Minute)
	token(t, s)
	s.fetches.Wait()
	inner.set(func(f *fakeSource) { f.err = nil })

	clock.advance(3*time.Minute - DefaultMinimumValidity) // exactly the minimum left

	assert.NotEqual(t, "token-1", token(t, s))
}

// A token that lives a minute, as the metadata endpoint's do, still has its
// replacement fetched before callers would wait: the window never shrinks
// below twice the minimum validity.
func TestTokenSource_ShortLivedTokensAreRefreshedAhead(t *testing.T) {
	s, inner, clock := newSource(t, time.Minute)
	token(t, s)
	clock.advance(40 * time.Second)

	assert.Equal(t, "token-1", token(t, s))
	s.fetches.Wait()

	assert.Equal(t, 2, inner.callCount())
	assert.Equal(t, "token-2", token(t, s))
}

// A caller that gives up gets its context's error; the fetch carries on and
// serves the next caller.
func TestTokenSource_TokenContextStopsWaitingButTheFetchCarriesOn(t *testing.T) {
	s, inner, _ := newSource(t, time.Hour)
	release := inner.hold()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := s.TokenContext(ctx)
	assert.ErrorIs(t, err, context.Canceled)
	release()
	s.fetches.Wait()

	assert.Equal(t, "token-1", token(t, s))
	assert.Equal(t, 1, inner.callCount())
}

func TestTokenSource_ATokenWithoutExpiryIsServedAndNeverRefreshed(t *testing.T) {
	s, inner, clock := newSource(t, time.Hour)
	inner.set(func(f *fakeSource) { f.noExpiry = true })
	token(t, s)
	clock.advance(24 * time.Hour)

	assert.Equal(t, "token-1", token(t, s))
	s.fetches.Wait()
	assert.Equal(t, 1, inner.callCount())
}

func TestTokenSource_NoTokenAndNoErrorIsAnError(t *testing.T) {
	s, inner, _ := newSource(t, time.Hour)
	inner.set(func(f *fakeSource) { f.nothing = true })

	_, err := s.Token()

	assert.ErrorIs(t, err, errNoToken)
}

func TestTokenSource_OptionsIgnoreValuesOutOfRange(t *testing.T) {
	s := NewTokenSource(&fakeSource{}, WithRefreshWithin(0), WithRefreshWithin(1.5), WithMinimumValidity(-time.Second), WithRetryAfter(-time.Second), WithLogger(nil))

	assert.Equal(t, DefaultRefreshWithin, s.refreshWithin)
	assert.Equal(t, DefaultMinimumValidity, s.minimumValidity)
	assert.Equal(t, DefaultRetryAfter, s.retryAfter)
	assert.NotNil(t, s.logger)
}
