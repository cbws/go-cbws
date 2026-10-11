package refresh

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.cbws.cloud/sdk/internal/tokentest"
	"go.cbws.cloud/sdk/oauth2/tokencache"
	"golang.org/x/oauth2"
)

// behindTokenCache builds a source behind a token cache, as credentials
// configured with one are. The clock starts at the wall clock's time,
// because the cache judges a token this process fetched by
// oauth2.Token.Valid, which reads the wall clock.
func behindTokenCache(t *testing.T) (oauth2.TokenSource, *TokenSource, *fakeSource, *fakeClock, *tokentest.MemoryCache) {
	t.Helper()

	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := &fakeClock{t: time.Now()}
	inner := &fakeSource{clock: clock, lifetime: time.Hour}
	source := NewTokenSource(inner, withClock(clock.now), WithLogger(quiet))
	cache := tokentest.NewMemoryCache()

	cached, err := tokencache.NewTokenSource(source, cache, tokencache.Key{
		Issuer:  "https://accounts.cbws.cloud/oauth2/token",
		Subject: t.Name(),
	}, tokencache.WithLogger(quiet))
	require.NoError(t, err)

	return cached, source, inner, clock, cache
}

// Inside the refresh window, calls through a token cache are answered at
// once with the held token while its replacement is fetched in the
// background, and the replacement is served and stored once it arrives.
// Nothing waits for it.
func TestTokenSource_RenewsInTheBackgroundBehindATokenCache(t *testing.T) {
	cached, source, inner, clock, cache := behindTokenCache(t)

	first, err := cached.Token()
	require.NoError(t, err)
	assert.Equal(t, "token-1", first.AccessToken)

	clock.advance(56*time.Minute + time.Second)
	release := inner.hold()

	for range 5 {
		token, err := cached.Token()
		require.NoError(t, err)
		assert.Equal(t, "token-1", token.AccessToken)
	}
	require.Eventually(t, func() bool { return inner.callCount() == 2 }, time.Second, time.Millisecond)
	release()
	source.fetches.Wait()

	renewed, err := cached.Token()
	require.NoError(t, err)
	assert.Equal(t, "token-2", renewed.AccessToken)
	assert.Equal(t, 2, inner.callCount())
	assert.Equal(t, []string{"token-2"}, cache.AccessTokens())
}

// A caller behind a token cache that gives up gets its context's error; the
// fetch carries on and serves the next caller.
func TestTokenSource_TokenContextReachesThroughATokenCache(t *testing.T) {
	cached, source, inner, _, _ := behindTokenCache(t)
	release := inner.hold()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	contextual, ok := cached.(interface {
		TokenContext(context.Context) (*oauth2.Token, error)
	})
	require.True(t, ok, "the token cache should take a context")

	done := make(chan error, 1)
	go func() {
		_, err := contextual.TokenContext(ctx)
		done <- err
	}()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		release()
		t.Fatal("TokenContext went on waiting after its context ended")
	}
	release()
	source.fetches.Wait()

	token, err := cached.Token()
	require.NoError(t, err)
	assert.Equal(t, "token-1", token.AccessToken)
	assert.Equal(t, 1, inner.callCount())
}
