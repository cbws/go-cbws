package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"go.cbws.cloud/sdk/oauth2/cli"
	service_account "go.cbws.cloud/sdk/oauth2/service-account"
	"go.cbws.cloud/sdk/oauth2/tokencache"

	"golang.org/x/oauth2"
)

// countingCache is a Cache that records what passed through it, so a test
// can tell a hit from a miss without inspecting the decorator.
type countingCache struct {
	mu      sync.Mutex
	entries map[string]*oauth2.Token
	stores  int
}

func newCountingCache() *countingCache {
	return &countingCache{entries: map[string]*oauth2.Token{}}
}

func (c *countingCache) Load(id string) (*oauth2.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	token, ok := c.entries[id]
	if !ok {
		return nil, tokencache.ErrMiss
	}

	return token, nil
}

func (c *countingCache) Store(id string, token *oauth2.Token) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stores++
	c.entries[id] = token

	return nil
}

func (c *countingCache) ids() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	ids := make([]string, 0, len(c.entries))
	for id := range c.entries {
		ids = append(ids, id)
	}

	return ids
}

// tokenEndpoint counts how often a token was actually minted, which is the
// number every test here is really about.
type tokenEndpoint struct {
	mu     sync.Mutex
	issued int
}

func (e *tokenEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.issued++

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  fmt.Sprintf("at-%d", e.issued),
		"token_type":    "bearer",
		"refresh_token": fmt.Sprintf("rt-%d", e.issued),
		"expires_in":    3600,
	})
}

func (e *tokenEndpoint) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.issued
}

// serveTokens points both the service-account and CLI flows at a fake
// authorization server for the duration of a test.
func serveTokens(t *testing.T) *tokenEndpoint {
	t.Helper()

	endpoint := &tokenEndpoint{}
	server := httptest.NewServer(endpoint)
	t.Cleanup(server.Close)

	previousSA := service_account.TokenURL()
	service_account.SetTokenURL(server.URL + "/token")
	t.Cleanup(func() { service_account.SetTokenURL(previousSA) })

	previousCLI := cli.Endpoint
	cli.Endpoint = oauth2.Endpoint{AuthURL: server.URL + "/auth", TokenURL: server.URL + "/token"}
	t.Cleanup(func() { cli.Endpoint = previousCLI })

	return endpoint
}

// TestCacheServesTheSecondProcess is the point of the whole package, taken
// through credential discovery rather than through the decorator: two
// lookups standing in for two short-lived processes, one token minted.
func TestCacheServesTheSecondProcess(t *testing.T) {
	for _, test := range []struct {
		name  string
		setUp func(t *testing.T, home string)
	}{
		{
			name: "a service account key",
			setUp: func(t *testing.T, home string) {
				t.Setenv("CBWS_CREDENTIALS", writeServiceAccountKey(t, home))
			},
		},
		{
			name: "the CLI configuration",
			setUp: func(t *testing.T, home string) {
				if err := os.WriteFile(filepath.Join(home, ".cbws.yaml"), []byte(tokenConfig), 0o600); err != nil {
					t.Fatalf("could not write the config: %+v", err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := isolate(t)
			endpoint := serveTokens(t)
			test.setUp(t, home)

			cache := newCountingCache()

			for i := range 2 {
				credentials, err := FindDefaultCredentialsWithOptions(
					context.Background(),
					[]string{"openid"},
					WithTokenCache(cache),
					WithCredentialGeneration("login-1"),
				)
				if err != nil {
					t.Fatalf("lookup %d: %+v", i, err)
				}

				token, err := credentials.TokenSource.Token()
				if err != nil {
					t.Fatalf("Token %d: %+v", i, err)
				}
				if token.AccessToken != "at-1" {
					t.Errorf("lookup %d served %q, want the single issued at-1", i, token.AccessToken)
				}
			}

			if got := endpoint.count(); got != 1 {
				t.Errorf("the authorization server issued %d tokens, want exactly 1", got)
			}
			if got := len(cache.ids()); got != 1 {
				t.Errorf("cache holds %d entries, want 1", got)
			}
		})
	}
}

// TestWithoutACacheNothingIsCached keeps the promise made to existing
// users: no cache configured means no wrapper and no reuse beyond the
// process, rather than the SDK picking somewhere to write tokens.
func TestWithoutACacheNothingIsCached(t *testing.T) {
	home := isolate(t)
	endpoint := serveTokens(t)
	t.Setenv("CBWS_CREDENTIALS", writeServiceAccountKey(t, home))

	for i := range 2 {
		credentials, err := FindDefaultCredentials(context.Background(), "openid")
		if err != nil {
			t.Fatalf("lookup %d: %+v", i, err)
		}

		if _, ok := credentials.TokenSource.(*tokencache.TokenSource); ok {
			t.Fatal("the token source was wrapped in a cache nobody asked for")
		}

		if _, err := credentials.TokenSource.Token(); err != nil {
			t.Fatalf("Token %d: %+v", i, err)
		}
	}

	if got := endpoint.count(); got != 2 {
		t.Errorf("the authorization server issued %d tokens, want one per lookup", got)
	}
}

// TestScopesIsolateCacheEntries: scopes bound what a token may do, so a
// lookup asking for more must not be served one issued for less.
func TestScopesIsolateCacheEntries(t *testing.T) {
	home := isolate(t)
	endpoint := serveTokens(t)
	t.Setenv("CBWS_CREDENTIALS", writeServiceAccountKey(t, home))

	cache := newCountingCache()

	for _, scopes := range [][]string{{"openid"}, {"openid", "compute"}} {
		credentials, err := FindDefaultCredentialsWithOptions(context.Background(), scopes, WithTokenCache(cache))
		if err != nil {
			t.Fatalf("lookup for %v: %+v", scopes, err)
		}
		if _, err := credentials.TokenSource.Token(); err != nil {
			t.Fatalf("Token for %v: %+v", scopes, err)
		}
	}

	if got := len(cache.ids()); got != 2 {
		t.Errorf("cache holds %d entries, want one per scope set", got)
	}
	if got := endpoint.count(); got != 2 {
		t.Errorf("the authorization server issued %d tokens, want one per scope set", got)
	}
}

// TestCredentialSourcesIsolateCacheEntries: a token minted for a service
// account is not a token for the logged-in user, however alike the requests
// look.
func TestCredentialSourcesIsolateCacheEntries(t *testing.T) {
	cache := newCountingCache()

	t.Run("service account", func(t *testing.T) {
		home := isolate(t)
		serveTokens(t)
		t.Setenv("CBWS_CREDENTIALS", writeServiceAccountKey(t, home))

		credentials, err := FindDefaultCredentialsWithOptions(context.Background(), []string{"openid"}, WithTokenCache(cache))
		if err != nil {
			t.Fatalf("lookup: %+v", err)
		}
		if _, err := credentials.TokenSource.Token(); err != nil {
			t.Fatalf("Token: %+v", err)
		}
	})

	t.Run("CLI configuration", func(t *testing.T) {
		home := isolate(t)
		serveTokens(t)
		if err := os.WriteFile(filepath.Join(home, ".cbws.yaml"), []byte(tokenConfig), 0o600); err != nil {
			t.Fatalf("could not write the config: %+v", err)
		}

		credentials, err := FindDefaultCredentialsWithOptions(
			context.Background(),
			[]string{"openid"},
			WithTokenCache(cache),
			WithCredentialGeneration("login-1"),
		)
		if err != nil {
			t.Fatalf("lookup: %+v", err)
		}
		if _, err := credentials.TokenSource.Token(); err != nil {
			t.Fatalf("Token: %+v", err)
		}
	})

	if got := len(cache.ids()); got != 2 {
		t.Errorf("cache holds %d entries, want the two credential sources kept apart", got)
	}
}

// TestNewFromJSONWithCache covers the explicit-key entry point, which a
// caller holding its own credentials uses instead of discovery.
func TestNewFromJSONWithCache(t *testing.T) {
	home := isolate(t)
	endpoint := serveTokens(t)

	data, err := os.ReadFile(writeServiceAccountKey(t, home))
	if err != nil {
		t.Fatalf("ReadFile: %+v", err)
	}

	cache := newCountingCache()

	for i := range 2 {
		credentials, err := NewFromJSONWithOptions(context.Background(), data, []string{"openid"}, WithTokenCache(cache))
		if err != nil {
			t.Fatalf("NewFromJSONWithOptions %d: %+v", i, err)
		}
		if _, err := credentials.TokenSource.Token(); err != nil {
			t.Fatalf("Token %d: %+v", i, err)
		}
	}

	if got := endpoint.count(); got != 1 {
		t.Errorf("the authorization server issued %d tokens, want exactly 1", got)
	}
}

// TestCacheOwnsTheAccessToken pins where the access token ends up, which is
// exactly one place in either configuration. With a cache the configuration
// file keeps only the refresh token; without one it keeps both, since that
// is the only cross-process reuse such a caller has.
func TestCacheOwnsTheAccessToken(t *testing.T) {
	t.Run("with a cache the configuration holds only the refresh token", func(t *testing.T) {
		home := isolate(t)
		serveTokens(t)
		path := filepath.Join(home, ".cbws.yaml")
		if err := os.WriteFile(path, []byte(tokenConfig), 0o600); err != nil {
			t.Fatalf("could not write the config: %+v", err)
		}

		cache := newCountingCache()

		credentials, err := FindDefaultCredentialsWithOptions(
			context.Background(),
			[]string{"openid"},
			WithTokenCache(cache),
			WithCredentialGeneration("login-1"),
		)
		if err != nil {
			t.Fatalf("lookup: %+v", err)
		}

		token, err := credentials.TokenSource.Token()
		if err != nil {
			t.Fatalf("Token: %+v", err)
		}
		if token.AccessToken != "at-1" {
			t.Fatalf("access token = %q, want at-1", token.AccessToken)
		}

		if got := configValue(t, path, "accesstoken"); got != "" {
			t.Errorf("configuration holds access token %q, want the cache to own it", got)
		}
		if got := configValue(t, path, "refreshtoken"); got != "rt-1" {
			t.Errorf("configuration refresh token = %q, want the rotated rt-1", got)
		}
		if cache.stores != 1 {
			t.Errorf("cache stored %d tokens, want 1", cache.stores)
		}
	})

	t.Run("without a cache the configuration keeps it", func(t *testing.T) {
		home := isolate(t)
		serveTokens(t)
		path := filepath.Join(home, ".cbws.yaml")
		if err := os.WriteFile(path, []byte(tokenConfig), 0o600); err != nil {
			t.Fatalf("could not write the config: %+v", err)
		}

		credentials, err := FindDefaultCredentials(context.Background(), "openid")
		if err != nil {
			t.Fatalf("lookup: %+v", err)
		}
		if _, err := credentials.TokenSource.Token(); err != nil {
			t.Fatalf("Token: %+v", err)
		}

		if got := configValue(t, path, "accesstoken"); got != "at-1" {
			t.Errorf("configuration access token = %q, want it kept for cross-process reuse", got)
		}
	})
}

// configValue pulls a scalar out of the configuration text by key.
func configValue(t *testing.T, path, key string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read %s: %+v", path, err)
	}

	for _, line := range strings.Split(string(content), "\n") {
		name, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if found && name == key {
			return strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}

	return ""
}

// TestCacheNeverHoldsTheRefreshToken: the token a CLI-configuration
// refresh returns carries the rotated, single-use refresh token. That
// credential belongs to the configuration store, under its lock and its
// login and logout lifecycle, and copying it into a cache would put it
// somewhere with none of those and where a logout cannot reach it.
func TestCacheNeverHoldsTheRefreshToken(t *testing.T) {
	home := isolate(t)
	serveTokens(t)
	if err := os.WriteFile(filepath.Join(home, ".cbws.yaml"), []byte(tokenConfig), 0o600); err != nil {
		t.Fatalf("could not write the config: %+v", err)
	}

	cache := newCountingCache()

	credentials, err := FindDefaultCredentialsWithOptions(
		context.Background(),
		[]string{"openid"},
		WithTokenCache(cache),
		WithCredentialGeneration("login-1"),
	)
	if err != nil {
		t.Fatalf("lookup: %+v", err)
	}

	token, err := credentials.TokenSource.Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}

	// The caller still gets whatever the source produced.
	if token.AccessToken != "at-1" {
		t.Errorf("caller was served %q, want at-1", token.AccessToken)
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	if len(cache.entries) != 1 {
		t.Fatalf("cache holds %d entries, want 1", len(cache.entries))
	}

	for id, cached := range cache.entries {
		if cached.RefreshToken != "" {
			t.Errorf("entry %s holds a refresh token, want only the bearer credential", id)
		}
		if cached.AccessToken != "at-1" {
			t.Errorf("entry %s holds access token %q, want at-1", id, cached.AccessToken)
		}
		if cached.Expiry.IsZero() {
			t.Errorf("entry %s has no expiry, so nothing can age it out", id)
		}
	}
}

// TestReloginIsNotServedTheEarlierSession is the reason the generation is
// required. The configuration path, issuer and scopes are all unchanged by
// logging out and back in, so without it the cache would go on serving the
// earlier session's token: as the wrong principal when the new login is
// someone else, and as a possibly revoked credential even when it is the
// same person again.
func TestReloginIsNotServedTheEarlierSession(t *testing.T) {
	home := isolate(t)
	endpoint := serveTokens(t)
	path := filepath.Join(home, ".cbws.yaml")

	cache := newCountingCache()

	tokenFor := func(t *testing.T, generation string) string {
		t.Helper()

		if err := os.WriteFile(path, []byte(tokenConfig), 0o600); err != nil {
			t.Fatalf("could not write the config: %+v", err)
		}

		credentials, err := FindDefaultCredentialsWithOptions(
			context.Background(),
			[]string{"openid"},
			WithTokenCache(cache),
			WithCredentialGeneration(generation),
		)
		if err != nil {
			t.Fatalf("lookup at %s: %+v", generation, err)
		}

		token, err := credentials.TokenSource.Token()
		if err != nil {
			t.Fatalf("Token at %s: %+v", generation, err)
		}

		return token.AccessToken
	}

	// Two logins by different people, and then a third by the first of
	// them again. That last one is the case a principal identity would get
	// wrong: same user, same path, same scopes, but the session before it
	// was logged out and its token may already have been revoked.
	first := tokenFor(t, "login-1")
	second := tokenFor(t, "login-2")
	relogin := tokenFor(t, "login-3")

	if first == second {
		t.Errorf("two logins were both served %q, want the second to have fetched its own", first)
	}
	if relogin == first || relogin == second {
		t.Errorf("a new login was served %q, an earlier session's token", relogin)
	}
	if got := endpoint.count(); got != 3 {
		t.Errorf("the authorization server issued %d tokens, want one per login", got)
	}
	if got := len(cache.ids()); got != 3 {
		t.Errorf("cache holds %d entries, want the logins kept apart", got)
	}

	// The same login asking again is still a hit, or the generation would
	// have cost the caching it exists to make safe.
	again := tokenFor(t, "login-3")
	if again != relogin {
		t.Errorf("the same login was served %q then %q, want the cached one", relogin, again)
	}
	if got := endpoint.count(); got != 3 {
		t.Errorf("the authorization server issued %d tokens, want the repeat served from cache", got)
	}
}

// TestCLIConfigIsNotCachedWithoutAGeneration: with no way to tell one
// login from the next, not caching is the safe answer, and the
// configuration goes on owning the access token exactly as it does with no
// cache at all.
func TestCLIConfigIsNotCachedWithoutAGeneration(t *testing.T) {
	home := isolate(t)
	endpoint := serveTokens(t)
	path := filepath.Join(home, ".cbws.yaml")
	if err := os.WriteFile(path, []byte(tokenConfig), 0o600); err != nil {
		t.Fatalf("could not write the config: %+v", err)
	}

	cache := newCountingCache()

	credentials, err := FindDefaultCredentialsWithOptions(context.Background(), []string{"openid"}, WithTokenCache(cache))
	if err != nil {
		t.Fatalf("lookup: %+v", err)
	}
	if _, err := credentials.TokenSource.Token(); err != nil {
		t.Fatalf("Token: %+v", err)
	}

	if got := len(cache.ids()); got != 0 {
		t.Errorf("cache holds %d entries, want none without a generation", got)
	}
	if got := configValue(t, path, "accesstoken"); got != "at-1" {
		t.Errorf("configuration access token = %q, want it kept since nothing else owns it", got)
	}
	if got := endpoint.count(); got != 1 {
		t.Errorf("the authorization server issued %d tokens, want 1", got)
	}
}
