package option

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	service_account "go.cbws.cloud/sdk/oauth2/service-account"
	"go.cbws.cloud/sdk/oauth2/tokencache"

	"golang.org/x/oauth2"
)

// memoryCache is the smallest thing satisfying tokencache.Cache, so these
// tests exercise the plumbing rather than a storage implementation.
type memoryCache struct {
	mu      sync.Mutex
	entries map[string]*oauth2.Token
}

func newMemoryCache() *memoryCache {
	return &memoryCache{entries: map[string]*oauth2.Token{}}
}

func (c *memoryCache) Load(id string) (*oauth2.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	token, ok := c.entries[id]
	if !ok {
		return nil, tokencache.ErrMiss
	}

	return token, nil
}

func (c *memoryCache) Store(id string, token *oauth2.Token) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[id] = token

	return nil
}

func (c *memoryCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.entries)
}

// tokenEndpoint counts how often a token was actually minted.
type tokenEndpoint struct {
	mu     sync.Mutex
	issued int
}

func (e *tokenEndpoint) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.issued++

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": fmt.Sprintf("at-%d", e.issued),
		"token_type":   "bearer",
		"expires_in":   3600,
	})
}

func (e *tokenEndpoint) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.issued
}

func serveTokens(t *testing.T) *tokenEndpoint {
	t.Helper()

	endpoint := &tokenEndpoint{}
	server := httptest.NewServer(endpoint)
	t.Cleanup(server.Close)

	previous := service_account.TokenURL()
	service_account.SetTokenURL(server.URL + "/token")
	t.Cleanup(func() { service_account.SetTokenURL(previous) })

	return endpoint
}

// TestDialSettingsCarryTheCache is the gap this covers: the cache is
// reachable from the option API a client is actually configured with,
// rather than only by building OAuth credentials by hand.
func TestDialSettingsCarryTheCache(t *testing.T) {
	cache := newMemoryCache()

	var settings DialSettings
	for _, option := range []ClientOption{
		WithTokenCache(cache),
		WithCredentialGeneration("login-1"),
	} {
		option.Apply(&settings)
	}

	if settings.TokenCache != tokencache.Cache(cache) {
		t.Error("WithTokenCache did not reach the dial settings")
	}
	if settings.CredentialGeneration != "login-1" {
		t.Errorf("CredentialGeneration = %q, want login-1", settings.CredentialGeneration)
	}
}

// TestCredsUsesTheCache walks the paths Creds takes and checks each one
// reuses a token rather than minting a second.
func TestCredsUsesTheCache(t *testing.T) {
	key := writeServiceAccountKey(t, t.TempDir())

	for _, test := range []struct {
		name     string
		settings func(t *testing.T) DialSettings
	}{
		{
			name: "credentials JSON",
			settings: func(t *testing.T) DialSettings {
				data, err := os.ReadFile(key)
				if err != nil {
					t.Fatalf("ReadFile: %+v", err)
				}

				return DialSettings{CredentialsJSON: data}
			},
		},
		{
			name:     "credentials file",
			settings: func(*testing.T) DialSettings { return DialSettings{CredentialsFile: key} },
		},
		{
			name: "the default lookup",
			settings: func(t *testing.T) DialSettings {
				t.Setenv("CBWS_CREDENTIALS", key)

				return DialSettings{}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoint := serveTokens(t)
			cache := newMemoryCache()

			for i := range 2 {
				settings := test.settings(t)
				settings.Scopes = []string{"openid"}
				settings.TokenCache = cache

				credentials, err := settings.Creds(context.Background())
				if err != nil {
					t.Fatalf("Creds %d: %+v", i, err)
				}

				token, err := credentials.TokenSource.Token()
				if err != nil {
					t.Fatalf("Token %d: %+v", i, err)
				}
				if token.AccessToken != "at-1" {
					t.Errorf("call %d served %q, want the single issued at-1", i, token.AccessToken)
				}
			}

			if got := endpoint.count(); got != 1 {
				t.Errorf("the authorization server issued %d tokens, want exactly 1", got)
			}
			if got := cache.len(); got != 1 {
				t.Errorf("cache holds %d entries, want 1", got)
			}
		})
	}
}

// TestCredsWithoutACacheMintsEachTime keeps the promise to existing users:
// a client configured as before behaves as before.
func TestCredsWithoutACacheMintsEachTime(t *testing.T) {
	endpoint := serveTokens(t)
	key := writeServiceAccountKey(t, t.TempDir())

	for i := range 2 {
		settings := DialSettings{CredentialsFile: key, Scopes: []string{"openid"}}

		credentials, err := settings.Creds(context.Background())
		if err != nil {
			t.Fatalf("Creds %d: %+v", i, err)
		}
		if _, err := credentials.TokenSource.Token(); err != nil {
			t.Fatalf("Token %d: %+v", i, err)
		}
	}

	if got := endpoint.count(); got != 2 {
		t.Errorf("the authorization server issued %d tokens, want one per client", got)
	}
}

// TestCredsLeavesACallerSuppliedSourceAlone: a source the caller built is
// used as given. Wrapping it would mean guessing at the authority it speaks
// for, and a key guessed wrong serves a token to the wrong identity.
func TestCredsLeavesACallerSuppliedSourceAlone(t *testing.T) {
	own := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "at-mine"})

	settings := DialSettings{TokenSource: own, TokenCache: newMemoryCache()}

	credentials, err := settings.Creds(context.Background())
	if err != nil {
		t.Fatalf("Creds: %+v", err)
	}
	if credentials.TokenSource != own {
		t.Error("the caller's own token source was wrapped")
	}
}

// writeServiceAccountKey generates a usable key file and returns its path.
// The key is generated rather than checked in so the repository holds no
// PEM-shaped material.
func writeServiceAccountKey(t *testing.T, dir string) string {
	t.Helper()

	data, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_name":   "my-project",
		"private_key_id": "key-1",
		"private_key":    generatePEM(t),
		"client_email":   "sa@my-project.example",
		"client_id":      "sa-client-id",
	})
	if err != nil {
		t.Fatalf("Marshal: %+v", err)
	}

	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %+v", err)
	}

	return path
}

func generatePEM(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %+v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %+v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}
