package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// fakeTokenEndpoint plays the Accounts token endpoint with single-use
// rotating refresh tokens: every accepted refresh invalidates the token it
// was given and issues the next one in the sequence, so a test that presents
// a spent token gets the same invalid_grant a real reuse would.
type fakeTokenEndpoint struct {
	mu        sync.Mutex
	accepted  map[string]bool
	presented []string
	issued    int
}

func newFakeTokenEndpoint(accept ...string) *fakeTokenEndpoint {
	f := &fakeTokenEndpoint{accepted: map[string]bool{}}
	for _, token := range accept {
		f.accepted[token] = true
	}

	return f
}

func (f *fakeTokenEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	presented := r.Form.Get("refresh_token")

	f.mu.Lock()
	defer f.mu.Unlock()
	f.presented = append(f.presented, presented)

	w.Header().Set("Content-Type", "application/json")

	if !f.accepted[presented] {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})

		return
	}

	delete(f.accepted, presented)
	f.issued++
	next := fmt.Sprintf("rt-%d", f.issued)
	f.accepted[next] = true

	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  fmt.Sprintf("at-%d", f.issued),
		"token_type":    "bearer",
		"refresh_token": next,
		"expires_in":    3600,
	})
}

func (f *fakeTokenEndpoint) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.presented)
}

// expiredConfig is a configuration whose access token has lapsed, holding a
// second key so a test can assert that persisting the token leaves the rest
// of the file alone.
const expiredConfig = `project_name: my-project
oauth_token:
  accesstoken: at-stale
  tokentype: bearer
  refreshtoken: rt-0
  expiry: 2020-01-01T00:00:00Z
`

// newTestSource writes content to a scratch configuration and returns a
// source pointed at the fake endpoint, plus the path so a test can inspect
// or rewrite what is stored.
func newTestSource(t *testing.T, endpoint *fakeTokenEndpoint, content string) (*TokenSource, string) {
	t.Helper()

	path := writeConfig(t, content)

	source, err := NewTokenSource(context.Background(), NewFileStore(path), nil, testEndpoint(t, endpoint), quietLogger())
	if err != nil {
		t.Fatalf("NewTokenSource: %+v", err)
	}

	return source, path
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), ".cbws.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("could not write scratch config: %+v", err)
	}

	return path
}

func testEndpoint(t *testing.T, fake *fakeTokenEndpoint) Option {
	t.Helper()

	return WithEndpoint(serve(t, fake))
}

// applyTestEndpoint points the package-level Endpoint at the fake for the
// duration of one test, for the entry points that take no options.
func applyTestEndpoint(t *testing.T, fake *fakeTokenEndpoint) {
	t.Helper()

	previous := Endpoint
	Endpoint = serve(t, fake)
	t.Cleanup(func() { Endpoint = previous })
}

func serve(t *testing.T, fake *fakeTokenEndpoint) oauth2.Endpoint {
	t.Helper()

	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)

	return oauth2.Endpoint{AuthURL: server.URL + "/auth", TokenURL: server.URL + "/token"}
}

// quietLogger keeps the warnings the source emits out of the test output,
// where they are expected rather than interesting.
func quietLogger() Option {
	return WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// storedValue pulls a scalar out of the configuration text, so a test
// asserts on what was written rather than on what a parser makes of it.
func storedValue(t *testing.T, path, key string) string {
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

// TestTokenRefreshedOnceAndPersisted is the regression test for the issue
// this type exists for: a command making many RPCs must issue exactly one
// token request, and the rotated refresh token must reach the file, or the
// next process presents a spent one and has the grant chain revoked.
func TestTokenRefreshedOnceAndPersisted(t *testing.T) {
	endpoint := newFakeTokenEndpoint("rt-0")
	source, path := newTestSource(t, endpoint, expiredConfig)

	for i := range 10 {
		token, err := source.Token()
		if err != nil {
			t.Fatalf("Token call %d: %+v", i, err)
		}
		if token.AccessToken != "at-1" {
			t.Fatalf("Token call %d returned %q, want the refreshed at-1", i, token.AccessToken)
		}
	}

	if got := endpoint.calls(); got != 1 {
		t.Errorf("token endpoint received %d requests, want exactly 1", got)
	}
	if got := storedValue(t, path, "refreshtoken"); got != "rt-1" {
		t.Errorf("persisted refresh token = %q, want the rotated rt-1", got)
	}
	if got := storedValue(t, path, "accesstoken"); got != "at-1" {
		t.Errorf("persisted access token = %q, want at-1", got)
	}
	if got := storedValue(t, path, "project_name"); got != "my-project" {
		t.Errorf("project_name = %q, want it untouched", got)
	}
}

// TestTokenRefreshAdoptsRotatedTokenFromDisk covers the cross-process case:
// another process rotated the refresh token while we held the old one, and
// presenting ours would be read as a replay and revoke the grant chain. The
// source must re-read under the lock and use what is stored.
func TestTokenRefreshAdoptsRotatedTokenFromDisk(t *testing.T) {
	endpoint := newFakeTokenEndpoint("rt-fresh")
	source, path := newTestSource(t, endpoint, expiredConfig)

	// Another process rotated rt-0 into rt-fresh after we loaded ours.
	rotated := strings.Replace(expiredConfig, "rt-0", "rt-fresh", 1)
	if err := os.WriteFile(path, []byte(rotated), 0o600); err != nil {
		t.Fatalf("could not simulate the other process: %+v", err)
	}

	token, err := source.Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if token.AccessToken != "at-1" {
		t.Errorf("access token = %q, want the refreshed at-1", token.AccessToken)
	}
	if got := endpoint.presented; len(got) != 1 || got[0] != "rt-fresh" {
		t.Errorf("endpoint was presented %v, want exactly [rt-fresh]", got)
	}
}

// TestTokenUsesValidTokenFromDisk: when another process has already
// refreshed and its access token is still good, no token request goes out.
func TestTokenUsesValidTokenFromDisk(t *testing.T) {
	endpoint := newFakeTokenEndpoint()
	source, path := newTestSource(t, endpoint, expiredConfig)

	fresh := `project_name: my-project
oauth_token:
  accesstoken: at-fresh
  tokentype: bearer
  refreshtoken: rt-9
  expiry: 2199-01-01T00:00:00Z
`
	if err := os.WriteFile(path, []byte(fresh), 0o600); err != nil {
		t.Fatalf("could not simulate the other process: %+v", err)
	}

	token, err := source.Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if token.AccessToken != "at-fresh" {
		t.Errorf("access token = %q, want the one the other process stored", token.AccessToken)
	}
	if got := endpoint.calls(); got != 0 {
		t.Errorf("token endpoint received %d requests, want none", got)
	}
}

// TestConcurrentTokenCallsRefreshOnce: a burst of parallel RPCs shares the
// mutex, so the single-use refresh token is spent once.
func TestConcurrentTokenCallsRefreshOnce(t *testing.T) {
	endpoint := newFakeTokenEndpoint("rt-0")
	source, _ := newTestSource(t, endpoint, expiredConfig)

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

	if got := endpoint.calls(); got != 1 {
		t.Errorf("token endpoint received %d requests, want exactly 1", got)
	}
}

// TestTokenFailsWhenTheStoreCannotBeLocked: without the lock two processes
// can spend the same single-use refresh token, and the loser has the whole
// grant chain revoked. One command failing is the cheaper outcome, so the
// refresh does not proceed unserialized.
func TestTokenFailsWhenTheStoreCannotBeLocked(t *testing.T) {
	endpoint := newFakeTokenEndpoint("rt-0")

	source, err := NewTokenSource(
		context.Background(),
		&stubStore{token: staleToken(), lockErr: errors.New("no locking on this filesystem")},
		nil,
		testEndpoint(t, endpoint),
		quietLogger(),
	)
	if err != nil {
		t.Fatalf("NewTokenSource: %+v", err)
	}

	_, err = source.Token()
	if err == nil {
		t.Fatal("Token refreshed without the lock")
	}
	if !strings.Contains(err.Error(), "lock") {
		t.Errorf("error = %v, want it to name the lock", err)
	}
	if got := endpoint.calls(); got != 0 {
		t.Errorf("token endpoint received %d requests, want none: the token must not be spent unserialized", got)
	}
}

// TestTokenFailsWhenTheRefreshCannotBeStored: Accounts has already spent the
// stored token by the time Save runs, so a save that fails leaves the spent
// one on disk for the next process to present. Reporting success there is
// what recreates the original incident one invocation later.
func TestTokenFailsWhenTheRefreshCannotBeStored(t *testing.T) {
	endpoint := newFakeTokenEndpoint("rt-0")
	store := &stubStore{token: staleToken(), saveErr: errors.New("read-only file system")}

	source, err := NewTokenSource(context.Background(), store, nil, testEndpoint(t, endpoint), quietLogger())
	if err != nil {
		t.Fatalf("NewTokenSource: %+v", err)
	}

	_, err = source.Token()
	if err == nil {
		t.Fatal("Token reported success for a rotation it could not store")
	}
	if !strings.Contains(err.Error(), "cbws init") {
		t.Errorf("error = %v, want it to say how to recover", err)
	}

	// Sticky: nothing later in this process can repair the stored
	// credential, so a second call must not look like success.
	if _, err := source.Token(); err == nil {
		t.Error("a later call succeeded, hiding that the stored credential is spent")
	}

	// The spent token must not be presented again by this process either.
	if got := endpoint.calls(); got != 1 {
		t.Errorf("token endpoint received %d requests, want exactly 1", got)
	}
}

// TestTokenRefreshFailureSuggestsInit: a spent refresh token is the state a
// user cannot get out of on their own, so the error has to say how.
func TestTokenRefreshFailureSuggestsInit(t *testing.T) {
	endpoint := newFakeTokenEndpoint() // accepts nothing
	source, _ := newTestSource(t, endpoint, expiredConfig)

	_, err := source.Token()
	if err == nil || !strings.Contains(err.Error(), "cbws init") {
		t.Errorf("error = %v, want a hint to run cbws init", err)
	}
}

// TestTokenSourceWithoutStoredToken: a configuration that exists but holds
// no token is not an error to be reported, it is a source to skip.
func TestTokenSourceWithoutStoredToken(t *testing.T) {
	path := writeConfig(t, "project_name: my-project\n")

	_, err := NewTokenSource(context.Background(), NewFileStore(path), nil)
	if !errors.Is(err, ErrNoToken) {
		t.Errorf("error = %v, want ErrNoToken", err)
	}
}

// TestTokenSourceWithoutConfigFile: likewise for a configuration that is
// not there at all, which callers recognise with os.IsNotExist.
func TestTokenSourceWithoutConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.yaml")

	_, err := NewTokenSource(context.Background(), NewFileStore(path), nil)
	if !os.IsNotExist(err) {
		t.Errorf("error = %v, want one satisfying os.IsNotExist", err)
	}
}

func staleToken() *oauth2.Token {
	return &oauth2.Token{
		TokenType:    "bearer",
		AccessToken:  "at-stale",
		RefreshToken: "rt-0",
		Expiry:       time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// stubStore is a Store whose failures a test can choose, for the paths a
// real file cannot be made to take reliably.
type stubStore struct {
	mu      sync.Mutex
	token   *oauth2.Token
	lockErr error
	saveErr error
}

func (s *stubStore) Load() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token == nil {
		return nil, ErrNoToken
	}

	return s.token, nil
}

func (s *stubStore) Save(token *oauth2.Token) error {
	if s.saveErr != nil {
		return s.saveErr
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = token

	return nil
}

func (s *stubStore) Lock() (func(), error) {
	if s.lockErr != nil {
		return nil, s.lockErr
	}

	return func() {}, nil
}
