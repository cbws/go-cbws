package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/oauth2"
)

// TestNewTokenSourceFromConfig covers the entry point the SDK itself calls,
// end to end over a real file. It takes no options, so the endpoint is
// overridden through the package variable, which is the escape hatch its
// documentation offers.
func TestNewTokenSourceFromConfig(t *testing.T) {
	endpoint := newFakeTokenEndpoint("rt-0")
	path := writeConfig(t, expiredConfig)

	applyTestEndpoint(t, endpoint)

	source, err := NewTokenSourceFromConfig(context.Background(), path, []string{"openid", "offline"})
	if err != nil {
		t.Fatalf("NewTokenSourceFromConfig: %+v", err)
	}

	token, err := source.Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if token.AccessToken != "at-1" {
		t.Errorf("access token = %q, want at-1", token.AccessToken)
	}
	if token.TokenType != "bearer" {
		t.Errorf("token type = %q, want bearer", token.TokenType)
	}
	if got := storedValue(t, path, "refreshtoken"); got != "rt-1" {
		t.Errorf("persisted refresh token = %q, want rt-1", got)
	}
}

// TestNewTokenSourceFromConfigTakesNoOptions pins the signature. A variadic
// parameter would keep every call site compiling while breaking anything
// that assigns the function to a declared type, so the compatibility this
// protects is not visible from the call sites alone.
func TestNewTokenSourceFromConfigTakesNoOptions(t *testing.T) {
	var _ func(context.Context, string, []string) (oauth2.TokenSource, error) = NewTokenSourceFromConfig
}

func TestNewTokenSourceFromConfigMissingFile(t *testing.T) {
	_, err := NewTokenSourceFromConfig(context.Background(), filepath.Join(t.TempDir(), "absent.yaml"), nil)

	if !os.IsNotExist(err) {
		t.Errorf("error = %v, want one satisfying os.IsNotExist", err)
	}
}

// TestNewTokenSourceCarriesScopes: the scopes a caller asks for have to
// reach the authorization server, since they bound what the token can do.
func TestNewTokenSourceCarriesScopes(t *testing.T) {
	scopes := []string{"openid", "offline"}

	source, err := NewTokenSource(context.Background(), &stubStore{token: staleToken()}, scopes)
	if err != nil {
		t.Fatalf("NewTokenSource: %+v", err)
	}

	if got := source.conf.Scopes; len(got) != 2 || got[0] != "openid" || got[1] != "offline" {
		t.Errorf("scopes = %v, want %v", got, scopes)
	}
	if source.conf.ClientID != ClientID {
		t.Errorf("client id = %q, want the CLI client %q", source.conf.ClientID, ClientID)
	}
	if source.conf.Endpoint != Endpoint {
		t.Errorf("endpoint = %+v, want the Accounts endpoint %+v", source.conf.Endpoint, Endpoint)
	}
}

// TestNewTokenSourceRejectsEmptyStore covers a Store implementation that
// reports neither a token nor an error, which would otherwise leave the
// source refreshing a nil token.
func TestNewTokenSourceRejectsEmptyStore(t *testing.T) {
	_, err := NewTokenSource(context.Background(), &nilStore{}, nil)

	if !errors.Is(err, ErrNoToken) {
		t.Errorf("error = %v, want ErrNoToken", err)
	}
}

// TestWithLoggerIgnoresNil: a caller passing no logger gets the default
// rather than a source that panics on its first warning.
func TestWithLoggerIgnoresNil(t *testing.T) {
	source, err := NewTokenSource(context.Background(), &stubStore{token: staleToken()}, nil, WithLogger(nil))
	if err != nil {
		t.Fatalf("NewTokenSource: %+v", err)
	}

	if source.logger == nil {
		t.Error("logger is nil, want the default left in place")
	}
}

// TestEndpointIsAccounts pins the endpoint the CLI and the SDK share, which
// cbws-cli reads from here rather than repeating.
func TestEndpointIsAccounts(t *testing.T) {
	if Endpoint.AuthURL != "https://accounts.cbws.cloud/oauth2/auth" {
		t.Errorf("auth URL = %q", Endpoint.AuthURL)
	}
	if Endpoint.TokenURL != "https://accounts.cbws.cloud/oauth2/token" {
		t.Errorf("token URL = %q", Endpoint.TokenURL)
	}
}

// TestNotifyingTokenSource covers the deprecated surface, which is exported
// and so still has to behave as it always has.
func TestNotifyingTokenSource(t *testing.T) {
	token := &oauth2.Token{AccessToken: "at-0"}

	t.Run("calls the function with the token", func(t *testing.T) {
		var seen *oauth2.Token

		source := NewNotifyingTokenSource(oauth2.StaticTokenSource(token), func(t *oauth2.Token) error {
			seen = t

			return nil
		})

		got, err := source.Token()
		if err != nil {
			t.Fatalf("Token: %+v", err)
		}
		if got != token || seen != token {
			t.Errorf("token = %v, notified with %v, want both to be %v", got, seen, token)
		}
	})

	t.Run("without a function", func(t *testing.T) {
		got, err := NewNotifyingTokenSource(oauth2.StaticTokenSource(token), nil).Token()
		if err != nil {
			t.Fatalf("Token: %+v", err)
		}
		if got != token {
			t.Errorf("token = %v, want %v", got, token)
		}
	})

	t.Run("reports the function's error", func(t *testing.T) {
		want := errors.New("rejected")

		_, err := NewNotifyingTokenSource(oauth2.StaticTokenSource(token), func(*oauth2.Token) error {
			return want
		}).Token()

		if !errors.Is(err, want) {
			t.Errorf("error = %v, want %v", err, want)
		}
	})

	t.Run("reports the underlying error", func(t *testing.T) {
		want := errors.New("no token")

		_, err := NewNotifyingTokenSource(failingSource{want}, func(*oauth2.Token) error {
			t.Error("the function was called for a token that was never obtained")

			return nil
		}).Token()

		if !errors.Is(err, want) {
			t.Errorf("error = %v, want %v", err, want)
		}
	})
}

// TestTwoSourcesOverOneFileRefreshOnce is the cross-process guarantee, with
// two sources over one configuration standing in for two CLI invocations.
// Only one of them may spend the refresh token: the other has to wait on the
// lock, re-read, and adopt what the first one stored. Presenting the spent
// token instead is what revokes the grant chain.
func TestTwoSourcesOverOneFileRefreshOnce(t *testing.T) {
	endpoint := newFakeTokenEndpoint("rt-0")
	path := writeConfig(t, expiredConfig)
	option := testEndpoint(t, endpoint)

	sources := make([]*TokenSource, 2)
	for i := range sources {
		source, err := NewTokenSource(context.Background(), NewFileStore(path), nil, option, quietLogger())
		if err != nil {
			t.Fatalf("NewTokenSource %d: %+v", i, err)
		}
		sources[i] = source
	}

	tokens := make([]string, len(sources))

	var wg sync.WaitGroup
	for i, source := range sources {
		wg.Add(1)

		go func() {
			defer wg.Done()

			token, err := source.Token()
			if err != nil {
				t.Errorf("source %d Token: %+v", i, err)

				return
			}
			tokens[i] = token.AccessToken
		}()
	}
	wg.Wait()

	if got := endpoint.calls(); got != 1 {
		t.Errorf("token endpoint received %d requests, want exactly 1: %v", got, endpoint.presented)
	}
	for i, token := range tokens {
		if token != "at-1" {
			t.Errorf("source %d ended on %q, want the single issued at-1", i, token)
		}
	}
	if got := storedValue(t, path, "refreshtoken"); got != "rt-1" {
		t.Errorf("persisted refresh token = %q, want rt-1", got)
	}
}

// nilStore reports neither a token nor an error, which no Store should do
// but which must not become a nil dereference here.
type nilStore struct{}

func (nilStore) Load() (*oauth2.Token, error) { return nil, nil }
func (nilStore) Save(*oauth2.Token) error     { return nil }
func (nilStore) Lock() (func(), error)        { return func() {}, nil }

type failingSource struct{ err error }

func (f failingSource) Token() (*oauth2.Token, error) { return nil, f.err }

// TestNewTokenSourceFromConfigReturnsANilSourceOnError: a failure has to
// yield an interface that is actually nil. Returning the typed nil pointer
// would give a caller checking for one a source it then dereferences.
func TestNewTokenSourceFromConfigReturnsANilSourceOnError(t *testing.T) {
	source, err := NewTokenSourceFromConfig(context.Background(), filepath.Join(t.TempDir(), "absent.yaml"), nil)
	if err == nil {
		t.Fatal("NewTokenSourceFromConfig succeeded for a file that is not there")
	}
	if source != nil {
		t.Errorf("source = %#v, want nil", source)
	}
}
