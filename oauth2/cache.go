package oauth2

import (
	"fmt"

	"go.cbws.cloud/sdk/oauth2/tokencache"

	"golang.org/x/oauth2"
)

// Option configures how credentials are discovered and used.
type Option func(*settings)

type settings struct {
	cache      tokencache.Cache
	generation string
}

// WithTokenCache reuses access tokens through cache, so that a token
// obtained by one process is served to the next instead of being fetched
// again.
//
// It is what makes a short-lived consumer cheap: a Kubernetes credential
// plugin, or any CLI command, otherwise asks the authorization server for a
// token on every invocation. Without this option nothing is written
// anywhere and reuse ends with the process, which is the behaviour every
// existing SDK user already has.
//
// Where the cache keeps its entries is the application's decision, because
// what is being kept is a bearer token. See tokencache.Cache.
func WithTokenCache(cache tokencache.Cache) Option {
	return func(s *settings) {
		s.cache = cache
	}
}

// WithCredentialGeneration names the current login behind a credential
// source that cannot identify one itself.
//
// The CBWS CLI configuration is the case this exists for. Its path is what
// identifies it to a cache, and a path says where a credential is read
// from rather than which session wrote it. Logging out and back in leaves
// that path unchanged, so without this a token cached before the logout
// would go on being served afterwards: as the wrong principal if the login
// was someone else, and as a credential the logout may already have had
// revoked even if it was the same person again.
//
// So the value has to change on every successful login, not merely when
// the user does. A random identifier written at login and removed at
// logout is the shape that works; a username or an account id is not,
// since logging out and back in as yourself would reuse it.
//
// Without one the CLI configuration credential is not cached at all. The
// SDK cannot tell one login from the next on the application's behalf, and
// serving a revoked or foreign credential is worse than fetching a token.
//
// Credentials that identify themselves, such as a service account key, do
// not need this and ignore it.
func WithCredentialGeneration(generation string) Option {
	return func(s *settings) {
		s.generation = generation
	}
}

func newSettings(options []Option) *settings {
	resolved := &settings{}
	for _, option := range options {
		option(resolved)
	}

	return resolved
}

// cached wraps source so its tokens are reused through the configured
// cache, under the authority described by key. With no cache configured it
// returns source untouched.
func (s *settings) cached(source oauth2.TokenSource, key tokencache.Key) (oauth2.TokenSource, error) {
	if s.cache == nil {
		return source, nil
	}

	cached, err := tokencache.NewTokenSource(source, s.cache, key)
	if err != nil {
		return nil, fmt.Errorf("cbws: could not cache tokens for %s: %w", key.Issuer, err)
	}

	return cached, nil
}
