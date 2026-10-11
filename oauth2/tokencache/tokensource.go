package tokencache

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"go.cbws.cloud/sdk/internal/tokensource"
	"golang.org/x/oauth2"
)

// A gRPC call's deadline reaches the wrapped source only through
// TokenContext.
var _ tokensource.ContextSource = (*TokenSource)(nil)

// DefaultSkew is how long before its expiry a token stops being served
// from the cache. A token that crossed a process boundary has to survive
// the request it is about to be used for, and the consumer may be a
// Kubernetes client that will hold it for a while longer still.
//
// It matches the skew the CBWS CLI already uses when it keeps a token file
// current, so a token this package declines to serve is one that command
// would have replaced too.
const DefaultSkew = 30 * time.Second

// TokenSource serves a token from a Cache, falling back to the source it
// wraps and storing what that returns.
//
// It is a decorator rather than a replacement: the wrapped source keeps
// whatever in-memory reuse it already had, and this adds reuse that
// survives the process.
//
// A wrapped source that takes a context, as the SDK's own sources do
// through TokenContext, holds and renews its token itself, and renews it
// only when it is asked while the token is close to expiry. So once this
// process has a token of its own, every call is passed to such a source
// rather than answered from a copy held here, which would keep those calls
// from it until the token was too close to expiry to serve. The call's
// context goes with it, bounding how long the call waits. A source that
// takes no context is not asked again while the token it last returned is
// valid.
//
// Two sources built over one key each keep their own token and may each
// fetch one, in a single process or across several. That is deliberate, and
// the reasoning is on Cache: coalescing them means holding a lock across
// the call to the wrapped source, which is arbitrary code that may reach
// another cache over the same key and wait for the lock its own caller
// holds. A duplicate access-token fetch costs a request; a deadlock costs
// the process.
type TokenSource struct {
	inner  oauth2.TokenSource
	cache  Cache
	id     string
	skew   time.Duration
	logger *slog.Logger
	now    func() time.Time

	// renewing is inner when it takes a context, and nil when it does not.
	renewing tokensource.ContextSource

	mu    sync.Mutex
	token *oauth2.Token

	// fromCache records where token came from, because the two answer to
	// different rules. One this process obtained is judged as any oauth2
	// source judges its own; one read back from storage keeps answering to
	// the configured skew for as long as it is held, or an entry accepted
	// just outside the skew would be served from memory well inside it.
	fromCache bool
}

// Option configures a TokenSource.
type Option func(*TokenSource)

// WithSkew sets how long before expiry a cached token stops being served,
// overriding DefaultSkew. A consumer that holds a token for longer than the
// call it fetched it for wants this raised.
func WithSkew(skew time.Duration) Option {
	return func(s *TokenSource) {
		if skew >= 0 {
			s.skew = skew
		}
	}
}

// WithLogger sets where the source reports a cache it could not write.
// Defaults to slog.Default(). Nothing it logs contains a token.
func WithLogger(logger *slog.Logger) Option {
	return func(s *TokenSource) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// withClock drives expiry from a test's clock rather than the wall.
func withClock(now func() time.Time) Option {
	return func(s *TokenSource) {
		if now != nil {
			s.now = now
		}
	}
}

// NewTokenSource wraps inner so that tokens are reused through cache under
// the authority described by key.
//
// Passing a nil cache returns inner unchanged, so a caller that has not
// been given a cache does not have to branch: the SDK's behaviour without
// one is exactly what it was.
func NewTokenSource(inner oauth2.TokenSource, cache Cache, key Key, options ...Option) (oauth2.TokenSource, error) {
	if inner == nil {
		return nil, errors.New("tokencache: no token source to wrap")
	}

	if cache == nil {
		return inner, nil
	}

	id, err := key.ID()
	if err != nil {
		return nil, fmt.Errorf("tokencache: %w", err)
	}

	source := &TokenSource{
		inner:  inner,
		cache:  cache,
		id:     id,
		skew:   DefaultSkew,
		logger: slog.Default(),
		now:    time.Now,
	}
	source.renewing, _ = inner.(tokensource.ContextSource)

	for _, option := range options {
		option(source)
	}

	return source, nil
}

// Token implements oauth2.TokenSource. It waits on the wrapped source for
// as long as that takes; TokenContext bounds the wait.
func (s *TokenSource) Token() (*oauth2.Token, error) {
	return s.TokenContext(context.Background())
}

// TokenContext is Token with a bound on the wait, for a wrapped source that
// takes a context: a caller whose context ends before that source has a
// token gets the context's error. A wrapped source that takes no context is
// waited on regardless.
func (s *TokenSource) TokenContext(ctx context.Context) (*oauth2.Token, error) {
	if s.renewing != nil {
		return s.deferred(ctx)
	}

	return s.held()
}

// deferred serves a call when the wrapped source renews its own token. A
// token read from the cache is served from here while it clears the skew,
// since the wrapped source has never seen it. Anything else is the wrapped
// source's to answer.
//
// Nothing is held across the call to the wrapped source. A caller with a
// deadline has to be able to give up, and one waiting on a lock here could
// not; concurrent callers are coalesced by the wrapped source instead.
func (s *TokenSource) deferred(ctx context.Context) (*oauth2.Token, error) {
	s.mu.Lock()
	if s.token == nil || s.fromCache {
		if s.token != nil && s.servable(s.token) {
			token := s.token
			s.mu.Unlock()

			return token, nil
		}

		if token := s.cached(); token != nil {
			s.token, s.fromCache = token, true
			s.mu.Unlock()

			return token, nil
		}
	}
	s.mu.Unlock()

	token, err := s.renewing.TokenContext(ctx)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// The wrapped source answers with the token it holds until it has a
	// newer one, so only a token not already held needs storing. One that
	// expires before the held token is an answer that was overtaken by a
	// renewal while it was on its way back, and replacing the held token
	// with it would store the older of the two.
	if s.token != nil && !s.fromCache &&
		(token.AccessToken == s.token.AccessToken || token.Expiry.Before(s.token.Expiry)) {
		return token, nil
	}

	s.token, s.fromCache = token, false
	s.store(token)

	return token, nil
}

// held serves a call when the wrapped source takes no context, from the
// token held here while it is usable. Callers are serialized, so a burst
// behind one source fetches once.
func (s *TokenSource) held() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.usable() {
		return s.token, nil
	}

	// Nothing is held across the call to inner below. See Cache: a lock
	// spanning it is what lets a wrapped source deadlock against its own
	// caller, and a duplicate fetch is the cheaper of the two outcomes.
	if token := s.cached(); token != nil {
		s.token, s.fromCache = token, true

		return token, nil
	}

	token, err := s.inner.Token()
	if err != nil {
		return nil, err
	}

	s.token, s.fromCache = token, false
	s.store(token)

	return token, nil
}

// store writes a token the wrapped source returned to the cache. Called
// with mu held.
func (s *TokenSource) store(token *oauth2.Token) {
	// A token already inside the skew is not stored. The source behind this
	// one refreshes on a narrower margin, so it can hand back something it
	// considers current and this considers spent; storing that would fill
	// the cache with entries every later reader rejects.
	cacheable := accessOnly(token)
	if !s.servable(cacheable) {
		return
	}

	// A token that cannot be stored is still a token. Nothing has been
	// consumed by fetching it and no other process is put at risk by the
	// entry being absent, so the only cost of giving up here is that the
	// next process fetches its own. That is the whole of the policy: this
	// cache never fails a call it could have served.
	if err := s.cache.Store(s.id, cacheable); err != nil {
		s.logger.Warn("Could not cache the access token", "error", err, "key", s.id)
	}
}

// usable reports whether the token already in hand can be served again.
//
// A token this process obtained answers to oauth2's own reading, so a
// source reporting no expiry is not re-asked on every call and one the
// wrapped source still considers current is not sent back to it. A token
// that came out of the cache answers to the configured skew for as long as
// it is held: it was accepted because it cleared that margin, and time
// passing does not make it clear it again.
func (s *TokenSource) usable() bool {
	if s.fromCache {
		return s.servable(s.token)
	}

	return s.token.Valid()
}

// cached reads the entry and returns it only if it can still be served.
// Anything unreadable, absent or aged out comes back nil, since all three
// call for the same thing: fetch a token and replace what is there.
func (s *TokenSource) cached() *oauth2.Token {
	stored, err := s.cache.Load(s.id)
	if err != nil {
		if !errors.Is(err, ErrMiss) {
			s.logger.Debug("Ignoring an unreadable token cache entry", "error", err, "key", s.id)
		}

		return nil
	}

	if stored == nil {
		return nil
	}

	// Narrowed on the way in as well as on the way out. This package owns
	// what an access-token cache may hold and cannot assume every Cache
	// enforced it: an entry written by an older version, by another
	// implementation, or edited by hand may carry a refresh token or an id
	// token, and handing that back would let it cross the boundary the
	// write side is careful about.
	token := accessOnly(stored)

	// An entry that held more than it should is replaced by what it should
	// have held, so the surplus credential stops sitting in storage rather
	// than merely stopping at this boundary. Before the entry is judged,
	// not after: one that has expired or cannot be presented still has the
	// credential in it, and is the entry most likely to sit there
	// untouched, since nothing will overwrite it until a fetch succeeds.
	if overfull(stored) {
		if err := s.cache.Store(s.id, token); err != nil {
			s.logger.Warn("Could not narrow an over-full token cache entry", "error", err, "key", s.id)
		}
	}

	if !s.servable(token) {
		return nil
	}

	return token
}

// sensitiveExtras are the fields an authorization server returns alongside
// an access token that are credentials in their own right.
var sensitiveExtras = []string{"refresh_token", "id_token"}

// overfull reports whether an entry carries more than a bearer credential
// and is worth rewriting in place.
//
// Extras cannot be enumerated through oauth2.Token, so this asks after the
// ones that matter by name rather than proving the entry holds nothing
// else. What leaves this package is narrowed unconditionally either way;
// this is about not leaving a credential at rest in storage.
func overfull(token *oauth2.Token) bool {
	if token.RefreshToken != "" {
		return true
	}

	for _, extra := range sensitiveExtras {
		if token.Extra(extra) != nil {
			return true
		}
	}

	return false
}

// accessOnly strips a token down to what a bearer credential needs, which
// is the whole of what this cache is allowed to keep. Building a new token
// rather than copying one also drops whatever extras the authorization
// server returned alongside it, an id token among them.
func accessOnly(token *oauth2.Token) *oauth2.Token {
	return &oauth2.Token{
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
		Expiry:      token.Expiry,
	}
}

// servable reports whether a token is fit to come out of, or go into, the
// cache.
//
// A token with no expiry never is, which is the opposite of what
// oauth2.Token.Valid makes of one. Valid reads a zero expiry as "never
// expires", a reasonable reading for a token a process just obtained and an
// unsafe one for a token read back from storage: nothing about the entry
// says how long ago it was written, so serving it would hand out a
// credential of unknown age forever.
func (s *TokenSource) servable(token *oauth2.Token) bool {
	if token == nil || token.AccessToken == "" || token.Expiry.IsZero() {
		return false
	}

	// An entry naming a scheme CBWS does not issue is a miss rather than
	// something to present: every token here is a bearer token, and
	// oauth2.Token.Type defaults to Bearer for an empty value, so anything
	// else is an entry written by something that does not belong here.
	if !strings.EqualFold(token.Type(), "bearer") {
		return false
	}

	return s.now().Add(s.skew).Before(token.Expiry)
}
