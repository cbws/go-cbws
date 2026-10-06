// Package refresh reuses an access token in memory and fetches its
// replacement before it expires, so a long-running consumer does not wait on
// a token request once per lifetime.
package refresh

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	// DefaultRefreshWithin is the fraction of a token's lifetime, counted back
	// from its expiry, in which serving it also starts fetching its
	// replacement: the last four minutes of an hour.
	//
	// It sits inside the window in which CBWS Accounts still serves a token
	// from its own cache, the last twelfth of the lifetime. A renewal asked for
	// any earlier would be answered with the token already held.
	DefaultRefreshWithin = 1.0 / 15

	// DefaultMinimumValidity is how long before its expiry a token stops being
	// served at all, and a caller waits for a fetch instead. It matches the
	// expiry delta golang.org/x/oauth2 applies to the tokens it reuses.
	DefaultMinimumValidity = 10 * time.Second

	// DefaultRetryAfter is how long a background fetch that failed, or that
	// returned no newer token, waits before a later call tries again.
	DefaultRetryAfter = 10 * time.Second
)

var errNoToken = errors.New("refresh: the wrapped token source returned no token and no error")

// TokenSource serves the token it holds while enough of it is left and
// fetches the next one in the background once it is close to expiry, so that
// callers keep being answered from memory. Concurrent callers share one fetch.
//
// It wraps any oauth2.TokenSource, and is meant to be the outermost source:
// the one a long-lived client calls on every request. Fetches run on the
// wrapped source's own context, not on a caller's, since a fetch started on
// behalf of one call is shared by every other.
type TokenSource struct {
	inner           oauth2.TokenSource
	refreshWithin   float64
	minimumValidity time.Duration
	retryAfter      time.Duration
	logger          *slog.Logger
	now             func() time.Time

	mu       sync.Mutex
	token    *oauth2.Token
	obtained time.Time
	// heldOff is when a background fetch last failed or brought nothing
	// newer. A later one waits retryAfter from then.
	heldOff time.Time
	flight  *flight

	// fetches tracks the fetches in progress, so tests can wait for
	// background ones.
	fetches sync.WaitGroup
}

// flight is a fetch in progress, shared by every caller that needs a token
// meanwhile.
type flight struct {
	done  chan struct{}
	token *oauth2.Token
	err   error
}

// Option configures a TokenSource.
type Option func(*TokenSource)

// WithRefreshWithin sets the fraction of the lifetime, counted back from
// expiry, in which the replacement is fetched in the background. A token
// issuer that serves tokens from a cache of its own needs this to start no
// earlier than the point at which it stops serving one, or a renewal is
// answered with the token already held.
func WithRefreshWithin(fraction float64) Option {
	return func(s *TokenSource) {
		if fraction > 0 && fraction < 1 {
			s.refreshWithin = fraction
		}
	}
}

// WithMinimumValidity sets how long before expiry a token stops being served.
func WithMinimumValidity(d time.Duration) Option {
	return func(s *TokenSource) {
		if d >= 0 {
			s.minimumValidity = d
		}
	}
}

// WithRetryAfter sets how long a background fetch that failed, or brought no
// newer token, waits before a later call tries again.
func WithRetryAfter(d time.Duration) Option {
	return func(s *TokenSource) {
		if d >= 0 {
			s.retryAfter = d
		}
	}
}

// WithLogger sets where background fetch failures are reported. Defaults to
// slog.Default(). Nothing it logs contains a token.
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

// NewTokenSource wraps inner so that its tokens are reused and replaced ahead
// of their expiry.
func NewTokenSource(inner oauth2.TokenSource, options ...Option) *TokenSource {
	s := &TokenSource{
		inner:           inner,
		refreshWithin:   DefaultRefreshWithin,
		minimumValidity: DefaultMinimumValidity,
		retryAfter:      DefaultRetryAfter,
		logger:          slog.Default(),
		now:             time.Now,
	}
	for _, option := range options {
		option(s)
	}

	return s
}

// Token implements oauth2.TokenSource. When no usable token is held it waits
// for a fetch however long that takes; TokenContext bounds the wait.
func (s *TokenSource) Token() (*oauth2.Token, error) {
	return s.TokenContext(context.Background())
}

// TokenContext is Token with a bound on the wait: a caller whose context ends
// before a fetch completes gets the context's error, and the fetch carries on
// for the next caller.
func (s *TokenSource) TokenContext(ctx context.Context) (*oauth2.Token, error) {
	now := s.now()

	s.mu.Lock()
	if s.servable(now) {
		if s.refreshDue(now) && now.Sub(s.heldOff) >= s.retryAfter {
			s.startLocked()
		}
		token := s.token
		s.mu.Unlock()

		return token, nil
	}
	f := s.startLocked()
	s.mu.Unlock()

	select {
	case <-f.done:
		return f.token, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// startLocked returns the fetch in progress, starting one if there is none.
// Called with mu held.
func (s *TokenSource) startLocked() *flight {
	if s.flight != nil {
		return s.flight
	}

	f := &flight{done: make(chan struct{})}
	s.flight = f
	s.fetches.Add(1)
	go func() {
		defer s.fetches.Done()
		defer close(f.done)

		f.token, f.err = s.inner.Token()
		if f.err == nil && f.token == nil {
			f.err = errNoToken
		}

		s.mu.Lock()
		defer s.mu.Unlock()
		s.flight = nil
		now := s.now()
		switch {
		case f.err != nil:
			s.heldOff = now
			if s.token != nil {
				s.logger.Warn("Could not refresh the access token ahead of its expiry", "error", f.err)
			}
		default:
			// A token that expires no later than the one held is what a
			// source answering from a cache hands back when asked too early.
			// Keeping it changes nothing, and asking again on the next call
			// would get it again, so this backs off as a failure does.
			if s.token != nil && !s.token.Expiry.IsZero() && !f.token.Expiry.After(s.token.Expiry) {
				s.heldOff = now

				return
			}
			s.token, s.obtained, s.heldOff = f.token, now, time.Time{}
		}
	}()

	return f
}

// servable reports whether the held token can be served. A token with no
// expiry is taken to never expire, as golang.org/x/oauth2 takes it. Called
// with mu held.
func (s *TokenSource) servable(now time.Time) bool {
	if s.token == nil || s.token.AccessToken == "" {
		return false
	}
	if s.token.Expiry.IsZero() {
		return true
	}

	return s.token.Expiry.Sub(now) > s.minimumValidity
}

// refreshDue reports whether the held token is close enough to expiry for its
// replacement to be fetched. The window is never shorter than twice the
// minimum validity, so a short-lived token is still replaced in the
// background before callers would have to wait. Called with mu held.
func (s *TokenSource) refreshDue(now time.Time) bool {
	if s.token.Expiry.IsZero() {
		return false
	}
	window := time.Duration(float64(s.token.Expiry.Sub(s.obtained)) * s.refreshWithin)
	window = max(window, 2*s.minimumValidity)

	return s.token.Expiry.Sub(now) <= window
}
