package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"golang.org/x/oauth2"
)

// TokenSource refreshes the token held by a Store and writes the result
// back.
//
// The Accounts service issues single-use rotating refresh tokens: a refresh
// invalidates the token it was given and returns its replacement. A stale
// refresh token therefore does not merely fail, its reuse is read as a
// stolen-token replay and revokes the entire grant chain, which the user
// experiences as being logged out. Two things follow, and this type exists
// for both. A refreshed token has to be persisted, or the next process
// presents one that has already been spent. And refreshes have to be
// serialized, in-process with a mutex and across processes with the Store's
// lock, with the stored token re-read under that lock so a token another
// process has already rotated is adopted rather than presented again.
//
// One instance per process is enough and is what callers should share:
// every client built from it then refreshes through the same mutex.
type TokenSource struct {
	ctx    context.Context
	conf   oauth2.Config
	store  Store
	logger *slog.Logger

	mu          sync.Mutex
	token       *oauth2.Token
	unpersisted error
}

// Option configures a TokenSource.
type Option func(*TokenSource)

// WithLogger sets where the source records that it refreshed, which is
// worth seeing when working out how often a short-lived consumer is going
// back to the authorization server. Everything that goes wrong is returned
// rather than logged. Defaults to slog.Default().
func WithLogger(logger *slog.Logger) Option {
	return func(s *TokenSource) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// WithEndpoint points the source at a different authorization server than
// Endpoint, which is what a test needs and what a non-production CBWS
// environment would use.
func WithEndpoint(endpoint oauth2.Endpoint) Option {
	return func(s *TokenSource) {
		s.conf.Endpoint = endpoint
	}
}

// NewTokenSource returns a TokenSource over store. The stored token is read
// once here so that a configuration holding no token is reported now rather
// than on the first request; ErrNoToken is what that returns.
func NewTokenSource(ctx context.Context, store Store, scopes []string, options ...Option) (*TokenSource, error) {
	token, err := store.Load()
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, ErrNoToken
	}

	source := &TokenSource{
		ctx:    ctx,
		store:  store,
		logger: slog.Default(),
		token:  token,
		conf: oauth2.Config{
			ClientID: ClientID,
			Scopes:   scopes,
			Endpoint: Endpoint,
		},
	}

	for _, option := range options {
		option(source)
	}

	return source, nil
}

// Token implements oauth2.TokenSource.
//
// Every step that cannot be completed safely fails the call rather than
// falling back. The trade is deliberate and it is not symmetric: a failed
// call costs one command, while presenting a refresh token that another
// process has already spent revokes the grant chain and logs the user out
// of everything. There is no step here whose failure is worth that.
func (s *TokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A rotation this process completed but could not store leaves the
	// spent token on disk for the next one to present. Nothing later in
	// this process can repair that, so the failure is reported for as long
	// as the source lives rather than once.
	if s.unpersisted != nil {
		return nil, s.unpersisted
	}

	if s.token.Valid() {
		return s.token, nil
	}

	// Without the lock there is no way to keep another process from
	// spending the same token at the same moment. A Store that cannot lock
	// its backing storage, but can serialize some other way, says so by
	// returning a no-op release from Lock.
	unlock, err := s.store.Lock()
	if err != nil {
		return nil, fmt.Errorf("could not lock the credential store to refresh the token: %w", err)
	}
	defer unlock()

	// Another process may have rotated the token between our last read and
	// this lock, which makes the re-read part of the correctness of the
	// refresh rather than an optimization over it.
	if err := s.adoptStoredToken(); err != nil {
		return nil, err
	}

	if s.token.Valid() {
		return s.token, nil
	}

	token, err := s.conf.TokenSource(s.ctx, s.token).Token()
	if err != nil {
		return nil, fmt.Errorf("could not refresh token, run 'cbws init' to log in again: %w", err)
	}

	// Ours is spent from here on, whatever happens to the store. Keeping
	// the replacement is what stops a later call in this process from
	// presenting the spent one and revoking the chain itself.
	s.token = token

	if err := s.store.Save(token); err != nil {
		s.unpersisted = fmt.Errorf(
			"refreshed the token but could not store it, so the stored credential is now spent; run 'cbws init' to log in again: %w",
			err,
		)

		return nil, s.unpersisted
	}

	// The expiry alone: a log line is the last place a credential should
	// end up, and it is the only field here worth having anyway.
	s.logger.Debug("Refreshed the CBWS credential", "expiry", token.Expiry)

	return token, nil
}

// adoptStoredToken re-reads the store under the lock and takes over
// whatever token is there, so a refresh token another process has already
// rotated is used instead of our spent copy.
//
// Anything that leaves it unable to say which token is current aborts the
// refresh. Our own copy cannot be assumed good: the whole reason to look is
// that another process may have replaced it.
func (s *TokenSource) adoptStoredToken() error {
	stored, err := s.store.Load()

	switch {
	// The credential was removed while we held a copy of it, which is what
	// logging out looks like from here. Refreshing would write it back and
	// undo that.
	case errors.Is(err, ErrNoToken):
		return errors.New("the stored credential was removed, so there is nothing to refresh; run 'cbws init' to log in again")

	case err != nil:
		return fmt.Errorf("could not re-read the credential store, so the stored token cannot be told from a spent one: %w", err)
	}

	// An entry with no refresh token cannot say whether ours is still
	// current, and refreshing on the strength of a copy that may already
	// have been replaced is the thing being avoided.
	if stored == nil || stored.RefreshToken == "" {
		return errors.New("the stored credential carries no refresh token; run 'cbws init' to log in again")
	}

	// A different refresh token means ours is spent. A valid stored token
	// means there is nothing left to refresh. Anything else is the token we
	// already hold.
	if stored.RefreshToken != s.token.RefreshToken || stored.Valid() {
		s.token = stored
	}

	return nil
}
