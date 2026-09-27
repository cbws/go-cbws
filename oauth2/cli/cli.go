// Package cli authenticates as the user the CBWS CLI is logged in as, by
// reading the token the CLI stores in its configuration file and keeping it
// refreshed.
//
// It is the credential of last resort for a developer's own machine: a tool
// built on the SDK picks it up without the developer having to issue a
// service account key for themselves. Because the token is shared with the
// CLI and with every other process reading the same file, refreshing it is
// a good deal more involved than handing out a bearer token, which is what
// TokenSource is for.
package cli

import (
	"context"

	"golang.org/x/oauth2"
)

// ClientID is the OAuth client the CBWS CLI and the SDK authenticate as. It
// is a public client, so this is an identifier rather than a secret.
const ClientID = "612537ce-d5ba-475f-a77e-c1f1197ad3d5"

// Endpoint is the CBWS Accounts authorization server. It is a variable so a
// test, or a deployment that is not production CBWS, can point the flow
// elsewhere; prefer WithEndpoint over assigning to it, which changes the
// behaviour of every source in the process.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://accounts.cbws.cloud/oauth2/auth",
	TokenURL: "https://accounts.cbws.cloud/oauth2/token",
}

// Config is the part of the CBWS CLI configuration file this package reads.
//
// Deprecated: the file is read through FileStore, which preserves the keys
// this type does not name. It remains because it is exported.
type Config struct {
	OAuthToken struct {
		AccessToken  string `yaml:"accesstoken"`
		TokenType    string `yaml:"tokentype"`
		Expiry       string
		RefreshToken string `yaml:"refreshtoken"`
	} `yaml:"oauth_token"`
}

// NewTokenSourceFromConfig returns a token source over the CBWS CLI
// configuration file at path, persisting each rotated refresh token back to
// it.
//
// A file that does not exist is reported with an error satisfying
// os.IsNotExist, and a file holding no token with ErrNoToken, so a caller
// choosing between credential sources can move on to the next one.
//
// The signature takes no options on purpose. Adding a variadic parameter
// keeps every call compiling but changes the function's type, which breaks
// anything that assigns it to a declared func type. Call NewTokenSource
// with NewFileStore to configure the source.
func NewTokenSourceFromConfig(ctx context.Context, path string, scopes []string) (oauth2.TokenSource, error) {
	source, err := NewTokenSource(ctx, NewFileStore(path), scopes)
	if err != nil {
		// Returning source directly would hand back an interface holding a
		// nil pointer, which is not nil and which a caller checking for one
		// would take for a usable source.
		return nil, err
	}

	return source, nil
}

// TokenNotifyFunc is a function that accepts an oauth2 Token upon refresh, and
// returns an error if it should not be used.
//
// Deprecated: notification is not enough to keep a rotating refresh token
// alive, since the callback fires after the token has already been spent
// and has no way to serialize against another process doing the same. Use
// TokenSource, which persists under a lock.
type TokenNotifyFunc func(*oauth2.Token) error

// NotifyingTokenSource is an oauth2.TokenSource that calls a function when a
// new token is obtained.
//
// Deprecated: see TokenNotifyFunc. It also calls f on every Token() rather
// than on an actual refresh, because the underlying source does not say
// which is which.
type NotifyingTokenSource struct {
	f   TokenNotifyFunc
	src oauth2.TokenSource
}

// NewNotifyingTokenSource creates a NotifyingTokenSource from an underlying src
// and calls f when a new token is obtained.
//
// Deprecated: see TokenNotifyFunc.
func NewNotifyingTokenSource(src oauth2.TokenSource, f TokenNotifyFunc) *NotifyingTokenSource {
	return &NotifyingTokenSource{f: f, src: src}
}

// Token fetches a new token from the underlying source.
func (s *NotifyingTokenSource) Token() (*oauth2.Token, error) {
	t, err := s.src.Token()
	if err != nil {
		return nil, err
	}
	if s.f == nil {
		return t, nil
	}
	return t, s.f(t)
}
