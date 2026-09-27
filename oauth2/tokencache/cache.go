// Package tokencache reuses an access token across process boundaries.
//
// The SDK's token sources already reuse a token in memory, which ends with
// the process. That is enough for a server and nothing at all for a
// short-lived consumer: a Kubernetes credential plugin, or any CLI command,
// starts a fresh process per invocation and asks the authorization server
// for a token it was already holding a moment ago.
//
// This package supplies the reuse without deciding where it is kept. The
// SDK owns what an entry means, when it has aged out and what identifies
// it; the application owns the storage, because writing bearer tokens to
// disk is its decision to make and not a default a library should pick.
// Nothing here caches anything until an application passes a Cache.
package tokencache

import (
	"errors"

	"golang.org/x/oauth2"
)

// ErrMiss is what Load returns when it holds no entry for a key. It is the
// ordinary outcome of a first call, not a failure, and it is the only error
// a Cache should use to say so.
var ErrMiss = errors.New("no cached token")

// Cache stores access tokens where they outlive the process.
//
// Implementations should treat an entry they cannot read as a miss rather
// than an error, since a corrupted entry and a missing one call for exactly
// the same thing: fetch a token and replace what is there. An error is for
// storage that is broken in a way the caller might want to hear about.
//
// A Cache is used from several goroutines at once and must be safe for
// concurrent use.
type Cache interface {
	// Load returns the token stored under id, or ErrMiss when there is
	// none. The token is returned as it was stored; judging whether it is
	// still usable belongs to the caller.
	Load(id string) (*oauth2.Token, error)

	// Store records token under id, replacing any existing entry.
	Store(id string, token *oauth2.Token) error
}

// Duplicate fetches
//
// Two sources over one key, in one process or in several, may each fetch a
// token where one would have done. Nothing here prevents that, and the
// omission is deliberate.
//
// Preventing it means holding a lock across the call to the wrapped source,
// and that source is arbitrary code: a decorator hides what it wraps, so a
// wrapped source may reach another cache over the same key and wait for a
// lock its own caller is holding. No inspection can rule that out. A
// duplicate access-token fetch costs one request and nothing else, because
// fetching an access token consumes nothing, while a deadlock costs the
// process.
//
// Where a fetch consumes something, the source that owns that credential
// serializes it. Obtaining an access token from the CBWS CLI credential
// spends a single-use refresh token, and the store behind it takes a
// cross-process lock and re-reads under that lock, so processes rotate one
// after another rather than racing, and none of them presents a token
// another has already spent.
//
// They do each rotate, though. A process that missed this cache goes on to
// refresh even if another has since stored a token, because the credential
// store it re-reads no longer carries an access token for it to notice: a
// cache owns that, which is the point. So a burst of N processes missing
// together costs N sequential rotations rather than one. That is safe and
// it is not free, and coalescing it needs the layer that wires the two
// together to re-check this cache while holding the credential-store lock.
