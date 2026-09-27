package tokencache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
)

// Key names the authority a token was issued under. Two requests may share
// a cached token exactly when every field here matches, so the fields are
// the ones that change what the token is allowed to do or who it speaks
// for. Leaving one out would let a token cross a boundary it was never
// issued for.
//
// None of it is secret. A key is derived from identity and request
// parameters, never from a token, a refresh token or key material, so the
// identifier it produces is safe to use as a filename and to put in a log.
type Key struct {
	// Issuer is the authorization server, metadata endpoint or other
	// authority that mints the token. It separates environments: a token
	// from a staging Accounts is not a token from production.
	Issuer string `json:"issuer"`

	// Subject identifies the principal or the credential the token is
	// obtained with, such as a service account client ID or the path of
	// the configuration a user is logged in through. It separates
	// identities sharing one issuer.
	Subject string `json:"subject"`

	// Scopes are the scopes requested for the token. Order does not
	// matter; they are compared as a set.
	Scopes []string `json:"scopes,omitempty"`

	// Audience is the audience requested for the token, where the flow has
	// one.
	Audience string `json:"audience,omitempty"`

	// Impersonate is the identity being impersonated, where the token is
	// obtained on behalf of someone other than Subject.
	Impersonate string `json:"impersonate,omitempty"`

	// Generation distinguishes one identity from the next behind a Subject
	// that cannot tell them apart on its own.
	//
	// A configuration file is the case this exists for. Its path names
	// where a credential is read from, not who it belongs to, so logging
	// out of it and back in as someone else leaves every other field
	// identical while the principal has changed underneath. An entry
	// written before that would then be served to the new identity, which
	// authenticates as the wrong person until it expires.
	//
	// Nothing the SDK can see distinguishes those two logins, so it is the
	// application that has to: supply a value that changes whenever the
	// identity behind Subject does. A caller whose Subject already names a
	// principal, such as a service account client id, has no use for this.
	Generation string `json:"generation,omitempty"`
}

// ErrIncompleteKey is returned for a key that names no authority at all.
// Such a key would be shared by every credential in the process, which is
// the one outcome a cache key exists to prevent.
var ErrIncompleteKey = errors.New("a cache key needs at least an issuer and a subject")

// ID returns the stable identifier the Cache stores an entry under.
//
// It is a digest rather than the fields themselves. The fields are not
// secret, but they are a principal's identity, and a digest keeps that out
// of filenames and logs while still being fixed-length and safe as a path
// element whatever the fields contain.
func (k Key) ID() (string, error) {
	if k.Issuer == "" || k.Subject == "" {
		return "", ErrIncompleteKey
	}

	// Scopes are a set: the same two scopes in either order describe the
	// same authority and must not produce two entries. Sorting a copy
	// leaves the caller's slice alone.
	canonical := k
	canonical.Scopes = slices.Sorted(slices.Values(k.Scopes))

	// JSON rather than a hand-rolled join, so no field value can be
	// mistaken for a separator and make two different keys agree.
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(encoded)

	return hex.EncodeToString(sum[:]), nil
}
