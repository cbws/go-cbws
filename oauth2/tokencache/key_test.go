package tokencache

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// TestKeyIsolation is the security property of the package: a token issued
// under one authority must never be served to a request made under
// another. Every field below changes what the token may do or who it
// speaks for, so every one of them has to change the identifier.
func TestKeyIsolation(t *testing.T) {
	base := Key{
		Issuer:      "https://accounts.cbws.cloud/oauth2/token",
		Subject:     "sa-client-id",
		Scopes:      []string{"openid", "offline"},
		Audience:    "https://compute.cbws.cloud",
		Impersonate: "someone@example.test",
	}

	tests := []struct {
		name  string
		other Key
	}{
		{name: "a different issuer is a different environment", other: modify(base, func(k *Key) {
			k.Issuer = "https://accounts.staging.cbws.cloud/oauth2/token"
		})},
		{name: "a different subject is a different principal", other: modify(base, func(k *Key) {
			k.Subject = "another-client-id"
		})},
		{name: "a narrower scope set is less authority", other: modify(base, func(k *Key) {
			k.Scopes = []string{"openid"}
		})},
		{name: "an extra scope is more authority", other: modify(base, func(k *Key) {
			k.Scopes = []string{"openid", "offline", "email"}
		})},
		{name: "no scopes at all", other: modify(base, func(k *Key) { k.Scopes = nil })},
		{name: "a different audience is a different service", other: modify(base, func(k *Key) {
			k.Audience = "https://vpc.cbws.cloud"
		})},
		{name: "a different impersonation target is a different identity", other: modify(base, func(k *Key) {
			k.Impersonate = "someone-else@example.test"
		})},
		{name: "no impersonation", other: modify(base, func(k *Key) { k.Impersonate = "" })},
	}

	want := id(t, base)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := id(t, test.other); got == want {
				t.Errorf("%+v shares an entry with %+v", test.other, base)
			}
		})
	}
}

// TestKeyIsStable: the identifier has to survive a restart, or nothing is
// ever a hit. Equal keys agree, and a scope set written in another order is
// the same authority rather than a second entry.
func TestKeyIsStable(t *testing.T) {
	key := Key{Issuer: "https://accounts.cbws.cloud/oauth2/token", Subject: "sa", Scopes: []string{"openid", "offline"}}

	// Computed separately rather than compared in place, which is the
	// point: the identifier has to be a function of the key alone.
	first, second := id(t, key), id(t, key)
	if first != second {
		t.Errorf("the same key produced %q and %q", first, second)
	}

	reordered := key
	reordered.Scopes = []string{"offline", "openid"}
	if id(t, reordered) != id(t, key) {
		t.Error("scope order changed the identifier, splitting one authority into two entries")
	}

	duplicated := key
	duplicated.Scopes = []string{"openid", "offline", "openid"}
	if id(t, duplicated) == id(t, key) {
		t.Error("a repeated scope was folded away; it should not silently mean the same set")
	}
}

// TestKeyDoesNotMutateItsInput: sorting the scopes must not reorder a slice
// the caller still holds and may be using for the request itself.
func TestKeyDoesNotMutateItsInput(t *testing.T) {
	scopes := []string{"offline", "openid"}
	key := Key{Issuer: "https://accounts.cbws.cloud/oauth2/token", Subject: "sa", Scopes: scopes}

	id(t, key)

	if scopes[0] != "offline" || scopes[1] != "openid" {
		t.Errorf("caller's scopes were reordered to %v", scopes)
	}
}

// TestKeyRevealsNothing: the identifier goes into filenames and logs, so it
// must not carry the identity it was built from, and it must be safe as a
// single path element whatever the fields contain.
func TestKeyRevealsNothing(t *testing.T) {
	key := Key{
		Issuer:  "https://accounts.cbws.cloud/oauth2/token",
		Subject: "../../etc/passwd someone@example.test",
	}

	got := id(t, key)

	for _, secret := range []string{"someone@example.test", "accounts.cbws.cloud", "passwd", "/", "..", " "} {
		if strings.Contains(got, secret) {
			t.Errorf("identifier %q contains %q", got, secret)
		}
	}
	if len(got) != 64 {
		t.Errorf("identifier is %d characters, want a 64-character digest", len(got))
	}
}

// TestKeyNeedsAnAuthority: a key naming nothing would be shared by every
// credential in the process, which is the one outcome a cache key exists to
// prevent.
func TestKeyNeedsAnAuthority(t *testing.T) {
	for _, test := range []struct {
		name string
		key  Key
	}{
		{name: "empty", key: Key{}},
		{name: "no issuer", key: Key{Subject: "sa"}},
		{name: "no subject", key: Key{Issuer: "https://accounts.cbws.cloud/oauth2/token"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.key.ID(); !errors.Is(err, ErrIncompleteKey) {
				t.Errorf("error = %v, want ErrIncompleteKey", err)
			}
		})
	}
}

// TestNewTokenSourceRejectsAnIncompleteKey: the key is checked when the
// source is built, not on the first request, so a wiring mistake surfaces
// at wiring time.
func TestNewTokenSourceRejectsAnIncompleteKey(t *testing.T) {
	_, err := NewTokenSource(&countingSource{}, newMemoryCache(), Key{})
	if !errors.Is(err, ErrIncompleteKey) {
		t.Errorf("error = %v, want ErrIncompleteKey", err)
	}
}

// TestNewTokenSourceWithoutACacheReturnsTheSource is what keeps existing
// SDK users where they were: no cache configured means no caching and no
// wrapper, rather than a decorator quietly deciding where to write tokens.
func TestNewTokenSourceWithoutACacheReturnsTheSource(t *testing.T) {
	inner := &countingSource{}

	source, err := NewTokenSource(inner, nil, Key{})
	if err != nil {
		t.Fatalf("NewTokenSource: %+v", err)
	}
	if source != oauth2.TokenSource(inner) {
		t.Error("a nil cache produced a wrapper, want the source returned unchanged")
	}
}

// TestNewTokenSourceNeedsASource guards the other nil.
func TestNewTokenSourceNeedsASource(t *testing.T) {
	if _, err := NewTokenSource(nil, newMemoryCache(), Key{Issuer: "i", Subject: "s"}); err == nil {
		t.Error("NewTokenSource accepted a nil source")
	}
}

func modify(base Key, change func(*Key)) Key {
	// The scopes are copied so a change cannot reach the base key's slice.
	other := base
	other.Scopes = append([]string(nil), base.Scopes...)
	change(&other)

	return other
}

func id(t *testing.T, key Key) string {
	t.Helper()

	got, err := key.ID()
	if err != nil {
		t.Fatalf("ID of %+v: %+v", key, err)
	}

	return got
}
