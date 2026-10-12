// Package defaultscopes lets a client name the scopes a token minted for it asks for when its
// caller names none.
//
// A client asks for its own service's scope, cbws.<service>, so a token minted for it is good for
// that service alone: a caller that holds the permissions for more cannot reach another service
// through it by accident. A caller that does want more, such as one calling several services,
// asks with option.WithScopes, which replaces the default.
//
// It is internal because the default is the client's to set, not the caller's.
package defaultscopes

import "go.cbws.cloud/sdk/option"

// With sets a client's default scopes.
func With(scopes ...string) option.ClientOption {
	return withDefaultScopes(scopes)
}

type withDefaultScopes []string

func (w withDefaultScopes) Apply(o *option.DialSettings) {
	o.DefaultScopes = append([]string(nil), w...)
}
