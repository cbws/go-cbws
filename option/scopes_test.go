package option

import (
	"slices"
	"testing"
)

// A client's default scopes apply until the caller asks for scopes of its own, which replace them
// rather than adding to them.
func TestScopesPreferTheCallersOverTheClientsDefault(t *testing.T) {
	var ds DialSettings
	if got := ds.scopes(); len(got) != 0 {
		t.Errorf("no defaults and no scopes asked for = %v, want none", got)
	}

	ds.DefaultScopes = []string{"cbws.registry"}
	if got := ds.scopes(); !slices.Equal(got, []string{"cbws.registry"}) {
		t.Errorf("scopes = %v, want the client's default", got)
	}

	WithScopes("cbws.registry.read-only", "cbws.compute").Apply(&ds)
	if got := ds.scopes(); !slices.Equal(got, []string{"cbws.registry.read-only", "cbws.compute"}) {
		t.Errorf("scopes = %v, want exactly what the caller asked for", got)
	}
}
