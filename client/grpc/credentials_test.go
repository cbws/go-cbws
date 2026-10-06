package grpc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.cbws.cloud/sdk/oauth2/cli"
	"golang.org/x/oauth2"
)

// TestCredentialsOutliveTheContextTheyAreBuiltWith builds credentials on a
// context that is cancelled before their first token is due, as a client
// built during one request and kept for later ones is. The CLI configuration
// is the source used because its refresh request is made on the context the
// source was built with.
func TestCredentialsOutliveTheContextTheyAreBuiltWith(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-2","token_type":"bearer","refresh_token":"rt-2","expires_in":3600}`))
	}))
	t.Cleanup(server.Close)

	previous := cli.Endpoint
	cli.Endpoint = oauth2.Endpoint{TokenURL: server.URL}
	t.Cleanup(func() { cli.Endpoint = previous })

	home := t.TempDir()
	config := filepath.Join(home, "cbws.yaml")
	require.NoError(t, os.WriteFile(config, []byte(`oauth_token:
  accesstoken: at-1
  tokentype: bearer
  refreshtoken: rt-1
  expiry: "2020-01-01T00:00:00Z"
`), 0o600))

	t.Setenv("HOME", home)
	t.Setenv("CLOUDBEAR_CREDENTIALS", "")
	t.Setenv("CBWS_CREDENTIALS", "")
	t.Setenv("CBWS_CONFIG_FILE", config)

	o, err := processAndValidateOpts(nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	credentials, err := clientCredentials(ctx, o)
	require.NoError(t, err)
	cancel()

	token, err := credentials.TokenSource.Token()
	require.NoError(t, err)
	assert.Equal(t, "at-2", token.AccessToken)
}
