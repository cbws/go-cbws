package service_account

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// isolate clears both ways of moving the token endpoint, so a test starts
// from the default whatever the environment running it has set.
func isolate(t *testing.T) {
	t.Helper()

	t.Setenv(TokenURLEnvVar, "")
	previous := tokenURL
	SetTokenURL("")
	t.Cleanup(func() { SetTokenURL(previous) })
}

func TestTokenURLDefaultsToThePublicEndpoint(t *testing.T) {
	isolate(t)

	if got := TokenURL(); got != "https://accounts.cbws.cloud/oauth2/token" {
		t.Errorf("TokenURL() = %q, want the public endpoint", got)
	}
}

func TestTokenURLFromEnvironment(t *testing.T) {
	isolate(t)
	t.Setenv(TokenURLEnvVar, "http://hydra.internal:4444/oauth2/token")

	if got := TokenURL(); got != "http://hydra.internal:4444/oauth2/token" {
		t.Errorf("TokenURL() = %q, want the URL from %s", got, TokenURLEnvVar)
	}
}

// TestSetTokenURLOverridesEnvironment keeps the services that set the URL in
// code on the endpoint they chose, whatever their environment says.
func TestSetTokenURLOverridesEnvironment(t *testing.T) {
	isolate(t)
	t.Setenv(TokenURLEnvVar, "http://from-env/oauth2/token")
	SetTokenURL("http://from-code/oauth2/token")

	if got := TokenURL(); got != "http://from-code/oauth2/token" {
		t.Errorf("TokenURL() = %q, want the URL set in code", got)
	}

	SetTokenURL("")
	if got := TokenURL(); got != "http://from-env/oauth2/token" {
		t.Errorf("after clearing, TokenURL() = %q, want the URL from %s", got, TokenURLEnvVar)
	}
}

// TestTokenSourceKeepsThePublicAudience is the property that makes moving
// the endpoint safe: the request goes to the configured address, but the
// assertion it carries is still addressed to the public token URL, which is
// what the token service validates it against.
func TestTokenSourceKeepsThePublicAudience(t *testing.T) {
	isolate(t)

	var audience string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("could not parse the token request: %+v", err)
		}

		parts := strings.Split(r.PostForm.Get("client_assertion"), ".")
		if len(parts) != 3 {
			t.Errorf("client_assertion is not a JWT: %q", r.PostForm.Get("client_assertion"))
			http.Error(w, "bad assertion", http.StatusBadRequest)
			return
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Errorf("could not decode the assertion: %+v", err)
		}
		var claims struct {
			Audience string `json:"aud"`
		}
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Errorf("could not parse the assertion claims: %+v", err)
		}
		audience = claims.Audience

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-1","token_type":"bearer","expires_in":3600}`))
	}))
	t.Cleanup(server.Close)

	t.Setenv(TokenURLEnvVar, server.URL+"/oauth2/token")

	tokenSource, err := testCredentials(t).TokenSource(context.Background(), []string{"scope"})
	if err != nil {
		t.Fatalf("TokenSource: %+v", err)
	}

	token, err := tokenSource.Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if token.AccessToken != "at-1" {
		t.Errorf("AccessToken = %q, want the one the configured endpoint issued", token.AccessToken)
	}
	if audience != "https://accounts.cbws.cloud/oauth2/token" {
		t.Errorf("assertion audience = %q, want the public token URL", audience)
	}
}

func testCredentials(t *testing.T) Credentials {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate a key: %+v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("could not marshal the key: %+v", err)
	}

	return Credentials{
		Type:         "service_account",
		PrivateKeyID: "key-1",
		PrivateKey:   string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		ClientEmail:  "sa@example.com",
		ClientID:     "client-1",
	}
}
