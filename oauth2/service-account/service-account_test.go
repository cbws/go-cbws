package service_account

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

// TestTokenSourceStaysWithinTheCallersBudget holds the key exchange open
// and checks that a token request on a cancelled or expiring context comes
// back within it, as a caller with a fixed deadline needs.
func TestTokenSourceStaysWithinTheCallersBudget(t *testing.T) {
	isolate(t)

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// The server ends a request's context when the client goes away
		// only once the request body has been read. A handler that leaves
		// the body unread outlives the exchange, and server.Close waits on
		// it for good.
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	t.Setenv(TokenURLEnvVar, server.URL+"/oauth2/token")

	credentials := testCredentials(t)

	for _, tt := range []struct {
		name string
		ctx  func(t *testing.T) context.Context
		want error
	}{
		{
			name: "cancelled",
			ctx: func(*testing.T) context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			want: context.Canceled,
		},
		{
			// The deadline starts in the subtest, so that it is still ahead
			// when the request is sent and the exchange is held open on it.
			name: "deadline",
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				t.Cleanup(cancel)
				return ctx
			},
			want: context.DeadlineExceeded,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tokenSource, err := credentials.TokenSource(tt.ctx(t), []string{"scope"})
			if err != nil {
				t.Fatalf("TokenSource: %+v", err)
			}

			start := time.Now()
			_, err = tokenSource.Token()
			if !errors.Is(err, tt.want) {
				t.Errorf("Token error = %v, want %v", err, tt.want)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Errorf("Token returned after %s, want within the caller's budget", elapsed)
			}
		})
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
		ProjectName:  "project-1",
		PrivateKeyID: "key-1",
		PrivateKey:   string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		ClientEmail:  "sa@example.com",
		ClientID:     "client-1",
	}
}

func TestParseCredentialsAcceptsAKeyFile(t *testing.T) {
	want := testCredentials(t)
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("could not marshal the key file: %+v", err)
	}

	got, err := ParseCredentials(data)
	if err != nil {
		t.Fatalf("ParseCredentials: %+v", err)
	}
	if *got != want {
		t.Errorf("ParseCredentials = %+v, want %+v", *got, want)
	}
}

func TestParseCredentialsRejects(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Credentials)
		data   string
		want   string
	}{
		{name: "not JSON", data: "not json", want: "not a CBWS service account key file"},
		{name: "wrong type", modify: func(c *Credentials) { c.Type = "authorized_user" }, want: `type "authorized_user"`},
		{
			name:   "missing fields",
			modify: func(c *Credentials) { c.ProjectName, c.ClientID = "", "" },
			want:   "missing project_name, client_id",
		},
		{name: "no PEM block", modify: func(c *Credentials) { c.PrivateKey = "not a key" }, want: "no PEM block"},
		{
			name: "not PKCS #8",
			modify: func(c *Credentials) {
				c.PrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")}))
			},
			want: "could not parse private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(tt.data)
			if tt.modify != nil {
				credentials := testCredentials(t)
				tt.modify(&credentials)

				var err error
				if data, err = json.Marshal(credentials); err != nil {
					t.Fatalf("could not marshal the key file: %+v", err)
				}
			}

			_, err := ParseCredentials(data)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ParseCredentials error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}
