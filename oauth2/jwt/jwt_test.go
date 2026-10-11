package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.cbws.cloud/sdk/internal/useragent"
)

func TestAssertionExpiry(t *testing.T) {
	privateKeyBytes, _ := pem.Decode([]byte("-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC2JqiHGhFRZTts\nSAVaQ9j96pjyN/yZIUKfcM6wv/gZ9uyDvWtoWPzUPry7cYJRYPNafOZ+40c6O8O9\nfBqQta2D8CpSiPnCLHQwdok2NShdb85g5NebZF/GNo9vJ4wrDD+w+EhZXL2yOvdt\nX8wVawCVMA++857ukc4NqHO/dmPSl6FY3Vbmc2tAoxvBdvRgSS9/nyZEVHVVGHf7\n8ZySXeXal7XLQroDU2MhFqvpxs5uIh9JbEBfMh/3bg/ejsQP4JYGXzxiRmk1XeAI\npGk1K43ZGDlbgj8JH/5DqbFmdeZ0mwL9AGcfKSgG9kBCUjcVV+8PBgDGereXTs1D\noPaZz6+JAgMBAAECggEATPxL0EYZObCyi9JoyLzSUoc7u2wkS8g980tnYFbSko7F\naey+H600trQJaqPP83spf344oTqIGTm3QjfYtn7C5ne0O4v/G61UMkN3PLz84Xjm\n3hb6dYfX3tuihdVOLceQh8h4M6S53EGF3+lURV0jMurMTOWEr8paL3WZ7jsod5G9\n/UEupmxsRT+mKOCTC/fWWt6fJwR9NqTtn5IBUH9E/lT1+x8Lpm694CwMeuXA4EBA\nL7rRiL6zBQElZb5HPK47t+XkvVmSnq/ndXMPYMfYQUl2ciWDqRx83NO53+5jCU3r\nJGqbTEUsKYbASQBJHavvj43Idhr/MDoPBekiryuRAQKBgQDhxGF+KJh+NS9PT+T9\nafdRxAj+vbSNcV4zWxiYxeKeSrLoHqbE2PR2YvaxAJ25Ti4TYYCzguqDVAHTUbio\nvumPRYp5p3xkJYM8W1qMhp4QD5A1uvjK6v+PLA6xCCyWNQmPoJHLuZ9jkFCD1vs7\nUrwJFTBzyw/AgEtCv1BfcI3X4QKBgQDOiw4dYL+b2t3lOfP4RQJQwTl5Kmi/BO7+\nDzZfGRD9VROmN+9vePaDPl7brC/9ETqy/J9kWL4P7a6z6hDGxNblko8WRIqZmbAD\nT+HHIWdSGRv+YZHy7vsWH6/dJj+Zpx5J3qN+W9a2zmcrATAN3bdFiS19fkFtkFDJ\nAPQsD0GsqQKBgQDJgv+CG7oA7HfN0wIRLwQRd2iP98OwfAAY1radpgMgRoxpovI3\nwW5yPOL0GhitzZpSsjSuBaxMjC8U71xjQgQ2XVu8OkJNIS6CMQghZgavTzTowHpQ\npHB22lxCp4kkiTJ/gFKiBIy/0ZAMHVchHDe546/bquPkbp6+dQTIKy5wAQKBgQCj\nyT1+KnSHoT4JQrWnEQJPC4sJ/IlnwP/MVD/nlbcVTVvxmbWzjhbd6J3MUXUUl48W\n1KGJL544f2Dkpx56oSlQj7IMFHpcZ7VeSwBdqq2GOwcp6DGWldBisOoC0wvoStAI\nABdiYm2YNYE2ZxC2TjXBXJDITVCRE7ocSzdVoRuRUQKBgQCk2llkK4NMcfR50IPI\nk8zVPIu21oC+Eb2kCnFDi1pP4+KeU073LrkhBmHZTp3M2utDUbQL33h3/LlcuYvl\nh8KC6lqXE4fZOdTk4ZlqSwipEh6PT3otxtgl/LlyO59wUm+vPak46k0ZIcIN3+Ah\nUd57QN5x7kV8R2VFHBRhnxAFlQ==\n-----END PRIVATE KEY-----\n"))
	if privateKeyBytes == nil {
		t.Errorf("PEM parse failed")

		return
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBytes.Bytes)
	if err != nil {
		t.Errorf("Private key parse failed: %+v", err)

		return
	}

	js := jwtSource{
		conf: &Config{
			PrivateKey:    privateKey,
			PrivateKeyID:  "c9d11f86-61d8-4cd7-ab9e-5b2f5a80550e",
			Subject:       "893e3210-b34c-49dd-adad-b33cba76eb07",
			TokenURL:      "https://accounts.cbws.cloud/oauth2/token",
			SigningMethod: jwt.GetSigningMethod("RS256"),
		},
	}
	assertion, err := js.assertion()
	if err != nil {
		t.Errorf("Assertion generation: %+v", err)

		return
	}

	claims := &JWTOAuthClaims{}
	token, err := jwt.ParseWithClaims(assertion, claims, func(token *jwt.Token) (interface{}, error) {
		return privateKey.(*rsa.PrivateKey).Public(), nil
	})
	if err != nil {
		t.Errorf("Assertion parse: %+v", err)
	}

	assert.True(t, token.Valid)
	assert.Greater(t, int(time.Unix(claims.ExpiresAt, 0).Sub(time.Now()).Seconds()), 1800)
}

// The token endpoint validates the assertion, so its encoding is a contract:
// a single audience as a string, the expiry in whole seconds, the key id in
// the header, and nothing it was not given.
func TestAssertionWireFormat(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	js := jwtSource{
		conf: &Config{
			ClientID:      "client-id",
			Subject:       "subject",
			PrivateKey:    privateKey,
			PrivateKeyID:  "key-id",
			Scopes:        []string{"a", "b"},
			TokenURL:      "https://accounts.cbws.cloud/oauth2/token",
			SigningMethod: jwt.GetSigningMethod("RS256"),
		},
	}
	assertion, err := js.assertion()
	require.NoError(t, err)

	segments := strings.Split(assertion, ".")
	require.Len(t, segments, 3)

	var header map[string]any
	decodeSegment(t, segments[0], &header)
	assert.Equal(t, map[string]any{"alg": "RS256", "typ": "JWT", "kid": "key-id"}, header)

	var claims map[string]json.RawMessage
	decodeSegment(t, segments[1], &claims)

	keys := make([]string, 0, len(claims))
	for key := range claims {
		keys = append(keys, key)
	}
	assert.ElementsMatch(t, []string{"aud", "exp", "jti", "iss", "sub", "scope"}, keys)

	assert.JSONEq(t, `"https://accounts.cbws.cloud/oauth2/token"`, string(claims["aud"]))
	assert.JSONEq(t, `"client-id"`, string(claims["iss"]))
	assert.JSONEq(t, `"subject"`, string(claims["sub"]))
	assert.JSONEq(t, `"a b"`, string(claims["scope"]))
	assert.Regexp(t, `^[0-9]+$`, string(claims["exp"]))
}

func decodeSegment(t *testing.T, segment string, into any) {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(segment)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, into))
}

func TestTokenExpiryFromIDToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	idToken := func(t *testing.T, claims jwt.MapClaims) string {
		t.Helper()

		signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("any key"))
		require.NoError(t, err)

		return signed
	}
	idTokenExpiry := time.Now().Add(20 * time.Minute).Truncate(time.Second)

	tests := []struct {
		name    string
		idToken string
		// wantExpiry is checked to the second; zero means expires_in applies.
		wantExpiry time.Time
		wantErr    bool
	}{
		{name: "IDTokenExpiryTakesPrecedence", idToken: idToken(t, jwt.MapClaims{"exp": idTokenExpiry.Unix()}), wantExpiry: idTokenExpiry},
		{name: "IDTokenWithoutExpiryKeepsExpiresIn", idToken: idToken(t, jwt.MapClaims{"sub": "subject"})},
		{name: "MalformedIDTokenFails", idToken: "not-a-jwt", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"access_token":"at","token_type":"bearer","expires_in":3600,"id_token":"`+tt.idToken+`"}`)
			}))
			defer server.Close()

			js := jwtSource{
				ctx: context.Background(),
				conf: &Config{
					PrivateKey:    privateKey,
					TokenURL:      server.URL,
					SigningMethod: jwt.GetSigningMethod("RS256"),
				},
			}
			token, err := js.Token()
			if tt.wantErr {
				require.Error(t, err)

				return
			}
			require.NoError(t, err)

			if tt.wantExpiry.IsZero() {
				assert.WithinDuration(t, time.Now().Add(time.Hour), token.Expiry, time.Minute)
			} else {
				assert.True(t, tt.wantExpiry.Equal(token.Expiry), "expiry %v, want %v", token.Expiry, tt.wantExpiry)
			}
		})
	}
}

func TestTokenRequestIdentifiesTheSDK(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var received http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"at","token_type":"bearer","expires_in":3600}`)
	}))
	defer server.Close()

	js := jwtSource{
		ctx: context.Background(),
		conf: &Config{
			PrivateKey:    privateKey,
			TokenURL:      server.URL,
			SigningMethod: jwt.GetSigningMethod("RS256"),
		},
	}
	_, err = js.Token()
	require.NoError(t, err)

	assert.Equal(t, useragent.SDK(), received.Get("User-Agent"))
	assert.Equal(t, useragent.APIClient(), received.Get(useragent.APIClientHeader))
}
