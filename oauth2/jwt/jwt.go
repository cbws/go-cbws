package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.cbws.cloud/sdk/internal/retry"
	"go.cbws.cloud/sdk/internal/useragent"
	"go.cbws.cloud/sdk/oauth2/refresh"
	"golang.org/x/oauth2"
)

var (
	defaultGrantType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// Config is the configuration for using JWT to fetch tokens,
// commonly known as "two-legged OAuth 2.0".
type Config struct {
	// Email is the OAuth client identifier used when communicating with
	// the configured OAuth provider.
	ClientID string

	// PrivateKey contains the contents of an RSA private key or the
	// contents of a PEM file that contains a private key. The provided
	// private key is used to sign JWT payloads.
	// PEM containers with a passphrase are not supported.
	// Use the following command to convert a PKCS 12 file into a PEM.
	//
	//    $ openssl pkcs12 -in key.p12 -out key.pem -nodes
	//
	PrivateKey interface{}

	// PrivateKeyID contains an optional hint indicating which key is being
	// used.
	PrivateKeyID string

	// Subject is the optional user to impersonate.
	Subject string

	// Scopes optionally specifies a list of requested permission scopes.
	Scopes []string

	// TokenURL is the endpoint required to complete the 2-legged JWT flow.
	TokenURL string

	// Audience is the endpoint authority to complete the 2-legged JWT flow.
	Audience string

	// Expires optionally specifies how long the token is valid for.
	Expires time.Duration

	SigningMethod jwt.SigningMethod
}

// TokenSource returns a JWT TokenSource using the configuration
// in c and the HTTP client from the provided context. It reuses its token
// and fetches the replacement in the background before it expires.
//
// Every token request is made on ctx, so ending it ends any exchange in
// progress and fails those that follow. A source meant to outlive a request
// is built on a context without that request's cancellation.
func (c *Config) TokenSource(ctx context.Context) oauth2.TokenSource {
	return refresh.NewTokenSource(jwtSource{ctx: ctx, conf: c})
}

// Client returns an HTTP client wrapping the context's
// HTTP transport and adding Authorization headers with tokens
// obtained from c.
//
// The returned client and its Transport should not be modified.
func (c *Config) Client(ctx context.Context) *http.Client {
	return oauth2.NewClient(ctx, c.TokenSource(ctx))
}

// jwtSource is a source that always does a signed JWT request for a token.
// TokenSource wraps it in a refresh.TokenSource.
type jwtSource struct {
	ctx  context.Context
	conf *Config

	// policy overrides defaultRetryPolicy, for tests that cannot wait on it.
	policy *retry.Policy
}

// Token exchanges a freshly signed assertion for an access token.
//
// A transport failure on the way to the token endpoint or back is retried
// with backoff, within the attempts and time defaultRetryPolicy allows and
// never past the end of the source's context. An answer from the endpoint
// is not retried, whatever its status: a rejected assertion fails at once.
//
// An attempt that failed after the endpoint received it may still have
// minted a token, so a retried exchange can leave one token issued that is
// never used; it expires on its own. Each attempt signs its own assertion,
// since the endpoint refuses an assertion whose id it has already seen.
func (js jwtSource) Token() (*oauth2.Token, error) {
	policy := defaultRetryPolicy
	if js.policy != nil {
		policy = *js.policy
	}

	hc := oauth2.NewClient(useragent.Context(js.ctx), nil)

	return retry.Do(js.ctx, policy, retryable, func(ctx context.Context) (*oauth2.Token, error) {
		return js.exchange(ctx, hc)
	})
}

// exchange makes a single token request on ctx, which bounds the response
// body's read as well as the request.
func (js jwtSource) exchange(ctx context.Context, hc *http.Client) (*oauth2.Token, error) {
	payload, err := js.assertion()
	if err != nil {
		return nil, err
	}

	v := url.Values{}
	v.Set("grant_type", "client_credentials")
	v.Set("client_assertion_type", defaultGrantType)
	v.Set("client_assertion", payload)
	v.Set("scope", strings.Join(js.conf.Scopes, " "))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, js.conf.TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := hc.Do(req)
	if err != nil {
		return nil, transportError{err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, transportError{err: err}
	}
	if c := resp.StatusCode; c < 200 || c > 299 {
		return nil, retrieveError(resp, body)
	}
	// tokenRes is the JSON response body.
	var tokenRes struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int64  `json:"expires_in"` // relative seconds from now
	}
	if err := json.Unmarshal(body, &tokenRes); err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %w", err)
	}
	token := &oauth2.Token{
		AccessToken: tokenRes.AccessToken,
		TokenType:   tokenRes.TokenType,
	}
	raw := make(map[string]interface{})
	json.Unmarshal(body, &raw) // no error checks for optional fields
	token = token.WithExtra(raw)

	if secs := tokenRes.ExpiresIn; secs > 0 {
		token.Expiry = time.Now().Add(time.Duration(secs) * time.Second)
	}
	if v := tokenRes.IDToken; v != "" {
		// The id token's expiry takes precedence over expires_in. It is read
		// without verifying the signature: it arrived over the same TLS
		// connection as the access token, and only its expiry is used.
		var claims jwt.RegisteredClaims
		if _, _, err := jwt.NewParser().ParseUnverified(v, &claims); err != nil {
			return nil, fmt.Errorf("oauth2: error decoding JWT token: %v", err)
		}
		if claims.ExpiresAt != nil {
			token.Expiry = claims.ExpiresAt.Time
		}
	}
	return token, nil
}

// retrieveError reports a token endpoint's refusal. The RFC 6749 error
// fields are filled in when the body carries them, so that the error's
// message names the refusal rather than quoting the body.
func retrieveError(resp *http.Response, body []byte) *oauth2.RetrieveError {
	var fields struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ErrorURI         string `json:"error_uri"`
	}
	_ = json.Unmarshal(body, &fields) // a body that is not an RFC 6749 error leaves them empty

	return &oauth2.RetrieveError{
		Response:         resp,
		Body:             body,
		ErrorCode:        fields.Error,
		ErrorDescription: fields.ErrorDescription,
		ErrorURI:         fields.ErrorURI,
	}
}

func (js jwtSource) assertion() (string, error) {
	t := js.conf.Expires
	if t == 0 {
		t = 3600
	}
	a := js.conf.Audience
	if a == "" {
		a = js.conf.TokenURL
	}
	claims := &JWTOAuthClaims{
		Audience:  a,
		ExpiresAt: time.Now().Add(t * time.Second).Unix(),
		ID:        uuid.New().String(),
		Issuer:    js.conf.ClientID,
		Subject:   js.conf.Subject,
		Scope:     strings.Join(js.conf.Scopes, " "),
	}

	jwtToken := jwt.NewWithClaims(js.conf.SigningMethod, claims)
	jwtToken.Header["kid"] = js.conf.PrivateKeyID

	return jwtToken.SignedString(js.conf.PrivateKey)
}

// JWTOAuthClaims are the claims of a client assertion.
//
// They are declared field by field rather than through jwt.RegisteredClaims
// so that the encoding depends on nothing process-wide. RegisteredClaims
// writes a single audience as a list or a string, and an expiry with or
// without a fraction, according to package variables any other code in the
// process may set; here aud is always a string and exp always whole seconds.
type JWTOAuthClaims struct {
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	ID        string `json:"jti,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Scope     string `json:"scope,omitempty"` // space-delimited list of the permissions the application requests
}

var _ jwt.Claims = (*JWTOAuthClaims)(nil)

// GetExpirationTime implements jwt.Claims.
func (c *JWTOAuthClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.ExpiresAt == 0 {
		return nil, nil
	}

	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

// GetIssuedAt implements jwt.Claims. An assertion carries no iat.
func (c *JWTOAuthClaims) GetIssuedAt() (*jwt.NumericDate, error) { return nil, nil }

// GetNotBefore implements jwt.Claims. An assertion carries no nbf.
func (c *JWTOAuthClaims) GetNotBefore() (*jwt.NumericDate, error) { return nil, nil }

// GetIssuer implements jwt.Claims.
func (c *JWTOAuthClaims) GetIssuer() (string, error) { return c.Issuer, nil }

// GetSubject implements jwt.Claims.
func (c *JWTOAuthClaims) GetSubject() (string, error) { return c.Subject, nil }

// GetAudience implements jwt.Claims.
func (c *JWTOAuthClaims) GetAudience() (jwt.ClaimStrings, error) {
	if c.Audience == "" {
		return nil, nil
	}

	return jwt.ClaimStrings{c.Audience}, nil
}
