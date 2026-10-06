package metadata

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
)

var endpoint = "http://169.254.169.254/cbws/core/test/token"

// Endpoint reports the metadata token endpoint. It is the issuer half of a
// token cache key, which needs to name the authority a token was minted by.
func Endpoint() string {
	return endpoint
}

// Option configures what a metadata TokenSource asks the endpoint for.
type Option func(*metadataSource)

// WithScopes requests tokens carrying scopes. Each scope is sent as its own
// scopes query parameter, which is the form the metadata server reads; a
// single comma-separated value would arrive there as one scope.
//
// Without it, or with no scopes, the request carries no query at all and the
// token gets whatever the authorization server grants by default.
func WithScopes(scopes ...string) Option {
	return func(s *metadataSource) {
		s.scopes = append(s.scopes, scopes...)
	}
}

// TokenSource returns a metadata TokenSource
func TokenSource(ctx context.Context, options ...Option) oauth2.TokenSource {
	source := metadataSource{ctx: ctx}
	for _, option := range options {
		option(&source)
	}

	source.endpoint = requestURL(endpoint, source.scopes)

	return oauth2.ReuseTokenSource(nil, source)
}

// requestURL adds the requested parameters to base, leaving it untouched
// when there are none so that a plain request stays byte-for-byte the same.
func requestURL(base string, scopes []string) string {
	if len(scopes) == 0 {
		return base
	}

	query := url.Values{"scopes": scopes}

	return base + "?" + query.Encode()
}

// metadataSource is a source that always requests a token from the CBWS metadata token endpoint.
type metadataSource struct {
	ctx      context.Context
	endpoint string
	scopes   []string
}

type UnexpectedMetadataResponse struct {
	StatusCode int
	Body       string
}

func (u UnexpectedMetadataResponse) Error() string {
	return fmt.Sprintf("unexpected metadata service response code %d: %s", u.StatusCode, u.Body)
}

func (js metadataSource) Token() (*oauth2.Token, error) {
	request, err := http.NewRequestWithContext(js.ctx, http.MethodGet, js.endpoint, nil)
	if err != nil {
		return nil, err
	}

	get, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = get.Body.Close() }()

	body, err := io.ReadAll(get.Body)
	if err != nil {
		return nil, err
	}

	if get.StatusCode != http.StatusOK {
		return nil, UnexpectedMetadataResponse{
			StatusCode: get.StatusCode,
			Body:       string(body),
		}
	}

	return &oauth2.Token{
		AccessToken: string(body),
		TokenType:   "Bearer",
		ExpiresIn:   60,
		Expiry:      time.Now().Add(60 * time.Second),
	}, nil
}
