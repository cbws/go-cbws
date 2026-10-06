package metadata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.cbws.cloud/sdk/internal/useragent"
	"go.cbws.cloud/sdk/oauth2/refresh"
	"golang.org/x/oauth2"
)

var (
	endpoint            = "http://169.254.169.254/cbws/core/test/token"
	projectNameEndpoint = "http://169.254.169.254/cbws/core/project-name"
)

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

// TokenSource returns a metadata TokenSource. It reuses its token and fetches
// the replacement in the background before it expires.
func TokenSource(ctx context.Context, options ...Option) oauth2.TokenSource {
	source := metadataSource{ctx: ctx}
	for _, option := range options {
		option(&source)
	}

	source.endpoint = requestURL(endpoint, source.scopes)

	return refresh.NewTokenSource(source)
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

// assumedLifetime is how long a token is taken to live when the endpoint does
// not say. It is short so that a token is never held past its real expiry.
const assumedLifetime = 60 * time.Second

// tokenResponse is the endpoint's answer to a request for JSON.
type tokenResponse struct {
	AccessToken string    `json:"accessToken"`
	ExpiresAt   time.Time `json:"expiresAt"`
	TokenType   string    `json:"tokenType"`
}

// Token asks for the token as JSON, which carries its real expiry, so the
// source holds it for its whole lifetime rather than re-asking every minute.
// An endpoint that answers in plain text gets the assumed lifetime instead.
//
// The request names JSON in Accept and in Content-Type: the metadata server
// has chosen its answer by the request's Content-Type.
func (js metadataSource) Token() (*oauth2.Token, error) {
	header := http.Header{
		"Accept":       {jsonMediaType},
		"Content-Type": {jsonMediaType},
	}
	body, contentType, err := request(js.ctx, js.endpoint, header)
	if err != nil {
		return nil, err
	}

	if mediaType, _, _ := mime.ParseMediaType(contentType); mediaType != jsonMediaType {
		return &oauth2.Token{
			AccessToken: body,
			TokenType:   "Bearer",
			ExpiresIn:   int64(assumedLifetime.Seconds()),
			Expiry:      time.Now().Add(assumedLifetime),
		}, nil
	}

	var response tokenResponse
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		return nil, fmt.Errorf("could not read the metadata token response: %w", err)
	}
	if response.AccessToken == "" {
		return nil, errors.New("the metadata token response carries no access token")
	}

	token := &oauth2.Token{
		AccessToken: response.AccessToken,
		TokenType:   response.TokenType,
		Expiry:      response.ExpiresAt,
	}
	if token.TokenType == "" {
		token.TokenType = "Bearer"
	}
	if token.Expiry.IsZero() {
		token.Expiry = time.Now().Add(assumedLifetime)
	}
	token.ExpiresIn = int64(time.Until(token.Expiry).Seconds())

	return token, nil
}

// projectName holds the machine's project once it is known. A machine never
// moves between projects, so one answer serves the whole process; a failure
// is not kept, so the next caller asks again.
var projectName struct {
	sync.Mutex
	value string
}

// ProjectName reports the project of the machine the caller runs on, which
// is the project its metadata tokens are minted for.
func ProjectName(ctx context.Context) (string, error) {
	projectName.Lock()
	defer projectName.Unlock()

	if projectName.value != "" {
		return projectName.value, nil
	}

	body, err := get(ctx, projectNameEndpoint)
	if err != nil {
		return "", err
	}

	projectName.value = strings.TrimSpace(body)

	return projectName.value, nil
}

const jsonMediaType = "application/json"

// get returns the body of a metadata endpoint, which answers in plain text.
func get(ctx context.Context, endpoint string) (string, error) {
	body, _, err := request(ctx, endpoint, nil)

	return body, err
}

// request returns the body of a metadata endpoint and the content type it
// answered with.
func request(ctx context.Context, endpoint string, header http.Header) (string, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", "", err
	}
	for name, values := range header {
		request.Header[name] = values
	}
	useragent.SetHTTP(request.Header)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", "", err
	}

	if response.StatusCode != http.StatusOK {
		return "", "", UnexpectedMetadataResponse{
			StatusCode: response.StatusCode,
			Body:       string(body),
		}
	}

	return string(body), response.Header.Get("Content-Type"), nil
}
