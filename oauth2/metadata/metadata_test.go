package metadata

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.cbws.cloud/sdk/internal/useragent"
)

func TestTokenSource(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		responseBody   string
		expectedToken  string
		expectedError  string
		expectedExpiry time.Duration
	}{
		{
			name:           "success",
			statusCode:     http.StatusOK,
			responseBody:   "test_access_token",
			expectedToken:  "test_access_token",
			expectedExpiry: 60 * time.Second,
		},
		{
			name:          "non-200 status code",
			statusCode:    http.StatusNotFound,
			responseBody:  "not found",
			expectedError: "unexpected metadata service response code 404: not found",
		},
		{
			name:          "internal server error",
			statusCode:    http.StatusInternalServerError,
			responseBody:  "server error",
			expectedError: "unexpected metadata service response code 500: server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = io.WriteString(w, tt.responseBody)
			}))
			defer server.Close()

			// Temporarily override the endpoint for testing
			originalEndpoint := endpoint
			endpoint = server.URL
			defer func() { endpoint = originalEndpoint }()

			ts := TokenSource(context.Background())
			token, err := ts.Token()

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.EqualError(t, err, tt.expectedError)
				assert.Nil(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, token)
				assert.Equal(t, tt.expectedToken, token.AccessToken)
				assert.Equal(t, "Bearer", token.TokenType)
				// Allow for a small time difference due to test execution time
				assert.InEpsilon(t, tt.expectedExpiry.Seconds(), time.Until(token.Expiry).Seconds(), 0.1)
			}
		})
	}
}

// serveJSON points the endpoint at a test server answering with body as
// contentType, and reports the request headers it received and how many
// requests it answered.
func serveJSON(t *testing.T, contentType, body string) (func() http.Header, func() int) {
	t.Helper()

	var mu sync.Mutex
	var header http.Header
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		header, requests = r.Header.Clone(), requests+1
		mu.Unlock()
		w.Header().Set("Content-Type", contentType)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)

	originalEndpoint := endpoint
	endpoint = server.URL
	t.Cleanup(func() { endpoint = originalEndpoint })

	return func() http.Header {
			mu.Lock()
			defer mu.Unlock()

			return header
		}, func() int {
			mu.Lock()
			defer mu.Unlock()

			return requests
		}
}

func TestTokenSourceAsksForJSON(t *testing.T) {
	received, _ := serveJSON(t, "text/plain; charset=utf-8", "test_access_token")

	_, err := TokenSource(context.Background()).Token()
	require.NoError(t, err)

	assert.Equal(t, "application/json", received().Get("Accept"))
	assert.Equal(t, "application/json", received().Get("Content-Type"), "the metadata server chooses its answer by this header")
}

func TestTokenRequestIdentifiesTheSDK(t *testing.T) {
	received, _ := serveJSON(t, "text/plain; charset=utf-8", "test_access_token")

	_, err := TokenSource(context.Background()).Token()
	require.NoError(t, err)

	assert.Equal(t, useragent.SDK(), received().Get("User-Agent"))
	assert.Equal(t, useragent.APIClient(), received().Get(useragent.APIClientHeader))
}

// A JSON answer carries the token's real expiry, so the token is held for its
// lifetime rather than the minute a plain answer is assumed to last.
func TestTokenSourceHoldsAJSONTokenUntilItsExpiry(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	for _, contentType := range []string{"application/json", "application/json; charset=utf-8"} {
		t.Run(contentType, func(t *testing.T) {
			_, requests := serveJSON(t, contentType,
				`{"accessToken":"json_access_token","expiresAt":"`+expiresAt.Format(time.RFC3339)+`","tokenType":"Bearer"}`)
			source := TokenSource(context.Background())

			token, err := source.Token()
			require.NoError(t, err)
			assert.Equal(t, "json_access_token", token.AccessToken)
			assert.Equal(t, "Bearer", token.TokenType)
			assert.True(t, token.Expiry.Equal(expiresAt), "expiry %s, want %s", token.Expiry, expiresAt)
			assert.InDelta(t, time.Hour.Seconds(), float64(token.ExpiresIn), 5)

			_, err = source.Token()
			require.NoError(t, err)
			assert.Equal(t, 1, requests(), "served from memory, not asked again")
		})
	}
}

func TestTokenSourceJSONWithoutExpiryAssumesAMinute(t *testing.T) {
	serveJSON(t, "application/json", `{"accessToken":"json_access_token"}`)

	token, err := TokenSource(context.Background()).Token()
	require.NoError(t, err)

	assert.Equal(t, "Bearer", token.TokenType)
	assert.InEpsilon(t, assumedLifetime.Seconds(), time.Until(token.Expiry).Seconds(), 0.1)
}

func TestTokenSourceRefusesAnUnusableJSONAnswer(t *testing.T) {
	for name, body := range map[string]string{
		"no access token": `{"expiresAt":"2030-01-01T00:00:00Z"}`,
		"malformed":       `{"accessToken":`,
	} {
		t.Run(name, func(t *testing.T) {
			serveJSON(t, "application/json", body)

			token, err := TokenSource(context.Background()).Token()

			assert.Error(t, err)
			assert.Nil(t, token)
		})
	}
}

// serveToken points the endpoint at a test server answering with a token, and
// reports the URL of the last request it received.
func serveToken(t *testing.T) func() *url.URL {
	t.Helper()

	var received *url.URL
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.URL
		_, _ = io.WriteString(w, "test_access_token")
	}))
	t.Cleanup(server.Close)

	originalEndpoint := endpoint
	endpoint = server.URL
	t.Cleanup(func() { endpoint = originalEndpoint })

	return func() *url.URL { return received }
}

func TestTokenSourceRequestsScopes(t *testing.T) {
	tests := []struct {
		name          string
		options       []Option
		expectedQuery url.Values
	}{
		{
			name: "no options",
		},
		{
			name:    "no scopes",
			options: []Option{WithScopes()},
		},
		{
			name:          "one scope",
			options:       []Option{WithScopes("email")},
			expectedQuery: url.Values{"scopes": {"email"}},
		},
		{
			name:          "several scopes keep their order",
			options:       []Option{WithScopes("openid", "email")},
			expectedQuery: url.Values{"scopes": {"openid", "email"}},
		},
		{
			name:          "repeated options accumulate",
			options:       []Option{WithScopes("openid"), WithScopes("email")},
			expectedQuery: url.Values{"scopes": {"openid", "email"}},
		},
		{
			name:          "reserved characters arrive intact",
			options:       []Option{WithScopes("a,b", "c&d=e")},
			expectedQuery: url.Values{"scopes": {"a,b", "c&d=e"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			received := serveToken(t)

			_, err := TokenSource(context.Background(), tt.options...).Token()
			require.NoError(t, err)
			require.NotNil(t, received())

			if tt.expectedQuery == nil {
				// A request without scopes stays exactly the request made
				// before there were options.
				assert.Empty(t, received().RawQuery)

				return
			}
			assert.Equal(t, tt.expectedQuery, received().Query())
		})
	}
}

func TestWithScopesCopiesTheCallersSlice(t *testing.T) {
	received := serveToken(t)

	scopes := []string{"email"}
	source := TokenSource(context.Background(), WithScopes(scopes...))
	scopes[0] = "changed"

	_, err := source.Token()
	require.NoError(t, err)
	assert.Equal(t, []string{"email"}, received().Query()["scopes"])
}

func TestProjectName(t *testing.T) {
	// serve answers the project endpoint and forgets any project an earlier
	// test left behind. It reports how many requests the server received.
	serve := func(t *testing.T, status int, body string) func() int {
		t.Helper()

		requests := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests++
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(server.Close)

		original := projectNameEndpoint
		projectNameEndpoint = server.URL
		projectName.value = ""
		t.Cleanup(func() {
			projectNameEndpoint = original
			projectName.value = ""
		})

		return func() int { return requests }
	}

	t.Run("the machine's project, asked for once", func(t *testing.T) {
		requests := serve(t, http.StatusOK, "my-project\n")

		for range 2 {
			name, err := ProjectName(context.Background())
			require.NoError(t, err)
			assert.Equal(t, "my-project", name)
		}
		assert.Equal(t, 1, requests())
	})

	t.Run("an error response, asked for again", func(t *testing.T) {
		requests := serve(t, http.StatusForbidden, "unknown machine")

		for range 2 {
			_, err := ProjectName(context.Background())
			assert.EqualError(t, err, "unexpected metadata service response code 403: unknown machine")
		}
		assert.Equal(t, 2, requests())
	})
}

func TestTokenSourceHonoursContext(t *testing.T) {
	serveToken(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := TokenSource(ctx).Token()
	assert.ErrorIs(t, err, context.Canceled)
}
