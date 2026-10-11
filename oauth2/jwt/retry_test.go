package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.cbws.cloud/sdk/internal/retry"
	"golang.org/x/oauth2"
)

// fastRetry keeps the shape of defaultRetryPolicy with delays a test can
// afford to wait out.
var fastRetry = retry.Policy{
	Attempts:       4,
	AttemptTimeout: 5 * time.Second,
	Budget:         10 * time.Second,
	InitialBackoff: time.Millisecond,
	MaxBackoff:     5 * time.Millisecond,
}

const tokenResponse = `{"access_token":"at","token_type":"bearer","expires_in":3600}`

// endpoint is a token endpoint that answers each request with the next of
// its responses, repeating the last once they run out, and records the
// assertions it was sent.
type endpoint struct {
	t         *testing.T
	responses []func(http.ResponseWriter, *http.Request)

	mu         sync.Mutex
	assertions []string
}

func serveEndpoint(t *testing.T, responses ...func(http.ResponseWriter, *http.Request)) (*endpoint, string) {
	t.Helper()

	e := &endpoint{t: t, responses: responses}
	server := httptest.NewServer(e)
	t.Cleanup(server.Close)

	return e, server.URL
}

func (e *endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		e.t.Errorf("could not parse the token request: %v", err)
	}

	e.mu.Lock()
	n := len(e.assertions)
	e.assertions = append(e.assertions, r.PostForm.Get("client_assertion"))
	e.mu.Unlock()

	e.responses[min(n, len(e.responses)-1)](w, r)
}

func (e *endpoint) requests() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	return len(e.assertions)
}

// reset drops the connection with a TCP reset once the request has been
// read, the way a connection torn down under a client looks to it.
func reset(w http.ResponseWriter, _ *http.Request) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		panic(err)
	}
	_ = conn.(*net.TCPConn).SetLinger(0)
	_ = conn.Close()
}

// stall never answers, holding the request until the client gives up on it.
func stall(_ http.ResponseWriter, r *http.Request) {
	<-r.Context().Done()
}

func issue(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, tokenResponse)
}

func status(code int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}
}

func testConfig(t *testing.T, tokenURL string) *Config {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return &Config{
		ClientID:      "client-1",
		PrivateKey:    privateKey,
		TokenURL:      tokenURL,
		SigningMethod: jwt.GetSigningMethod("RS256"),
	}
}

func testSource(t *testing.T, ctx context.Context, tokenURL string, policy retry.Policy) jwtSource {
	t.Helper()

	return jwtSource{ctx: ctx, conf: testConfig(t, tokenURL), policy: &policy}
}

func TestTokenRetriesAResetExchange(t *testing.T) {
	e, url := serveEndpoint(t, reset, issue)

	token, err := testSource(t, context.Background(), url, fastRetry).Token()
	require.NoError(t, err)

	assert.Equal(t, "at", token.AccessToken)
	require.Equal(t, 2, e.requests())
	assert.NotEqual(t, e.assertions[0], e.assertions[1], "each attempt signs its own assertion")
}

func TestTokenGivesUpOnPersistentResets(t *testing.T) {
	e, url := serveEndpoint(t, reset)

	_, err := testSource(t, context.Background(), url, fastRetry).Token()
	require.Error(t, err)

	assert.Equal(t, fastRetry.Attempts, e.requests())
	assert.Contains(t, err.Error(), "after 4 attempts")
	assert.True(t, transportFailure(err), "error = %v, want the transport failure", err)
}

func TestTokenRetriesAStalledAttempt(t *testing.T) {
	e, url := serveEndpoint(t, stall, issue)

	policy := fastRetry
	policy.AttemptTimeout = 100 * time.Millisecond

	token, err := testSource(t, context.Background(), url, policy).Token()
	require.NoError(t, err)

	assert.Equal(t, "at", token.AccessToken)
	assert.Equal(t, 2, e.requests())
}

func TestTokenStopsAtItsBudget(t *testing.T) {
	_, url := serveEndpoint(t, stall)

	policy := fastRetry
	policy.AttemptTimeout = 100 * time.Millisecond
	policy.Budget = 250 * time.Millisecond
	policy.Attempts = 100

	start := time.Now()
	_, err := testSource(t, context.Background(), url, policy).Token()
	require.Error(t, err)

	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestTokenDoesNotRetryARejection(t *testing.T) {
	const body = `{"error":"invalid_grant","error_description":"the key is not active"}`
	e, url := serveEndpoint(t, status(http.StatusBadRequest, body), issue)

	_, err := testSource(t, context.Background(), url, fastRetry).Token()
	require.Error(t, err)

	assert.Equal(t, 1, e.requests())

	var retrieve *oauth2.RetrieveError
	require.ErrorAs(t, err, &retrieve)
	assert.Equal(t, "invalid_grant", retrieve.ErrorCode)
	assert.Equal(t, "the key is not active", retrieve.ErrorDescription)
	assert.NotContains(t, err.Error(), "{", "the message names the refusal rather than quoting the body")
}

func TestTokenDoesNotRetryAnAnswer(t *testing.T) {
	e, url := serveEndpoint(t, status(http.StatusServiceUnavailable, "unavailable"), issue)

	_, err := testSource(t, context.Background(), url, fastRetry).Token()
	require.Error(t, err)

	assert.Equal(t, 1, e.requests())
	var retrieve *oauth2.RetrieveError
	assert.ErrorAs(t, err, &retrieve)
}

func TestTokenDoesNotRetryAnUnreadableToken(t *testing.T) {
	e, url := serveEndpoint(t, status(http.StatusOK, "not json"), issue)

	_, err := testSource(t, context.Background(), url, fastRetry).Token()
	require.Error(t, err)

	assert.Equal(t, 1, e.requests())
}

func TestTokenHonoursACancelledContext(t *testing.T) {
	e, url := serveEndpoint(t, issue)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := testSource(t, ctx, url, fastRetry).Token()

	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 0, e.requests())
}

func TestTokenHonoursCancellationDuringAnAttempt(t *testing.T) {
	e, url := serveEndpoint(t, stall)

	ctx, cancel := context.WithCancel(context.Background())
	source := testSource(t, ctx, url, fastRetry)
	time.AfterFunc(100*time.Millisecond, cancel)

	_, err := source.Token()

	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, e.requests())
}

func TestTokenHonoursCancellationDuringBackoff(t *testing.T) {
	e, url := serveEndpoint(t, reset)

	policy := fastRetry
	policy.InitialBackoff = time.Minute
	policy.MaxBackoff = time.Minute

	ctx, cancel := context.WithCancel(context.Background())
	source := testSource(t, ctx, url, policy)
	time.AfterFunc(100*time.Millisecond, cancel)

	start := time.Now()
	_, err := source.Token()

	assert.ErrorIs(t, err, context.Canceled)
	assert.True(t, transportFailure(err), "error = %v, want the transport failure that led to the wait", err)
	assert.Equal(t, 1, e.requests())
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestTokenHonoursTheCallersDeadline(t *testing.T) {
	_, url := serveEndpoint(t, stall)

	conf := testConfig(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := jwtSource{ctx: ctx, conf: conf}.Token()

	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 2*time.Second)
}

// TestTokenSourceRecoversOnce goes through the source Config hands out,
// which shares one exchange between concurrent callers and serves its token
// until it is close to expiry: a reset costs one more request, not one per
// caller, and a token in hand is not fetched again.
func TestTokenSourceRecoversOnce(t *testing.T) {
	var release sync.WaitGroup
	release.Add(1)
	first := func(w http.ResponseWriter, r *http.Request) {
		release.Wait()
		reset(w, r)
	}
	e, url := serveEndpoint(t, first, issue)

	source := testConfig(t, url).TokenSource(context.Background())

	const callers = 8
	var (
		started sync.WaitGroup
		done    sync.WaitGroup
		failed  atomic.Int32
	)
	started.Add(callers)
	done.Add(callers)
	for range callers {
		go func() {
			defer done.Done()
			started.Done()
			token, err := source.Token()
			if err != nil || token.AccessToken != "at" {
				failed.Add(1)
			}
		}()
	}
	started.Wait()
	release.Done()
	done.Wait()

	assert.Zero(t, failed.Load())
	assert.Equal(t, 2, e.requests())

	token, err := source.Token()
	require.NoError(t, err)
	assert.Equal(t, "at", token.AccessToken)
	assert.Equal(t, 2, e.requests(), "a valid token is reused")
}

// transportFailure reports whether err carries a connection that broke,
// which a reset can surface as either of two errors depending on when the
// client reads.
func transportFailure(err error) bool {
	var transport transportError
	if !errors.As(err, &transport) {
		return false
	}

	return strings.Contains(err.Error(), "connection reset") || errors.Is(err, io.EOF)
}
