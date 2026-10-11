package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.cbws.cloud/sdk/internal/tokentest"
	"go.cbws.cloud/sdk/oauth2/refresh"
	"go.cbws.cloud/sdk/oauth2/tokencache"
	"go.cbws.cloud/sdk/option"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// tokenChains are the token sources a client is built on: a renewing source
// on its own, and behind a token cache, as credentials configured with one
// are.
var tokenChains = []struct {
	name string
	wrap func(t *testing.T, inner oauth2.TokenSource) oauth2.TokenSource
}{
	{
		name: "without a token cache",
		wrap: func(_ *testing.T, inner oauth2.TokenSource) oauth2.TokenSource {
			return refresh.NewTokenSource(inner)
		},
	},
	{
		name: "with a token cache",
		wrap: func(t *testing.T, inner oauth2.TokenSource) oauth2.TokenSource {
			cached, err := tokencache.NewTokenSource(refresh.NewTokenSource(inner), tokentest.NewMemoryCache(), tokencache.Key{
				Issuer:  "https://accounts.cbws.cloud/oauth2/token",
				Subject: t.Name(),
			})
			require.NoError(t, err)

			return cached
		},
	},
}

// within runs call and fails the test if it has not returned in time, so a
// call that ignores its context fails rather than hangs.
func within(t *testing.T, call func() error) error {
	t.Helper()

	done := make(chan error, 1)
	go func() { done <- call() }()

	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("the call went on waiting for a token after its context ended")

		return nil
	}
}

// A call that runs out of time or is cancelled while its token is being
// fetched ends then, with its context's code, and the fetch it gave up on
// still serves the next call.
func TestACallsContextBoundsItsWaitForAToken(t *testing.T) {
	for _, chain := range tokenChains {
		t.Run(chain.name, func(t *testing.T) {
			dialer, received := serveTLS(t)
			gated := tokentest.NewGatedSource()
			t.Cleanup(gated.Open)

			conn, err := New(context.Background(),
				option.WithEndpoint("example.com:443"),
				option.WithTokenSource(chain.wrap(t, gated)),
				option.WithGRPCDialOption(grpc.WithContextDialer(dialer)),
			)
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			client := healthpb.NewHealthClient(conn)

			err = within(t, func() error {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				_, err := client.Check(ctx, &healthpb.HealthCheckRequest{})

				return err
			})
			assert.Equal(t, codes.DeadlineExceeded, status.Code(err), "%v", err)

			err = within(t, func() error {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(50*time.Millisecond, cancel)
				_, err := client.Check(ctx, &healthpb.HealthCheckRequest{})

				return err
			})
			assert.Equal(t, codes.Canceled, status.Code(err), "%v", err)

			gated.Open()
			_, err = client.Check(context.Background(), &healthpb.HealthCheckRequest{})
			require.NoError(t, err)

			assert.Equal(t, []string{"Bearer token-1"}, received().Get("authorization"))
			assert.Equal(t, 1, gated.Calls(), "the fetch the callers gave up on should have served the next call")
		})
	}
}

// A token source that takes no context is still asked for every call's
// token.
func TestAPlainTokenSourceStillAuthenticatesCalls(t *testing.T) {
	dialer, received := serveTLS(t)
	source := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "static", TokenType: "Bearer"})

	conn, err := New(context.Background(),
		option.WithEndpoint("example.com:443"),
		option.WithTokenSource(source),
		option.WithGRPCDialOption(grpc.WithContextDialer(dialer)),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = healthpb.NewHealthClient(conn).Check(context.Background(), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)

	assert.Equal(t, []string{"Bearer static"}, received().Get("authorization"))
}
