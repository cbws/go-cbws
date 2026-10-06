package grpc

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.cbws.cloud/sdk/internal/useragent"
	"go.cbws.cloud/sdk/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

// serve starts a health server over a bufconn and returns the options that
// dial it, along with the metadata of the most recent call it received.
func serve(t *testing.T) ([]option.ClientOption, *metadata.MD) {
	t.Helper()

	var received metadata.MD
	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		received, _ = metadata.FromIncomingContext(ctx)
		return handler(ctx, req)
	}))
	healthpb.RegisterHealthServer(server, health.NewServer())

	go func() {
		if err := server.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("server: %v", err)
		}
	}()
	t.Cleanup(server.Stop)

	return []option.ClientOption{
		option.WithEndpoint("bufnet"),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		})),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	}, &received
}

func check(t *testing.T, ctx context.Context, opts ...option.ClientOption) {
	t.Helper()

	conn, err := New(context.Background(), opts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
}

func TestUserAgentAlwaysCarriesTheSDK(t *testing.T) {
	tests := []struct {
		name   string
		app    []option.ClientOption
		prefix string
	}{
		{name: "no application", prefix: useragent.SDK() + " grpc-go/"},
		{
			name:   "application first",
			app:    []option.ClientOption{option.WithUserAgent("cbws-cli/0.61.0")},
			prefix: "cbws-cli/0.61.0 " + useragent.SDK() + " grpc-go/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, received := serve(t)

			check(t, context.Background(), append(opts, tt.app...)...)

			ua := received.Get("user-agent")
			require.Len(t, ua, 1)
			assert.True(t, strings.HasPrefix(ua[0], tt.prefix), "user-agent %q", ua[0])
		})
	}
}

func TestAPIClientHeaderCannotBeReplaced(t *testing.T) {
	opts, received := serve(t)

	ctx := metadata.AppendToOutgoingContext(context.Background(),
		useragent.APIClientHeader, "spoofed/1.0",
		"x-other", "kept",
	)
	check(t, ctx, opts...)

	assert.Equal(t, []string{apiClient}, received.Get(useragent.APIClientHeader))
	assert.Equal(t, []string{"kept"}, received.Get("x-other"))
	assert.Contains(t, apiClient, " grpc/"+grpc.Version)
}

func TestAPIClientHeaderOnAProvidedConnection(t *testing.T) {
	opts, received := serve(t)

	dialled, err := New(context.Background(), opts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dialled.Close() })

	check(t, context.Background(), option.WithGRPCConn(dialled.client), option.WithoutAuthentication())

	assert.Equal(t, []string{apiClient}, received.Get(useragent.APIClientHeader))
}
