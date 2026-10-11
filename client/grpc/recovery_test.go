package grpc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	service_account "go.cbws.cloud/sdk/oauth2/service-account"
	"go.cbws.cloud/sdk/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

// TestFirstCallSurvivesAResetTokenExchange makes a client's first call, a
// read, while the token endpoint resets the connection carrying the first
// key exchange. The call goes through the client's own per-call
// credentials and transport security, and succeeds with the token the
// retried exchange obtained.
func TestFirstCallSurvivesAResetTokenExchange(t *testing.T) {
	var (
		mu       sync.Mutex
		requests int
	)
	tokens := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()

		mu.Lock()
		requests++
		first := requests == 1
		mu.Unlock()

		if first {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)

				return
			}
			_ = conn.(*net.TCPConn).SetLinger(0)
			_ = conn.Close()

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"bearer","expires_in":3600}`))
	}))
	t.Cleanup(tokens.Close)
	t.Setenv(service_account.TokenURLEnvVar, tokens.URL)

	dialer, received := serveTLS(t)

	conn, err := New(context.Background(),
		option.WithEndpoint("example.com:443"),
		option.WithCredentialsJSON(serviceAccountKey(t)),
		option.WithGRPCDialOption(grpc.WithContextDialer(dialer)),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = healthpb.NewHealthClient(conn).Check(context.Background(), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)

	assert.Equal(t, []string{"Bearer at"}, received().Get("authorization"))
	mu.Lock()
	assert.Equal(t, 2, requests)
	mu.Unlock()
}

// serveTLS starts a health server over a bufconn behind a certificate for
// example.com, and makes that certificate the process's trusted root: the
// client's transport security verifies against the system roots, which
// read SSL_CERT_FILE the first time they are needed.
func serveTLS(t *testing.T) (func(context.Context, string) (net.Conn, error), func() metadata.MD) {
	t.Helper()

	issuer := httptest.NewUnstartedServer(http.NotFoundHandler())
	issuer.StartTLS()
	certificates := issuer.TLS.Certificates
	root := issuer.Certificate()
	issuer.Close()

	roots := filepath.Join(t.TempDir(), "roots.pem")
	require.NoError(t, os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), 0o600))
	t.Setenv("SSL_CERT_FILE", roots)

	var (
		mu       sync.Mutex
		received metadata.MD
	)
	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: certificates})),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			mu.Lock()
			received, _ = metadata.FromIncomingContext(ctx)
			mu.Unlock()

			return handler(ctx, req)
		}),
	)
	healthpb.RegisterHealthServer(server, health.NewServer())

	go func() {
		if err := server.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("server: %v", err)
		}
	}()
	t.Cleanup(server.Stop)

	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}
	last := func() metadata.MD {
		mu.Lock()
		defer mu.Unlock()

		return received
	}

	return dialer, last
}

func serviceAccountKey(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	data, err := json.Marshal(service_account.Credentials{
		Type:         service_account.KeyType,
		ProjectName:  "project-1",
		PrivateKeyID: "key-1",
		PrivateKey:   string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		ClientEmail:  "sa@example.com",
		ClientID:     "client-1",
	})
	require.NoError(t, err)

	return data
}
