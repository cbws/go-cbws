package perrpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// waitingSource takes a context and waits for it to end, as a source does
// while a fetch it shares is still in progress.
type waitingSource struct {
	tokenCalls int
}

func (s *waitingSource) Token() (*oauth2.Token, error) {
	s.tokenCalls++

	return nil, errors.New("Token should not be called on a source that takes a context")
}

func (s *waitingSource) TokenContext(ctx context.Context) (*oauth2.Token, error) {
	<-ctx.Done()

	return nil, ctx.Err()
}

// securedAt returns a context carrying the request info grpc-go hands per-RPC
// credentials for a connection at the given security level.
func securedAt(level credentials.SecurityLevel) context.Context {
	return credentials.NewContextWithRequestInfo(context.Background(), credentials.RequestInfo{
		AuthInfo: credentials.TLSInfo{CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: level}},
	})
}

func TestAPlainSourceSuppliesTheAuthorizationHeader(t *testing.T) {
	creds := New(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "at", TokenType: "bearer"}), false)

	md, err := creds.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, map[string]string{"authorization": "Bearer at"}, md)
}

// The call's context ends the wait, and the call fails with that context's
// code rather than as a failure to authenticate.
func TestTheCallsContextBoundsTheWait(t *testing.T) {
	source := &waitingSource{}
	creds := New(source, false)

	deadline, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := creds.GetRequestMetadata(deadline)
	assert.Equal(t, codes.DeadlineExceeded, status.Code(err), "%v", err)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = creds.GetRequestMetadata(cancelled)
	assert.Equal(t, codes.Canceled, status.Code(err), "%v", err)

	assert.Zero(t, source.tokenCalls)
}

// A source's own failure is returned as it is, for grpc-go to report as a
// failure to authenticate, even when it is a context error of the source's
// own while the call's context is still live.
func TestASourceFailureIsNotReportedAsTheCallsContext(t *testing.T) {
	for _, failure := range []error{errors.New("token endpoint refused"), context.DeadlineExceeded} {
		creds := New(&failingSource{err: failure}, false)

		_, err := creds.GetRequestMetadata(context.Background())
		require.ErrorIs(t, err, failure)
		_, isStatus := status.FromError(err)
		assert.False(t, isStatus, "%v", err)
	}
}

type failingSource struct{ err error }

func (s *failingSource) Token() (*oauth2.Token, error) { return nil, s.err }

func TestTransportSecurityIsCheckedOnlyWhenRequired(t *testing.T) {
	source := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "at"})

	required := New(source, true)
	assert.True(t, required.RequireTransportSecurity())

	_, err := required.GetRequestMetadata(securedAt(credentials.NoSecurity))
	assert.ErrorContains(t, err, "unable to transfer TokenSource PerRPCCredentials")

	md, err := required.GetRequestMetadata(securedAt(credentials.PrivacyAndIntegrity))
	require.NoError(t, err)
	assert.Equal(t, "Bearer at", md["authorization"])

	optional := New(source, false)
	assert.False(t, optional.RequireTransportSecurity())

	_, err = optional.GetRequestMetadata(securedAt(credentials.NoSecurity))
	assert.NoError(t, err)
}
