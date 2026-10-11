// Package perrpc attaches an access token to each gRPC call an SDK client
// makes, asking for the token on the call's own context.
//
// grpc-go's oauth.TokenSource adapter does the same job but calls Token,
// which takes no context, so a call's deadline and cancellation never reach
// the source it waits on. This credential hands them over to any source that
// can take them.
package perrpc

import (
	"context"
	"errors"
	"fmt"

	"go.cbws.cloud/sdk/internal/tokensource"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type tokenCredentials struct {
	source                   oauth2.TokenSource
	requireTransportSecurity bool
}

// New returns credentials that send a token from source with every call.
//
// requireTransportSecurity is what the credentials report to grpc-go, which
// then refuses to send them over a connection without transport security.
// When it is set the credentials also refuse a connection whose security
// level is below privacy and integrity, as grpc-go's own OAuth credentials
// do, and check that before asking for a token rather than after.
func New(source oauth2.TokenSource, requireTransportSecurity bool) credentials.PerRPCCredentials {
	return tokenCredentials{source: source, requireTransportSecurity: requireTransportSecurity}
}

// GetRequestMetadata returns the authorization header for one call. The
// token is asked for on ctx, which is the call's context, so the call's
// deadline bounds the wait for a token and cancelling the call ends it.
func (c tokenCredentials) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	if c.requireTransportSecurity {
		info, _ := credentials.RequestInfoFromContext(ctx)
		if err := credentials.CheckSecurityLevel(info.AuthInfo, credentials.PrivacyAndIntegrity); err != nil {
			return nil, fmt.Errorf("unable to transfer TokenSource PerRPCCredentials: %w", err)
		}
	}

	token, err := tokensource.Token(ctx, c.source)
	if err != nil {
		return nil, callError(ctx, err)
	}

	return map[string]string{
		"authorization": token.Type() + " " + token.AccessToken,
	}, nil
}

// RequireTransportSecurity reports whether the credentials may only be sent
// over a connection with transport security.
func (c tokenCredentials) RequireTransportSecurity() bool {
	return c.requireTransportSecurity
}

// callError reports a call that ran out of time or was cancelled while it
// waited for a token as exactly that. grpc-go reports any other credential
// error as a failure to authenticate, which would tell a caller retrying on
// its own deadline that its credentials were at fault.
func callError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		return status.FromContextError(err).Err()
	}

	return err
}
