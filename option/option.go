package option

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"

	creds "go.cbws.cloud/sdk/oauth2"

	"golang.org/x/oauth2"
	"google.golang.org/grpc"
)

type DialSettings struct {
	Endpoint        string
	Scopes          []string
	TokenSource     oauth2.TokenSource
	Credentials     *creds.Credentials
	CredentialsFile string // if set, Token Source is ignored.
	CredentialsJSON []byte
	NoAuth          bool
	UserAgent       string
	GRPCConn        *grpc.ClientConn
	GRPCDialOpts    []grpc.DialOption
}

func (ds DialSettings) Validate() error {
	hasCreds := ds.TokenSource != nil || ds.CredentialsFile != "" || ds.Credentials != nil
	if ds.NoAuth && hasCreds {
		return errors.New("options.WithoutAuthentication is incompatible with any option that provides credentials")
	}
	// Credentials should not appear with other options.
	// We currently allow TokenSource and CredentialsFile to coexist.
	nCreds := 0
	if ds.Credentials != nil {
		nCreds++
	}
	if ds.CredentialsJSON != nil {
		nCreds++
	}
	if ds.CredentialsFile != "" {
		nCreds++
	}
	if ds.TokenSource != nil {
		nCreds++
	}
	// Accept only one form of credentials
	if nCreds > 1 {
		return errors.New("multiple credential options provided")
	}

	return nil
}

func (ds DialSettings) Creds(ctx context.Context) (*creds.Credentials, error) {
	if ds.Credentials != nil {
		return ds.Credentials, nil
	}
	if ds.CredentialsJSON != nil {
		return creds.NewFromJSON(ctx, ds.CredentialsJSON, ds.Scopes)
	}
	if ds.CredentialsFile != "" {
		data, err := ioutil.ReadFile(ds.CredentialsFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read credentials file: %v", err)
		}
		return creds.NewFromJSON(ctx, data, ds.Scopes)
	}
	if ds.TokenSource != nil {
		return &creds.Credentials{TokenSource: ds.TokenSource}, nil
	}

	cred, err := creds.FindDefaultCredentials(ctx, ds.Scopes...)
	if err != nil {
		return nil, err
	}
	if len(cred.JSON) > 0 {
		return creds.NewFromJSON(ctx, cred.JSON, ds.Scopes)
	}

	return cred, nil
}

type ClientOption interface {
	Apply(*DialSettings)
}

// WithTokenSource returns a ClientOption that specifies an OAuth2 token
// source to be used as the basis for authentication.
func WithTokenSource(s oauth2.TokenSource) ClientOption {
	return withTokenSource{s}
}

type withTokenSource struct{ ts oauth2.TokenSource }

func (w withTokenSource) Apply(o *DialSettings) {
	o.TokenSource = w.ts
}

type withCredFile string

func (w withCredFile) Apply(o *DialSettings) {
	o.CredentialsFile = string(w)
}

// WithCredentialsFile returns a ClientOption that authenticates
// API calls with the given service account or refresh token JSON
// credentials file.
func WithCredentialsFile(filename string) ClientOption {
	return withCredFile(filename)
}

// WithCredentialsJSON returns a ClientOption that authenticates
// API calls with the given service account or refresh token JSON
// credentials.
func WithCredentialsJSON(p []byte) ClientOption {
	return withCredentialsJSON(p)
}

type withCredentialsJSON []byte

func (w withCredentialsJSON) Apply(o *DialSettings) {
	o.CredentialsJSON = make([]byte, len(w))
	copy(o.CredentialsJSON, w)
}

type withCreds creds.Credentials

func (w *withCreds) Apply(o *DialSettings) {
	o.Credentials = (*creds.Credentials)(w)
}

// WithCredentials returns a ClientOption that authenticates API calls.
func WithCredentials(creds *creds.Credentials) ClientOption {
	return (*withCreds)(creds)
}

func WithEndpoint(url string) ClientOption {
	return withEndpoint(url)
}

type withEndpoint string

func (w withEndpoint) Apply(o *DialSettings) {
	o.Endpoint = string(w)
}

// WithScopes returns a ClientOption that overrides the default OAuth2 scopes
// to be used for a service.
func WithScopes(scope ...string) ClientOption {
	return withScopes(scope)
}

type withScopes []string

func (w withScopes) Apply(o *DialSettings) {
	o.Scopes = make([]string, len(w))
	copy(o.Scopes, w)
}

// WithUserAgent returns a ClientOption that sets the User-Agent.
func WithUserAgent(ua string) ClientOption {
	return withUA(ua)
}

type withUA string

func (w withUA) Apply(o *DialSettings) { o.UserAgent = string(w) }

// WithGRPCConn returns a ClientOption that specifies the gRPC client
// connection to use as the basis of communications. This option may only be
// used with services that support gRPC as their communication transport. When
// used, the WithGRPCConn option takes precedent over all other supplied
// options.
func WithGRPCConn(conn *grpc.ClientConn) ClientOption {
	return withGRPCConn{conn}
}

type withGRPCConn struct{ conn *grpc.ClientConn }

func (w withGRPCConn) Apply(o *DialSettings) {
	o.GRPCConn = w.conn
}

// WithGRPCDialOption returns a ClientOption that appends a new grpc.DialOption
// to an underlying gRPC dial. It does not work with WithGRPCConn.
func WithGRPCDialOption(opt grpc.DialOption) ClientOption {
	return withGRPCDialOption{opt}
}

type withGRPCDialOption struct{ opt grpc.DialOption }

func (w withGRPCDialOption) Apply(o *DialSettings) {
	o.GRPCDialOpts = append(o.GRPCDialOpts, w.opt)
}

// WithoutAuthentication returns a ClientOption that specifies that no
// authentication should be used. It is suitable only for testing and for
// accessing public resources.
// It is an error to provide both WithoutAuthentication and any of WithTokenSource or WithCredentialsFile.
func WithoutAuthentication() ClientOption {
	return withoutAuthentication{}
}

type withoutAuthentication struct{}

func (w withoutAuthentication) Apply(o *DialSettings) { o.NoAuth = true }
