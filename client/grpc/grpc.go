package grpc

import (
	"context"

	"go.cbws.cloud/sdk/internal/perrpc"
	"go.cbws.cloud/sdk/internal/useragent"
	creds "go.cbws.cloud/sdk/oauth2"
	"go.cbws.cloud/sdk/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// apiClient is the SDK's identification header for gRPC calls.
var apiClient = useragent.APIClient("grpc/" + grpc.Version)

type GRPCClient struct {
	client *grpc.ClientConn
}

func (g *GRPCClient) Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error {
	return g.client.Invoke(withAPIClient(ctx), method, args, reply, opts...)
}

func (g *GRPCClient) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return g.client.NewStream(withAPIClient(ctx), desc, method, opts...)
}

// withAPIClient sets the SDK's identification header on the outgoing call,
// replacing any value the caller put in the context. It is set per call
// rather than at dial time so that it is also sent over a connection passed
// in with option.WithGRPCConn.
func withAPIClient(ctx context.Context) context.Context {
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Set(useragent.APIClientHeader, apiClient)

	return metadata.NewOutgoingContext(ctx, md)
}

func (g *GRPCClient) Close() error {
	return g.client.Close()
}

// transportCredentials secures the connection of a client that sends
// credentials, given the options the client was built with. It verifies the
// server against the system roots.
var transportCredentials = func([]option.ClientOption) credentials.TransportCredentials {
	return credentials.NewClientTLSFromCert(nil, "")
}

// New dials the endpoint the options name. The credentials it builds fetch
// tokens for as long as the client lives, so ending ctx does not end them:
// ctx may be a request's context even when the client outlives the request.
// Each call's own context bounds how long that call waits for a token.
func New(ctx context.Context, opts ...option.ClientOption) (*GRPCClient, error) {
	o, err := processAndValidateOpts(opts)
	if err != nil {
		return nil, err
	}

	if !o.NoAuth {
		creds, err := clientCredentials(ctx, o)
		if err != nil {
			return nil, err
		}
		if creds != nil {
			o.GRPCDialOpts = append(
				o.GRPCDialOpts,
				grpc.WithPerRPCCredentials(perrpc.New(creds.TokenSource, true)),
				grpc.WithTransportCredentials(transportCredentials(opts)),
			)
		}
	}
	o.GRPCDialOpts = append(o.GRPCDialOpts, grpc.WithUserAgent(useragent.String(o.UserAgent)))

	if o.GRPCConn == nil {
		o.GRPCConn, err = grpc.Dial(o.Endpoint, o.GRPCDialOpts...)
		if err != nil {
			return nil, err
		}
	}

	return &GRPCClient{
		client: o.GRPCConn,
	}, nil
}

// clientCredentials builds the client's credentials on a context that keeps
// ctx's values but not its cancellation. Token sources hold the context they
// are built with and make every later token request on it, so a cancellation
// would fail every refresh once the first token expires.
func clientCredentials(ctx context.Context, o *option.DialSettings) (*creds.Credentials, error) {
	return o.Creds(context.WithoutCancel(ctx))
}

func processAndValidateOpts(opts []option.ClientOption) (*option.DialSettings, error) {
	var o option.DialSettings
	for _, opt := range opts {
		opt.Apply(&o)
	}
	if err := o.Validate(); err != nil {
		return nil, err
	}
	return &o, nil
}
