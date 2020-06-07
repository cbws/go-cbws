package grpc

import (
	"context"
	"github.com/cbws/go-cbws/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

type GRPCClient struct {
	client *grpc.ClientConn
}

func (g *GRPCClient) Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error {
	return g.client.Invoke(ctx, method, args, reply, opts...)
}

func (g *GRPCClient) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return g.client.NewStream(ctx, desc, method, opts...)
}

func New(ctx context.Context, opts ...option.ClientOption) (*GRPCClient, error) {
	o, err := processAndValidateOpts(opts)
	if err != nil {
		return nil, err
	}

	if !o.NoAuth {
		creds, err := o.Creds(ctx)
		if err != nil {
			return nil, err
		}
		if creds != nil {
			o.GRPCDialOpts = append(
				o.GRPCDialOpts,
				grpc.WithPerRPCCredentials(oauth.TokenSource{TokenSource: creds.TokenSource}),
				grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
			)
		}
	}
	if o.UserAgent != "" {
		o.GRPCDialOpts = append(o.GRPCDialOpts, grpc.WithUserAgent(o.UserAgent))
	}

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
