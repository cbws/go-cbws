package v1alpha1

import (
	"context"

	"github.com/cbws/go-cbws/client/grpc"
	"github.com/cbws/go-cbws/option"

	"github.com/cbws/go-cbws-grpc/cbws/vpn/v1alpha1"
)

const endpoint = "vpn.cbws.cloud:443"

//const scope = "https://vpn.cbws.cloud/"

func NewClient(ctx context.Context, opts ...option.ClientOption) (*Client, error) {
	o := []option.ClientOption{
		option.WithEndpoint(endpoint),
		//option.WithScopes(scope),
		option.WithUserAgent("go-cbws VPN"),
	}
	o = append(o, opts...)

	conn, err := grpc.New(ctx, o...)
	if err != nil {
		return nil, err
	}

	return &Client{
		client: v1alpha1.NewVPNServiceClient(conn),
	}, nil
}

type Client struct {
	client v1alpha1.VPNServiceClient
}

func (c Client) UnderlyingClient() v1alpha1.VPNServiceClient {
	return c.client
}
