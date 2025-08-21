package v1alpha1

import (
	"context"

	"go.cbws.cloud/sdk/client/grpc"
	"go.cbws.cloud/sdk/option"

	"go.cbws.cloud/api/vpc/v1alpha1"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
)

const endpoint = "vpc.cbws.cloud:443"

func NewClient(ctx context.Context, project string, opts ...option.ClientOption) (*Client, error) {
	o := []option.ClientOption{
		option.WithEndpoint(endpoint),
		option.WithUserAgent("go-cbws vpc"),
	}
	o = append(o, opts...)

	conn, err := grpc.New(ctx, o...)
	if err != nil {
		return nil, err
	}

	return &Client{
		client:      v1alpha1.NewVpcServiceClient(conn),
		longrunning: longrunningpb.NewOperationsClient(conn),
		project:     project,
	}, nil
}

type Client struct {
	client      v1alpha1.VpcServiceClient
	longrunning longrunningpb.OperationsClient
	project     string
}

func (c Client) UnderlyingClient() v1alpha1.VpcServiceClient {
	return c.client
}

func (c Client) Longrunning() longrunningpb.OperationsClient {
	return c.longrunning
}
