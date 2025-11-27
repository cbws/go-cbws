package v1alpha1

import (
	"context"

	"go.cbws.cloud/sdk/client/grpc"
	"go.cbws.cloud/sdk/option"

	"go.cbws.cloud/api/service_management/service_usage/v1alpha1"
)

const endpoint = "dns:///serviceusage.cbws.cloud:443"

func NewClient(ctx context.Context, opts ...option.ClientOption) (*Client, error) {
	o := []option.ClientOption{
		option.WithEndpoint(endpoint),
		option.WithUserAgent("go-cbws service-usage"),
	}
	o = append(o, opts...)

	conn, err := grpc.New(ctx, o...)
	if err != nil {
		return nil, err
	}

	return &Client{
		client: v1alpha1.NewServiceUsageServiceClient(conn),
	}, nil
}

type Client struct {
	client v1alpha1.ServiceUsageServiceClient
}

func (c Client) UnderlyingClient() v1alpha1.ServiceUsageServiceClient {
	return c.client
}
