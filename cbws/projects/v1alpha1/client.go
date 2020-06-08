package v1alpha1

import (
	"context"

	"github.com/cbws/go-cbws/client/grpc"
	"github.com/cbws/go-cbws/option"

	"github.com/cbws/go-cbws-grpc/cbws/projects/v1alpha1"
)

const endpoint = "projects.cbws.xyz:443"

func NewClient(ctx context.Context, opts ...option.ClientOption) (*Client, error) {
	o := []option.ClientOption{
		option.WithEndpoint(endpoint),
		option.WithUserAgent("go-cbws projects"),
	}
	o = append(o, opts...)

	conn, err := grpc.New(ctx, o...)
	if err != nil {
		return nil, err
	}

	return &Client{
		client: v1alpha1.NewProjectsServiceClient(conn),
	}, nil
}

type Client struct {
	client v1alpha1.ProjectsServiceClient
}

func (c Client) UnderlyingClient() v1alpha1.ProjectsServiceClient {
	return c.client
}
