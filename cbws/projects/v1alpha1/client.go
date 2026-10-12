package v1alpha1

import (
	"context"

	"go.cbws.cloud/sdk/client/grpc"
	"go.cbws.cloud/sdk/internal/defaultscopes"
	"go.cbws.cloud/sdk/option"

	"go.cbws.cloud/api/projects/v1alpha1"
)

const endpoint = "dns:///projects.cbws.cloud:443"

func NewClient(ctx context.Context, opts ...option.ClientOption) (*Client, error) {
	o := []option.ClientOption{
		option.WithEndpoint(endpoint),
		defaultscopes.With("cbws.projects"),
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
