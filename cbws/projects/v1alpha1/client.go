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
		// Unexported and unused outside this package: FoldersService is not public yet, so
		// folders_internal.go, not this file, is what turns it into a client. See the comment
		// there for why that split exists.
		conn: conn,
	}, nil
}

type Client struct {
	client v1alpha1.ProjectsServiceClient
	conn   *grpc.GRPCClient
}

func (c Client) UnderlyingClient() v1alpha1.ProjectsServiceClient {
	return c.client
}
