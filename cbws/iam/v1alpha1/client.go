package v1alpha1

import (
	"context"

	"go.cbws.cloud/sdk/client/grpc"
	"go.cbws.cloud/sdk/internal/defaultscopes"
	"go.cbws.cloud/sdk/option"

	"go.cbws.cloud/api/iam/v1alpha1"
)

const endpoint = "dns:///iam.cbws.cloud:443"

// NewClient connects to CBWS IAM. The connection is held until Close, so a
// consumer that replaces its credentials builds a new Client and closes the
// one it replaces.
func NewClient(ctx context.Context, opts ...option.ClientOption) (*Client, error) {
	o := []option.ClientOption{
		option.WithEndpoint(endpoint),
		defaultscopes.With("cbws.iam"),
	}
	o = append(o, opts...)

	conn, err := grpc.New(ctx, o...)
	if err != nil {
		return nil, err
	}

	return &Client{
		conn:   conn,
		client: v1alpha1.NewIAMServiceClient(conn),
	}, nil
}

type Client struct {
	conn   *grpc.GRPCClient
	client v1alpha1.IAMServiceClient
}

func (c Client) UnderlyingClient() v1alpha1.IAMServiceClient {
	return c.client
}

// Close releases the connection. Calls made after it fail.
func (c *Client) Close() error {
	return c.conn.Close()
}
