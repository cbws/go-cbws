package v1alpha1

import (
	"context"
	"io"

	longrunning "github.com/cbws/go-cbws/cbws/longrunning/v1alpha1"
	"github.com/cbws/go-cbws/client/grpc"
	"github.com/cbws/go-cbws/option"

	pbvm "github.com/cbws/go-cbws-grpc/cbws/virtual-machines/v1alpha1"
)

const endpoint = "vm.cbws.cloud:443"

func NewClient(ctx context.Context, project string, opts ...option.ClientOption) (*Client, error) {
	o := []option.ClientOption{
		option.WithEndpoint(endpoint),
		option.WithUserAgent("go-cbws virtual-machines"),
	}
	o = append(o, opts...)

	conn, err := grpc.New(ctx, o...)
	if err != nil {
		return nil, err
	}

	operationsClient, err := longrunning.NewClient(ctx, endpoint, opts...)
	if err != nil {
		return nil, err
	}

	return &Client{
		clientConn:       conn,
		client:           pbvm.NewVirtualMachinesServiceClient(conn),
		operationsClient: operationsClient,
		project:          project,
	}, nil
}

type Client struct {
	client           pbvm.VirtualMachinesServiceClient
	clientConn       io.Closer
	operationsClient *longrunning.Client
	project          string
}

func (c *Client) Close() error {
	return c.clientConn.Close()
}
