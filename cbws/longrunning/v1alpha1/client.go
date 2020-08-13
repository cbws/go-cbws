package v1alpha1

import (
	"context"
	"io"

	"github.com/cbws/go-cbws/client/grpc"
	"github.com/cbws/go-cbws/option"

	pblongrunning "google.golang.org/genproto/googleapis/longrunning"
)

func NewClient(ctx context.Context, endpoint string, opts ...option.ClientOption) (*Client, error) {
	o := []option.ClientOption{
		option.WithEndpoint(endpoint),
		option.WithUserAgent("go-cbws longrunning"),
	}
	o = append(o, opts...)

	conn, err := grpc.New(ctx, o...)
	if err != nil {
		return nil, err
	}

	return &Client{
		clientConn: conn,
		client:     pblongrunning.NewOperationsClient(conn),
	}, nil
}

type Client struct {
	client     pblongrunning.OperationsClient
	clientConn io.Closer
}

func (c *Client) Close() error {
	return c.clientConn.Close()
}

func (c *Client) Handler(op *pblongrunning.Operation) *Handler {
	return &Handler{
		c:         c,
		Operation: (*Operation)(op),
	}
}
