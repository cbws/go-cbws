package v1alpha1

import (
	"context"

	"github.com/cbws/go-cbws-grpc/cbws/vpn/v1alpha1"
	"github.com/cbws/go-pagination"
)

func (c Client) PaginateInstances(parent string, opts ...PaginateInstancesOption) pagination.Paginator {
	r := v1alpha1.ListInstancesRequest{}
	r.Parent = parent

	return func(ctx context.Context, first, last *int, before, after pagination.Cursor) (*pagination.Connection, error) {
		connection := &pagination.Connection{
			PageInfo: pagination.PageInfo{},
		}
		if first != nil {
			r.PageSize = int32(*first)
		}
		if after != nil {
			r.PageToken = after.GetCursor()
		}

		response, err := c.client.ListInstances(ctx, &r)
		if err != nil {
			return nil, err
		}
		for _, instance := range response.Instances {
			connection.Edges = append(connection.Edges, pagination.Edge{
				Node: *instance,
			})
		}
		connection.PageInfo.EndCursor = pagination.StringCursor(response.NextPageToken)
		connection.PageInfo.HasNextPage = response.NextPageToken != ""

		return connection, nil
	}
}

type PaginateInstancesOption interface {
	Apply(request *v1alpha1.ListInstancesRequest)
}

func (c Client) CreateInstance(ctx context.Context, parent, name string, opts ...CreateInstanceOption) (*v1alpha1.Instance, error) {
	r := &v1alpha1.CreateInstanceRequest{
		Parent:        parent,
		Name:          name,
		Instance:      &v1alpha1.Instance{},
		XXX_sizecache: 0,
	}
	for _, opt := range opts {
		opt.Apply(r)
	}

	return c.client.CreateInstance(ctx, r)
}

type CreateInstanceOption interface {
	Apply(request *v1alpha1.CreateInstanceRequest)
}

func WithCreateInstanceDisplayName(displayName string) CreateInstanceOption {
	return createInstanceWithDisplayName(displayName)
}

type createInstanceWithDisplayName string

func (c createInstanceWithDisplayName) Apply(r *v1alpha1.CreateInstanceRequest) {
	r.Instance.DisplayName = string(c)
}

func WithCreateInstanceIPv6DefaultGateway(enable bool) CreateInstanceOption {
	return createInstanceWithIPv6DefaultGateway(enable)
}

type createInstanceWithIPv6DefaultGateway bool

func (c createInstanceWithIPv6DefaultGateway) Apply(r *v1alpha1.CreateInstanceRequest) {
	r.Instance.Ipv6DefaultGateway = bool(c)
}

func WithCreateInstanceIPv4DefaultGateway(enable bool) CreateInstanceOption {
	return createInstanceWithIPv4DefaultGateway(enable)
}

type createInstanceWithIPv4DefaultGateway bool

func (c createInstanceWithIPv4DefaultGateway) Apply(r *v1alpha1.CreateInstanceRequest) {
	r.Instance.Ipv4DefaultGateway = bool(c)
}

func (c Client) DeleteInstance(ctx context.Context, name string, opts ...DeleteInstanceOption) error {
	r := &v1alpha1.DeleteInstanceRequest{
		Name:          name,
		XXX_sizecache: 0,
	}
	for _, opt := range opts {
		opt.Apply(r)
	}

	_, err := c.client.DeleteInstance(ctx, r)
	return err
}

type DeleteInstanceOption interface {
	Apply(request *v1alpha1.DeleteInstanceRequest)
}
