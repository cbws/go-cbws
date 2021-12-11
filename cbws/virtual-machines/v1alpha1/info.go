package v1alpha1

import (
	"context"
	"fmt"

	pbvm "github.com/cbws/go-cbws-grpc/cbws/virtual-machines/v1alpha1"
	"github.com/cbws/go-pagination"
	"google.golang.org/genproto/protobuf/field_mask"
)

type Instance *pbvm.Instance

type getFieldMask field_mask.FieldMask

func (g *getFieldMask) set(r *pbvm.GetInstanceRequest) {
	r.ReadMask = (*field_mask.FieldMask)(g)
}

func WithGetFieldMask(paths []string) *getFieldMask {
	return &getFieldMask{
		Paths: paths,
	}
}

type GetOption interface {
	set(r *pbvm.GetInstanceRequest)
}

func (c Client) Get(ctx context.Context, id string, opts ...GetOption) (Instance, error) {
	r := &pbvm.GetInstanceRequest{
		Name: fmt.Sprintf("projects/%s/instances/%s", c.project, id),
	}
	for _, opt := range opts {
		opt.set(r)
	}

	instance, err := c.client.GetInstance(ctx, r)
	if err != nil {
		return nil, err
	}

	return instance, err
}

type listFieldMask field_mask.FieldMask

func (g *listFieldMask) set(r *pbvm.ListInstancesRequest) {
	r.ReadMask = (*field_mask.FieldMask)(g)
}

func WithListFieldMask(paths []string) *listFieldMask {
	return &listFieldMask{
		Paths: paths,
	}
}

type ListOption interface {
	set(r *pbvm.ListInstancesRequest)
}

func (c Client) Paginate(opts ...ListOption) pagination.Paginator {
	r := &pbvm.ListInstancesRequest{
		Parent: fmt.Sprintf("projects/%s", c.project),
	}
	for _, opt := range opts {
		opt.set(r)
	}

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

		response, err := c.client.ListInstances(ctx, r)
		if err != nil {
			return nil, err
		}
		for _, instance := range response.Instances {
			connection.Edges = append(connection.Edges, pagination.Edge{
				Node: Instance(instance),
			})
		}
		connection.PageInfo.EndCursor = pagination.StringCursor(response.NextPageToken)
		connection.PageInfo.HasNextPage = response.NextPageToken != ""

		return connection, nil
	}
}
