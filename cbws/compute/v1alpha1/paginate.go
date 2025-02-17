package v1alpha1

import (
	"context"
	"log"

	"go.cbws.cloud/api/compute/v1alpha1"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/cbws/go-pagination"
)

func (c Client) PaginateMachines(opts ...PaginateMachinesOption) pagination.Paginator {
	r := &v1alpha1.ListMachinesRequest{}

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
		r.Parent = "projects/" + c.project
		for _, opt := range opts {
			opt.Apply(r)
		}

		log.Printf("Request: %+v", r)

		response, err := c.client.ListMachines(ctx, r)
		if err != nil {
			return nil, err
		}
		for _, instance := range response.Machines {
			connection.Edges = append(connection.Edges, pagination.Edge{
				Node: instance,
			})
		}
		connection.PageInfo.EndCursor = pagination.StringCursor(response.NextPageToken)
		connection.PageInfo.HasNextPage = response.NextPageToken != ""

		return connection, nil
	}
}

type PaginateMachinesOption interface {
	Apply(request *v1alpha1.ListMachinesRequest)
}

func WithReadMask(paths []string) PaginateMachinesOption {
	return paginateMachinesWithReadMask(paths)
}

type paginateMachinesWithReadMask []string

func (c paginateMachinesWithReadMask) Apply(r *v1alpha1.ListMachinesRequest) {
	r.ReadMask = &fieldmaskpb.FieldMask{Paths: c}
}
