package v1alpha1

import (
	"context"
	"fmt"
	"strings"

	"go.cbws.cloud/api/vpc/v1alpha1"

	"github.com/cbws/go-pagination"
)

func (c Client) PaginateVpcs(opts ...PaginateVpcsOption) pagination.Paginator {
	r := &v1alpha1.ListVpcsRequest{}

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

		response, err := c.client.ListVpcs(ctx, r)
		if err != nil {
			return nil, err
		}
		for _, instance := range response.Vpcs {
			connection.Edges = append(connection.Edges, pagination.Edge{
				Node: instance,
			})
		}
		connection.PageInfo.EndCursor = pagination.StringCursor(response.NextPageToken)
		connection.PageInfo.HasNextPage = response.NextPageToken != ""

		return connection, nil
	}
}

type PaginateVpcsOption interface {
	Apply(request *v1alpha1.ListVpcsRequest)
}

func (c Client) PaginatePrivateNetworks(opts ...PaginatePrivateNetworksOption) pagination.Paginator {
	r := &v1alpha1.ListPrivateNetworksRequest{}

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
		r.Parent = "projects/" + c.project + "/vpcs/default"
		for _, opt := range opts {
			opt.Apply(r)
		}

		response, err := c.client.ListPrivateNetworks(ctx, r)
		if err != nil {
			return nil, err
		}
		for _, instance := range response.PrivateNetworks {
			connection.Edges = append(connection.Edges, pagination.Edge{
				Node: instance,
			})
		}
		connection.PageInfo.EndCursor = pagination.StringCursor(response.NextPageToken)
		connection.PageInfo.HasNextPage = response.NextPageToken != ""

		return connection, nil
	}
}

type PaginatePrivateNetworksOption interface {
	Apply(request *v1alpha1.ListPrivateNetworksRequest)
}

func WithPrivateNetworkVpc(vpc string) paginatePrivateNetworksWithVpc {
	return paginatePrivateNetworksWithVpc(vpc)
}

type paginatePrivateNetworksWithVpc string

func (c paginatePrivateNetworksWithVpc) Apply(r *v1alpha1.ListPrivateNetworksRequest) {
	projectName := strings.Split(r.Parent, "/")[1]

	r.Parent = fmt.Sprintf("projects/%s/vpcs/%s", projectName, c)
}

//
//func (c Client) PaginateSubnets(opts ...PaginateSubnetsOption) pagination.Paginator {
//	r := &v1alpha1.ListSubnetsRequest{}
//
//	return func(ctx context.Context, first, last *int, before, after pagination.Cursor) (*pagination.Connection, error) {
//		connection := &pagination.Connection{
//			PageInfo: pagination.PageInfo{},
//		}
//		if first != nil {
//			r.PageSize = int32(*first)
//		}
//		if after != nil {
//			r.PageToken = after.GetCursor()
//		}
//		//r.Parent = "projects/" + c.project
//		for _, opt := range opts {
//			opt.Apply(r)
//		}
//
//		response, err := c.client.ListSubnets(ctx, r)
//		if err != nil {
//			return nil, err
//		}
//		for _, instance := range response.Subnets {
//			connection.Edges = append(connection.Edges, pagination.Edge{
//				Node: instance,
//			})
//		}
//		connection.PageInfo.EndCursor = pagination.StringCursor(response.NextPageToken)
//		connection.PageInfo.HasNextPage = response.NextPageToken != ""
//
//		return connection, nil
//	}
//}
//
//type PaginateSubnetsOption interface {
//	Apply(request *v1alpha1.ListSubnetsRequest)
//}
//
//func WithSubnetReadMask(paths []string) PaginateSubnetsOption {
//	return paginateSubnetsWithReadMask(paths)
//}
//
//type paginateSubnetsWithReadMask []string
//
//func (c paginateSubnetsWithReadMask) Apply(r *v1alpha1.ListSubnetsRequest) {
//	r.ReadMask = &fieldmaskpb.FieldMask{Paths: c}
//}
