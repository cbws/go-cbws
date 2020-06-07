package v1alpha1

import (
	"context"
	"github.com/cbws/go-cbws-grpc/cbws/vpn/v1alpha1"
	"github.com/cbws/go-pagination"
)

func (c Client) PaginateProfiles(parent string, opts ...PaginateProfilesOption) pagination.Paginator {
	r := v1alpha1.ListProfilesRequest{}
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

		response, err := c.client.ListProfiles(ctx, &r)
		if err != nil {
			return nil, err
		}
		for _, instance := range response.Profiles {
			connection.Edges = append(connection.Edges, pagination.Edge{
				Node: *instance,
			})
		}
		connection.PageInfo.EndCursor = pagination.StringCursor(response.NextPageToken)
		connection.PageInfo.HasNextPage = response.NextPageToken != ""

		return connection, nil
	}
}

type PaginateProfilesOption interface {
	Apply(request *v1alpha1.ListProfilesRequest)
}

func (c Client) CreateProfile(ctx context.Context, parent, name string, opts ...CreateProfileOption) (*v1alpha1.Profile, error) {
	r := &v1alpha1.CreateProfileRequest{
		Parent:        parent,
		Name:          name,
		Profile:       &v1alpha1.Profile{},
		XXX_sizecache: 0,
	}
	for _, opt := range opts {
		opt.Apply(r)
	}

	return c.client.CreateProfile(ctx, r)
}

type CreateProfileOption interface {
	Apply(request *v1alpha1.CreateProfileRequest)
}

func WithCreateProfileDisplayName(displayName string) CreateProfileOption {
	return createProfileWithDisplayName(displayName)
}

type createProfileWithDisplayName string

func (c createProfileWithDisplayName) Apply(r *v1alpha1.CreateProfileRequest) {
	r.Profile.DisplayName = string(c)
}

func (c Client) DeleteProfile(ctx context.Context, name string, opts ...DeleteProfileOption) error {
	r := &v1alpha1.DeleteProfileRequest{
		Name:          name,
		XXX_sizecache: 0,
	}
	for _, opt := range opts {
		opt.Apply(r)
	}

	_, err := c.client.DeleteProfile(ctx, r)
	return err
}

type DeleteProfileOption interface {
	Apply(request *v1alpha1.DeleteProfileRequest)
}
