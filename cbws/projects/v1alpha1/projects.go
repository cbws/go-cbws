package v1alpha1

import (
	"context"

	"github.com/cbws/go-cbws-grpc/cbws/projects/v1alpha1"
	"github.com/cbws/go-pagination"
)

func (c Client) PaginateProjects(opts ...PaginateProjectsOption) pagination.Paginator {
	r := v1alpha1.ListProjectsRequest{}

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

		response, err := c.client.ListProjects(ctx, &r)
		if err != nil {
			return nil, err
		}
		for _, instance := range response.Projects {
			connection.Edges = append(connection.Edges, pagination.Edge{
				Node: *instance,
			})
		}
		connection.PageInfo.EndCursor = pagination.StringCursor(response.NextPageToken)
		connection.PageInfo.HasNextPage = response.NextPageToken != ""

		return connection, nil
	}
}

type PaginateProjectsOption interface {
	Apply(request *v1alpha1.ListProjectsRequest)
}

func (c Client) CreateProject(ctx context.Context, parent, name string, opts ...CreateProjectOption) (*v1alpha1.Project, error) {
	r := &v1alpha1.CreateProjectRequest{
		Parent:  parent,
		Name:    name,
		Project: &v1alpha1.Project{},
	}
	for _, opt := range opts {
		opt.Apply(r)
	}

	return c.client.CreateProject(ctx, r)
}

type CreateProjectOption interface {
	Apply(request *v1alpha1.CreateProjectRequest)
}

func WithCreateProjectDisplayName(displayName string) CreateProjectOption {
	return createProjectWithDisplayName(displayName)
}

type createProjectWithDisplayName string

func (c createProjectWithDisplayName) Apply(r *v1alpha1.CreateProjectRequest) {
	r.Project.DisplayName = string(c)
}

func (c Client) GetProject(ctx context.Context, name string, opts ...GetProjectOption) (*v1alpha1.Project, error) {
	r := &v1alpha1.GetProjectRequest{
		Name:    name,
	}
	for _, opt := range opts {
		opt.Apply(r)
	}

	return c.client.GetProject(ctx, r)
}

type GetProjectOption interface {
	Apply(request *v1alpha1.GetProjectRequest)
}
