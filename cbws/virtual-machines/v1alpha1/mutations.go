package v1alpha1

import (
	"context"
	"fmt"

	pbvm "github.com/cbws/go-cbws-grpc/cbws/virtual-machines/v1alpha1"
	pblongrunning "google.golang.org/genproto/googleapis/longrunning"
)

func (c Client) Stop(ctx context.Context, id string) (*pblongrunning.Operation, error) {
	return c.client.StopInstance(ctx, &pbvm.StopInstanceRequest{
		Name: fmt.Sprintf("projects/%s/instances/%s", c.project, id),
	})
}

func (c Client) Start(ctx context.Context, id string) (*pblongrunning.Operation, error) {
	return c.client.StartInstance(ctx, &pbvm.StartInstanceRequest{
		Name: fmt.Sprintf("projects/%s/instances/%s", c.project, id),
	})
}

func (c Client) Reset(ctx context.Context, id string) (*pblongrunning.Operation, error) {
	return c.client.ResetInstance(ctx, &pbvm.ResetInstanceRequest{
		Name: fmt.Sprintf("projects/%s/instances/%s", c.project, id),
	})
}
