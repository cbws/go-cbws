package v1alpha1

import (
	"context"
	"fmt"

	longrunning "github.com/cbws/go-cbws/cbws/longrunning/v1alpha1"

	pbvm "github.com/cbws/go-cbws-grpc/cbws/virtual-machines/v1alpha1"
	pblongrunning "google.golang.org/genproto/googleapis/longrunning"
	"google.golang.org/genproto/googleapis/rpc/status"
)

type DeleteOperationHandler struct {
	handler *longrunning.Handler
}

type DeleteWaitOption interface {
	set(*waitDelete)
}

type waitDelete struct {
}

func (h *DeleteOperationHandler) Wait(ctx context.Context, opts ...DeleteWaitOption) (*status.Status, error) {
	wc := &waitDelete{}
	for _, opt := range opts {
		opt.set(wc)
	}
	var wopts []longrunning.WaitOption

	err := h.handler.Wait(ctx, wopts...)
	if err != nil {
		return nil, err
	}

	switch result := h.handler.Operation.Result.(type) {
	case *pblongrunning.Operation_Error:
		return result.Error, nil
	case *pblongrunning.Operation_Response:
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown type: %T", result)
	}
}

func (c Client) Delete(ctx context.Context, id string) (*DeleteOperationHandler, error) {
	operation, err := c.client.DeleteInstance(ctx, &pbvm.DeleteInstanceRequest{
		Name: fmt.Sprintf("projects/%s/instances/%s", c.project, id),
	})
	if err != nil {
		return nil, err
	}

	return &DeleteOperationHandler{
		c.operationsClient.Handler(operation),
	}, err
}
