package v1alpha1

import (
	"context"
	"fmt"
	longrunning "github.com/cbws/go-cbws/cbws/longrunning/v1alpha1"

	pbvm "github.com/cbws/go-cbws-grpc/cbws/virtual-machines/v1alpha1"
	"github.com/golang/protobuf/ptypes/any"
	pblongrunning "google.golang.org/genproto/googleapis/longrunning"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type CreateOperationHandler struct {
	instance *Instance
	handler *longrunning.Handler
}

type cmc chan *pbvm.CreateInstanceMetadata

func WithInstanceMetadataChannel(cmc cmc) cmc {
	return cmc
}

func (cmc cmc) set(r *waitCreate) {
	r.cmc = cmc
}

type CreateWaitOption interface {
	set(*waitCreate)
}

type waitCreate struct {
	cmc cmc
}

func (h *CreateOperationHandler) Wait(ctx context.Context, opts ...CreateWaitOption) (*Instance, *status.Status, error) {
	wc := &waitCreate{}
	for _, opt := range opts {
		opt.set(wc)
	}
	var wopts []longrunning.WaitOption

	if wc.cmc != nil {
		mc := make(chan *any.Any)
		wopts = append(wopts, longrunning.WithMetadataChannel(mc))
		go func() {
			for {
				select {
				case m, ok := <-mc:
					if !ok {
						return
					}

					cm := &pbvm.CreateInstanceMetadata{}
					err := m.UnmarshalTo(cm)
					if err != nil {
						return
					}

					wc.cmc <- cm
				}
			}
		}()
	}

	err := h.handler.Wait(ctx, wopts...)
	if err != nil {
		return nil, nil, err
	}

	switch result := h.handler.Operation.Result.(type) {
	case *pblongrunning.Operation_Error:
		return nil, result.Error, nil
	case *pblongrunning.Operation_Response:
		r := &pbvm.Instance{}
		err := anypb.UnmarshalTo(result.Response, r, proto.UnmarshalOptions{})
		if err != nil {
			return nil, nil, err
		}

		return (*Instance)(r), nil, nil
	default:
		return nil, nil, fmt.Errorf("unknown type: %T", result)
	}
}

func (c Client) Create(ctx context.Context, id string, instance *Instance) (*CreateOperationHandler, error) {
	operation, err := c.client.CreateInstance(ctx, &pbvm.CreateInstanceRequest{
		Parent:     fmt.Sprintf("projects/%s", c.project),
		InstanceId: id,
		Instance:   (*pbvm.Instance)(instance),
	})
	if err != nil {
		return nil, err
	}

	instance.Name = fmt.Sprintf("projects/%s/instances/%s", c.project, id)

	return &CreateOperationHandler{
		handler: c.operationsClient.Handler(operation),
		instance: instance,
	}, err
}
