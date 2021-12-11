package v1alpha1

import (
	"context"
	"fmt"
	longrunning "github.com/cbws/go-cbws/cbws/longrunning/v1alpha1"
	"google.golang.org/genproto/protobuf/field_mask"

	pbvm "github.com/cbws/go-cbws-grpc/cbws/virtual-machines/v1alpha1"
	"github.com/golang/protobuf/ptypes/any"
	pblongrunning "google.golang.org/genproto/googleapis/longrunning"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type UpdateOperationHandler struct {
	handler *longrunning.Handler
}

type umc chan *pbvm.UpdateInstanceMetadata

func WithUpdateInstanceMetadataChannel(umc umc) umc {
	return umc
}

func (umc umc) set(r *waitUpdate) {
	r.umc = umc
}

type UpdateWaitOption interface {
	set(*waitUpdate)
}

type waitUpdate struct {
	umc umc
}

func (h *UpdateOperationHandler) Wait(ctx context.Context, opts ...UpdateWaitOption) (Instance, *status.Status, error) {
	wc := &waitUpdate{}
	for _, opt := range opts {
		opt.set(wc)
	}
	var wopts []longrunning.WaitOption

	if wc.umc != nil {
		mc := make(chan *any.Any)
		wopts = append(wopts, longrunning.WithMetadataChannel(mc))
		go func() {
			for {
				select {
				case m, ok := <-mc:
					if !ok {
						return
					}

					cm := &pbvm.UpdateInstanceMetadata{}
					err := m.UnmarshalTo(cm)
					if err != nil {
						return
					}

					wc.umc <- cm
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

		return r, nil, nil
	default:
		return nil, nil, fmt.Errorf("unknown type: %T", result)
	}
}

func (c Client) Update(ctx context.Context, id string, instance Instance, fields []string) (*UpdateOperationHandler, error) {
	instance.Name = fmt.Sprintf("projects/%s/instances/%s", c.project, id)

	operation, err := c.client.UpdateInstance(ctx, &pbvm.UpdateInstanceRequest{
		Instance:   instance,
		UpdateMask: &field_mask.FieldMask{Paths: fields},
	})
	if err != nil {
		return nil, err
	}

	return &UpdateOperationHandler{
		c.operationsClient.Handler(operation),
	}, err
}
