package v1alpha1

import (
	"context"

	"github.com/golang/protobuf/ptypes/any"
	"google.golang.org/genproto/googleapis/longrunning"
)

type MetadataChannel chan *any.Any

func WithMetadataChannel(mc MetadataChannel) MetadataChannel {
	return mc
}

func (mc MetadataChannel) set(_ *longrunning.WaitOperationRequest, r *waitRequest) {
	r.mc = mc
}

type WaitOption interface {
	set(*longrunning.WaitOperationRequest, *waitRequest)
}

type waitRequest struct {
	mc chan *any.Any
}

func (c Client) Wait(ctx context.Context, name string, opts ...WaitOption) (*Operation, error) {
	r := &longrunning.WaitOperationRequest{
		Name: name,
	}
	wr := &waitRequest{}
	for _, opt := range opts {
		opt.set(r, wr)
	}
	defer func() {
		if wr.mc == nil {
			return
		}

		close(wr.mc)
	}()
	for {
		op, err := c.client.WaitOperation(ctx, r)
		if err != nil {
			return nil, err
		}

		if wr.mc != nil {
			wr.mc <- op.Metadata
		}

		if op.Done {
			return (*Operation)(op), nil
		}
	}
}
