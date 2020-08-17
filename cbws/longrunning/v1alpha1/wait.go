package v1alpha1

import (
	"context"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"google.golang.org/genproto/googleapis/longrunning"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type MetadataChannel chan *any.Any

func WithMetadataChannel(mc MetadataChannel) MetadataChannel {
	return mc
}

func (mc MetadataChannel) set(_ *longrunning.WaitOperationRequest, r *waitRequest) {
	r.mc = mc
}

type waitTimeout time.Duration

func WithWaitTimeout(timeout time.Duration) waitTimeout {
	return waitTimeout(timeout)
}

func (t waitTimeout) set(r *longrunning.WaitOperationRequest, rr *waitRequest) {
	r.Timeout = ptypes.DurationProto(time.Duration(t))
	rr.timeout = time.Duration(t)
}


type WaitOption interface {
	set(*longrunning.WaitOperationRequest, *waitRequest)
}

type waitRequest struct {
	mc chan *any.Any
	timeout time.Duration
}

func (c Client) Wait(ctx context.Context, name string, opts ...WaitOption) (*Operation, error) {
	r := &longrunning.WaitOperationRequest{
		Name: name,
	}
	wr := &waitRequest{
		timeout: 10*time.Second,
	}
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
		op, err := c.wait(ctx, r, wr)
		if err != nil {
			return nil, err
		}
		if op != nil {
			return op, nil
		}
	}
}

func (c Client) wait(ctx context.Context, r *longrunning.WaitOperationRequest, wr *waitRequest) (*Operation, error) {
	waitContext, cancel := context.WithTimeout(ctx, wr.timeout+(5*time.Second))
	defer cancel()

	op, err := c.client.WaitOperation(waitContext, r)
	if err != nil {
		if e, ok := status.FromError(err); ok {
			switch e.Code() {
			case codes.Internal:
				return nil, nil
			case codes.DeadlineExceeded:
				return nil, nil
			}
		}

		return nil, err
	}

	if wr.mc != nil {
		wr.mc <- op.Metadata
	}

	if op.Done {
		return (*Operation)(op), nil
	}

	return nil, nil
}
