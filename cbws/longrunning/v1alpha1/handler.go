package v1alpha1

import (
	"context"

	"google.golang.org/genproto/googleapis/longrunning"
)

type Operation longrunning.Operation

type Handler struct {
	c         *Client
	Operation *Operation
}

func (h *Handler) Wait(ctx context.Context, opts ...WaitOption) error {
	op, err := h.c.Wait(ctx, h.Operation.Name, opts...)
	if err != nil {
		return err
	}

	h.Operation = op

	return nil
}
