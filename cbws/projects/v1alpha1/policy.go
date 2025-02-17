package v1alpha1

import (
	"context"
	"fmt"

	"go.cbws.cloud/api/iam/policy/v1alpha1"
)

func (c Client) GetIAMPolicy(ctx context.Context, name string) (*v1alpha1.Policy, error) {
	return c.UnderlyingClient().GetPolicy(ctx, &v1alpha1.GetPolicyRequest{
		Resource: fmt.Sprintf("projects/%s", name),
	})
}

func (c Client) SetIAMPolicy(ctx context.Context, name string, policy *v1alpha1.Policy) (*v1alpha1.Policy, error) {
	return c.UnderlyingClient().SetPolicy(ctx, &v1alpha1.SetPolicyRequest{
		Resource: fmt.Sprintf("projects/%s", name),
		Policy:   policy,
	})
}
