package v1alpha1

import (
	"context"
	"errors"
	"fmt"
	"path"
	"time"

	"go.cbws.cloud/api/iam/v1alpha1"
	serviceaccount "go.cbws.cloud/sdk/oauth2/service-account"

	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/durationpb"
)

// ServiceAccountName returns the resource name of a service account,
// `projects/{project}/serviceAccounts/{account}`. The account is its email
// address or its unique id.
func ServiceAccountName(project, account string) string {
	return fmt.Sprintf("projects/%s/serviceAccounts/%s", project, account)
}

// ServiceAccountKeyName returns the resource name of a service account key,
// `projects/{project}/serviceAccounts/{account}/keys/{key}`. The key is the
// private_key_id of its key file.
func ServiceAccountKeyName(project, account, key string) string {
	return ServiceAccountName(project, account) + "/keys/" + key
}

// GenerateAccessToken mints an access token for serviceAccount, a resource
// name as ServiceAccountName returns it, with the given scopes. The caller
// needs permission to generate tokens for that account, which is how one
// identity impersonates another.
//
// The token cannot be revoked early, so its lifetime is the only bound on
// its use; WithLifetime asks for one other than the server's default.
// Delegation chains are not offered, since CBWS does not accept them.
func (c *Client) GenerateAccessToken(ctx context.Context, serviceAccount string, scopes []string, opts ...TokenOption) (*oauth2.Token, error) {
	r := &v1alpha1.GenerateAccessTokenRequest{
		Name:  serviceAccount,
		Scope: scopes,
	}
	for _, opt := range opts {
		opt.Apply(r)
	}

	response, err := c.client.GenerateAccessToken(ctx, r)
	if err != nil {
		return nil, err
	}

	// A token without an expiry reads as one that never expires to
	// golang.org/x/oauth2 and everything built on it, so one is refused
	// rather than handed on.
	if response.GetAccessToken() == "" || response.GetExpireTime() == nil {
		return nil, fmt.Errorf("IAM returned no access token or no expiry for %s", serviceAccount)
	}

	return &oauth2.Token{
		AccessToken: response.GetAccessToken(),
		TokenType:   "Bearer",
		Expiry:      response.GetExpireTime().AsTime(),
	}, nil
}

// TokenOption configures a GenerateAccessToken request.
type TokenOption interface {
	Apply(request *v1alpha1.GenerateAccessTokenRequest)
}

// WithLifetime asks for a token that expires d after it is minted. The server
// decides which lifetimes it accepts and refuses the request otherwise; the
// returned token's expiry is the one the server granted. Without this option
// the server's default lifetime applies.
func WithLifetime(d time.Duration) TokenOption {
	return withLifetime(d)
}

type withLifetime time.Duration

func (w withLifetime) Apply(r *v1alpha1.GenerateAccessTokenRequest) {
	r.Lifetime = durationpb.New(time.Duration(w))
}

// CreatedServiceAccountKey is a key IAM has just created, with the key file
// that authenticates as it. The key file is returned once, at creation, and
// IAM keeps no copy.
type CreatedServiceAccountKey struct {
	// Name is the key's resource name, as ServiceAccountKeyName returns it.
	Name string

	// CredentialsJSON is the key file exactly as IAM returned it, ready for
	// option.WithCredentialsJSON or for storing.
	CredentialsJSON []byte

	// Credentials is CredentialsJSON parsed and validated.
	Credentials *serviceaccount.Credentials
}

// UnusableKeyError reports a key IAM created whose key file cannot be used.
// The key exists all the same, so Name is what a caller deletes or reports.
type UnusableKeyError struct {
	Name string
	Err  error
}

func (e *UnusableKeyError) Error() string {
	return fmt.Sprintf("IAM created key %s, but its key file is not usable: %v", e.Name, e.Err)
}

func (e *UnusableKeyError) Unwrap() error {
	return e.Err
}

// CreateServiceAccountKey creates a user-managed key for serviceAccount, a
// resource name as ServiceAccountName returns it, and returns its key file.
//
// The key file is checked before it is returned: it must parse, carry
// everything needed to authenticate, and name the key IAM says it created.
// A key that fails the check is reported as an *UnusableKeyError, since it
// exists in IAM regardless.
func (c *Client) CreateServiceAccountKey(ctx context.Context, serviceAccount string) (*CreatedServiceAccountKey, error) {
	key, err := c.client.CreateServiceAccountKey(ctx, &v1alpha1.CreateServiceAccountKeyRequest{
		Parent:         serviceAccount,
		PrivateKeyType: v1alpha1.ServiceAccountPrivateKeyType_SERVICE_ACCOUNT_PRIVATE_KEY_TYPE_CREDENTIALS_FILE,
	})
	if err != nil {
		return nil, err
	}

	credentials, err := serviceaccount.ParseCredentials(key.GetPrivateKeyData())
	if err != nil {
		return nil, &UnusableKeyError{Name: key.GetName(), Err: err}
	}

	if path.Base(key.GetName()) != credentials.PrivateKeyID {
		return nil, &UnusableKeyError{
			Name: key.GetName(),
			Err:  fmt.Errorf("the key file names key %s", credentials.PrivateKeyID),
		}
	}

	return &CreatedServiceAccountKey{
		Name:            key.GetName(),
		CredentialsJSON: key.GetPrivateKeyData(),
		Credentials:     credentials,
	}, nil
}

// DeleteServiceAccountKey deletes a user-managed key by its resource name, as
// ServiceAccountKeyName returns it. Tokens already minted with the key stay
// valid until they expire.
func (c *Client) DeleteServiceAccountKey(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("a service account key name is required")
	}

	_, err := c.client.DeleteServiceAccountKey(ctx, &v1alpha1.DeleteServiceAccountKeyRequest{
		Name: name,
	})

	return err
}

// ListServiceAccountKeys lists the keys of serviceAccount, a resource name as
// ServiceAccountName returns it, limited to the given key types when any are
// given. Listed keys carry no key file.
func (c *Client) ListServiceAccountKeys(ctx context.Context, serviceAccount string, keyTypes ...v1alpha1.ServiceAccountKeyType) ([]*v1alpha1.ServiceAccountKey, error) {
	response, err := c.client.ListServiceAccountKeys(ctx, &v1alpha1.ListServiceAccountKeysRequest{
		Parent:   serviceAccount,
		KeyTypes: keyTypes,
	})
	if err != nil {
		return nil, err
	}

	return response.GetKeys(), nil
}
