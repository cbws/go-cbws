package v1alpha1

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.cbws.cloud/api/iam/v1alpha1"
	serviceaccount "go.cbws.cloud/sdk/oauth2/service-account"
	"go.cbws.cloud/sdk/option"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const serviceAccount = "projects/project-1/serviceAccounts/sa@project-1.iam-sa.cbws.xyz"

type fakeIAM struct {
	v1alpha1.UnimplementedIAMServiceServer

	generate func(*v1alpha1.GenerateAccessTokenRequest) (*v1alpha1.GenerateAccessTokenResponse, error)
	create   func(*v1alpha1.CreateServiceAccountKeyRequest) (*v1alpha1.ServiceAccountKey, error)
	remove   func(*v1alpha1.DeleteServiceAccountKeyRequest) (*emptypb.Empty, error)
	list     func(*v1alpha1.ListServiceAccountKeysRequest) (*v1alpha1.ListServiceAccountKeysResponse, error)
}

func (f *fakeIAM) GenerateAccessToken(_ context.Context, r *v1alpha1.GenerateAccessTokenRequest) (*v1alpha1.GenerateAccessTokenResponse, error) {
	return f.generate(r)
}

func (f *fakeIAM) CreateServiceAccountKey(_ context.Context, r *v1alpha1.CreateServiceAccountKeyRequest) (*v1alpha1.ServiceAccountKey, error) {
	return f.create(r)
}

func (f *fakeIAM) DeleteServiceAccountKey(_ context.Context, r *v1alpha1.DeleteServiceAccountKeyRequest) (*emptypb.Empty, error) {
	return f.remove(r)
}

func (f *fakeIAM) ListServiceAccountKeys(_ context.Context, r *v1alpha1.ListServiceAccountKeysRequest) (*v1alpha1.ListServiceAccountKeysResponse, error) {
	return f.list(r)
}

func newTestClient(t *testing.T, server *fakeIAM) *Client {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	v1alpha1.RegisterIAMServiceServer(s, server)

	go func() {
		if err := s.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("server: %v", err)
		}
	}()
	t.Cleanup(s.Stop)

	client, err := NewClient(context.Background(),
		option.WithEndpoint("bufnet"),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		})),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	return client
}

func keyFile(t *testing.T, keyID string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	data, err := json.Marshal(serviceaccount.Credentials{
		Type:         serviceaccount.KeyType,
		ProjectName:  "project-1",
		PrivateKeyID: keyID,
		PrivateKey:   string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		ClientEmail:  "sa@project-1.iam-sa.cbws.xyz",
		ClientID:     "client-1",
	})
	require.NoError(t, err)

	return data
}

func TestResourceNames(t *testing.T) {
	assert.Equal(t, serviceAccount, ServiceAccountName("project-1", "sa@project-1.iam-sa.cbws.xyz"))
	assert.Equal(t, serviceAccount+"/keys/key-1", ServiceAccountKeyName("project-1", "sa@project-1.iam-sa.cbws.xyz", "key-1"))
}

func TestGenerateAccessToken(t *testing.T) {
	expiry := time.Date(2026, 10, 6, 13, 0, 0, 0, time.UTC)

	var received *v1alpha1.GenerateAccessTokenRequest
	client := newTestClient(t, &fakeIAM{
		generate: func(r *v1alpha1.GenerateAccessTokenRequest) (*v1alpha1.GenerateAccessTokenResponse, error) {
			received = r

			return &v1alpha1.GenerateAccessTokenResponse{
				AccessToken: "at-1",
				ExpireTime:  timestamppb.New(expiry),
			}, nil
		},
	})

	token, err := client.GenerateAccessToken(context.Background(), serviceAccount, []string{"openid", "cbws"})
	require.NoError(t, err)

	assert.Equal(t, "at-1", token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.True(t, token.Expiry.Equal(expiry), "expiry %s", token.Expiry)

	assert.Equal(t, serviceAccount, received.GetName())
	assert.Equal(t, []string{"openid", "cbws"}, received.GetScope())
	assert.Nil(t, received.GetLifetime(), "without WithLifetime the server's default applies")
}

func TestGenerateAccessTokenWithLifetime(t *testing.T) {
	var received *v1alpha1.GenerateAccessTokenRequest
	client := newTestClient(t, &fakeIAM{
		generate: func(r *v1alpha1.GenerateAccessTokenRequest) (*v1alpha1.GenerateAccessTokenResponse, error) {
			received = r

			return &v1alpha1.GenerateAccessTokenResponse{
				AccessToken: "at-1",
				ExpireTime:  timestamppb.Now(),
			}, nil
		},
	})

	_, err := client.GenerateAccessToken(context.Background(), serviceAccount, []string{"cbws"}, WithLifetime(15*time.Minute))
	require.NoError(t, err)

	require.NotNil(t, received.GetLifetime())
	assert.Equal(t, 15*time.Minute, received.GetLifetime().AsDuration())
}

// TestGenerateAccessTokenRefusesATokenWithoutExpiry keeps a token that would
// read as everlasting from reaching the caller.
func TestGenerateAccessTokenRefusesATokenWithoutExpiry(t *testing.T) {
	client := newTestClient(t, &fakeIAM{
		generate: func(*v1alpha1.GenerateAccessTokenRequest) (*v1alpha1.GenerateAccessTokenResponse, error) {
			return &v1alpha1.GenerateAccessTokenResponse{AccessToken: "at-1"}, nil
		},
	})

	_, err := client.GenerateAccessToken(context.Background(), serviceAccount, []string{"cbws"})
	assert.ErrorContains(t, err, "no expiry")
}

func TestGenerateAccessTokenKeepsTheStatus(t *testing.T) {
	client := newTestClient(t, &fakeIAM{
		generate: func(*v1alpha1.GenerateAccessTokenRequest) (*v1alpha1.GenerateAccessTokenResponse, error) {
			return nil, status.Error(codes.PermissionDenied, "denied")
		},
	})

	_, err := client.GenerateAccessToken(context.Background(), serviceAccount, []string{"cbws"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestCreateServiceAccountKey(t *testing.T) {
	data := keyFile(t, "key-2")

	var received *v1alpha1.CreateServiceAccountKeyRequest
	client := newTestClient(t, &fakeIAM{
		create: func(r *v1alpha1.CreateServiceAccountKeyRequest) (*v1alpha1.ServiceAccountKey, error) {
			received = r

			return &v1alpha1.ServiceAccountKey{
				Name:           serviceAccount + "/keys/key-2",
				PrivateKeyData: data,
			}, nil
		},
	})

	key, err := client.CreateServiceAccountKey(context.Background(), serviceAccount)
	require.NoError(t, err)

	assert.Equal(t, serviceAccount, received.GetParent())
	assert.Equal(t, v1alpha1.ServiceAccountPrivateKeyType_SERVICE_ACCOUNT_PRIVATE_KEY_TYPE_CREDENTIALS_FILE, received.GetPrivateKeyType())

	assert.Equal(t, serviceAccount+"/keys/key-2", key.Name)
	assert.Equal(t, data, key.CredentialsJSON)
	assert.Equal(t, "key-2", key.Credentials.PrivateKeyID)
	assert.Equal(t, "project-1", key.Credentials.ProjectName)
}

// TestCreateServiceAccountKeyReportsAnUnusableKey checks that a key whose
// file cannot be used is still named, since it exists in IAM regardless.
func TestCreateServiceAccountKeyReportsAnUnusableKey(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "key file names another key", data: keyFile(t, "key-3"), want: "names key key-3"},
		{name: "not a key file", data: []byte("{}"), want: "type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestClient(t, &fakeIAM{
				create: func(*v1alpha1.CreateServiceAccountKeyRequest) (*v1alpha1.ServiceAccountKey, error) {
					return &v1alpha1.ServiceAccountKey{
						Name:           serviceAccount + "/keys/key-2",
						PrivateKeyData: tt.data,
					}, nil
				},
			})

			key, err := client.CreateServiceAccountKey(context.Background(), serviceAccount)
			assert.Nil(t, key)

			var unusable *UnusableKeyError
			require.ErrorAs(t, err, &unusable)
			assert.Equal(t, serviceAccount+"/keys/key-2", unusable.Name)
			assert.ErrorContains(t, err, tt.want)
		})
	}
}

func TestDeleteServiceAccountKey(t *testing.T) {
	var received *v1alpha1.DeleteServiceAccountKeyRequest
	client := newTestClient(t, &fakeIAM{
		remove: func(r *v1alpha1.DeleteServiceAccountKeyRequest) (*emptypb.Empty, error) {
			received = r

			return &emptypb.Empty{}, nil
		},
	})

	require.NoError(t, client.DeleteServiceAccountKey(context.Background(), serviceAccount+"/keys/key-1"))
	assert.Equal(t, serviceAccount+"/keys/key-1", received.GetName())

	assert.Error(t, client.DeleteServiceAccountKey(context.Background(), ""))
}

func TestListServiceAccountKeys(t *testing.T) {
	var received *v1alpha1.ListServiceAccountKeysRequest
	client := newTestClient(t, &fakeIAM{
		list: func(r *v1alpha1.ListServiceAccountKeysRequest) (*v1alpha1.ListServiceAccountKeysResponse, error) {
			received = r

			return &v1alpha1.ListServiceAccountKeysResponse{
				Keys: []*v1alpha1.ServiceAccountKey{{Name: serviceAccount + "/keys/key-1"}},
			}, nil
		},
	})

	keys, err := client.ListServiceAccountKeys(context.Background(), serviceAccount,
		v1alpha1.ServiceAccountKeyType_SERVICE_ACCOUNT_KEY_TYPE_USER_MANAGED)
	require.NoError(t, err)

	require.Len(t, keys, 1)
	assert.Equal(t, serviceAccount+"/keys/key-1", keys[0].GetName())
	assert.Equal(t, serviceAccount, received.GetParent())
	assert.Equal(t, []v1alpha1.ServiceAccountKeyType{v1alpha1.ServiceAccountKeyType_SERVICE_ACCOUNT_KEY_TYPE_USER_MANAGED}, received.GetKeyTypes())
}

func TestCloseReleasesTheConnection(t *testing.T) {
	client := newTestClient(t, &fakeIAM{
		remove: func(*v1alpha1.DeleteServiceAccountKeyRequest) (*emptypb.Empty, error) {
			return &emptypb.Empty{}, nil
		},
	})

	require.NoError(t, client.Close())

	err := client.DeleteServiceAccountKey(context.Background(), serviceAccount+"/keys/key-1")
	assert.Equal(t, codes.Canceled, status.Code(err))
}
