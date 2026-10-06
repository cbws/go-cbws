package service_account

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	oauth2_jwt "go.cbws.cloud/sdk/oauth2/jwt"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
)

// TokenURLEnvVar names the environment variable that moves the endpoint a
// key is exchanged at, typically to reach the token service from inside the
// platform rather than through its public hostname. It moves only the
// address: the assertion stays addressed to the public token URL, which is
// the audience the token service checks it against.
const TokenURLEnvVar = "CBWS_TOKEN_URL"

const defaultTokenURL = "https://accounts.cbws.cloud/oauth2/token"

const audience = defaultTokenURL

// tokenURL is the endpoint set by SetTokenURL, empty when none was set.
var tokenURL string

type Credentials struct {
	Type         string `json:"type"`
	ProjectName  string `json:"project_name"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	ClientID     string `json:"client_id"`
}

// KeyType is the type every service account key file declares.
const KeyType = "service_account"

// ParseCredentials parses a service account key file, such as the one IAM
// returns when it creates a key, and checks it with Validate. It is for a
// caller that keeps or handles a key file itself; authenticating with one
// needs only option.WithCredentialsJSON.
func ParseCredentials(data []byte) (*Credentials, error) {
	var credentials Credentials
	if err := json.Unmarshal(data, &credentials); err != nil {
		return nil, fmt.Errorf("not a CBWS service account key file: %w", err)
	}

	if err := credentials.Validate(); err != nil {
		return nil, err
	}

	return &credentials, nil
}

// Validate reports whether the credentials are a complete key file as IAM
// issues it: of KeyType, naming its project, account and key, and holding a
// private key that parses. Only the token endpoint can say whether a key
// that passes is still active.
func (c Credentials) Validate() error {
	if c.Type != KeyType {
		return fmt.Errorf("key file has type %q, expected %q", c.Type, KeyType)
	}

	var missing []string
	for _, field := range []struct{ name, value string }{
		{"project_name", c.ProjectName},
		{"private_key_id", c.PrivateKeyID},
		{"private_key", c.PrivateKey},
		{"client_email", c.ClientEmail},
		{"client_id", c.ClientID},
	} {
		if field.value == "" {
			missing = append(missing, field.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("key file is missing %s", strings.Join(missing, ", "))
	}

	_, err := c.privateKey()

	return err
}

// privateKey decodes the PEM-encoded PKCS #8 key the credentials sign their
// assertions with.
func (c Credentials) privateKey() (any, error) {
	privateKeyBytes, _ := pem.Decode([]byte(c.PrivateKey))
	if privateKeyBytes == nil {
		// Reported rather than returned as a nil source with no error: a
		// caller choosing between credentials cannot tell those apart from
		// success, and hands the nil on to be dereferenced on the first
		// request instead of at the point the key was rejected.
		return nil, fmt.Errorf("could not decode the private key of %s: no PEM block found", c.ClientEmail)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBytes.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key: %+v", err)
	}

	return privateKey, nil
}

func (c Credentials) TokenSource(ctx context.Context, scopes []string) (oauth2.TokenSource, error) {
	privateKey, err := c.privateKey()
	if err != nil {
		return nil, err
	}

	OAuth2Config := oauth2_jwt.Config{
		ClientID:      c.ClientID,
		Subject:       c.ClientID,
		PrivateKey:    privateKey,
		PrivateKeyID:  c.PrivateKeyID,
		TokenURL:      TokenURL(),
		Audience:      audience,
		SigningMethod: jwt.GetSigningMethod("RS256"),
		Scopes:        scopes,
	}
	return OAuth2Config.TokenSource(ctx), nil
}

func NewTokenSource(ctx context.Context, credentialsFile string, scopes []string) (oauth2.TokenSource, error) {
	data, err := ioutil.ReadFile(credentialsFile)
	if err != nil {
		return nil, fmt.Errorf("could not read credentials file: %+v", err)
	}

	credentials := Credentials{}

	err = json.Unmarshal(data, &credentials)
	if err != nil {
		return nil, fmt.Errorf("could not parse credentials file: %+v", err)
	}

	return credentials.TokenSource(ctx, scopes)
}

// SetTokenURL sets the endpoint keys are exchanged at, taking precedence over
// TokenURLEnvVar. An empty URL clears it, so the variable or the default
// applies again.
func SetTokenURL(newTokenURL string) {
	tokenURL = newTokenURL
}

// TokenURL reports the endpoint tokens are obtained from: the one set by
// SetTokenURL, else TokenURLEnvVar, else the public token URL. It is the
// issuer half of a token cache key, which needs to name the authority a
// token was minted by so that two environments cannot share an entry.
func TokenURL() string {
	if tokenURL != "" {
		return tokenURL
	}
	if fromEnv := os.Getenv(TokenURLEnvVar); fromEnv != "" {
		return fromEnv
	}

	return defaultTokenURL
}
