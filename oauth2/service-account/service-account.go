package service_account

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

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

func (c Credentials) TokenSource(ctx context.Context, scopes []string) (oauth2.TokenSource, error) {
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
