package service_account

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	oauth2_jwt "go.cbws.cloud/sdk/oauth2/jwt"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
)

var tokenURL = "https://accounts.cbws.cloud/oauth2/token"

const audience = "https://accounts.cbws.cloud/oauth2/token"

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
		return nil, nil
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
		TokenURL:      tokenURL,
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

func SetTokenURL(newTokenURL string) {
	tokenURL = newTokenURL
}
