package cli

import (
	"context"
	"io/ioutil"
	"log"
	"time"

	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

const ClientID = "612537ce-d5ba-475f-a77e-c1f1197ad3d5"

type Config struct {
	OAuthToken struct {
		AccessToken  string `yaml:"accesstoken"`
		TokenType    string `yaml:"tokentype"`
		Expiry       string
		RefreshToken string `yaml:"refreshtoken"`
	} `yaml:"oauth_token"`
}

func NewTokenSourceFromConfig(ctx context.Context, config string, scopes []string) (oauth2.TokenSource, error) {
	data, err := ioutil.ReadFile(config)
	if err != nil {
		return nil, err
	}

	c := Config{}
	err = yaml.Unmarshal(data, &c)
	if err != nil {
		return nil, err
	}

	OAuthConfig := &oauth2.Config{
		ClientID: ClientID,
		Scopes:   scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.cbws.cloud/oauth2/auth",
			TokenURL: "https://accounts.cbws.cloud/oauth2/token",
		},
	}

	token := &oauth2.Token{
		TokenType:    c.OAuthToken.TokenType,
		RefreshToken: c.OAuthToken.RefreshToken,
	}
	tokenExpiry, err := time.Parse(time.RFC3339Nano, c.OAuthToken.Expiry)
	if err != nil {
		return nil, err
	}
	token.Expiry = tokenExpiry
	token.AccessToken = c.OAuthToken.AccessToken
	return NewNotifyingTokenSource(
		OAuthConfig.TokenSource(ctx, token),
		func(newToken *oauth2.Token) error {
			if token.AccessToken == newToken.AccessToken {
				return nil
			}

			log.Printf("Token refreshed")

			//viper.Set("oauth_token", newToken)
			//if err := viper.WriteConfig(); err != nil {
			//	log.Fatalf("Could not write config")
			//}

			return nil
		},
	), nil
}

// TokenNotifyFunc is a function that accepts an oauth2 Token upon refresh, and
// returns an error if it should not be used.
type TokenNotifyFunc func(*oauth2.Token) error

// NotifyingTokenSource is an oauth2.TokenSource that calls a function when a
// new token is obtained.
type NotifyingTokenSource struct {
	f   TokenNotifyFunc
	src oauth2.TokenSource
}

// NewNotifyingTokenSource creates a NotifyingTokenSource from an underlying src
// and calls f when a new token is obtained.
func NewNotifyingTokenSource(src oauth2.TokenSource, f TokenNotifyFunc) *NotifyingTokenSource {
	return &NotifyingTokenSource{f: f, src: src}
}

// Token fetches a new token from the underlying source.
func (s *NotifyingTokenSource) Token() (*oauth2.Token, error) {
	t, err := s.src.Token()
	if err != nil {
		return nil, err
	}
	if s.f == nil {
		return t, nil
	}
	return t, s.f(t)
}
