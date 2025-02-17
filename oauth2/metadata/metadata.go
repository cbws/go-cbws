package jwt

import (
	"context"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// TokenSource returns a metadata TokenSource
func TokenSource(ctx context.Context) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(nil, metadataSource{ctx})
}

// metadataSource is a source that always requests a token from the CBWS metadata token endpoint.
type metadataSource struct {
	ctx context.Context
}

func (js metadataSource) Token() (*oauth2.Token, error) {
	get, err := http.Get("http://169.254.169.254/cbws/core/test/token")
	if err != nil {
		return nil, err
	}

	token, err := io.ReadAll(get.Body)
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken: string(token),
		TokenType:   "Bearer",
		ExpiresIn:   60,
		Expiry:      time.Now().Add(60 * time.Second),
	}, nil
}
