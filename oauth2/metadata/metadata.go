package metadata

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

var endpoint = "http://169.254.169.254/cbws/core/test/token"

// Endpoint reports the metadata token endpoint. It is the issuer half of a
// token cache key, which needs to name the authority a token was minted by.
func Endpoint() string {
	return endpoint
}

// TokenSource returns a metadata TokenSource
func TokenSource(ctx context.Context) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(nil, metadataSource{
		ctx:      ctx,
		endpoint: endpoint,
	})
}

// metadataSource is a source that always requests a token from the CBWS metadata token endpoint.
type metadataSource struct {
	ctx      context.Context
	endpoint string
}

type UnexpectedMetadataResponse struct {
	StatusCode int
	Body       string
}

func (u UnexpectedMetadataResponse) Error() string {
	return fmt.Sprintf("unexpected metadata service response code %d: %s", u.StatusCode, u.Body)
}

func (js metadataSource) Token() (*oauth2.Token, error) {
	get, err := http.Get(js.endpoint)
	if err != nil {
		return nil, err
	}
	defer get.Body.Close()

	body, err := io.ReadAll(get.Body)
	if err != nil {
		return nil, err
	}

	if get.StatusCode != http.StatusOK {
		return nil, UnexpectedMetadataResponse{
			StatusCode: get.StatusCode,
			Body:       string(body),
		}
	}

	return &oauth2.Token{
		AccessToken: string(body),
		TokenType:   "Bearer",
		ExpiresIn:   60,
		Expiry:      time.Now().Add(60 * time.Second),
	}, nil
}
