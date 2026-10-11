package tokensource

import (
	"context"
	"testing"

	"golang.org/x/oauth2"
)

type contextual struct{ ctx context.Context }

func (c *contextual) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: "from Token"}, nil
}

func (c *contextual) TokenContext(ctx context.Context) (*oauth2.Token, error) {
	c.ctx = ctx

	return &oauth2.Token{AccessToken: "from TokenContext"}, nil
}

func TestASourceThatTakesAContextIsGivenIt(t *testing.T) {
	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "caller")
	source := &contextual{}

	token, err := Token(ctx, source)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	if token.AccessToken != "from TokenContext" {
		t.Errorf("access token = %q, want it from TokenContext", token.AccessToken)
	}
	if source.ctx == nil || source.ctx.Value(key{}) != "caller" {
		t.Errorf("TokenContext was not given the caller's context")
	}
}

func TestASourceThatTakesNoContextIsAskedThroughToken(t *testing.T) {
	token, err := Token(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "static"}))
	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	if token.AccessToken != "static" {
		t.Errorf("access token = %q, want static", token.AccessToken)
	}
}
