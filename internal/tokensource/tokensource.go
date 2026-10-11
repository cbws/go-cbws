// Package tokensource names the form of token source a caller can stop
// waiting on, and asks for a token through it wherever a source offers it.
//
// golang.org/x/oauth2 gives a token source no context, so a call that has a
// deadline of its own cannot hand it to the source it is waiting on. The
// SDK's own sources take one through TokenContext. Everything that asks a
// source for a token on behalf of a call goes through Token here, so a
// source that can honour the call's context is given it and one that cannot
// is asked exactly as before.
package tokensource

import (
	"context"

	"golang.org/x/oauth2"
)

// ContextSource is a token source that takes a context bounding how long a
// caller waits for a token.
//
// TokenContext answers as Token does, except that a caller whose context
// ends before a token is ready gets the context's error. Ending the context
// gives up the wait, not the work: a fetch shared with other callers carries
// on for them.
//
// An implementation holds its token in memory and answers from it while it
// lasts, so asking one on every call costs no request. A source that wraps
// one relies on that to defer to it rather than keep a copy of its own.
type ContextSource interface {
	oauth2.TokenSource
	TokenContext(ctx context.Context) (*oauth2.Token, error)
}

// Token asks source for a token, on ctx when source is a ContextSource and
// through its Token method otherwise. A source that takes no context is
// waited on for as long as it takes.
func Token(ctx context.Context, source oauth2.TokenSource) (*oauth2.Token, error) {
	if contextual, ok := source.(ContextSource); ok {
		return contextual.TokenContext(ctx)
	}

	return source.Token()
}
