// Package useragent builds the headers that identify the SDK on every
// request it sends.
//
// Two headers carry the identification. User-Agent is shared with the
// application, which puts its own product token in front of the SDK's.
// APIClientHeader belongs to the SDK alone, in a fixed shape that callers
// cannot change, so it can be relied on when the User-Agent cannot.
package useragent

import (
	"context"
	"net/http"
	"runtime"
	"strings"

	"go.cbws.cloud/sdk/internal/version"
	"golang.org/x/oauth2"
)

// APIClientHeader names the header holding the SDK's own identification.
const APIClientHeader = "x-cbws-api-client"

// product is the SDK's product token, without its version.
const product = "go-cbws"

// SDK returns the SDK's product token, for example "go-cbws/1.18.0".
func SDK() string {
	return product + "/" + version.Get()
}

// String returns the User-Agent for an application whose own product token
// is app. The SDK's token is always present, after the application's.
func String(app string) string {
	app = strings.TrimSpace(app)
	if app == "" {
		return SDK()
	}

	return app + " " + SDK()
}

// APIClient returns the value of APIClientHeader: the Go version and the
// SDK's token, followed by the tokens in extra, which name the transport.
// The language token is prefixed "lang-" so a reader can find the runtime
// without knowing which language each SDK is written in.
func APIClient(extra ...string) string {
	tokens := append([]string{"lang-go/" + goVersion(), SDK()}, extra...)

	return strings.Join(tokens, " ")
}

// goVersion returns the Go release without its "go" prefix. A development
// toolchain reports something like "devel go1.26-abcdef", and only its first
// word is kept so the value stays a single token.
func goVersion() string {
	fields := strings.Fields(runtime.Version())
	if len(fields) == 0 {
		return "unknown"
	}

	return strings.TrimPrefix(fields[0], "go")
}

// SetHTTP sets both headers on h for an HTTP request the SDK sends without
// an application's User-Agent.
func SetHTTP(h http.Header) {
	h.Set("User-Agent", SDK())
	h.Set(APIClientHeader, APIClient())
}

// Context returns ctx with an HTTP client that sets both headers on every
// request, for code that takes its client from the context the way
// golang.org/x/oauth2 does. A client the caller already placed in ctx is
// kept and wrapped rather than replaced.
func Context(ctx context.Context) context.Context {
	base := oauth2.NewClient(ctx, nil)

	client := *base
	client.Transport = transport{base: base.Transport}

	return context.WithValue(ctx, oauth2.HTTPClient, &client)
}

type transport struct {
	base http.RoundTripper
}

func (t transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// A RoundTripper must not modify the request it is given.
	req = req.Clone(req.Context())
	SetHTTP(req.Header)

	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}

	return base.RoundTrip(req)
}
