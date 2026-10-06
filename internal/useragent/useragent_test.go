package useragent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.cbws.cloud/sdk/internal/version"
	"golang.org/x/oauth2"
)

func TestString(t *testing.T) {
	sdk := "go-cbws/" + version.Get()

	assert.Equal(t, sdk, String(""))
	assert.Equal(t, sdk, String("  "))
	assert.Equal(t, "cbws-cli/0.61.0 "+sdk, String("cbws-cli/0.61.0"))
	assert.Equal(t, "cbws-cli/0.61.0 "+sdk, String(" cbws-cli/0.61.0 "))
}

func TestAPIClient(t *testing.T) {
	value := APIClient("grpc/1.77.0")

	fields := strings.Fields(value)
	require.Len(t, fields, 3)
	assert.True(t, strings.HasPrefix(fields[0], "lang-go/"))
	assert.NotContains(t, fields[0], "lang-go/go")
	assert.Equal(t, "go-cbws/"+version.Get(), fields[1])
	assert.Equal(t, "grpc/1.77.0", fields[2])
}

func TestContextSetsHeaders(t *testing.T) {
	var got http.Header
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	response, err := oauth2.NewClient(Context(context.Background()), nil).Do(request)
	require.NoError(t, err)
	_ = response.Body.Close()

	assert.Equal(t, SDK(), got.Get("User-Agent"))
	assert.Equal(t, APIClient(), got.Get(APIClientHeader))
	assert.Empty(t, request.Header, "the caller's request was modified")
}

func TestContextKeepsTheCallersClient(t *testing.T) {
	used := false
	caller := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		used = true
		assert.Equal(t, SDK(), r.Header.Get("User-Agent"))

		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: r}, nil
	})}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, caller)

	response, err := oauth2.NewClient(Context(ctx), nil).Get("http://example.invalid")
	require.NoError(t, err)
	_ = response.Body.Close()

	assert.True(t, used)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
