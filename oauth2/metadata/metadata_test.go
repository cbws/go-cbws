package metadata

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTokenSource(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		responseBody   string
		expectedToken  string
		expectedError  string
		expectedExpiry time.Duration
	}{
		{
			name:           "success",
			statusCode:     http.StatusOK,
			responseBody:   "test_access_token",
			expectedToken:  "test_access_token",
			expectedExpiry: 60 * time.Second,
		},
		{
			name:          "non-200 status code",
			statusCode:    http.StatusNotFound,
			responseBody:  "not found",
			expectedError: "unexpected metadata service response code 404: not found",
		},
		{
			name:          "internal server error",
			statusCode:    http.StatusInternalServerError,
			responseBody:  "server error",
			expectedError: "unexpected metadata service response code 500: server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = io.WriteString(w, tt.responseBody)
			}))
			defer server.Close()

			// Temporarily override the endpoint for testing
			originalEndpoint := endpoint
			endpoint = server.URL
			defer func() { endpoint = originalEndpoint }()

			ts := TokenSource(context.Background())
			token, err := ts.Token()

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.EqualError(t, err, tt.expectedError)
				assert.Nil(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, token)
				assert.Equal(t, tt.expectedToken, token.AccessToken)
				assert.Equal(t, "Bearer", token.TokenType)
				// Allow for a small time difference due to test execution time
				assert.InEpsilon(t, tt.expectedExpiry.Seconds(), time.Until(token.Expiry).Seconds(), 0.1)
			}
		})
	}
}
