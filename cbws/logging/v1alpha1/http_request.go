package v1alpha1

import (
	"net/http"
	"time"

	pblogging "github.com/cbws/go-cbws-grpc/cbws/logging/v1alpha1"
	"github.com/golang/protobuf/ptypes"
)

// HTTPRequest contains an http.Request as well as additional
// information about the request and its response.
type HTTPRequest struct {
	// Request is the http.Request passed to the handler.
	Request *http.Request

	// RequestSize is the size of the HTTP request message in bytes, including
	// the request headers and the request body.
	RequestSize int64

	// Status is the response code indicating the status of the response.
	// Examples: 200, 404.
	Status int

	// ResponseSize is the size of the HTTP response message sent back to the client, in bytes,
	// including the response headers and the response body.
	ResponseSize int64

	// Latency is the request processing latency on the server, from the time the request was
	// received until the response was sent.
	Latency time.Duration

	// LocalIP is the IP address (IPv4 or IPv6) of the origin server that the request
	// was sent to.
	LocalIP string

	// RemoteIP is the IP address (IPv4 or IPv6) of the client that issued the
	// HTTP request. Examples: "192.168.1.1", "FE80::0202:B3FF:FE1E:8329".
	RemoteIP string

	// CacheHit reports whether an entity was served from cache (with or without
	// validation).
	CacheHit bool

	// CacheValidatedWithOriginServer reports whether the response was
	// validated with the origin server before being served from cache. This
	// field is only meaningful if CacheHit is true.
	CacheValidatedWithOriginServer bool
}

func fromHTTPRequest(r *HTTPRequest) *pblogging.HttpRequest {
	if r == nil {
		return nil
	}
	if r.Request == nil {
		panic("HTTPRequest must have a non-nil Request")
	}
	u := *r.Request.URL
	u.Fragment = ""
	pb := &pblogging.HttpRequest{
		RequestMethod:                r.Request.Method,
		RequestUri:                   u.String(),
		RequestSize:                  r.RequestSize,
		Status:                       int32(r.Status),
		ResponseSize:                 r.ResponseSize,
		UserAgent:                    r.Request.UserAgent(),
		ServerIp:                     r.LocalIP,
		RemoteIp:                     r.RemoteIP,
		Referer:                      r.Request.Referer(),
		CacheHit:                     r.CacheHit,
		CacheIsOriginServerValidated: r.CacheValidatedWithOriginServer,
	}
	if r.Latency != 0 {
		pb.Latency = ptypes.DurationProto(r.Latency)
	}
	return pb
}
