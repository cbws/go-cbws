package v1alpha1

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/cbws/go-cbws/client/grpc"
	"github.com/cbws/go-cbws/option"

	pblogging "github.com/cbws/go-cbws-grpc/cbws/logging/v1alpha1"
)

const endpoint = "logging.cbws.xyz:443"

func NewClient(ctx context.Context, parent string, opts ...option.ClientOption) (*Client, error) {
	o := []option.ClientOption{
		option.WithEndpoint(endpoint),
		option.WithUserAgent("go-cbws logging"),
	}
	o = append(o, opts...)

	conn, err := grpc.New(ctx, o...)
	if err != nil {
		return nil, err
	}

	c := &Client{
		clientConn: conn,
		client:     pblogging.NewLoggingServiceClient(conn),
		errc:       make(chan error, 10), // create a small buffer for errors
		donec:      make(chan struct{}),
		parent:     parent,
	}
	// Call the user's function synchronously, to make life easier for them.
	go func() {
		for err := range c.errc {
			fmt.Fprintf(os.Stderr, "logging: %v", err)
		}
	}()
	return c, nil
}

type Client struct {
	client     pblogging.LoggingServiceClient
	mu         sync.Mutex
	errc       chan error // should be buffered to minimize dropped errors
	nErrs      int        // number of errors we saw
	lastErr    error      // last error we saw
	parent     string
	donec      chan struct{}  // closed on Client.Close to close Logger bundlers
	loggers    sync.WaitGroup // so we can wait for loggers to close
	closed     bool
	clientConn io.Closer
}

// error puts the error on the client's error channel
// without blocking, and records summary error info.
func (c *Client) error(err error) {
	select {
	case c.errc <- err:
	default:
	}
	c.mu.Lock()
	c.lastErr = err
	c.nErrs++
	c.mu.Unlock()
}

func (c *Client) extractErrorInfo() error {
	var err error
	c.mu.Lock()
	if c.lastErr != nil {
		err = fmt.Errorf("saw %d errors; last: %v", c.nErrs, c.lastErr)
		c.nErrs = 0
		c.lastErr = nil
	}
	c.mu.Unlock()
	return err
}

func (c *Client) Close() error {
	defer c.clientConn.Close()

	if c.closed {
		return nil
	}
	close(c.donec)   // close Logger bundlers
	c.loggers.Wait() // wait for all bundlers to flush and close
	// Now there can be no more errors.
	close(c.errc) // terminate error goroutine

	// Prefer errors arising from logging to the error returned from Close.
	err := c.extractErrorInfo()
	c.closed = true

	return err
}
