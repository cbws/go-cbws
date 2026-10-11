package retry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var fast = Policy{
	Attempts:       4,
	AttemptTimeout: time.Second,
	Budget:         5 * time.Second,
	InitialBackoff: time.Millisecond,
	MaxBackoff:     5 * time.Millisecond,
}

// always and never stand in for a caller's classifier.
func always(error) bool { return true }
func never(error) bool  { return false }

func TestBackoffStaysWithinItsBounds(t *testing.T) {
	policy := Policy{InitialBackoff: 100 * time.Millisecond, MaxBackoff: time.Second}

	for attempt, want := range map[int]time.Duration{
		1:  100 * time.Millisecond,
		2:  200 * time.Millisecond,
		4:  800 * time.Millisecond,
		5:  time.Second,
		70: time.Second,
	} {
		for range 50 {
			got := policy.Backoff(attempt)
			assert.GreaterOrEqual(t, got, want/2, "attempt %d", attempt)
			assert.LessOrEqual(t, got, want, "attempt %d", attempt)
		}
	}
}

// sent wraps cause the way net/http reports a failed request.
func sent(cause error) error {
	return &url.Error{Op: "Post", URL: "http://token", Err: &net.OpError{
		Op:  "read",
		Net: "tcp",
		Err: os.NewSyscallError("read", cause),
	}}
}

type timeout struct{}

func (timeout) Error() string   { return "i/o timeout" }
func (timeout) Timeout() bool   { return true }
func (timeout) Temporary() bool { return true }

func TestTransient(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "reset", err: sent(syscall.ECONNRESET), want: true},
		{name: "refused", err: sent(syscall.ECONNREFUSED), want: true},
		{name: "aborted", err: sent(syscall.ECONNABORTED), want: true},
		{name: "broken pipe", err: sent(syscall.EPIPE), want: true},
		{name: "EOF", err: &url.Error{Op: "Post", URL: "http://token", Err: io.EOF}, want: true},
		{name: "unexpected EOF", err: fmt.Errorf("reading body: %w", io.ErrUnexpectedEOF), want: true},
		{name: "attempt timeout", err: &url.Error{Op: "Post", URL: "http://token", Err: context.DeadlineExceeded}, want: true},
		{name: "network timeout", err: &url.Error{Op: "Post", URL: "http://token", Err: timeout{}}, want: true},
		{name: "cancelled", err: &url.Error{Op: "Post", URL: "http://token", Err: context.Canceled}},
		{name: "unreachable network", err: sent(syscall.ENETUNREACH)},
		{name: "other", err: errors.New("x509: certificate signed by unknown authority")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Transient(tt.err))
		})
	}
}

func TestDoRetriesUntilSuccess(t *testing.T) {
	calls := 0
	got, err := Do(context.Background(), fast, always, func(context.Context) (string, error) {
		calls++
		if calls < 3 {
			return "", io.EOF
		}

		return "ok", nil
	})

	require.NoError(t, err)
	assert.Equal(t, "ok", got)
	assert.Equal(t, 3, calls)
}

func TestDoStopsAtANonRetryableError(t *testing.T) {
	calls := 0
	_, err := Do(context.Background(), fast, never, func(context.Context) (string, error) {
		calls++

		return "", io.EOF
	})

	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, 1, calls)
}

func TestDoStopsAfterItsAttempts(t *testing.T) {
	calls := 0
	_, err := Do(context.Background(), fast, always, func(context.Context) (string, error) {
		calls++

		return "", io.EOF
	})

	assert.ErrorIs(t, err, io.EOF)
	assert.Contains(t, err.Error(), "after 4 attempts")
	assert.Equal(t, fast.Attempts, calls)
}

func TestDoBoundsEachAttempt(t *testing.T) {
	policy := fast
	policy.AttemptTimeout = 50 * time.Millisecond

	calls := 0
	got, err := Do(context.Background(), policy, Transient, func(ctx context.Context) (string, error) {
		calls++
		if calls == 1 {
			<-ctx.Done()

			return "", ctx.Err()
		}

		return "ok", nil
	})

	require.NoError(t, err)
	assert.Equal(t, "ok", got)
	assert.Equal(t, 2, calls)
}

func TestDoStopsAtItsBudget(t *testing.T) {
	policy := fast
	policy.AttemptTimeout = 50 * time.Millisecond
	policy.Budget = 120 * time.Millisecond
	policy.Attempts = 100

	start := time.Now()
	_, err := Do(context.Background(), policy, Transient, func(ctx context.Context) (string, error) {
		<-ctx.Done()

		return "", ctx.Err()
	})

	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), time.Second)
}

func TestDoStopsWhenCancelledDuringBackoff(t *testing.T) {
	policy := fast
	policy.InitialBackoff = time.Minute
	policy.MaxBackoff = time.Minute

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	calls := 0
	start := time.Now()
	_, err := Do(ctx, policy, always, func(context.Context) (string, error) {
		calls++

		return "", io.EOF
	})

	assert.ErrorIs(t, err, context.Canceled)
	assert.ErrorIs(t, err, io.EOF, "the failure that led to the wait is kept")
	assert.Equal(t, 1, calls)
	assert.Less(t, time.Since(start), time.Second)
}

func TestDoDoesNotAskTheClassifierOnceTheRunHasEnded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	asked := false
	_, err := Do(ctx, fast, func(error) bool {
		asked = true

		return true
	}, func(context.Context) (string, error) {
		cancel()

		return "", io.EOF
	})

	assert.ErrorIs(t, err, io.EOF)
	assert.False(t, asked)
}
