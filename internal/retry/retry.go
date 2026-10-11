// Package retry repeats an exchange with an authorization server that
// failed in transit: bounded attempts, a timeout on each, an overall
// budget, and jittered backoff between them.
//
// Retrying is the exchange's own decision, never a wrapper's. A caller may
// use this only for an exchange that is safe to repeat after an ambiguous
// outcome, one in which the server may have acted on a request whose answer
// never arrived. An exchange that spends a single-use credential, such as a
// rotating refresh token, is not: repeating it replays a credential the
// server may already have consumed.
package retry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"syscall"
	"time"
)

// Policy bounds a retried exchange: how many attempts it makes, how long
// each may take, how long all of them together may take, and how long it
// waits between them.
type Policy struct {
	Attempts       int
	AttemptTimeout time.Duration
	Budget         time.Duration
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

// Backoff returns how long to wait after the given failed attempt, counting
// from one. The delay doubles per attempt up to MaxBackoff and is jittered
// over its upper half, so processes that failed together do not retry in
// step.
func (p Policy) Backoff(attempt int) time.Duration {
	delay := p.InitialBackoff << (attempt - 1)
	if delay <= 0 || delay > p.MaxBackoff {
		delay = p.MaxBackoff
	}

	return delay/2 + rand.N(delay/2+1)
}

// Do runs attempt until it succeeds, until it fails with an error retryable
// rejects, or until the policy's attempts or budget run out. ctx bounds the
// whole run, and each attempt also gets a context bounded by
// AttemptTimeout.
//
// retryable is asked only while the run as a whole is still live, so a
// context.DeadlineExceeded it sees is the attempt's own timeout rather than
// the end of the budget or of ctx.
func Do[T any](ctx context.Context, p Policy, retryable func(error) bool, attempt func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, p.Budget)
	defer cancel()

	for n := 1; ; n++ {
		result, err := run(ctx, p.AttemptTimeout, attempt)
		if err == nil {
			return result, nil
		}

		var zero T
		if ctx.Err() != nil || !retryable(err) {
			return zero, err
		}
		if n >= p.Attempts {
			return zero, fmt.Errorf("%w (after %d attempts)", err, n)
		}
		if waitErr := wait(ctx, p.Backoff(n)); waitErr != nil {
			return zero, fmt.Errorf("%w (gave up after %d attempts: %w)", err, n, waitErr)
		}
	}
}

// run makes a single attempt on a context bounded by timeout.
func run[T any](ctx context.Context, timeout time.Duration, attempt func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return attempt(ctx)
}

// Transient reports whether err was caused by a connection that broke or
// never formed, or by an attempt that ran out of its own time. A TLS or URL
// error, or anything the server answered, would fail the same way again.
//
// It judges only the cause. Which errors to put in front of it, those of
// carrying the request and its answer rather than of the answer itself, is
// for the caller to decide.
func Transient(err error) bool {
	switch {
	case errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, syscall.ECONNABORTED),
		errors.Is(err, syscall.EPIPE),
		errors.Is(err, io.EOF),
		errors.Is(err, io.ErrUnexpectedEOF):
		return true
	}

	var netErr net.Error

	return errors.As(err, &netErr) && netErr.Timeout()
}

// wait sleeps for d, returning early with ctx's error if ctx ends first.
func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
