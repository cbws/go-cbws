package jwt

import (
	"errors"
	"time"

	"go.cbws.cloud/sdk/internal/retry"
)

// defaultRetryPolicy is sized against an endpoint that answers in well under
// a second. A single attempt is cut off long before a stalled connection
// would give up on its own, and the whole exchange still fits inside the
// deadline a caller such as a credential plugin typically allows.
var defaultRetryPolicy = retry.Policy{
	Attempts:       4,
	AttemptTimeout: 10 * time.Second,
	Budget:         30 * time.Second,
	InitialBackoff: 250 * time.Millisecond,
	MaxBackoff:     2 * time.Second,
}

// transportError is a failure to carry the exchange to the token endpoint
// and its answer back, as opposed to an answer from it. Only these are ever
// retried: an answer, whatever its status, is the endpoint's decision.
type transportError struct {
	err error
}

func (e transportError) Error() string {
	return "oauth2: cannot fetch token: " + e.err.Error()
}

func (e transportError) Unwrap() error {
	return e.err
}

// retryable reports whether a failed exchange is worth another attempt: a
// transport failure whose cause retry.Transient accepts.
func retryable(err error) bool {
	var transport transportError

	return errors.As(err, &transport) && retry.Transient(err)
}
