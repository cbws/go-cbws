package v1alpha1

import (
	"io"
)

// A WriterOption is a configuration option for a Writer.
type WriterOption interface {
	set(*entityWriter)
}

type severityOption Severity

func (s severityOption) set(writer *entityWriter) {
	writer.e.Severity = Severity(s)
}

func WithSeverity(severity Severity) WriterOption {
	return severityOption(severity)
}

func (l *Logger) Writer(opts ...WriterOption) io.Writer {
	writer := &entityWriter{l, Entry{
		Resource: l.monitoredResource,
	}}
	for _, opt := range opts {
		opt.set(writer)
	}

	return writer
}

type entityWriter struct {
	l *Logger
	e Entry
}

func (w entityWriter) Write(p []byte) (n int, err error) {
	w.e.Payload = string(p)
	w.l.Log(w.e)

	return len(p), nil
}
