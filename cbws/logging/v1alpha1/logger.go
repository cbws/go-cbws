package v1alpha1

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	pbapi "github.com/cbws/go-cbws-grpc/cbws/api/v1alpha1"
	pblogging "github.com/cbws/go-cbws-grpc/cbws/logging/v1alpha1"
	"google.golang.org/grpc/status"
)

// A LoggerOption is a configuration option for a Logger.
type LoggerOption interface {
	set(*Logger)
}

func (c *Client) Logger(logID string, opts ...LoggerOption) *Logger {
	logger := &Logger{
		c:       c,
		logName: fmt.Sprintf("%s/logs/%s", c.parent, logID),
		cEntry:  make(chan *pblogging.LogEntry, 25),
		donec:   make(chan struct{}),
		monitoredResource: &pbapi.MonitoredResource{
			Type: "projects.cbws.xyz/Project",
			Name: fmt.Sprintf("//projects.cbws.xyz/%s", c.parent),
		},
	}

	go func() {
		for {
			logger.bufferMutex.RLock()
			if len(logger.bufferedEntries) >= 1000 {
				logger.bufferMutex.RUnlock()

				continue
			}

			select {
			case entry, ok := <-logger.cEntry:
				if !ok {
					logger.bufferMutex.RUnlock()

					return
				}

				logger.bufferMutex.RUnlock()
				logger.bufferMutex.Lock()
				logger.bufferedEntries = append(logger.bufferedEntries, entry)
				logger.bufferMutex.Unlock()
			}
		}
	}()
	go func() {
		for {
			select {
			case <-time.After(time.Millisecond * 250):
				logger.handleBufferedEntries(context.Background())
			case <-logger.donec:
				return
			}
		}
	}()
	c.loggers.Add(1)
	// Start a goroutine that cleans up the bundler, its channel
	// and the writer goroutines when the client is closed.
	go func() {
		defer c.loggers.Done()
		<-c.donec

		close(logger.cEntry)
		logger.donec <- struct {
		}{}
		logger.handleBufferedEntries(context.Background())
	}()

	return logger
}

type Logger struct {
	c                 *Client
	logName           string
	monitoredResource *pbapi.MonitoredResource
	bufferedEntries   []*pblogging.LogEntry
	bufferMutex       sync.RWMutex
	cEntry            chan *pblogging.LogEntry
	donec             chan struct{}
}

// Log buffers the Entry for output to the logging service. It never blocks.
func (l *Logger) Log(e Entry) {
	ent, err := toLogEntry(e)
	if err != nil {
		l.c.error(err)
		return
	}

	l.cEntry <- ent
}

func (l *Logger) StandardLogger(opts ...WriterOption) *log.Logger {
	return log.New(l.Writer(opts...), "", 0)
}

func (l *Logger) handleBufferedEntries(ctx context.Context) {
	l.bufferMutex.Lock()
	defer l.bufferMutex.Unlock()

	if len(l.bufferedEntries) == 0 {
		return
	}

	l.bufferedEntries = l.writeLogEntries(ctx, l.bufferedEntries)
}

func (l *Logger) writeLogEntries(ctx context.Context, entries []*pblogging.LogEntry) []*pblogging.LogEntry {
	_, err := l.c.client.WriteLogEntries(ctx, &pblogging.WriteLogEntriesRequest{
		DefaultParent:  l.logName,
		PartialSuccess: true,
		LogEntries:     entries,
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			l.c.error(e.Err())

			return entries
		}
		l.c.error(err)

		return entries
	}

	return []*pblogging.LogEntry{}
}
