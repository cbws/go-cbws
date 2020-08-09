package v1alpha1

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	pbapi "github.com/cbws/go-cbws-grpc/cbws/api/v1alpha1"
	pblogging "github.com/cbws/go-cbws-grpc/cbws/logging/v1alpha1"
	"github.com/golang/protobuf/ptypes"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"google.golang.org/protobuf/encoding/protojson"
)

// Entry is a log entry.
type Entry struct {
	// Timestamp is the time of the entry. If zero, the current time is used.
	Timestamp time.Time

	// Severity is the entry's severity level.
	// The zero value is Unspecified.
	Severity Severity

	// Payload must be either a string, or something that marshals via the
	// encoding/json package to a JSON object (and not any other type of JSON value).
	Payload interface{}

	// Labels optionally specifies key/value labels for the log entry.
	// The Logger.Log method takes ownership of this map. See Logger.CommonLabels
	// for more about labels.
	Labels map[string]string

	// InsertID is a unique ID for the log entry. If you provide this field,
	// the logging service considers other log entries in the same log with the
	// same ID as duplicates which can be removed. If omitted, the logging
	// service will generate a unique ID for this log entry. Note that because
	// this client retries RPCs automatically, it is possible (though unlikely)
	// that an Entry without an InsertID will be written more than once.
	InsertID string

	// HTTPRequest optionally specifies metadata about the HTTP request
	// associated with this log entry, if applicable. It is optional.
	HTTPRequest *HTTPRequest

	// Operation optionally provides information about an operation associated
	// with the log entry, if applicable.
	Operation *pblogging.LogEntryOperation

	// LogName is the full log name, in the form
	// "projects/{ProjectID}/logs/{LogID}". It is set by the client when
	// reading entries. It is an error to set it when writing entries.
	LogName string

	// Resource is the monitored resource associated with the entry.
	Resource *pbapi.MonitoredResource
}

func toLogEntry(e Entry) (*pblogging.LogEntry, error) {
	if e.LogName != "" {
		return nil, errors.New("logging: Entry.LogName should be not be set when writing")
	}
	t := e.Timestamp
	if t.IsZero() {
		t = time.Now()
	}
	ts, err := ptypes.TimestampProto(t)
	if err != nil {
		return nil, err
	}
	ent := &pblogging.LogEntry{
		EntryTime:   ts,
		Severity:    pblogging.LogSeverity(e.Severity),
		InsertId:    e.InsertID,
		HttpRequest: fromHTTPRequest(e.HTTPRequest),
		Operation:   e.Operation,
		Labels:      e.Labels,
		Resource:    e.Resource,
	}
	switch p := e.Payload.(type) {
	case string:
		ent.Payload = &pblogging.LogEntry_TextPayload{TextPayload: p}
	default:
		s, err := toProtoStruct(p)
		if err != nil {
			return nil, err
		}
		ent.Payload = &pblogging.LogEntry_JsonPayload{JsonPayload: s}
	}
	return ent, nil
}

// toProtoStruct converts v, which must marshal into a JSON object,
// into a Google Struct proto.
func toProtoStruct(v interface{}) (*structpb.Struct, error) {
	// Fast path: if v is already a *structpb.Struct, nothing to do.
	if s, ok := v.(*structpb.Struct); ok {
		return s, nil
	}
	// v is a Go value that supports JSON marshalling. We want a Struct
	// protobuf. Some day we may have a more direct way to get there, but right
	// now the only way is to marshal the Go value to JSON, unmarshal into a
	// map, and then build the Struct proto from the map.
	var jb []byte
	var err error
	if raw, ok := v.(json.RawMessage); ok { // needed for Go 1.7 and below
		jb = []byte(raw)
	} else {
		jb, err = json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("logging: json.Marshal: %v", err)
		}
	}
	var m map[string]interface{}
	err = json.Unmarshal(jb, &m)
	if err != nil {
		return nil, fmt.Errorf("logging: json.Unmarshal: %v", err)
	}
	return jsonMapToProtoStruct(m)
}

func jsonMapToProtoStruct(m map[string]interface{}) (*structpb.Struct, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	st := &structpb.Struct{}

	err = protojson.Unmarshal(b, st)
	return st, err
}
