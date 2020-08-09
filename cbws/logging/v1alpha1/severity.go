package v1alpha1

import (
	"encoding/json"
	"strconv"
	"strings"

	pblogging "github.com/cbws/go-cbws-grpc/cbws/logging/v1alpha1"
)

// Severity is the severity of the event described in a log entry. These
// guideline severity levels are ordered, with numerically smaller levels
// treated as less severe than numerically larger levels.
type Severity int

const (
	// Unspecified means the log entry has no assigned severity level.
	Unspecified = Severity(pblogging.LogSeverity_LOG_SEVERITY_UNSPECIFIED)
	// Debug means debug or trace information.
	Debug = Severity(pblogging.LogSeverity_LOG_SEVERITY_DEBUG)
	// Info means routine information, such as ongoing status or performance.
	Info = Severity(pblogging.LogSeverity_LOG_SEVERITY_INFO)
	// Notice means normal but significant events, such as start up, shut down, or configuration.
	Notice = Severity(pblogging.LogSeverity_LOG_SEVERITY_NOTICE)
	// Warning means events that might cause problems.
	Warning = Severity(pblogging.LogSeverity_LOG_SEVERITY_WARNING)
	// Error means events that are likely to cause problems.
	Error = Severity(pblogging.LogSeverity_LOG_SEVERITY_ERROR)
	// Critical means events that cause more severe problems or brief outages.
	Critical = Severity(pblogging.LogSeverity_LOG_SEVERITY_CRITICAL)
	// Alert means a person must take an action immediately.
	Alert = Severity(pblogging.LogSeverity_LOG_SEVERITY_ALERT)
	// Emergency means one or more systems are unusable.
	Emergency = Severity(pblogging.LogSeverity_LOG_SEVERITY_EMERGENCY)
)

var severityName = map[Severity]string{
	Unspecified: "Unspecified",
	Debug:       "Debug",
	Info:        "Info",
	Notice:      "Notice",
	Warning:     "Warning",
	Error:       "Error",
	Critical:    "Critical",
	Alert:       "Alert",
	Emergency:   "Emergency",
}

// String converts a severity level to a string.
func (v Severity) String() string {
	// same as proto.EnumName
	s, ok := severityName[v]
	if ok {
		return s
	}
	return strconv.Itoa(int(v))
}

// UnmarshalJSON turns a string representation of severity into the type
// Severity.
func (v *Severity) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*v = ParseSeverity(s)
	return nil
}

// ParseSeverity returns the Severity whose name equals s, ignoring case. It
// returns Default if no Severity matches.
func ParseSeverity(s string) Severity {
	sl := strings.ToLower(s)
	for sev, name := range severityName {
		if strings.ToLower(name) == sl {
			return sev
		}
	}
	return Unspecified
}
