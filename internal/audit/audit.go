package audit

import "time"

type EventType string

const (
	EventWorkloadPreparing   EventType = "workload_preparing"
	EventWorkloadStarted     EventType = "workload_started"
	EventWorkloadTerminating EventType = "workload_terminating"
	EventCleanupStarted      EventType = "workload_cleanup_started"
	EventWorkloadFinished    EventType = "workload_finished"
	EventWorkloadFailed      EventType = "workload_failed"
)

type Event struct {
	Time       time.Time `json:"time"`
	Type       EventType `json:"type"`
	WorkloadID string    `json:"workload_id"`

	PID    int    `json:"pid,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type Sink interface {
	Record(Event)
}

type SinkFunc func(Event)

func (f SinkFunc) Record(event Event) {
	f(event)
}

type DiscardSink struct{}

func (DiscardSink) Record(Event) {}
