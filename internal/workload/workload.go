package workload

import (
	"fmt"
	"time"
)

type State string

const (
	StatePreparing   State = "preparing"
	StateRunning     State = "running"
	StateTerminating State = "terminating"
	StateCleaning    State = "cleaning"
	StateFinished    State = "finished"
	StateFailed      State = "failed"
)

type Workload struct {
	id    string
	spec  Spec
	state State

	createdAt  time.Time
	startedAt  time.Time
	finishedAt time.Time
}

func New(id string, spec Spec) (*Workload, error) {
	if id == "" {
		return nil, fmt.Errorf("workload ID must not be empty")
	}
	if err := spec.Validate(); err != nil {
		return nil, fmt.Errorf("invalid workload spec: %w", err)
	}

	return &Workload{
		id:        id,
		spec:      cloneSpec(spec),
		state:     StatePreparing,
		createdAt: time.Now(),
	}, nil
}

func (w *Workload) ID() string {
	return w.id
}

func (w *Workload) Spec() Spec {
	return cloneSpec(w.spec)
}

func (w *Workload) State() State {
	return w.state
}

func (w *Workload) CreatedAt() time.Time {
	return w.createdAt
}

func (w *Workload) StartedAt() time.Time {
	return w.startedAt
}

func (w *Workload) FinishedAt() time.Time {
	return w.finishedAt
}

func (w *Workload) Transition(next State) error {
	var allowed bool

	switch w.state {
	case StatePreparing:
		allowed = next == StateRunning || next == StateCleaning

	case StateRunning:
		allowed = next == StateTerminating || next == StateCleaning

	case StateTerminating:
		allowed = next == StateCleaning

	case StateCleaning:
		allowed = next == StateFinished || next == StateFailed

	case StateFinished, StateFailed:
		allowed = false
	}

	if !allowed {
		return fmt.Errorf(
			"invalid workload state transition: %s -> %s",
			w.state,
			next,
		)
	}

	now := time.Now()
	w.state = next
	switch next {

	case StateRunning:
		w.startedAt = now

	case StateFinished, StateFailed:
		w.finishedAt = now

	}
	return nil
}
