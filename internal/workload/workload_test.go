package workload

import "testing"

func TestNew(t *testing.T) {
	spec := Spec{
		Command: "echo",
		Args:    []string{"hello"},
	}

	w, err := New("test-workload", spec)

	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if w.ID() != "test-workload" {
		t.Fatalf(
			"unexpected ID: got %q, want %q",
			w.ID(),
			"test-workload",
		)
	}

	if w.State() != StatePreparing {
		t.Fatalf(
			"unexpected initial state: got %q, want %q",
			w.State(),
			StatePreparing,
		)
	}

	if w.CreatedAt().IsZero() {
		t.Fatal("expected CreatedAt to be set")
	}

	if !w.StartedAt().IsZero() {
		t.Fatal("expected StartedAt to be zero before running")
	}

	if !w.FinishedAt().IsZero() {
		t.Fatal("expected FinishedAt to be zero before completion")
	}
}
func TestTransition(t *testing.T) {
	tests := []struct {
		name    string
		from    State
		to      State
		wantErr bool
	}{
		{
			name:    "preparing to running",
			from:    StatePreparing,
			to:      StateRunning,
			wantErr: false,
		},
		{
			name:    "preparing to cleaning",
			from:    StatePreparing,
			to:      StateCleaning,
			wantErr: false,
		},
		{
			name:    "running to terminating",
			from:    StateRunning,
			to:      StateTerminating,
			wantErr: false,
		},
		{
			name:    "running to cleaning",
			from:    StateRunning,
			to:      StateCleaning,
			wantErr: false,
		},
		{
			name:    "terminating to cleaning",
			from:    StateTerminating,
			to:      StateCleaning,
			wantErr: false,
		},
		{
			name:    "cleaning to finished",
			from:    StateCleaning,
			to:      StateFinished,
			wantErr: false,
		},
		{
			name:    "cleaning to failed",
			from:    StateCleaning,
			to:      StateFailed,
			wantErr: false,
		},

		// Invalid transitions
		{
			name:    "preparing directly to finished",
			from:    StatePreparing,
			to:      StateFinished,
			wantErr: true,
		},
		{
			name:    "running directly to finished",
			from:    StateRunning,
			to:      StateFinished,
			wantErr: true,
		},
		{
			name:    "finished back to running",
			from:    StateFinished,
			to:      StateRunning,
			wantErr: true,
		},
		{
			name:    "failed back to running",
			from:    StateFailed,
			to:      StateRunning,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &Workload{
				id:    "test-workload",
				state: tt.from,
			}

			err := w.Transition(tt.to)

			if tt.wantErr {
				if err == nil {
					t.Fatalf(
						"expected transition %s -> %s to fail",
						tt.from,
						tt.to,
					)
				}

				if w.State() != tt.from {
					t.Fatalf(
						"state changed after invalid transition: got %q, want %q",
						w.State(),
						tt.from,
					)
				}

				return
			}

			if err != nil {
				t.Fatalf(
					"transition %s -> %s returned error: %v",
					tt.from,
					tt.to,
					err,
				)
			}

			if w.State() != tt.to {
				t.Fatalf(
					"unexpected state: got %q, want %q",
					w.State(),
					tt.to,
				)
			}
		})
	}
}

func TestZeroValueCannotTransition(t *testing.T) {
	var w Workload

	err := w.Transition(StateRunning)

	if err == nil {
		t.Fatal("expected zero-value workload transition to fail")
	}

	if w.State() != State("") {
		t.Fatalf(
			"zero-value workload state changed: got %q",
			w.State(),
		)
	}
}

func TestNewRejectsEmptyID(t *testing.T) {
	w, err := New("", Spec{
		Command: "echo",
	})

	if err == nil {
		t.Fatal("expected empty workload ID to return an error")
	}

	if w != nil {
		t.Fatal("expected nil workload for invalid ID")
	}
}

func TestTransitionUpdatesTimestamps(t *testing.T) {
	w, err := New("test-workload", Spec{
		Command: "echo",
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	err = w.Transition(StateRunning)
	if err != nil {
		t.Fatalf("transition to running failed: %v", err)
	}

	if w.StartedAt().IsZero() {
		t.Fatal("expected StartedAt to be set")
	}

	if !w.FinishedAt().IsZero() {
		t.Fatal("expected FinishedAt to remain zero while running")
	}

	err = w.Transition(StateCleaning)
	if err != nil {
		t.Fatalf("transition to cleaning failed: %v", err)
	}

	err = w.Transition(StateFinished)
	if err != nil {
		t.Fatalf("transition to finished failed: %v", err)
	}

	if w.FinishedAt().IsZero() {
		t.Fatal("expected FinishedAt to be set")
	}

	if w.FinishedAt().Before(w.StartedAt()) {
		t.Fatal("FinishedAt must not be before StartedAt")
	}
}

func TestNewRejectsInvalidSpec(t *testing.T) {
	w, err := New("test-workload", Spec{})

	if err == nil {
		t.Fatal("expected invalid spec to return an error")
	}

	if w != nil {
		t.Fatal("expected nil workload for invalid spec")
	}
}
func TestNewCopiesSpec(t *testing.T) {
	spec := Spec{
		Command: "echo",
		Args:    []string{"original"},
		Env:     []string{"KEY=value"},
	}

	w, err := New("test-workload", spec)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	spec.Args[0] = "changed"
	spec.Env[0] = "KEY=changed"

	got := w.Spec()

	if len(got.Args) != 1 {
		t.Fatalf(
			"unexpected args length: got %d, want 1",
			len(got.Args),
		)
	}

	if len(got.Env) != 1 {
		t.Fatalf(
			"unexpected env length: got %d, want 1",
			len(got.Env),
		)
	}

	if got.Args[0] != "original" {
		t.Fatalf(
			"unexpected arg: got %q, want %q",
			got.Args[0],
			"original",
		)
	}

	if got.Env[0] != "KEY=value" {
		t.Fatalf(
			"unexpected env: got %q, want %q",
			got.Env[0],
			"KEY=value",
		)
	}
}
