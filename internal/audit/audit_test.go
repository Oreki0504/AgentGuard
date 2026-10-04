package audit

import "testing"

func TestSinkFuncRecordsEvent(t *testing.T) {
	var got Event

	sink := SinkFunc(func(event Event) {
		got = event
	})

	want := Event{
		Type:       EventWorkloadStarted,
		WorkloadID: "test-workload",
		PID:        1234,
	}

	sink.Record(want)

	if got.Type != want.Type {
		t.Fatalf(
			"unexpected event type: got %q, want %q",
			got.Type,
			want.Type,
		)
	}

	if got.WorkloadID != want.WorkloadID {
		t.Fatalf(
			"unexpected workload ID: got %q, want %q",
			got.WorkloadID,
			want.WorkloadID,
		)
	}

	if got.PID != want.PID {
		t.Fatalf(
			"unexpected PID: got %d, want %d",
			got.PID,
			want.PID,
		)
	}
}
