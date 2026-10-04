package workload

import (
	"testing"
	"time"
)

func TestSpecValidate(t *testing.T) {
	tests := []struct {
		name    string
		spec    Spec
		wantErr bool
	}{
		{
			name: "valid minimal spec",
			spec: Spec{
				Command: "echo",
			},
			wantErr: false,
		},
		{
			name: "valid resource limits",
			spec: Spec{
				Command: "echo",
				Timeout: 5 * time.Second,
				Resources: ResourceSpec{
					MemoryBytes:  512 * 1024 * 1024,
					MaxProcesses: 64,
				},
			},
			wantErr: false,
		},
		{
			name: "empty command",
			spec: Spec{
				Command: "",
			},
			wantErr: true,
		},
		{
			name: "negative timeout",
			spec: Spec{
				Command: "echo",
				Timeout: -1 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "negative memory limit",
			spec: Spec{
				Command: "echo",
				Resources: ResourceSpec{
					MemoryBytes: -1,
				},
			},
			wantErr: true,
		},
		{
			name: "negative process limit",
			spec: Spec{
				Command: "echo",
				Resources: ResourceSpec{
					MaxProcesses: -1,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.Validate()

			if tt.wantErr && err == nil {
				t.Fatal("expected validation error")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}
