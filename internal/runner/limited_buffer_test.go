package runner

import "testing"

func TestLimitedBuffer(t *testing.T) {
	b := limitedBuffer{limit: 5}

	tests := []struct {
		input     string
		want      string
		truncated bool
	}{
		{"abc", "abc", false},
		{"de", "abcde", false},
		{"fgh", "abcde", true},
		{"more", "abcde", true},
	}

	for _, tc := range tests {
		n, err := b.Write([]byte(tc.input))

		if err != nil || n != len(tc.input) {
			t.Fatalf(
				"Write(%q) = (%d, %v)",
				tc.input, n, err,
			)
		}

		if b.String() != tc.want ||
			b.truncated != tc.truncated {
			t.Fatalf(
				"after %q: got %q, truncated=%t",
				tc.input, b.String(), b.truncated,
			)
		}
	}
}

func TestLimitedBufferZeroLimit(t *testing.T) {
	b := limitedBuffer{limit: 0}

	n, err := b.Write([]byte("abc"))

	if err != nil || n != 3 ||
		b.String() != "" || !b.truncated {
		t.Fatalf(
			"unexpected result: n=%d err=%v output=%q truncated=%t",
			n, err, b.String(), b.truncated,
		)
	}
}

func TestLimitedBufferEmptyWrite(t *testing.T) {
	b := limitedBuffer{limit: 0}

	n, err := b.Write(nil)

	if err != nil || n != 0 || b.truncated {
		t.Fatalf(
			"unexpected result: n=%d err=%v truncated=%t",
			n, err, b.truncated,
		)
	}
}
