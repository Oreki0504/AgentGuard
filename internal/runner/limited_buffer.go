package runner

import "bytes"

const maxCapturedOutputBytes = 1 << 20

type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	received := len(p)

	// Calculate how many bytes we can still keep.
	remaining := b.limit - b.buf.Len()

	if remaining < 0 {
		remaining = 0
	}

	// Keep no more than the remaining capacity.
	toKeep := received
	if toKeep > remaining {
		toKeep = remaining
	}

	if toKeep > 0 {
		_, _ = b.buf.Write(p[:toKeep])
	}

	// Mark the output as truncated if any bytes were discarded.
	if toKeep < received {
		b.truncated = true
	}

	// Report all bytes as comsumed, including discarded bytes.
	return received, nil

}

func (b *limitedBuffer) String() string {
	return b.buf.String()
}
