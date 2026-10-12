package linux

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const MaxMessageSize = 4096

type Message struct {
	Version  int    `json:"version"`
	Type     string `json:"type"`
	Stage    string `json:"stage,omitempty"`
	Reason   string `json:"reason,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
}

func (m Message) Validate() error {
	if m.Version != Version {
		return fmt.Errorf("unsupported status version")
	}
	switch m.Type {
	case "READY":
		if m.Stage != "" || m.Reason != "" || m.ExitCode != nil {
			return fmt.Errorf("invalid READY")
		}
	case "ERROR":
		switch m.Stage {
		case "config", "namespace", "rootfs", "privilege", "exec", "protocol", "init":
		default:
			return fmt.Errorf("invalid error stage")
		}
		if m.Reason == "" || len(m.Reason) > 512 || m.ExitCode != nil {
			return fmt.Errorf("invalid ERROR")
		}
	case "EXIT":
		if m.ExitCode == nil || *m.ExitCode < 0 || *m.ExitCode > 255 || m.Stage != "" || m.Reason != "" {
			return fmt.Errorf("invalid EXIT")
		}
	default:
		return fmt.Errorf("unknown status type")
	}
	return nil
}

// Length framing prevents unbounded allocations and does not treat EOF as a
// successful exec. Unknown JSON fields and trailing JSON are rejected.
func writeFrame(w io.Writer, value any, limit int) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > limit {
		return fmt.Errorf("protocol frame too large")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if _, err = w.Write(header[:]); err != nil {
		return err
	}
	_, err = io.Copy(w, bytes.NewReader(data))
	return err
}

func readFrame(r io.Reader, value any, limit int) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return fmt.Errorf("read frame header: %w", err)
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > uint32(limit) {
		return fmt.Errorf("invalid frame length")
	}
	data := make([]byte, int(n))
	if _, err := io.ReadFull(r, data); err != nil {
		return fmt.Errorf("read frame: %w", err)
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing protocol data")
	}
	return nil
}

func WriteMessage(w io.Writer, m Message) error {
	if err := m.Validate(); err != nil {
		return err
	}
	return writeFrame(w, m, MaxMessageSize)
}

func ReadMessage(r io.Reader) (Message, error) {
	var m Message
	if err := readFrame(r, &m, MaxMessageSize); err != nil {
		return m, err
	}
	return m, m.Validate()
}

// Failure contains only a bounded trusted stage/reason, never argv or env.
type Failure struct{ Stage, Reason string }

func (e *Failure) Error() string { return "sandbox " + e.Stage + ": " + e.Reason }

func messageError(m Message) error { return &Failure{Stage: m.Stage, Reason: m.Reason} }
