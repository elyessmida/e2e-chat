// Package framing provides simple length-prefixed frame read/write helpers.
//
// Frame format on the wire:
//
//	[4 bytes big-endian uint32: payload length] [N bytes: payload]
package framing

import (
	"encoding/binary"
	"fmt"
	"io"
)

const maxFrameSize = 64 * 1024 * 1024 // 64 MiB safety cap

// WriteFrame writes a single length-prefixed frame to w.
// The length header is a 4-byte big-endian uint32 followed by the payload.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrameSize {
		return fmt.Errorf("framing: payload too large (%d bytes)", len(payload))
	}

	// Write 4-byte big-endian length header.
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("framing: write header: %w", err)
	}

	// Write payload.
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("framing: write payload: %w", err)
	}
	return nil
}

// ReadFrame reads a single length-prefixed frame from r and returns the payload.
// It returns io.EOF when the connection is cleanly closed before the header.
func ReadFrame(r io.Reader) ([]byte, error) {
	// Read 4-byte big-endian length header.
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		// Propagate io.EOF / io.ErrUnexpectedEOF directly so callers can
		// detect clean disconnects.
		return nil, err
	}

	size := binary.BigEndian.Uint32(header[:])
	if size > maxFrameSize {
		return nil, fmt.Errorf("framing: frame too large (%d bytes)", size)
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("framing: read payload: %w", err)
	}
	return payload, nil
}
