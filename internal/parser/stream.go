package parser

import (
	"io"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/tcpassembly"
)

// stream is a one-direction TCP byte stream that decouples the assembler
// (which calls Reassembled from the single-threaded parse loop) from the
// consumer goroutine (which parses HTTP and may briefly block while reading a
// message body). Bytes are appended to a bounded buffer; Reassembled blocks
// only if the buffer is full, which applies natural backpressure without
// risking a deadlock — the consumer always drains, and FIN/RST eventually
// arrives because the parse loop is never stuck waiting on a consumer.
type stream struct {
	netFlow, transFlow gopacket.Flow
	isClient           bool

	mu      sync.Mutex
	cond    *sync.Cond
	buf     []byte // buffered payload not yet consumed
	closed  bool   // ReassemblyComplete seen (FIN/RST or flush)
	started bool   // first payload seen

	firstSeen     time.Time
	lastSeen      time.Time // timestamp of the last chunk buffered
	lastChunkSeen time.Time // timestamp of the chunk most recently consumed
	bytesTotal    int64
}

const maxStreamBuffer = 32 * 1024 * 1024 // 32 MiB per-direction backpressure cap

func newStream(netFlow, transFlow gopacket.Flow, isClient bool) *stream {
	s := &stream{netFlow: netFlow, transFlow: transFlow, isClient: isClient}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Reassembled implements tcpassembly.Stream. It appends available bytes and
// returns promptly, applying backpressure only when the per-direction buffer
// is full.
func (s *stream) Reassembled(reassembly []tcpassembly.Reassembly) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Append chunks; honor flow control if the buffer is already huge.
	for _, r := range reassembly {
		if len(r.Bytes) > 0 {
			for len(s.buf) > maxStreamBuffer && !s.closed {
				s.cond.Wait()
			}
			if s.closed {
				return
			}
			if !s.started {
				s.started = true
				s.firstSeen = r.Seen
			}
			s.lastSeen = r.Seen
			s.buf = append(s.buf, r.Bytes...)
			s.bytesTotal += int64(len(r.Bytes))
		}
		if r.End {
			// FIN/RST: mark end after the already-queued bytes are consumed.
			s.closed = true
		}
	}
	s.cond.Broadcast()
}

// ReassemblyComplete implements tcpassembly.Stream (called after FlushAll).
func (s *stream) ReassemblyComplete() {
	s.mu.Lock()
	s.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

// Read implements io.Reader, returning the next available buffered bytes.
func (s *stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.buf) == 0 && !s.closed {
		s.cond.Wait()
	}
	if len(s.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	// Timestamp of "now" in stream time = the last chunk's seen time.
	s.lastChunkSeen = s.lastSeen
	if len(s.buf) == 0 {
		// Wake any blocked Reassembled now that we have room.
		s.cond.Broadcast()
	}
	return n, nil
}

// markClosed is used by the connection when it gives up on a direction so the
// consumer unblocks.
func (s *stream) markClosed() {
	s.mu.Lock()
	s.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()
}
