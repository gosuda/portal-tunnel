package overlay

import (
	"bytes"
	"sort"
	"sync"

	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	defaultPepperChunkSize = 192
	pepperPadToken         = "Packet"
)

// PepperTie stacks onion ciphertext into fixed-size chunks padded with the
// literal "Packet" pattern so that every hop observes uniform payloads.
// Chunks are pushed onto a LIFO stack and later reassembled using the stack
// order to restore the original plaintext.
type PepperTie struct {
	chunkSize int

	mu     sync.Mutex
	stack  [][]byte
	active [][]byte
}

func NewPepperTie(chunkSize int) *PepperTie {
	if chunkSize <= 0 {
		chunkSize = defaultPepperChunkSize
	}
	return &PepperTie{chunkSize: chunkSize}
}

func (t *PepperTie) ChunkSize() int {
	return t.chunkSize
}

func (t *PepperTie) Depth() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.stack)
}

// Wrap splits payload into padded chunks and records them on the tie stack.
func (t *PepperTie) Wrap(payload []byte) [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	chunks := t.chunkPayload(payload)
	t.stack = append(t.stack, chunks...)
	t.active = duplicateChunks(chunks)
	return duplicateChunks(chunks)
}

// Reassemble pops len(chunks) entries from the stack and reconstructs the
// original payload by reversing stack order and trimming pad bytes.
func (t *PepperTie) Reassemble(chunks [][]byte) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(chunks) == 0 || len(t.stack) < len(chunks) {
		return nil
	}
	start := len(t.stack) - len(chunks)
	popped := append([][]byte(nil), t.stack[start:]...)
	t.stack = t.stack[:start]
	return trimPepperPad(bytes.Join(reverseChunks(popped), nil))
}

func (t *PepperTie) State() types.PepperTieState {
	t.mu.Lock()
	defer t.mu.Unlock()
	return types.PepperTieState{
		ChunkSize:  t.chunkSize,
		StackDepth: len(t.stack),
	}
}

func (t *PepperTie) chunkPayload(payload []byte) [][]byte {
	if len(payload) == 0 {
		return nil
	}
	var chunks [][]byte
	for len(payload) > 0 {
		chunk := make([]byte, t.chunkSize)
		n := copy(chunk, payload)
		payload = payload[n:]
		if n < t.chunkSize {
			fill := []byte(pepperPadToken)
			pos := n
			for pos < t.chunkSize {
				for _, b := range fill {
					if pos >= t.chunkSize {
						break
					}
					chunk[pos] = b
					pos++
				}
			}
		}
		chunks = append(chunks, chunk)
	}
	return chunks
}

func reverseChunks(chunks [][]byte) [][]byte {
	for i := 0; i < len(chunks)/2; i++ {
		j := len(chunks) - 1 - i
		chunks[i], chunks[j] = chunks[j], chunks[i]
	}
	return chunks
}

func duplicateChunks(chunks [][]byte) [][]byte {
	if len(chunks) == 0 {
		return nil
	}
	out := make([][]byte, len(chunks))
	for i, chunk := range chunks {
		copyChunk := make([]byte, len(chunk))
		copy(copyChunk, chunk)
		out[i] = copyChunk
	}
	return out
}

func trimPepperPad(buf []byte) []byte {
	token := []byte(pepperPadToken)
	for len(buf) >= len(token) {
		if !bytes.HasSuffix(buf, token) {
			break
		}
		buf = buf[:len(buf)-len(token)]
	}
	return append([]byte(nil), buf...)
}

// PepperFlood distributes small payload bursts across the healthiest subset
// of nodes in a route by consulting their relay health metrics.
type PepperFlood struct {
	tie       *PepperTie
	maxBursts int
}

func NewPepperFlood(tie *PepperTie) *PepperFlood {
	if tie == nil {
		tie = NewPepperTie(defaultPepperChunkSize)
	}
	return &PepperFlood{tie: tie, maxBursts: 3}
}

func (f *PepperFlood) Plan(route []uint32, health map[uint32]policy.RelayHealth) types.PepperFloodPlan {
	if len(route) == 0 {
		return types.PepperFloodPlan{}
	}
	type scored struct {
		id      uint32
		latency float64
	}
	scores := make([]scored, 0, len(route))
	for _, id := range route {
		h := health[id]
		lat := h.PingLatencyMs
		if lat <= 0 {
			lat = 1000
		}
		if !h.Healthy {
			lat *= 10
		}
		if h.Fallback {
			lat *= 2
		}
		scores = append(scores, scored{id: id, latency: lat})
	}
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].latency < scores[j].latency
	})
	targets := make([]uint32, 0, f.maxBursts)
	for i := 0; i < len(scores) && i < f.maxBursts; i++ {
		targets = append(targets, scores[i].id)
	}
	if len(targets) == 0 {
		return types.PepperFloodPlan{}
	}
	burst := f.tie.chunkSize / len(targets)
	if burst <= 0 {
		burst = f.tie.chunkSize
	}
	return types.PepperFloodPlan{
		Targets:   targets,
		BurstSize: burst,
	}
}
