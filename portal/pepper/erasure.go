package pepper

import (
	"errors"
	"fmt"

	"github.com/klauspost/reedsolomon"
)

var ErrInsufficientShards = errors.New("insufficient pepper shards for reconstruction")

type Codec interface {
	Encode(source [][]byte) ([][]byte, error)
	Reconstruct(shards [][]byte) ([][]byte, error)
	K() int
	N() int
	ShardSize() int
}

// ReedSolomonCodec is the production erasure-coding implementation for Pepper.
// It uses one narrow dependency, github.com/klauspost/reedsolomon, for audited
// fixed-size shard encoding and reconstruction only.
type ReedSolomonCodec struct {
	k         int
	n         int
	shardSize int
	codec     reedsolomon.Encoder
}

func NewReedSolomonCodec(k, n, shardSize int) (*ReedSolomonCodec, error) {
	switch {
	case k <= 0:
		return nil, errors.New("reed-solomon k must be greater than zero")
	case n <= 0:
		return nil, errors.New("reed-solomon n must be greater than zero")
	case k > n:
		return nil, errors.New("reed-solomon k cannot exceed n")
	case shardSize <= 0:
		return nil, errors.New("reed-solomon shard size must be greater than zero")
	}
	codec, err := reedsolomon.New(k, n-k)
	if err != nil {
		return nil, err
	}
	return &ReedSolomonCodec{
		k:         k,
		n:         n,
		shardSize: shardSize,
		codec:     codec,
	}, nil
}

func (r *ReedSolomonCodec) K() int         { return r.k }
func (r *ReedSolomonCodec) N() int         { return r.n }
func (r *ReedSolomonCodec) ShardSize() int { return r.shardSize }

func (r *ReedSolomonCodec) Encode(source [][]byte) ([][]byte, error) {
	if len(source) != r.k {
		return nil, fmt.Errorf("expected %d source shards, got %d", r.k, len(source))
	}
	shards := make([][]byte, r.n)
	for i := 0; i < r.k; i++ {
		if len(source[i]) != r.shardSize {
			return nil, fmt.Errorf("source shard %d has size %d, want %d", i, len(source[i]), r.shardSize)
		}
		shards[i] = append([]byte(nil), source[i]...)
	}
	for i := r.k; i < r.n; i++ {
		shards[i] = make([]byte, r.shardSize)
	}
	if err := r.codec.Encode(shards); err != nil {
		return nil, err
	}
	return shards, nil
}

func (r *ReedSolomonCodec) Reconstruct(shards [][]byte) ([][]byte, error) {
	if len(shards) != r.n {
		return nil, fmt.Errorf("expected %d shards, got %d", r.n, len(shards))
	}
	present := 0
	work := make([][]byte, r.n)
	for i := range shards {
		if shards[i] == nil {
			work[i] = nil
			continue
		}
		if len(shards[i]) != r.shardSize {
			return nil, fmt.Errorf("shard %d has size %d, want %d", i, len(shards[i]), r.shardSize)
		}
		work[i] = append([]byte(nil), shards[i]...)
		present++
	}
	if present < r.k {
		return nil, ErrInsufficientShards
	}
	if err := r.codec.ReconstructData(work); err != nil {
		return nil, err
	}
	out := make([][]byte, r.k)
	for i := 0; i < r.k; i++ {
		if work[i] == nil {
			return nil, fmt.Errorf("data shard %d could not be reconstructed", i)
		}
		out[i] = append([]byte(nil), work[i]...)
	}
	return out, nil
}
