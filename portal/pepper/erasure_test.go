package pepper

import (
	"bytes"
	"testing"
)

func TestErasureReconstructsFromKOfNShards(t *testing.T) {
	t.Parallel()

	codec, err := NewReedSolomonCodec(4, 6, 32)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}
	source := [][]byte{
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		bytes.Repeat([]byte{0x04}, 32),
	}
	shards, err := codec.Encode(source)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	shards[1] = nil
	shards[5] = nil

	recovered, err := codec.Reconstruct(shards)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	for i := range source {
		if !bytes.Equal(source[i], recovered[i]) {
			t.Fatalf("recovered shard %d mismatch", i)
		}
	}
}

func TestErasureFailsWithFewerThanKShards(t *testing.T) {
	t.Parallel()

	codec, err := NewReedSolomonCodec(4, 6, 32)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}
	source := [][]byte{
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		bytes.Repeat([]byte{0x04}, 32),
	}
	shards, err := codec.Encode(source)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	shards[0] = nil
	shards[1] = nil
	shards[2] = nil

	if _, err := codec.Reconstruct(shards); err == nil {
		t.Fatal("expected reconstruction with fewer than k shards to fail")
	}
}
