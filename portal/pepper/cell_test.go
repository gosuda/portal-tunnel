package pepper

import (
	"bytes"
	"reflect"
	"testing"
)

func TestPepperCellSerializedSize(t *testing.T) {
	t.Parallel()

	var cell Cell
	encoded, err := cell.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal cell: %v", err)
	}
	if got, want := len(encoded), DefaultCellSize; got != want {
		t.Fatalf("encoded size = %d, want %d", got, want)
	}
}

func TestPepperCellHasNoLengthField(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeOf(Cell{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if name == "Length" || name == "CellLen" || name == "Len" {
			t.Fatalf("unexpected length field %q present in Cell", name)
		}
	}
}

func TestOuterCellSerializationContainsOnlyOuterHeaderAndPayload(t *testing.T) {
	t.Parallel()

	var cell Cell
	cell.Version = Version1
	cell.SuiteID = SuiteV1
	cell.CircuitID = 0x0102030405060708
	copy(cell.HopTag[:], bytes.Repeat([]byte{0xAB}, len(cell.HopTag)))

	encoded, err := cell.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal cell: %v", err)
	}
	if got, want := len(encoded), CellHeaderSize+len(cell.Payload); got != want {
		t.Fatalf("encoded size = %d, want %d", got, want)
	}

	fieldNames := []string{
		"BundleID",
		"StreamID",
		"ShardIndex",
		"MessageLength",
		"UnpaddedLength",
	}
	typ := reflect.TypeOf(Cell{})
	for _, forbidden := range fieldNames {
		if _, ok := typ.FieldByName(forbidden); ok {
			t.Fatalf("unexpected forbidden field %q present in Cell", forbidden)
		}
	}
}
