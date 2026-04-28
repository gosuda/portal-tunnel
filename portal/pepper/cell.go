package pepper

import (
	"encoding/binary"
	"errors"
)

const (
	CellHeaderSize  = 1 + 1 + 2 + 8 + 16
	CellPayloadSize = DefaultCellSize - CellHeaderSize
)

var ErrInvalidCellSize = errors.New("invalid pepper cell size")

type Cell struct {
	Version   uint8
	Flags     uint8
	SuiteID   uint16
	CircuitID uint64
	HopTag    [16]byte
	Payload   [CellPayloadSize]byte
}

func (c Cell) MarshalBinary() ([]byte, error) {
	if c.Version == 0 {
		c.Version = Version1
	}
	if c.SuiteID == 0 {
		c.SuiteID = SuiteV1
	}
	buf := make([]byte, DefaultCellSize)
	buf[0] = c.Version
	buf[1] = c.Flags
	binary.BigEndian.PutUint16(buf[2:4], c.SuiteID)
	binary.BigEndian.PutUint64(buf[4:12], c.CircuitID)
	copy(buf[12:28], c.HopTag[:])
	copy(buf[28:], c.Payload[:])
	return buf, nil
}

func (c *Cell) UnmarshalBinary(data []byte) error {
	if len(data) != DefaultCellSize {
		return ErrInvalidCellSize
	}
	c.Version = data[0]
	c.Flags = data[1]
	c.SuiteID = binary.BigEndian.Uint16(data[2:4])
	c.CircuitID = binary.BigEndian.Uint64(data[4:12])
	copy(c.HopTag[:], data[12:28])
	copy(c.Payload[:], data[28:])
	return nil
}
