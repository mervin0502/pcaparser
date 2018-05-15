package pcaparser

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

//const
const (
	PacketHeaderLen = 16
)

//errors
var (
	ErrPacketHeaderTooShort = errors.New("packet header too short.")
)

//PacketHeader
type PacketHeader struct {
	TimestampOfSec      uint32
	TimestampOfMicrosec uint32
	IncludedLen         uint32
	ActualLen           uint32

	bo binary.ByteOrder
}

//ParsePacketHeader
func ParsePacketHeader(p *Pcap, data []byte) (*PacketHeader, error) {
	if len(data) < PacketHeaderLen {
		return nil, ErrPacketHeaderTooShort
	}
	ph := &PacketHeader{
		TimestampOfSec:      p.ByteOrder.Uint32(data[0:4]),
		TimestampOfMicrosec: p.ByteOrder.Uint32(data[4:8]),
		IncludedLen:         p.ByteOrder.Uint32(data[8:12]),
		ActualLen:           p.ByteOrder.Uint32(data[12:16]),

		bo: p.ByteOrder,
	}

	return ph, nil
}

//String
func (p *PacketHeader) String() string {
	return fmt.Sprintf("timestamp(seconds)=%v timestamp(microseconds)=%v capLen=%v len=%v", p.TimestampOfSec, p.TimestampOfMicrosec, p.IncludedLen, p.ActualLen)
}

//Bytes
func (ph PacketHeader) Bytes() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, ph.bo, ph.TimestampOfSec)
	binary.Write(&buf, ph.bo, ph.TimestampOfMicrosec)
	binary.Write(&buf, ph.bo, ph.IncludedLen)
	binary.Write(&buf, ph.bo, ph.ActualLen)
	return buf.Bytes()
}
