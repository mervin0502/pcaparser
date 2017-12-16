package pcaparser

import (
	"errors"
	"fmt"
	"time"
)

//const
const (
	PacketHeaderLen = 16
)

//errors
var (
	errPacketHeaderTooShort = errors.New("packet header too short.")
)

//PacketHeader
type PacketHeader struct {
	TimestampOfSec      uint32
	TimestampOfMicrosec uint32
	IncludedLen         uint32
	ActualLen           uint32
}

//ParsePacketHeader
func ParsePacketHeader(p *Pcap, data []byte) (*PacketHeader, error) {
	if len(data) < PacketHeaderLen {
		return nil, errPacketHeaderTooShort
	}
	ph := &PacketHeader{
		TimestampOfSec:      p.ByteOrder.Uint32(data[0:4]),
		TimestampOfMicrosec: p.ByteOrder.Uint32(data[4:8]),
		IncludedLen:         p.ByteOrder.Uint32(data[8:12]),
		ActualLen:           p.ByteOrder.Uint32(data[12:16]),
	}

	return ph, nil
}

//String
func (p *PacketHeader) String() string {
	return fmt.Sprintf("timestamp(seconds)=%v timestamp(microseconds)=%v capLen=%v len=%v", p.TimestampOfSec, p.TimestampOfMicrosec, p.IncludedLen, p.ActualLen)
}

//Date
func (ph *PacketHeader) Date() string {
	layout := "2006-01-02 15:04:05"
	return time.Unix(int64(ph.TimestampOfSec), int64(ph.TimestampOfMicrosec)).Format(layout)
}
