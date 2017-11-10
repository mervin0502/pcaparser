package pcaparser

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	errMissingUDPHeader = errors.New("missing header")
)

const (
	DefaultUDPHeaderLen = 8
	minLength           = 8 //the udp packet length
)

//UDPHeader
type UDPHeader struct {
	SrcPort  uint16 `source port`
	DstPort  uint16 `destination port`
	Length   uint16 `UDP data length, minimum is 8(header length)`
	CheckSum uint16 `check code`
}

// Parse packet into TCPHeader structure
func ParseUDPHeader(data []byte) *UDPHeader {
	udp := &UDPHeader{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		CheckSum: binary.BigEndian.Uint16(data[6:8]),
	}
	return udp
}

//String
func (u *UDPHeader) String() string {
	return fmt.Sprintf("srcPort=%v dstPort=%v length=%v checksum=%v", u.SrcPort, u.DstPort, u.Length, u.CheckSum)
}
