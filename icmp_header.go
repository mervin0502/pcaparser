package pcaparser

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	DefaultICMPHeaderLen = 8
)

var (
	errICMPHeaderTooShort = errors.New("icmp header too short.")
)

//ICMPHeader
type ICMPHeader struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Other    [4]byte
}

//ParseICMPHeader
func ParseICMPHeader(data []byte) (*ICMPHeader, error) {
	if len(data) < DefaultICMPHeaderLen {
		return nil, errICMPHeaderTooShort
	}
	i := &ICMPHeader{
		Type:     uint8(data[0]),
		Code:     uint8(data[1]),
		Checksum: binary.BigEndian.Uint16(data[2:4]),
		Other:    [4]byte{data[4], data[5], data[6], data[7]},
	}
	return i, nil
}

//String
func (i *ICMPHeader) String() string {
	return fmt.Sprintf("type=%v code=%v checksum=%v", i.Type, i.Code, i.Checksum)
}
