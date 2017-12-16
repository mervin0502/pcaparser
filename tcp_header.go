package pcaparser

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	FIN = 1  // 00 0001
	SYN = 2  // 00 0010
	RST = 4  // 00 0100
	PSH = 8  // 00 1000
	ACK = 16 // 01 0000
	URG = 32 // 10 0000

	DefaultTCPHeaderLen    = 20
	DefaultMaxTCPOffsetLen = 15
)

var (
	errMissingTCPHeader  = errors.New("missing tcp header")
	errTCPHeaderTooShort = errors.New("tcp header too short")
)

//TCPHeader
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8 // 4 bits
	Reserved   uint8 // 6 bits
	Ctrl       uint8 // 6 bits
	Window     uint16
	Checksum   uint16 // Kernel will set this if it's 0
	Urgent     uint16
	Options    []TCPOption
}

//TCPOption
type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

// Parse packet into TCPHeader structure
func ParseTCPHeader(data []byte) *TCPHeader {
	var tcp TCPHeader
	r := bytes.NewReader(data)
	binary.Read(r, binary.BigEndian, &tcp.SrcPort)
	binary.Read(r, binary.BigEndian, &tcp.DstPort)
	binary.Read(r, binary.BigEndian, &tcp.SeqNum)
	binary.Read(r, binary.BigEndian, &tcp.AckNum)

	var mix uint16
	binary.Read(r, binary.BigEndian, &mix)
	tcp.DataOffset = byte(mix >> 12)     // top 4 bits
	tcp.Reserved = byte(mix >> 6 & 0x3f) // 6 bits
	tcp.Ctrl = byte(mix & 0x3f)          // bottom 6 bits

	binary.Read(r, binary.BigEndian, &tcp.Window)
	binary.Read(r, binary.BigEndian, &tcp.Checksum)
	binary.Read(r, binary.BigEndian, &tcp.Urgent)
	return &tcp
}

//String
func (t *TCPHeader) String() string {
	return fmt.Sprintf("srcPort=%v dstPort=%v seqNum=%v ackNum=%v dataOffset=%v reserved=%v ctrl=%v window=%v checksum=%v urgent=%v", t.SrcPort, t.DstPort, t.SeqNum, t.AckNum, t.DataOffset, t.Reserved, t.Ctrl, t.Window, t.Checksum, t.Urgent)
}
