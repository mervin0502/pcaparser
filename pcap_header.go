package pcaparser

import (
	"encoding/binary"
	"errors"
	"fmt"
)

//const
const (
	PcapHeaderLen = 24

	DefaultPcapMagic = 0xa1b2c3d4
	DefaultPcapMajor = 0x02
	DefaultPcapMinor = 0x04
)

//errors
var (
	errPcapHeaderTooShort = errors.New("pcap header too short.")
	errPcapHeaderMagic    = errors.New("not the pcap file based on magic field")
)

//PcapHeader
type PcapHeader struct {
	Magic    uint32 // default 0xa1b2c3d4
	Major    uint16 // 0x02
	Minor    uint16 //0x04
	ThisZone uint32 //0x0
	SigFigs  uint32 //0x0
	SnapLen  uint32
	LinkType uint32
}

//ParsePcapHeader
func ParsePcapHeader(p *Pcap, data []byte) (*PcapHeader, error) {
	if len(data) < PcapHeaderLen {
		return nil, errPcapHeaderTooShort
	}
	magic := binary.LittleEndian.Uint32(data[0:4])
	/*
	   magicNumber  = 0xa1b2c3d4
	   magicNumberR = 0xd4c3b2a1

	   magicNumberNano  = 0xa1b23c4d
	   magicNumberNanoR = 0x4d3cb2a1
	*/
	// log.Printf("%#x", data[0:4])
	switch magic {
	case 0xd4c3b2a1:
		p.ByteOrder = binary.BigEndian
		break
	case 0x4d3cb2a1:
		p.ByteOrder = binary.BigEndian
		break
	case 0xb2ad4c3:
		p.ByteOrder = binary.LittleEndian
	default:
		p.ByteOrder = binary.LittleEndian

	}

	// if magic != DefaultPcapMagic {
	// 	return nil, errPcapHeaderMagic
	// }
	ph := &PcapHeader{
		Magic:    magic,
		Major:    p.ByteOrder.Uint16(data[4:6]),
		Minor:    p.ByteOrder.Uint16(data[6:8]),
		ThisZone: p.ByteOrder.Uint32(data[8:12]),
		SigFigs:  p.ByteOrder.Uint32(data[12:16]),
		SnapLen:  p.ByteOrder.Uint32(data[16:20]),
		LinkType: p.ByteOrder.Uint32(data[20:24]),
	}

	return ph, nil
}

//String
func (p *PcapHeader) String() string {
	return fmt.Sprintf("magic=%v major=%v minor=%v thisZone=%v sigFigs=%v snaplen=%v linkType=%v", p.Magic, p.Major, p.Minor, p.ThisZone, p.SigFigs, p.SnapLen, p.LinkType)
}
