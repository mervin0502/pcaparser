package pcaparser

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

const (
	EthernetHeaderLen = 14
)

var (
	errEthernetHeaderTooShort = errors.New("ethernet header too short.")
)

type EtherType uint16

const (
	E_IPv4Type          EtherType = 0x0800
	E_ARPType           EtherType = 0x0806
	E_RARPType          EtherType = 0x8035
	E_EthertalkType     EtherType = 0x809D
	E_AARPType          EtherType = 0x80F3
	E_IEE802QType       EtherType = 0x8100
	E_NovellIPXType     EtherType = 0x8137
	E_NovellType        EtherType = 0x8138
	E_Ipv6Type          EtherType = 0x86DD
	E_CobraNetType      EtherType = 0x8819
	E_IEE902ADType      EtherType = 0x88a8
	E_MPLSUnicastType   EtherType = 0x8847
	E_MPLSMulticastType EtherType = 0x8848
	E_PPOEDiscoveryType EtherType = 0x8863
	E_PPOESessionType   EtherType = 0x8864
	E_IEEE802XType      EtherType = 0x888E
	E_HyperSCSIType     EtherType = 0x889A
	E_ATAType           EtherType = 0x88A2
	E_EtherCATType      EtherType = 0x88A4
	E_SERCOSIIIType     EtherType = 0x88CD
	E_MEF8Type          EtherType = 0x88D8
	E_IEEE802AEType     EtherType = 0x88E5
	E_FibreType         EtherType = 0x8906
	E_FCoEType          EtherType = 0x8914
	E_QinQType          EtherType = 0x9100
	E_LLTType           EtherType = 0xCAFE
)

//EthernetHeader
type EthernetHeader struct {
	// Preamble uint64 //8 bytes
	DstMac net.HardwareAddr //6 bytes
	SrcMac net.HardwareAddr //6 bytes
	Type   EtherType        //2 bytes 0x8000:ip 0x8060:arp
	// Data   []byte //46~1500 bytes
	// FCS      uint32 //4b ytes
}

//ParserEthernetHeader
func ParseEthernetHeader(data []byte) (*EthernetHeader, error) {
	if len(data) < EthernetHeaderLen {
		return nil, errEthernetHeaderTooShort
	}
	e := &EthernetHeader{
		DstMac: data[0:6],
		SrcMac: data[6:12],
		Type:   EtherType(binary.BigEndian.Uint16(data[12:14])),
	}
	return e, nil
}

//String
func (e *EthernetHeader) String() string {
	return fmt.Sprintf("dstMac=%v srcMac=%v type=%v", e.DstMac, e.SrcMac, e.Type.Int())
}

//String
func (e EtherType) String() string {
	var out string
	// log.Println(uint16(e), uint16(E_IPv4Type))
	switch e {
	case E_IPv4Type:
		out = "Internet Protocol, Version 4 (IPv4)"
		break
	case E_ARPType:
		out = "Address Resolution Protocol (ARP)"
		break
	case E_RARPType:
		out = "Reverse Address Resolution Protocol (RARP)"
		break
	case E_EthertalkType:
		out = "AppleTalk (Ethertalk)"
		break
	case E_AARPType:
		out = "AppleTalk Address Resolution Protocol (AARP)"
		break
	case E_IEE802QType:
		out = "IEEE 802.1Q-tagged frame"
		break
	case E_NovellIPXType:
		out = "Novell IPX (alt)"
		break
	case E_NovellType:
		out = "Novell"
		break
	case E_Ipv6Type:
		out = "Internet Protocol, Version 6 (IPv6)"
		break
	case E_CobraNetType:
		out = "CobraNet"
		break
	case E_IEE902ADType:
		out = "Provider Bridging (IEEE 802.1ad)"
		break
	case E_MPLSUnicastType:
		out = "MPLS unicast"
		break
	case E_MPLSMulticastType:
		out = "MPLS multicast"
		break
	case E_PPOEDiscoveryType:
		out = "PPPoE Discovery Stage"
		break
	case E_PPOESessionType:
		out = "PPPoE Session Stage"
		break
	case E_IEEE802XType:
		out = "EAP over LAN (IEEE 802.1X)"
		break
	case E_HyperSCSIType:
		out = "HyperSCSI (SCSI over Ethernet)"
		break
	case E_ATAType:
		out = "ATA over Ethernet"
		break
	case E_EtherCATType:
		out = "EtherCAT Protocol"
		break
	case E_SERCOSIIIType:
		out = "SERCOS-III"
		break
	case E_MEF8Type:
		out = "Circuit Emulation Services over Ethernet (MEF-8)"
		break
	case E_IEEE802AEType:
		out = "MAC security (IEEE 802.1AE)"
		break
	case E_FibreType:
		out = "Fibre Channel over Ethernet"
		break
	case E_FCoEType:
		out = "FCoE initialization protocol"
		break
	case E_QinQType:
		out = "Q-in-Q"
		break
	case E_LLTType:
		out = "Veritas Low Latency Transport (LLT)"
		break
	default:
		out = strconv.FormatUint(uint64(uint16(e)), 10)
	}
	return out
}

//Int
func (e EtherType) Int() int {
	return int(uint16(e))
}
