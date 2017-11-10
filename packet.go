package pcaparser

import (
	"io"
	"log"
)

//Packet
type Packet struct {
	Header *PacketHeader
	Data   interface{}
}

//ParsePacket
func ParsePacket(pcap *Pcap) (*Packet, error) {

	p := new(Packet)
	//get 14-bytes
	headerData := make([]byte, PacketHeaderLen)
	_, err := pcap.r.Read(headerData)
	if err != nil {
		if err == io.EOF {
			return nil, err
		}
		log.Panicln(err)
	}

	//header
	ph, err := ParsePacketHeader(pcap, headerData)
	if err != nil {
		log.Panicln(err)
	}
	p.Header = ph

	//data
	data := make([]byte, ph.Len)
	_, err = pcap.r.Read(data)
	if err != nil {
		log.Panicln(err)
	}
	//ethernet
	e, err := ParseEthernet(data)
	if err != nil {
		log.Panicln(err)
	}
	p.Data = e
	return p, nil
}
