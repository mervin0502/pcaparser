package pcaparser

import (
	"encoding/binary"
	"io"
	"log"
	"os"
)

type Pcap struct {
	Header *PcapHeader

	ByteOrder  binary.ByteOrder
	r          io.Reader
	headerData []byte
}

//NewPcapFromFile
func NewPcapFromFile(file string) *Pcap {
	fp, err := os.OpenFile(file, os.O_RDONLY, 0666)
	if err != nil {
		log.Panicln(err)
	}
	return NewPcapFromReader(fp)
}

//NewPcapFromReader
func NewPcapFromReader(r io.Reader) *Pcap {

	p := &Pcap{}
	p.ByteOrder = binary.LittleEndian
	p.r = r

	//get 24-bytes
	data := make([]byte, PcapHeaderLen)
	_, err := p.r.Read(data)
	if err != nil {
		log.Panicln(err)
	}
	p.headerData = data
	return p
}

//ReadHeader
func (p *Pcap) ReadHeader() (*PcapHeader, error) {

	//parser
	h, err := ParsePcapHeader(p, p.headerData)
	p.Header = h

	// log.Println(h.String())
	return h, err
}

//ReadPacket
func (p *Pcap) ReadPacket() *Packet {

	//ip data
	packet, err := ParsePacket(p)
	if err != nil {
		if err == io.EOF {
			log.Println("done")
			return nil
		}
		log.Panicln(err)
	}
	return packet

}
