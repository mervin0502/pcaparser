package pcaparser

import (
	"encoding/binary"
	"io"
	"log"
	"os"
)

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

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
	// r := bufio.NewReader(fp)
	return NewPcapFromReader(fp)
}

//NewPcapFromReader
func NewPcapFromReader(r io.Reader) *Pcap {

	p := &Pcap{}
	p.r = r

	//get 24-bytes
	data := make([]byte, PcapHeaderLen)
	_, err := p.r.Read(data)
	if err != nil {
		log.Panicln(err)
	}
	p.Header, err = ParsePcapHeader(p, data)
	if err != nil {
		log.Panicln(err)
	}
	// p.headerData = data
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
func (p *Pcap) ReadPacket() (*Packet, error) {

	//ip data
	// glog.V(2).Infoln("read packet, go...")
	packet, err := ParsePacket(p)
	if err != nil {
		return nil, err
	}
	return packet, nil
}

//SplitWithDuration
// func (p *Pcap) SplitWithDuration(dstDir string, duration time.Duration) {

// }

//Close
func (p *Pcap) Close() {
	r, _ := p.r.(*os.File)
	r.Close()

}
