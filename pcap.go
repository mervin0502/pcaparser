package pcaparser

import (
	"encoding/binary"
	"io"
	"os"
	"reflect"

	"github.com/golang/glog"
)

// func init() {
// 	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
// }

type Pcap struct {
	Header *PcapHeader

	ByteOrder binary.ByteOrder
	r         io.Reader
	// reader     *bufio.Reader
	headerData []byte
}

//NewPcapFromFile
func NewPcapFromFile(file string) *Pcap {
	fp, err := os.OpenFile(file, os.O_RDONLY, 0666)
	if err != nil {
		glog.Fatalln(err)
	}
	// r := bufio.NewReader(fp)
	return NewPcapFromReader(fp)
}

//NewPcapFromReader
func NewPcapFromReader(r io.Reader) *Pcap {

	p := &Pcap{}
	p.r = r
	// p.reader = bufio.NewReader(r)

	//get 24-bytes
	data := make([]byte, PcapHeaderLen)
	_, err := p.r.Read(data)
	if err != nil {
		glog.Fatalln(err)
	}
	p.Header, err = ParsePcapHeader(p, data)
	if err != nil {
		glog.Fatalln(err)
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
		return packet, err
	}
	return packet, nil
}

//SplitWithDuration
// func (p *Pcap) SplitWithDuration(dstDir string, duration time.Duration) {

// }
//Reader return the io.reader of pcap file
func (p *Pcap) Reader() io.Reader {
	return p.r
}

//Reset
func (p *Pcap) Reset() {
	_t := reflect.TypeOf(p.r)
	_v := reflect.ValueOf(p.r)
	switch _t.String() {
	case "*os.File":
		_v0 := reflect.Value(reflect.ValueOf(int64(PcapHeaderLen)))
		_v1 := reflect.Value(reflect.ValueOf(int(0)))
		_v.MethodByName("Seek").Call([]reflect.Value{_v0, _v1})
		break
	default:
		glog.Fatalln("Reset wrong...")
	}
	// glog.V(2).Infof("#%v#%v#%v#%v", _t, _t.Kind().String(), _t.Name(), _t.String())
}

//Close
func (p *Pcap) Close() {
	r, _ := p.r.(*os.File)
	r.Close()
}
