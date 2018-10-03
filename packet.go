package pcaparser

import (
	"time"
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
	err := read(pcap.r, headerData, PacketHeaderLen)
	if err != nil {
		// glog.Errorf("read bytes error: %v", err)
		return nil, err
	}
	// glog.V(2).Infoln("read bytes")
	//header
	ph, err := ParsePacketHeader(pcap, headerData)
	if err != nil {
		// glog.Errorf("parse packet header error: %v", err)
		return nil, err
	}
	// glog.V(2).Infoln("parse packet header")
	p.Header = ph
	var data []byte
	var readDataLen int
	if ph.IncludedLen == 0 {
		p.Data = nil
		// glog.V(2).Infoln("p.Data=nil")
		return p, nil
	} else if ph.IncludedLen > pcap.Header.SnapLen {
		readDataLen = int(pcap.Header.SnapLen)
	} else {
		readDataLen = int(ph.IncludedLen)
	}
	// glog.V(2).Infof("len: snapLen=%d inclLen=%d origLen=%d", pcap.Header.SnapLen, ph.IncludedLen, ph.ActualLen)
	//data
	data = make([]byte, readDataLen)
	err = read(pcap.r, data, readDataLen)
	if err != nil {
		// glog.Errorf("read bytes error: %v", err)
		return p, err
	}
	// glog.V(2).Infoln("read bytes for data")
	//ethernet
	if len(data) < EthernetHeaderLen {
		p.Data = data
		return p, nil
	}
	e, err := ParseEthernet(data)
	// if err != nil {
	// 	glog.Errorf("parse ethernet error:%p,  %v", p, err)
	// 	// return p, err
	// }
	// glog.V(2).Infoln("parse packet data(ethernet)")
	p.Data = e
	return p, err
}

//Time
func (ph *Packet) Time() time.Time {
	return time.Unix(int64(ph.Header.TimestampOfSec), int64(ph.Header.TimestampOfMicrosec)*1000)
}
