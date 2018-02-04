package pcaparser

import (
	"encoding/binary"
	"io"
	"os"

	"github.com/golang/glog"
)

//FilterByIPv4Protocol
func (p *Pcap) FilterByIPv4Protocol(dstFile string, prot IPv4Protocol) {
	var writer *os.File
	var packetData []byte
	var readDataLen int
	var err error

	writer, err = os.OpenFile(dstFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		glog.Errorln(err)
	}
	writer.Write(p.Header.Bytes())

	defer writer.Close()
Loop:
	for {
		//get 14-bytes
		packetHeaderData := make([]byte, PacketHeaderLen)
		err := read(p.r, packetHeaderData, PacketHeaderLen)
		if err != nil {
			if err == io.EOF {
				break
			}
			glog.Warningf("%v", err)
			break Loop
		}
		ph, err := ParsePacketHeader(p, packetHeaderData)
		if err != nil {
			glog.Errorln(err)
		}

		if ph.IncludedLen > p.Header.SnapLen {
			readDataLen = int(p.Header.SnapLen)
		} else {
			readDataLen = int(ph.IncludedLen)
		}
		packetData = make([]byte, readDataLen)
		err = read(p.r, packetData, readDataLen)
		if err != nil {
			glog.Errorln(err)
		}
		//packetData
		// ethernet header(14byte) > ipv4 header(20bytes)
		//ethernet: 12:14(0x0800) > ip header 9
		if len(packetData) < EthernetHeaderLen+IPv4HeaderLen {
			continue
		}
		if EtherType(binary.BigEndian.Uint16(packetData[12:14])) == E_IPv4Type &&
			IPv4Protocol(packetData[23]) == prot {
			writer.Write(append(packetHeaderData, packetData...))
		}
	}
}

//
func (p *Pcap) FilterByPort(dstFile string, port uint16) {
	ports := []uint16{port}
	p.FilterByPorts(dstFile, ports)
}
func (p *Pcap) FilterByPorts(dstFile string, ports []uint16) {
	var writer *os.File
	var packetData []byte
	var ipData []byte
	var readDataLen int
	var err error
	var srcPort uint16
	var dstPort uint16

	writer, err = os.OpenFile(dstFile, os.O_CREATE|os.O_RDWR, 0775)
	if err != nil {
		glog.Errorln(err)
	}
	writer.Write(p.Header.Bytes())

	defer writer.Close()
	// return
Loop:
	for {
		//get 14-bytes
		// glog.V(2).Infoln("new packet")
		packetHeaderData := make([]byte, PacketHeaderLen)
		err := read(p.r, packetHeaderData, PacketHeaderLen)
		if err != nil {
			if err == io.EOF {
				break
			}
			glog.Warningf("%v", err)
			break Loop
		}
		// glog.V(2).Infoln("new packet1")
		ph, err := ParsePacketHeader(p, packetHeaderData)
		if err != nil {
			glog.Errorln(err)
		}
		// glog.V(2).Infoln("new packet")
		// glog.V(2).Infof("%v", ph.Date())
		if ph.IncludedLen > p.Header.SnapLen {
			readDataLen = int(p.Header.SnapLen)
		} else {
			readDataLen = int(ph.IncludedLen)
		}
		// glog.V(2).Infof("%d", readDataLen)
		packetData = make([]byte, readDataLen)
		err = read(p.r, packetData, readDataLen)
		if err != nil {
			glog.Errorln(err)
		}
		// glog.V(2).Infoln("new packet 3")
		//packetData
		// ethernet header(14byte) > ipv4 header(20bytes)
		//ethernet: 12:14(0x0800) > ip header 9
		if len(packetData) < EthernetHeaderLen+IPv4HeaderLen {
			glog.V(2).Infof("packetData len(%d) is less EthernetHeaderLen+IPv4HeaderLen", len(packetData))
			continue
		}
		if EtherType(binary.BigEndian.Uint16(packetData[12:14])) != E_IPv4Type {
			// glog.V(2).Infof("format", ...)
			// glog.V(2).Infof("%v %#x is not ipv4", EtherType(binary.BigEndian.Uint16(packetData[12:14])), packetData[12:14])
			continue
		}
		if IPv4Protocol(packetData[23]) != IP_UDPType &&
			IPv4Protocol(packetData[23]) != IP_TCPType {
			// glog.V(2).Infof("%v is not tcp or udp", IPv4Protocol(packetData[23]))
			continue
		}
		hdrlen := int(packetData[14]&0x0F) << 2
		ipData = packetData[EthernetHeaderLen+hdrlen:]
		if len(ipData) < 4 {
			continue
		}
		srcPort = binary.BigEndian.Uint16(ipData[0:2])
		dstPort = binary.BigEndian.Uint16(ipData[2:4])
		// glog.V(2).Infof("%d %d %d", IPv4Protocol(packetData[23]), srcPort, dstPort)
	Loop1:
		for _, port := range ports {
			if srcPort == port || dstPort == port {
				writer.Write(append(packetHeaderData, packetData...))
				break Loop1
			}
		}

	}
}
