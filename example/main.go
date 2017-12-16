package main

import (
	"io"
	"log"

	"mervin.me/pcaparser"
)

func main() {
	extractTime()
}

func extractTime() {
	file := "/home/mervin/Work/07Data/Internet-Traffic/ISOT_Botnet/ISOT_Botnet_DataSet_2010.pcap"
	pcap := pcaparser.NewPcapFromFile(file)
	// pcap.ReadHeader()
	// var packet *pcaparser.Packet
	for {
		// var err error
		packet, err := pcap.ReadPacket()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				log.Panicln(err)
			}
		}
		log.Println(packet.Header.Date())
		// header := packet.Header
		// log.Println(header)
		// ethernet, ok := packet.Data.(*pcaparser.Ethernet)
		// if !ok {
		// 	continue
		// }
		// ethernetHeader := ethernet.Header
		// log.Println(ethernetHeader)
		// ipv4, ok := ethernet.Data.(*pcaparser.IPv4)
		// if !ok {
		//  continue
		// }
		// // log.Println(ipv4)
		// ipv4Header := ipv4.Header
		// ipv4Data := reflect.ValueOf(ipv4.Data).Elem()
		// switch ipv4Data.Type().String() {
		// case "pcaparser.TCP":
		//  tcpHeader := ipv4Data.FieldByName("Header")
		//  log.Println("tcp", tcpHeader.Elem().FieldByName("SrcPort"), tcpHeader.Elem().FieldByName("DstPort"))
		//  break
		// case "pcaparser.UDP":
		//  udpHeader := ipv4Data.FieldByName("Header")
		//  log.Println("udp", udpHeader.Elem().FieldByName("SrcPort"), udpHeader.Elem().FieldByName("DstPort"))
		//  break
		// default:

		// }
		// break
		// log.Println(ipv4Header)
	}

}
