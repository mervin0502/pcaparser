
## A parser tool of `PCAP` file

The **pcapaser** is a pure golang implementation of the [pcap file](http://wiki.wireshark.org/Development/LibpcapFileFormat). Now it can parse the ipv4, tcp, udp, and icmp protocols.


## Usage

```golang
import (
    "log"
    "reflect"

    "mervin.me/pcaparser"
)
func main() {
    file := "xxx.pcap"
    pcap := pcaparser.NewPcapFromFile(file)
    // pcap.ReadHeader()
    var packet *pcaparser.Packet
    for {
        // var err error
        packet = pcap.ReadPacket()
        header := packet.Header
        log.Println(header)
        ethernet, ok := packet.Data.(*pcaparser.Ethernet)
        if !ok {
            continue
        }
        ethernetHeader := ethernet.Header
        log.Println(ethernetHeader)
        ipv4, ok := ethernet.Data.(*pcaparser.IPv4)
        if !ok {
            continue
        }
        // log.Println(ipv4)
        ipv4Header := ipv4.Header
        ipv4Data := reflect.ValueOf(ipv4.Data).Elem()
        switch ipv4Data.Type().String() {
        case "pcaparser.TCP":
            tcpHeader := ipv4Data.FieldByName("Header")
            log.Println("tcp", tcpHeader.Elem().FieldByName("SrcPort"), tcpHeader.Elem().FieldByName("DstPort"))
            break
        case "pcaparser.UDP":
            udpHeader := ipv4Data.FieldByName("Header")
            log.Println("udp", udpHeader.Elem().FieldByName("SrcPort"), udpHeader.Elem().FieldByName("DstPort"))
            break
        default:

        }
        log.Println(ipv4Header)
    }

}

```

For further examples, see the [API documentation](http://godoc.org/github.com/mervin0502/pcaparser).

