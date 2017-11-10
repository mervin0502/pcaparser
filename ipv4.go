package pcaparser

import "log"

//IPv4
type IPv4 struct {
	Header *IPv4Header
	Data   interface{}
}

//ParseIPv4
func ParseIPv4(data []byte) (*IPv4, error) {

	i := new(IPv4)
	//header
	ih, err := ParseIPv4Header(data)
	if err != nil {
		log.Panicln(err)
	}
	i.Header = ih
	//data
	data = data[ih.Len:]
	switch ih.Protocol {
	case IP_ICMPType:
		i.Data = ParseICMP(data)
	case IP_TCPType:
		i.Data = ParseTCP(data)
		break
	case IP_UDPType:
		i.Data = ParseUDP(data)
		break
	// case IP_ICMPType:

	// 	break
	// case IP_IGMPType:

	// 	break
	// case IP_IPv4Type:

	// 	break
	// case IP_TCPType:
	// 	ParseTCP(data)
	// 	break
	// case IP_EGPType:

	// 	break
	// case IP_IGPType:

	// 	break
	// case IP_UDPType:

	// 	break
	// case IP_RDPType:

	// 	break
	// case IP_IPv6Type:

	// 	break
	default:
		// ParseTCP(data)
		break
	}
	return i, nil
}
