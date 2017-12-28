package pcaparser

import (
	"fmt"

	"github.com/golang/glog"
)

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
		glog.Errorln(err)
		return nil, err
	}
	i.Header = ih
	//data
	data = data[ih.Len:]
	switch ih.Protocol {
	case IP_ICMPType:
		i.Data, err = ParseICMP(data)
	case IP_TCPType:
		i.Data, err = ParseTCP(data)
		break
	case IP_UDPType:
		i.Data, err = ParseUDP(data)
		break
	// case IP_ICMPType:

	// 	break
	// case IP_IGMPType:

	// 	break
	// case IP_IPv4Type:

	// 	break
	default:
		// ParseTCP(data)
		break
	}
	return i, err
}

func (i *IPv4) String() string {
	return fmt.Sprintf("%s \n\n %s", i.Header.String(), i.Data)
}
