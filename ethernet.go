package pcaparser

import "github.com/golang/glog"

type Ethernet struct {
	Header *EthernetHeader
	Data   interface{}
}

func ParseEthernet(data []byte) (*Ethernet, error) {
	e := &Ethernet{}
	// log.Println(len(data), EthernetHeaderLen)
	eh, err := ParseEthernetHeader(data[0:EthernetHeaderLen])
	if err != nil {
		glog.Errorln(err)
		return nil, err
	}

	e.Header = eh
	//data
	data = data[EthernetHeaderLen:]
	var dataObj interface{}
	switch eh.Type {
	case E_IPv4Type:
		dataObj, err = ParseIPv4(data)
		break
	default:
		dataObj = nil
		// log.Println(eh.Type.String())
	}
	if err != nil {
		return e, err
	}
	e.Data = dataObj
	return e, nil
}
