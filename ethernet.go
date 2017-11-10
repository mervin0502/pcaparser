package pcaparser

import "log"

type Ethernet struct {
	Header *EthernetHeader
	Data   interface{}
}

func ParseEthernet(data []byte) (*Ethernet, error) {
	e := &Ethernet{}
	eh, err := ParseEthernetHeader(data[0:EthernetHeaderLen])
	if err != nil {
		log.Panicln(err)
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
		log.Println(eh.Type.String())
	}
	if err != nil {
		return nil, err
	}
	e.Data = dataObj
	return e, nil
}
