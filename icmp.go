package pcaparser

import "log"

//ICMP
type ICMP struct {
	Header *ICMPHeader
	Data   []byte
}

//ParseICMP
func ParseICMP(data []byte) (*ICMP, error) {
	i := new(ICMP)
	if len(data) < DefaultICMPHeaderLen {
		return nil, ErrIPv4HeaderTooShort
	}
	//header
	ih, err := ParseICMPHeader(data[0:DefaultICMPHeaderLen])
	if err != nil {
		log.Panicln(err)
	}
	i.Header = ih
	// log.Println("icmp", ih.String())
	//data
	i.Data = data[DefaultICMPHeaderLen:]

	return i, nil
}
