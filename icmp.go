package pcaparser

import "log"

//ICMP
type ICMP struct {
	Header *ICMPHeader
	Data   []byte
}

//ParseICMP
func ParseICMP(data []byte) *ICMP {
	i := new(ICMP)
	//header
	ih, err := ParseICMPHeader(data[0:DefaultICMPHeaderLen])
	if err != nil {
		log.Panicln(err)
	}
	i.Header = ih
	log.Println("icmp", ih.String())
	//data
	i.Data = data[DefaultICMPHeaderLen:]

	return i
}
