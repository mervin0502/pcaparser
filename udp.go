package pcaparser

//UDP
type UDP struct {
	Header *UDPHeader
	Data   []byte
}

//ParseUDP
func ParseUDP(data []byte) (*UDP, error) {
	t := &UDP{}
	//header
	if len(data) < DefaultUDPHeaderLen {
		return nil, errUDPHeaderTooShort
	}
	th := ParseUDPHeader(data[0:DefaultUDPHeaderLen])
	t.Header = th
	//data
	t.Data = data[DefaultUDPHeaderLen:]
	return t, nil
}
