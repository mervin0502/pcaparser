package pcaparser

//UDP
type UDP struct {
	Header  *UDPHeader
	Data    []byte
	DataLen int

	raw []byte
}

//ParseUDP
func ParseUDP(data []byte) (*UDP, error) {
	t := &UDP{}
	t.raw = data
	//header
	if len(data) < DefaultUDPHeaderLen {
		if len(data) >= 4 {
			th := ParseUDPHeader(append(data[0:4], byte(0), byte(0), byte(0), byte(0)))
			t.Header = th
			return t, ErrUDPHeaderOnlyWithPort
		} else {
			return t, ErrUDPHeaderTooShort
		}
	}
	th := ParseUDPHeader(data[0:DefaultUDPHeaderLen])
	t.Header = th
	//data
	t.DataLen = len(data[DefaultUDPHeaderLen:])
	t.Data = data[DefaultUDPHeaderLen:]
	return t, nil
}
//HeaderBytes return the bytes of tcp header
func (t *UDP) HeaderBytes() []byte {
	return t.raw[0:DefaultUDPHeaderLen]
}


//DataBytes return the bytes of tcp data
func (t *UDP) DataBytes() []byte {
	return t.raw[DefaultUDPHeaderLen:]
}
