package pcaparser

//UDP
type UDP struct {
	Header  *UDPHeader
	Data    []byte
	DataLen int
}

//ParseUDP
func ParseUDP(data []byte) (*UDP, error) {
	t := &UDP{}
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
