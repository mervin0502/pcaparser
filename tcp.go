package pcaparser

//TCP
type TCP struct {
	Header  *TCPHeader
	Data    interface{}
	DataLen int

	raw []byte
}

type TCPType uint16

const (
	TCP_HTTP_TYPE TCPType = 80
)

//ParseTCP
func ParseTCP(data []byte) (*TCP, error) {
	t := &TCP{}
	t.raw = data
	dataLen := len(data)
	if dataLen < DefaultTCPHeaderLen {
		if dataLen >= 4 {
			th := ParseTCPHeader(append(data[0:4], make([]byte, DefaultTCPHeaderLen-4)...))
			t.Header = th
			return t, ErrTCPHeaderOnlyWithPort
		} else {
			return nil, ErrTCPHeaderTooShort
		}

	}
	//header
	th := ParseTCPHeader(data[0:DefaultTCPHeaderLen])
	t.Header = th
	//options
	//Todo: tcp options
	var tcpHeaderLen int
	tcpHeaderLen = int(th.DataOffset * 4)
	if tcpHeaderLen > dataLen {
		tcpHeaderLen = dataLen
	}
	if tcpHeaderLen > DefaultTCPHeaderLen {
		t.Header.Options = ParseTCPOptions(data[DefaultTCPHeaderLen:tcpHeaderLen])
	}
	//data
	t.DataLen = len(data[tcpHeaderLen:])
	var err error
	switch TCPType(th.DstPort) {
	case TCP_HTTP_TYPE:
		// glog.V(2).Infoln(th.DataOffset*4, len(data))
		t.Data, err = ParseHttp(data[tcpHeaderLen:])
	default:
		t.Data = data[tcpHeaderLen:]
	}

	return t, err
}

//HeaderBytes return the bytes of tcp header
func (t *TCP) HeaderBytes() []byte {
	var tcpHeaderLen int
	 dataLen := len(t.raw)
	tcpHeaderLen = int(t.Header.DataOffset * 4)
	if tcpHeaderLen > dataLen {
		tcpHeaderLen = dataLen
	}
	return t.raw[0:tcpHeaderLen]
}


//DataBytes return the bytes of tcp data
func (t *TCP) DataBytes() []byte {
	var tcpHeaderLen int
	dataLen := len(t.raw)
	tcpHeaderLen = int(t.Header.DataOffset * 4)
	if tcpHeaderLen > dataLen {
		tcpHeaderLen = dataLen
	}
	return t.raw[tcpHeaderLen:]
}
