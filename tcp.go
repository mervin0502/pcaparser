package pcaparser

//TCP
type TCP struct {
	Header *TCPHeader
	Data   interface{}
}

type TCPType uint16

const (
	TCP_HTTP_TYPE TCPType = 80
)

//ParseTCP
func ParseTCP(data []byte) (*TCP, error) {
	t := &TCP{}
	dataLen := len(data)
	if dataLen < DefaultTCPHeaderLen {
		return nil, errICMPHeaderTooShort
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
