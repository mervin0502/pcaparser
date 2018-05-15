package pcaparser

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
)

const (
	Version          = 4  // protocol version
	IPv4HeaderLen    = 20 // header length without extension headers
	maxIPv4HeaderLen = 60 // sensible default, revisit if later RFCs define new usage of version and header length fields
)

var (
	ErrIPv4HeaderTooShort = errors.New("header too short")
	errBufferTooShort     = errors.New("buffer too short")

	// See http://www.freebsd.org/doc/en/books/porters-handbook/freebsd-versions.html.
	freebsdVersion uint32
)

type IPv4HeaderFlags int

const (
	MoreFragments IPv4HeaderFlags = 1 << iota // more fragments flag
	DontFragment                              // don't fragment flag
)

//IPv4Protocol
type IPv4Protocol uint8

const (
	IP_ICMPType IPv4Protocol = 1
	IP_IGMPType IPv4Protocol = 2
	IP_IPv4Type IPv4Protocol = 6
	IP_TCPType  IPv4Protocol = 6
	IP_EGPType  IPv4Protocol = 8
	IP_IGPType  IPv4Protocol = 9
	IP_UDPType  IPv4Protocol = 17
	IP_RDPType  IPv4Protocol = 27
	IP_IPv6Type IPv4Protocol = 41
)

// A Header represents an IPv4 header.
type IPv4Header struct {
	Version  int             // protocol version
	Len      int             // header length
	TOS      int             // type-of-service
	TotalLen int             // packet total length
	ID       int             // identification
	Flags    IPv4HeaderFlags // flags
	FragOff  int             // fragment offset
	TTL      int             // time-to-live
	Protocol IPv4Protocol    // next protocol
	Checksum int             // checksum
	Src      net.IP          // source address
	Dst      net.IP          // destination address
	Options  []byte          // options, extension headers
}

func (h *IPv4Header) String() string {
	if h == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ver=%d hdrlen=%d tos=%#x totallen=%d id=%#x flags=%#x fragoff=%#x ttl=%d proto=%d cksum=%#x src=%v dst=%v", h.Version, h.Len, h.TOS, h.TotalLen, h.ID, h.Flags, h.FragOff, h.TTL, h.Protocol, h.Checksum, h.Src, h.Dst)
}

// ParseIPv4Header parses b as an IPv4 header.
func ParseIPv4Header(b []byte) (*IPv4Header, error) {
	if len(b) < IPv4HeaderLen {
		return nil, ErrIPv4HeaderTooShort
	}
	hdrlen := int(b[0]&0x0f) << 2
	if hdrlen > len(b) {
		return nil, errBufferTooShort
	}
	h := &IPv4Header{
		Version:  int(b[0] >> 4),
		Len:      hdrlen,
		TOS:      int(b[1]),
		ID:       int(binary.BigEndian.Uint16(b[4:6])),
		TTL:      int(b[8]),
		Protocol: IPv4Protocol(b[9]),
		Checksum: int(binary.BigEndian.Uint16(b[10:12])),
		Src:      net.IPv4(b[12], b[13], b[14], b[15]),
		Dst:      net.IPv4(b[16], b[17], b[18], b[19]),
	}
	switch runtime.GOOS {
	case "darwin", "dragonfly", "netbsd":
		h.TotalLen = int(binary.BigEndian.Uint16(b[2:4])) + hdrlen
		h.FragOff = int(binary.BigEndian.Uint16(b[6:8]))
	case "freebsd":
		if freebsdVersion < 1100000 {
			h.TotalLen = int(binary.BigEndian.Uint16(b[2:4]))
			if freebsdVersion < 1000000 {
				h.TotalLen += hdrlen
			}
			h.FragOff = int(binary.BigEndian.Uint16(b[6:8]))
		} else {
			h.TotalLen = int(binary.BigEndian.Uint16(b[2:4]))
			h.FragOff = int(binary.BigEndian.Uint16(b[6:8]))
		}
	default:
		h.TotalLen = int(binary.BigEndian.Uint16(b[2:4]))
		h.FragOff = int(binary.BigEndian.Uint16(b[6:8]))
	}
	h.Flags = IPv4HeaderFlags(h.FragOff&0xe000) >> 13
	h.FragOff = h.FragOff & 0x1fff
	if hdrlen-IPv4HeaderLen > 0 {
		h.Options = make([]byte, hdrlen-IPv4HeaderLen)
		copy(h.Options, b[IPv4HeaderLen:])
	}
	return h, nil
}
