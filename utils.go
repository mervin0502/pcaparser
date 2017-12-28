package pcaparser

import (
	"io"
)

func read(r io.Reader, data []byte, size int) error {
	//https://golang.org/pkg/io/#Reader
	temp := make([]byte, size)
	curLen := 0
	for {
		n, err := r.Read(temp)
		if err != nil {
			if n == 0 && err == io.ErrUnexpectedEOF {
				return io.EOF
			} else if err != io.ErrUnexpectedEOF {
				return err
			}
		}
		copy(data[curLen:], temp[0:n])
		curLen += n
		if curLen < size {
			temp = make([]byte, size-curLen)
			continue
		} else {
			break
		}
	}
	// temp = nil
	return nil
}
