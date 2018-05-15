package pcaparser

import (
	"io"
	"os"
	"time"

	"github.com/golang/glog"
)

func Combine(pcapfile1, pcapfile2, dstFile string) {

	f1, err := os.Open(pcapfile1)
	if err != nil {
		glog.Fatalln(err)
	}
	pcapReader1 := NewPcapFromReader(f1)
	f2, err := os.Open(pcapfile2)
	if err != nil {
		glog.Fatalln(err)
	}
	pcapReader2 := NewPcapFromReader(f2)
	defer pcapReader1.Close()
	defer pcapReader2.Close()

	writer, err := os.OpenFile(dstFile, os.O_CREATE|os.O_RDWR, 0775)
	if err != nil {
		glog.Errorln(err)
	}
	writer.Write(pcapReader1.Header.Bytes())
	defer writer.Close()

	var reader *Pcap
	var preT, t1, t2 time.Time
	var preData, data1, data2 []byte
	var err1, err2 error
	var c int
	t1, data1, err1 = readPacketBytes(pcapReader1)
	t2, data2, err2 = readPacketBytes(pcapReader2)
	if err1 != nil {
		if err1 == io.EOF {
			c = -1
			reader = pcapReader2
		} else {
			glog.Fatalln(err1)
		}
	}
	if err2 != nil {
		if err2 == io.EOF {
			c = -1
			reader = pcapReader1
		} else {
			glog.Fatalln(err2)
		}
	}
	if t1.Before(t2) {
		//t1 < t2
		preT = t2
		preData = data2

		if c != -1 {
			c = 1
			reader = pcapReader1
		}
		writer.Write(data1)
	} else {
		//t1 > t2
		preT = t1
		preData = data1

		if c != -1 {
			c = 2
			reader = pcapReader2
		}
		writer.Write(data2)
	}
Loop:
	for {
		t, data, err := readPacketBytes(reader)
		if err != nil {
			if err == io.EOF {
				//write
				if c == 1 {
					c = -1
					reader = pcapReader2
				} else if c == 2 {
					c = -1
					reader = pcapReader1
				} else {
					//
					writer.Write(data)
					break Loop
				}
			} else {
				glog.Fatalln(err)
			}
		}

		if t.Before(preT) {
			writer.Write(data)
		} else {
			writer.Write(preData)

			preT = t
			preData = data
			if c == 1 {
				c = 2
				reader = pcapReader2
			} else if c == 2 {
				c = 1
				reader = pcapReader1
			}
		}
	}
}

func readPacketBytes(reader *Pcap) (t time.Time, data []byte, err error) {
	packetHeaderData := make([]byte, PacketHeaderLen)
	err = read(reader.r, packetHeaderData, PacketHeaderLen)
	if err != nil {
		return t, packetHeaderData, err
	}
	ph, err := ParsePacketHeader(reader, packetHeaderData)
	if err != nil {
		return t, packetHeaderData, err
	}
	t = time.Unix(int64(ph.TimestampOfSec), int64(ph.TimestampOfMicrosec)*1000)
	readDataLen := 0
	if ph.IncludedLen > reader.Header.SnapLen {
		readDataLen = int(reader.Header.SnapLen)
	} else {
		readDataLen = int(ph.IncludedLen)
	}
	data = make([]byte, readDataLen)
	err = read(reader.r, data, readDataLen)
	if err != nil {
		return t, append(packetHeaderData, data...), err
	}
	return t, append(packetHeaderData, data...), nil
}
