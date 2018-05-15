package pcaparser

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/golang/glog"
)

//SplitByDate
func (p *Pcap) SplitByDate(dstDir string) {

	var dstFile string
	var writer *os.File
	var cur, start, end time.Time
	var endFlag bool
	var packetData []byte
	var readDataLen int
	endFlag = true
Loop:
	for {
		//get 14-bytes
		packetHeaderData := make([]byte, PacketHeaderLen)
		err := read(p.r, packetHeaderData, PacketHeaderLen)
		if err != nil {
			if err == io.EOF {
				break
			}
			glog.Warningf("%v", err)
			break Loop
		}
		ph, err := ParsePacketHeader(p, packetHeaderData)
		if err != nil {
			glog.Errorln(err)
		}
		cur = time.Unix(int64(ph.TimestampOfSec), int64(ph.TimestampOfMicrosec)*1000)
		if endFlag {

			h, M, s := cur.Hour(), cur.Minute(), cur.Second()
			offset := int64(h*60*60 + M*60 + s)
			secOfDay := int64(24 * 60 * 60)
			start = time.Unix(cur.Unix()-offset, 0)
			end = time.Unix(cur.Unix()+secOfDay-offset, 0)

			y, m, d := cur.Date()
			dstFile = filepath.Join(dstDir, fmt.Sprintf("%d-%d-%d.pcap", y, int(m), d))
			writer, err = os.OpenFile(dstFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0755)
			if err != nil {
				glog.Errorln(err)
			}
			writer.Write(p.Header.Bytes())
			endFlag = false
			glog.V(2).Infof("start=%v cur=%v end=%v", start, cur, end)
		}
		if ph.IncludedLen > p.Header.SnapLen {
			readDataLen = int(p.Header.SnapLen)
		} else {
			readDataLen = int(ph.IncludedLen)
		}
		packetData = make([]byte, readDataLen)
		err = read(p.r, packetData, readDataLen)
		if err != nil {
			glog.Errorln(err)
		}
		if cur.UnixNano() > end.UnixNano() || cur.UnixNano() < start.UnixNano() {

			h, M, s := cur.Hour(), cur.Minute(), cur.Second()
			offset := int64(h*60*60 + M*60 + s)
			secOfDay := int64(24 * 60 * 60)
			start = time.Unix(cur.Unix()-offset, 0)
			end = time.Unix(cur.Unix()+secOfDay-offset, 0)

			writer.Close()
			y, m, d := cur.Date()
			dstFile = filepath.Join(dstDir, fmt.Sprintf("%d-%d-%d.pcap", y, int(m), d))
			writer, err = os.OpenFile(dstFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0755)
			if err != nil {
				glog.Errorln(err)
			}
			writer.Write(p.Header.Bytes())
			writer.Write(append(packetHeaderData, packetData...))
			glog.V(2).Infof("start=%v cur=%v end=%v", start, cur, end)
		} else {
			writer.Write(append(packetHeaderData, packetData...))
		}
	}
}

//SplitWithTime
func (p *Pcap) SplitWithTime(dstFile string, start time.Time, end time.Time, sorted bool) bool {
	fp, err := os.Create(dstFile)
	if err != nil {
		glog.Errorln(err)
	}
	fp.Write(p.Header.Bytes())
	defer fp.Close()

	var cur time.Time
	var packetData []byte
	var readDataLen int

	flag := 10
	coutner := 1
Loop:
	for {
		//get 14-bytes
		packetHeaderData := make([]byte, PacketHeaderLen)
		err := read(p.r, packetHeaderData, PacketHeaderLen)
		if err != nil {
			if err == io.EOF {
				break
			}
			glog.Warningf("%v", err)
			break Loop
		}
		ph, err := ParsePacketHeader(p, packetHeaderData)
		if err != nil {
			glog.Errorln(err)
		}
		cur = time.Unix(int64(ph.TimestampOfSec), int64(ph.TimestampOfMicrosec)*1000)
		cur = cur.In(start.Location())

		// glog.V(2).Infof("%v", cur)
		// break Loop

		if ph.IncludedLen > p.Header.SnapLen {
			readDataLen = int(p.Header.SnapLen)
		} else {
			readDataLen = int(ph.IncludedLen)
		}
		packetData = make([]byte, readDataLen)
		err = read(p.r, packetData, readDataLen)
		if err != nil {
			if err == io.EOF {
				fp.Write(append(packetHeaderData, packetData...))
				break
			}
			glog.Errorln(err)
		}
		//to buf
		// glog.V(2).Infof("%s %s %s", cur, start, end)
		if cur.Before(start) {
			// if cur.UnixNano() < start.UnixNano() {
			continue
		}
		if cur.After(end) {
			// if cur.UnixNano() > end.UnixNano() {
			if sorted {
				coutner += 1
			}
			if coutner > flag {
				break Loop
			}
			continue
		}
		fp.Write(append(packetHeaderData, packetData...))
	}

	return true
}
