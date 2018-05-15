package pcaparser

import (
	"io"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/golang/glog"
)

//SortType
type SortType uint8

const (
	ASC  SortType = iota //ascending
	DESC                 //descending
)

//SortByTime
func (p *Pcap) SortByTime(dstFile string, st SortType) {
	loc := time.UTC
	startTime, endTime, n := getSETimeFromFlowFile(p, loc)
	glog.V(2).Infof("%v %v %d ", startTime, endTime, n)

	var perPacketSizeInDuration float64 = 500000
	du := time.Duration(math.Ceil(endTime.Sub(startTime).Seconds()/(float64(n)/perPacketSizeInDuration))) * time.Second

	// glog.V(2).Infof("%v %v %v ", math.Ceil(float64(n)/perPacketSizeInDuration), endTime.Sub(startTime).Seconds()/(float64(n)/perPacketSizeInDuration), du.Seconds())
	var packetData []byte
	var readDataLen int
	var pac packet
	var ps []packet
	var preTime, curTime, nextTime time.Time
	var tmpFileConter int = 0
	var tmpDir, tmpFile string
	tmpDir, err := ioutil.TempDir("", "pcap")
	if err != nil {
		glog.Fatalln(err)
	}
	defer os.RemoveAll(tmpDir)

	ps = make([]packet, 0)
	p.Reset()

	// os.Exit(0)
	preTime = startTime
	nextTime = startTime.Add(du)
Loop1:
	for {
	Loop2:
		for {
			packetHeaderData := make([]byte, PacketHeaderLen)
			// glog.V(2).Infoln("1")
			err := read(p.r, packetHeaderData, PacketHeaderLen)
			// glog.V(2).Infoln("2")
			if err != nil {
				if err == io.EOF {
					break Loop2
				}
				glog.Fatalf("%v", err)
			}

			ph, err := ParsePacketHeader(p, packetHeaderData)
			if err != nil {
				glog.Fatalln(err)
			}
			// glog.V(2).Infoln("3")
			curTime = time.Unix(int64(ph.TimestampOfSec), int64(ph.TimestampOfMicrosec)*1000).UTC()

			if ph.IncludedLen > p.Header.SnapLen {
				readDataLen = int(p.Header.SnapLen)
			} else {
				readDataLen = int(ph.IncludedLen)
			}
			packetData = make([]byte, readDataLen)
			err = read(p.r, packetData, readDataLen)
			if err != nil {
				if err == io.EOF {
					break Loop2
				}
				glog.Fatalf("%v", err)
			}
			pac = packet{}
			pac.t = curTime
			// append(packetHeaderData, packetData...)
			pac.data = make([]byte, PacketHeaderLen+readDataLen)
			copy(pac.data[0:PacketHeaderLen], packetHeaderData)
			copy(pac.data[PacketHeaderLen:PacketHeaderLen+readDataLen], packetData)
			// glog.V(2).Infof("%v %v", curTime, t)
			if curTime.After(preTime) && curTime.Before(nextTime) {
				ps = append(ps, pac)
			}
		} //for loop2
		if st == ASC {
			By(asc).Sort(ps)
		} else {
			By(desc).Sort(ps)
		}
		//write to tmp file
		tmpFile = filepath.Join(tmpDir, strconv.Itoa(tmpFileConter))
		glog.V(2).Infof("%d %s", len(ps), tmpFile)
		glog.V(2).Infof("%v %v", preTime, nextTime)
		toTmpFile(tmpFile, ps)
		ps = make([]packet, 0)
		p.Reset()
		tmpFileConter += 1
		preTime = nextTime
		nextTime = nextTime.Add(du)
		if preTime.After(endTime) {
			break Loop1
		}
	} //for loop1

	//combine file
	fp, err := os.Create(dstFile)
	if err != nil {
		glog.Errorln(err)
	}
	defer fp.Close()
	fp.Write(p.Header.Bytes())
	if st == DESC {
		for i := tmpFileConter - 1; i >= 0; i -= 1 {
			tmpFile = filepath.Join(tmpDir, strconv.Itoa(i))
			data, err := ioutil.ReadFile(tmpFile)
			if err != nil {
				glog.Fatalln(err)
			}
			fp.Write(data)
		}
	} else {
		for i := 0; i < tmpFileConter; i += 1 {
			tmpFile = filepath.Join(tmpDir, strconv.Itoa(i))
			data, err := ioutil.ReadFile(tmpFile)
			if err != nil {
				glog.Fatalln(err)
			}
			fp.Write(data)
		}
	}

}

/*

 */
//getSETimeFromFlowFile
func getSETimeFromFlowFile(p *Pcap, loc *time.Location) (time.Time, time.Time, int) {
	var startTime, curTime, endTime time.Time
	layout := "2006-01-02 15:04:05"
	startTime = time.Now().In(loc)
	endTime, _ = time.ParseInLocation(layout, "1970-01-01 00:00:00", loc)
	var packetData []byte
	var readDataLen int
	counter := 0
Loop:
	for {
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

		curTime = time.Unix(int64(ph.TimestampOfSec), int64(ph.TimestampOfMicrosec)*1000).UTC()

		if curTime.Before(startTime) {
			startTime = curTime
		}
		if curTime.After(endTime) {
			endTime = curTime
		}
		// glog.V(2).Infof("%v %v %v", startTime, curTime, endTime)
		counter += 1

		if ph.IncludedLen > p.Header.SnapLen {
			readDataLen = int(p.Header.SnapLen)
		} else {
			readDataLen = int(ph.IncludedLen)
		}
		packetData = make([]byte, readDataLen)
		err = read(p.r, packetData, readDataLen)
		if err != nil {
			if err == io.EOF {
				break
			}
			glog.Errorln(err)
		}
	}
	return startTime, endTime, counter
}

func toTmpFile(f string, ps []packet) {
	fp, err := os.Create(f)
	if err != nil {
		glog.Errorln(err)
	}
	defer fp.Close()
	for _, pac := range ps {
		fp.Write(pac.data)
	}
}

/*
 sort
*/
//packet
type packet struct {
	t    time.Time
	data []byte
}

//By
type By func(p1, p2 *packet) bool

func (b By) Sort(ps []packet) {
	pss := &packetSorter{
		ps: ps,
		by: b,
	}
	sort.Sort(pss)
}

//packetSorter
type packetSorter struct {
	ps []packet
	by func(p1, p2 *packet) bool
}

//Len
func (p *packetSorter) Len() int {
	return len(p.ps)
}

//Swap
func (p *packetSorter) Swap(i, j int) {
	p.ps[i], p.ps[j] = p.ps[j], p.ps[i]
}

//Less
func (p *packetSorter) Less(i, j int) bool {
	return p.by(&p.ps[i], &p.ps[j])
}

//desc
func desc(p1, p2 *packet) bool {
	return p1.t.After(p2.t)
}

//asc
func asc(p1, p2 *packet) bool {
	return p1.t.Before(p2.t)
}
