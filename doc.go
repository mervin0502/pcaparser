package pcaparser

/*
Refs:
https://www.cnblogs.com/qishui/p/5437301.html
https://github.com/dominikh/go-pcap/blob/master/pcap.go


File format:
|Pcap header| Packet header1 | packet Data1| Packet header2 | packet Data2|


Pcap header format: 24bytes

-----------------------
|       magic 4B      |
+---------------------+
| major 2B | minor 2B |
+----------+----------+
|      ThisZone 4B    |
+---------------------+
|      SigFigs 4B     |
+---------------------+
|      SnapLen 4B     |
+_____________________+
|      LinkType 4B    |
+---------------------+

Packet header format: 16B
------------------------
|      TimeStamp 4B    |
+----------------------+
|      TimeStamp 4B    |
+----------------------+
|      CapLen 4B       |
+----------------------+
|      Len 4B          |
------------------------

0x1A 2B 3C 4D == 439041101


Ethernet format:
前导码：
Ethernet II是由8个8‘b10101010构成，
IEEE802.3由7个8‘b10101010+1个字节SFD
DefaultPreamble         = 0xAAAAAAAAAAAAAA
DefualtStartOfDelimiter = 0xAB
| Preable (7 bytes) | delimiter(1 byte) | dst mac(6 bytes ) | src mac(6 bytes) | type (2 bytes) | data | FCS (4 bytes) |

type:
0x8000 -> ip
0x8060 -> arp


ipv4 format:



数值
值描述

0   保留字段，用于IPv6(跳跃点到跳跃点选项)
1   Internet控制消息 (ICMP)
2   Internet组管理 (IGMP)
3   网关到网关 (GGP)
4   1P中的IP(封装)
5   流
6   传输控制 (TCP)
7   CBT
8   外部网关协议 (EGP)
9   任何私有内部网关(Cisco在它的IGRP实现中使用) (IGP)
10  BBNRCC监视
11  网络语音协议
12  PUP
13  ARGUS
14  EMCON
15  网络诊断工具
16  混乱(Chaos)
17  用户数据报文 (UDP)
18  复用
19  DCN测量子系统
20  主机监视
21  包无线测量
22  XEROXNSIDP
23  Trunk-1
24  Trunk-2
25  leaf-1
26  1eaf-2
27  可靠的数据协议
28  Internet可靠交易
29  1SO传输协议第四类 (TP4)
30  大块数据传输协议
31  MFE网络服务协议
32  MERIT节点之间协议
33  序列交换协议
34  第三方连接协议
35  域之间策略路由协议
36  XTP
37  数据报文传递协议
38  IDPR控制消息传输协议
39  TP+ +传输协议
40  IL传输协议
41  1Pv6
42  资源命令路由协议
43  1Pv6的路由报头
44  1Pv6的片报头
45  域之间路由协议
46  保留协议
47  通用路由封装
48  可移动主机路由协议
49  BNA
50  1Pv6封装安全有效负载
51  1Pv6验证报头
52  集成的网络层安全TUBA
53  带加密的IP
54  NBMA地址解析协议
55  IP可移动性
56  使用Kryptonet钥匙管理的传输层安全协议
57  SKIP
58  1Pv6的ICMP
59  1Pv6的无下一个报头
60  IPv6的信宿选项
61  任何主机内部协议
62  CFTP
63  任何本地网络
64  SATNET和BackroomEXPAK
65  Kryptolan
66  MIT远程虚拟磁盘协议
67  Internet Pluribus包核心
68  任何分布式文件系统
69  SATNET监视
70  VISA协议
71  Internet包核心工具
72  计算机协议Network Executive
73  计算机协议Heart Beat
74  Wang Span网络
75  包视频协议
76  Backroom SATNET监视
77  SUN ND PROTOCOL—临时
78  WIDEBAND监视
79  WIDEBAND EXPAK
80  ISO Internet协议
81  VMTP
82  SECURE—VMTP(安全的VMTP)
83  VINES
84  TTP
85  NSFNET—IGP
86  不同网关协议
87  TCF
88  EIGRP
89  OSPF IGP
90  Sprite RPC协议
9]  Locus地址解析协议
92  多播传输协议
93  AX.25帧
94  IP内部的IP封装协议
95  可移动网络互连控制协议
96  旗语通讯安全协议
97  IP中的以太封装
98  封装报头
99  任何私有加密方案
100 GMTP
101 Ipsilon流量管理协议
102 PNNI over IP
103 协议独立多播
104 ARIS
105 SCPS
106 QNX
107 活动网络
108 IP有效负载压缩协议
109 Sitara网络协议
110 Compaq对等协议
111 IP中的IPX
112 虚拟路由器冗余协议
113 PGM可靠传输协议
114 任何0跳跃协议
115 第二层隧道协议
116 D-II数据交换(DDX)
117 交互式代理传输协议
118 日程计划传输协议
119 SpectraLink无线协议
120 UTI
121 简单消息协议
122 SM
123 性能透明性协议
124 ISIS over IPv4
125 FIRE
126 Combat无线传输协议
127 Combat无线用户数据报文
128 SSCOPMCE
129 IPLT
130 安全包防护
131 IP中的私有IP封装
132 流控制传输协议
133～254 未分配
255 保留


tcp format:
    +---------------+----------------+
    | source port 16| dst port 16   |
    +--------------------------------+
    |           sequence number  32  |
    +--------------------------------+
    |         ack number  32         |
    +---+-----+++++++----------------+
    |off  reser                      |
    +---------------+----------------+
    |            options             |
    +--------------------------------+
    |            data                |
    +--------------------------------+

3）TCP首部总长度：由TCP头中的“数据偏移”字段决定。该字段占4bit，取最大的1111时，也就是十进制的15，TCP首部的偏移单位为4byte，那么TCP首部长度最长为15*4=60字节。
4）选项和填充 的长度：＝ TCP首部总长度 － 20字节的固定长度。由3）的计算可知，TCP首部总长度最大为60字节，那么“选项和填充”字段的长度最大为40字节。填充是为了使TCP首部为4byte的整数倍。


udp format:





ICMP
https://tools.ietf.org/html/rfc792

ICMP request/echo
+-------+-------+----------------+
|       |       |                |
+---------------+----------------+
|               |                |
+--------------------------------+
|               data                                     |
+--------------------------------+


ICMP unreachable
+-------+-------+-----------------+
|       |       |                 |
+---------------------------------+
|                                                                   |
+---------------------------------+
|   IP header + 8 byte data         |
+---------------------------------+


*/
