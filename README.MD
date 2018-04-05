# PYTHON BASED NETWORK SNIFFER (TASK 2)

1. ABSTRACT

This documentation is intended to explain a python based network tool called Packet Sniffer. This packet sniffer can be used legitimately by a network or system administrator to monitor and troubleshoot network traffic. It decodes the network traffic and makes sense of it. When somebody runs this packet sniffer on a computer, the selected network interface of that computer will be switched into promiscuous mode, listening to all the network traffic on the network rather than just those packets intended for it. It makes a copy of each packet flowing through that network interface and finds the source and destination MAC addresses of the packets. It decodes the protocols in the packets given below:

1. IP (Internet Protocol)
2. TCP (Transmission Control Protocol)
3. UDP (User Datagram Protocol)

The output is appended into a text file, so that the people can understand the network traffic and later analyze it.

1. Technical documentation

Platform: Linux, Python3

This sniffer is implemented by using raw socket. A raw socket is used to receive raw packets. This means packets received at the Ethernet layer will directly pass to the raw socket. Following code is used to implement raw socket in python3.

| _import socket __import os__ os.system(&quot;ip link set %s promisc on&quot;%(sys.argv[1]))__rsocket=socket.socket(socket.PF\_PACKET,socket.SOCK\_RAW,socket.htons(0x0003));__while(True):__        buffers=rsocket.recvfrom(65565)_ |
| --- |

_ os.system(&quot;ip link set %s promisc on&quot;%(sys.argv[1])). This line will set the promiscuous mode on selected  network interface_

- _socket.PF\_PACKET_ is used to send and receive packets at most basic level that is data link layer.
- _socket.SOCK\_RAW_ is used to create raw socket
- _socket.htons(0x0003)_ is used to indicate all types of protocols

Infinite while loop is used to read packets constantly. _rsocket.recvfrom()_ is used to receive data into buffer. This buffer contains raw data received at Data Link Layer.

| hexdump=[&quot;%02X&quot;%(i) for i in buffers[0]] |
| --- |

This line will convert the data in buffer into hex dump (raw data in hexa-decimal format)

Ex:

00 18 8b 75 1d e0 00 1f f3 d8 47 ab 08 00 45 00

00 44 ad 0b 00 00 40 11 72 72 ac 14 02 fd ac 14

00 06 e5 87 00 35 00 30 5b 6d ab c9 01 00 00 01

00 00 00 00 00 00 09 6d 63 63 6c 65 6c 6c 61 6e

02 63 73 05 6d 69 61 6d 69 03 65 64 75 00 00

**2.1.  Identifying Ethernet Headers**

From the above hex-dump we can extract source and destination mac addresses, Ethernet type, protocol headers and data payload

Ex:

00 18 8b 75 1d e0 00 1f f3 d8 47 ab 08 0045 00

00 44 ad 0b 00 00 40 11 72 72 ac 14 02 fd ac 14

00 06e5 87 00 35 00 30 5b 6dab c9 01 00 00 01

00 00 00 00 00 00 09 6d 63 63 6c 65 6c 6c 61 6e

02 63 73 05 6d 69 61 6d 69 03 65 64 75 00 00

Hex dump in red color represents Ethernet headers. Mapping of hex values to corresponding Ethernet header fields is mentioned below by using color coding.

00 18 8b 75 1d e000 1f f3 d8 47 ab08 00

Destination MAC: 00:18:8b:75:1d:e0

Source MAC:00:1f:f3:d8:47:ab

Type: 0x0800 (IP)

This sniffer can identify the Ethernet headers and prints in following format

**N** bytes received Frame **S.No Destination\_MAC** &lt; **Source\_MAC Ethernet\_type  **

Ex: 54 bytes received Frame 888 00:50:56:EF:39:1C &lt; 00:0C:29:96:8B:8B Internet Protocol version 4 (IPv4)

**2.2.  Identifying IPv4 Headers**

| _if(etype==&quot;0800&quot;):__                filedes.write(&quot;\nIPv4 Packet&quot;);__                ProcessIPv4Packet(packet, len(packet)); __else:__                 print(&quot;&quot;);__                filedes.write(&quot;\n??????????? Skipping Packet ????????????????\n&quot;);_ |
| --- |

If Ethernet type is 08 00 (IPv4) then the program will print the IP otherwise it will skip the packets by printing Ethernet type

ProcessIPv4Packet is a method which will identify the type of packet (TCP/UDP/ICMP/IGMP/Others) and call appropriate method to print headers. But whatever function _ProcessIPv4Packet_ method calls the primary call in each method is _ print\_ip\_header(packet,Size)_ which will print the IP Headers.

| _def print\_ip\_header(Buffer,Size):__    filedes.write(&quot;\n\nIP Header&quot;)__    filedes.write(&quot;\n        |-IP Version        : %d&quot;%(int(Buffer[0][0],base=16)));__    hlen=int(Buffer[0][1],base=16)__    filedes.write(&quot;\n        |-IP Header Length  : %d DWORDS or %d Bytes&quot;%(hlen,hlen\*4));__    filedes.write(&quot;\n        |-Type Of Service   : %d&quot;%(int(Buffer[1],base=16)));__    tlen=int(Buffer[2]+Buffer[3],base=16)__    filedes.write(&quot;\n        |-IP Total Length   : %d  Bytes(Size of Packet)&quot;%(tlen))__    ipid=int(Buffer[4]+Buffer[5],base=16)__    filedes.write(&quot;\n        |-Identification    : %d&quot;%(ipid));__    filedes.write(&quot;\n        |-TTL      : %d&quot;%(int(Buffer[8],base=16)));__    filedes.write(&quot;\n        |-Protocol : %d&quot;%(int(Buffer[9],base=16)));__    checksum=int(Buffer[10]+Buffer[11],base=16)__    filedes.write(&quot;\n        |-Checksum : %d&quot;%(checksum));__    sip=&quot;%d.%d.%d.%d&quot;%(int(Buffer[12],base=16),int(Buffer[13],base=16),__                                             int(Buffer[14],base=16),int( Buffer[15],base=16))__    filedes.write(&quot;\n        |-Source IP        : %s&quot;%(sip));__    dip=&quot;%d.%d.%d.%d&quot;%(int(Buffer[16],base=16),int(Buffer[17],base=16),__                                            int(Buffer[18],base=16),int(Buffer[19],base=16))__    filedes.write(&quot;\n        |-Destination IP   : %s&quot;%(dip));_ |
| --- |
|   |

This method takes IP Packet as input and prints the IP headers

Ex : IP Packet

45 00 00 44 ad 0b 00 00 40 11 72 72 ac 14 02 fd

ac 14 00 06 e5 87 00 35 00 30 5b 6d ab c9 01 00

00 01 00 00 00 00 00 00 09 6d 63 63 6c 65 6c 6c

61 6e 02 63 73 05 6d 69 61 6d 69 03 65 64 75 00

00

Hex data in blue color represents IP headers. Mapping of hex values to corresponding IP packet header fields is mentioned below by using color coding.

45 00 00 44ad 0b 00 00 401172 72ac 14 02 fdac 14 00 06

      |- IP Version: 4

      |- IP Header length: 5 DWORDS 20 bytes

      |- Type of Service: 0x00

      |- IP Total Length: 0x0044 Bytes (Size of Packet)

      |- Identification: 0xad0b

      |- TTL: 0x40

      |- Protocol: 0x11

      |- Checksom: 0x7272

      |- Source IP: 0xac.0x14.0x02.0xfd (172.20.2.253)

      |- Destination IP: 0xac.0x14.0x00.0x06 (172.20.0.6)

**2.3.  Identifying UDP Headers**

| def print\_udp\_header(Buffer,Size):    filedes.write(&quot;\n\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*UDP Packet\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*&quot;);     print\_ip\_header(Buffer,Size)             filedes.write(&quot;\n\nUDP Header\n&quot;);    sport=int(Buffer[20]+Buffer[21],base=16)    filedes.write(&quot;\n |-Source Port      : %u&quot;%(sport));    dport=int(Buffer[22]+Buffer[23],base=16)    filedes.write(&quot;\n |-Destination Port : %u&quot;%(dport));    length=int(Buffer[24]+Buffer[25],base=16)    filedes.write(&quot;\n |-UDP Length       : %d&quot;%(length));    cs=int(Buffer[25]+Buffer[26],base=16)    filedes.write(&quot;\n |-UDP Checksum     : %d&quot;%(cs));    filedes.write(&quot;\n&quot;);    filedes.write(&quot;\n                     DATA Dump                         &quot;);    filedes.write(&quot;\n&quot;);    filedes.write(&quot;\nIP Header&quot;);    PrintData2(Buffer,20);    filedes.write(&quot;\n&quot;)    filedes.write(&quot;\nUDP Header&quot;);    PrintData2(Buffer[21:27],len(Buffer[21:27]));             filedes.write(&quot;\nData Payload&quot;);     PrintData2(Buffer[27:],len(Buffer[27:]));                   filedes.write(&quot;\n###########################################################\n&quot;); |
| --- |
|   |

This method will take IP packet as input and prints UDP headers

Ex : IP Packet

45 00 00 44 ad 0b 00 00 40 11 72 72 ac 14 02 fd

ac 14 00 06 e5 87 00 35 00 30 5b 6d ab c9 01 00

00 01 00 00 00 00 00 00 09 6d 63 63 6c 65 6c 6c

61 6e 02 63 73 05 6d 69 61 6d 69 03 65 64 75 00

00

Hex data in green color represents UDP headers. Mapping of hex values to corresponding  UDP header fileds is mentioned below by using color coding.

User Datagram Protocol

e5 8700 3500 305b 6d

        |- Source port: 0xe587

        |- Destination port: 0x0035

        |- UDP Length: 0x0030

        |- UDP Checksum: 0x5b6d

**2.3.  Identifying TCP Headers**

| def print\_tcp\_header(packet,Size):    filedes.write(&quot;\n\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*TCP Packet\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*&quot;);                 print\_ip\_header(packet,Size)             filedes.write(&quot;\n\n&quot;);    filedes.write(&quot;\nTCP Header&quot;);    sport=int(packet[20]+packet[21],base=16)    filedes.write(&quot;\n |-Source Port      : %u&quot;%(sport));    dport=int(packet[22]+packet[23],base=16)    filedes.write(&quot;\n |-Destination Port : %u&quot;%(dport));    sn=int(packet[24]+packet[25]+packet[26]+packet[27],base=16)    filedes.write(&quot;\n |-Sequence Number    : %u&quot;%(sn));    an=int(packet[28]+packet[29]+packet[30]+packet[31],base=16)    filedes.write(&quot;\n |-Acknowledge Number : %u&quot;%(an));    hlen=int(packet[32][0],base=16)        filedes.write(&quot;\n |-Header Length  : %d DWORDS or %d Bytes&quot;%(hlen,hlen\*4));    flags=((bin(int(packet[33],base=16)))[2:])    flags=(&#39;0&#39;\*(8-len(flags)))+flags    filedes.write(&quot;\n |-Urgent Flag          : %c&quot;%(flags[2]));    filedes.write(&quot;\n |-Acknowledgement Flag : %c&quot;%(flags[3]));    filedes.write(&quot;\n |-Push Flag            : %c&quot;%(flags[4]));    filedes.write(&quot;\n |-Reset Flag           : %c&quot;%(flags[5]));    filedes.write(&quot;\n |-Synchronise Flag     : %c&quot;%(flags[6]));    filedes.write(&quot;\n |-Finish Flag          : %c&quot;%(flags[7]));    win=int(packet[34]+packet[35],base=16)    filedes.write(&quot;\n |-Window         : %d&quot;%(win));    cs=int(packet[36]+packet[37],base=16)    filedes.write(&quot;\n |-Checksum       : %d&quot;%(cs));    up=int(packet[38]+packet[39],base=16)    filedes.write(&quot;\n |-Urgent Pointer : %d&quot;%(up));    filedes.write(&quot;\n&quot;);    filedes.write(&quot;\n                     DATA Dump                         \n&quot;);    filedes.write(&quot;\nIP Header&quot;);    PrintData2(packet,20);    filedes.write(&quot;\n&quot;)    filedes.write(&quot;\nTCP Header&quot;);    PrintData2(packet[21:40],len(packet[21:40]));             filedes.write(&quot;\nData Payload&quot;);      PrintData2(packet[40:],len(packet[40:]));                             filedes.write(&quot;\n###########################################################\n&quot;); |
| --- |

This method will take IP packet as input and prints TCP headers

45 00 00 3C 0A 73 40 00 40 06 4C 54 AC 10 83 96

D8 3A DC 13 C4 DA 00 50 95 9C 56 C9 00 00 00 00

A0 02 72 10 E4 23 00 00 02 04 05 B4 04 02 08 0A

DF 5B 79 7E 00 00 00 00 01 03 03

Hex data in green color represents TCP headers. Mapping of hex values to corresponding TCP packet header fields is mentioned below by using color coding.

C4 DA00 5095 9C 56 C900 00 00 00A00272 10E4 2300 00

TCP Header

   |-Source Port: 0xC4DA

   |-Destination Port: 0x0050

   |-Sequence Number: 0x959C56C9

   |-Acknowledge Number: 0x00000000

   |-Header Length: 0xA  DWORDS or 40 BYTES

   0x02 -&gt;b00000010

   |-Urgent Flag: 0

   |-Acknowledgement Flag: 0

   |-Push Flag: 0

   |-Reset Flag: 0

   |-Synchronize Flag: 1

   |-Finish Flag: 0

   |-Window: 0x7210

   |-Checksum: 0xE423

   |-Urgent Pointer: 0x0000

After getting header values and payload everything will be converted into ASCII and stored in dump.txt.
