             Date 13-11-2017
PYTHON BASED NETWORK SNIFFER

This documentation is intended to explain a python based network tool called Packet Sniffer. This packet sniffer can be used legitimately by a network or system administrator to monitor and troubleshoot network traffic. It decodes the network traffic and makes sense of it. When somebody runs this packet sniffer on a computer, the selected network interface of that computer will be switched into promiscuous mode, listening to all the network traffic on the network rather than just those packets intended for it. It makes a copy of each packet flowing through that network interface and finds the source and destination MAC addresses of the packets. It decodes the protocols in the packets given below:
IP (Internet Protocol)
TCP (Transmission Control Protocol)
UDP (User Datagram Protocol)
The output is appended into a text file, so that the people can understand the network traffic and later analyze it.
Technical documentation
Platform: Linux, Python3
This sniffer is implemented by using raw socket. A raw socket is used to receive raw packets. This means packets received at the Ethernet layer will directly pass to the raw socket. Following code is used to implement raw socket in python3.
import socket
import os
os.system("ip link set %s promisc on"%(sys.argv[1]))
rsocket=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0003));
while(True):
	buffers=rsocket.recvfrom(65565)

 os.system("ip link set %s promisc on"%(sys.argv[1])). This line will set the promiscuous mode on selected  network interface
 
socket.PF_PACKET is used to send and receive packets at most basic level that is data link layer. 
socket.SOCK_RAW is used to create raw socket
socket.htons(0x0003) is used to indicate all types of protocols
Infinite while loop is used to read packets constantly. rsocket.recvfrom() is used to receive data into buffer. This buffer contains raw data received at Data Link Layer.
hexdump=["%02X"%(i) for i in buffers[0]]

This line will convert the data in buffer into hex dump (raw data in hexa-decimal format)
Ex: 
00 18 8b 75 1d e0 00 1f f3 d8 47 ab 08 00 45 00   
00 44 ad 0b 00 00 40 11 72 72 ac 14 02 fd ac 14   
00 06 e5 87 00 35 00 30 5b 6d ab c9 01 00 00 01   
00 00 00 00 00 00 09 6d 63 63 6c 65 6c 6c 61 6e   
02 63 73 05 6d 69 61 6d 69 03 65 64 75 00 00      

2.1.  Identifying Ethernet Headers
From the above hex-dump we can extract source and destination mac addresses, Ethernet type, protocol headers and data payload
Ex:
00 18 8b 75 1d e0 00 1f f3 d8 47 ab 08 00 45 00   
00 44 ad 0b 00 00 40 11 72 72 ac 14 02 fd ac 14   
00 06 e5 87 00 35 00 30 5b 6d ab c9 01 00 00 01   
00 00 00 00 00 00 09 6d 63 63 6c 65 6c 6c 61 6e   
02 63 73 05 6d 69 61 6d 69 03 65 64 75 00 00 

Hex dump in red color represents Ethernet headers. Mapping of hex values to corresponding Ethernet header fields is mentioned below by using color coding.
00 18 8b 75 1d e0 00 1f f3 d8 47 ab 08 00 

Destination MAC: 00:18:8b:75:1d:e0 
Source MAC:00:1f:f3:d8:47:ab 
Type: 0x0800 (IP)

This sniffer can identify the Ethernet headers and prints in following format
N bytes received Frame S.No Destination_MAC < Source_MAC Ethernet_type  
Ex: 54 bytes received Frame 888 00:50:56:EF:39:1C < 00:0C:29:96:8B:8B Internet Protocol version 4 (IPv4) 



2.2.  Identifying IPv4 Headers
if(etype=="0800"):
		filedes.write("\nIPv4 Packet");
		ProcessIPv4Packet(packet, len(packet));
else:
		print("");
		filedes.write("\n??????????? Skipping Packet ????????????????\n");

If Ethernet type is 08 00 (IPv4) then the program will print the IP otherwise it will skip the packets by printing Ethernet type     
ProcessIPv4Packet is a method which will identify the type of packet (TCP/UDP/ICMP/IGMP/Others) and call appropriate method to print headers. But whatever function ProcessIPv4Packet method calls the primary call in each method is  print_ip_header(packet,Size) which will print the IP Headers.


def print_ip_header(Buffer,Size):
    filedes.write("\n\nIP Header")
    filedes.write("\n	|-IP Version        : %d"%(int(Buffer[0][0],base=16)));
    hlen=int(Buffer[0][1],base=16)
    filedes.write("\n	|-IP Header Length  : %d DWORDS or %d Bytes"%(hlen,hlen*4));
    filedes.write("\n	|-Type Of Service   : %d"%(int(Buffer[1],base=16)));
    tlen=int(Buffer[2]+Buffer[3],base=16)
    filedes.write("\n	|-IP Total Length   : %d  Bytes(Size of Packet)"%(tlen))
    ipid=int(Buffer[4]+Buffer[5],base=16)
    filedes.write("\n	|-Identification    : %d"%(ipid));
    filedes.write("\n	|-TTL      : %d"%(int(Buffer[8],base=16)));
    filedes.write("\n	|-Protocol : %d"%(int(Buffer[9],base=16)));
    checksum=int(Buffer[10]+Buffer[11],base=16)
    filedes.write("\n	|-Checksum : %d"%(checksum));
    sip="%d.%d.%d.%d"%(int(Buffer[12],base=16),int(Buffer[13],base=16),
                                             int(Buffer[14],base=16),int( Buffer[15],base=16))
    filedes.write("\n	|-Source IP        : %s"%(sip));
    dip="%d.%d.%d.%d"%(int(Buffer[16],base=16),int(Buffer[17],base=16),
                                            int(Buffer[18],base=16),int(Buffer[19],base=16))
    filedes.write("\n	|-Destination IP   : %s"%(dip));



This method takes IP Packet as input and prints the IP headers











Ex : IP Packet
45 00 00 44 ad 0b 00 00 40 11 72 72 ac 14 02 fd 
ac 14 00 06 e5 87 00 35 00 30 5b 6d ab c9 01 00 
00 01 00 00 00 00 00 00 09 6d 63 63 6c 65 6c 6c
61 6e 02 63 73 05 6d 69 61 6d 69 03 65 64 75 00
00

Hex data in blue color represents IP headers. Mapping of hex values to corresponding IP packet header fields is mentioned below by using color coding. 
45 00 00 44 ad 0b 00 00 40 11 72 72 ac 14 02 fd ac 14 00 06

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

2.3.  Identifying UDP Headers
def print_udp_header(Buffer,Size):
    filedes.write("\n***********************UDP Packet*************************"); 
    print_ip_header(Buffer,Size)         
    filedes.write("\n\nUDP Header\n");
    sport=int(Buffer[20]+Buffer[21],base=16)
    filedes.write("\n	|-Source Port      : %u"%(sport));
    dport=int(Buffer[22]+Buffer[23],base=16)
    filedes.write("\n	|-Destination Port : %u"%(dport));
    length=int(Buffer[24]+Buffer[25],base=16)
    filedes.write("\n	|-UDP Length       : %d"%(length));
    cs=int(Buffer[25]+Buffer[26],base=16)
    filedes.write("\n	|-UDP Checksum     : %d"%(cs));
    filedes.write("\n");
    filedes.write("\n                     DATA Dump                         ");
    filedes.write("\n");
    filedes.write("\nIP Header");
    PrintData2(Buffer,20);
    filedes.write("\n")
    filedes.write("\nUDP Header");
    PrintData2(Buffer[21:27],len(Buffer[21:27]));
         
 

   filedes.write("\nData Payload");  
   PrintData2(Buffer[27:],len(Buffer[27:]));                   filedes.write("\n###########################################################\n");



This method will take IP packet as input and prints UDP headers
Ex : IP Packet
45 00 00 44 ad 0b 00 00 40 11 72 72 ac 14 02 fd 
ac 14 00 06 e5 87 00 35 00 30 5b 6d ab c9 01 00 
00 01 00 00 00 00 00 00 09 6d 63 63 6c 65 6c 6c
61 6e 02 63 73 05 6d 69 61 6d 69 03 65 64 75 00
00

Hex data in green color represents UDP headers. Mapping of hex values to corresponding  UDP header fileds is mentioned below by using color coding. 
User Datagram Protocol

e5 87 00 35 00 30 5b 6d

	|- Source port: 0xe587 
	|- Destination port: 0x0035 
	|- UDP Length: 0x0030 
	|- UDP Checksum: 0x5b6d 





2.3.  Identifying TCP Headers

def print_tcp_header(packet,Size):
    filedes.write("\n***********************TCP Packet*************************");    
         
    print_ip_header(packet,Size)
         
    filedes.write("\n\n");
    filedes.write("\nTCP Header");
    sport=int(packet[20]+packet[21],base=16)
    filedes.write("\n	|-Source Port      : %u"%(sport));
    dport=int(packet[22]+packet[23],base=16)
    filedes.write("\n	|-Destination Port : %u"%(dport));
    sn=int(packet[24]+packet[25]+packet[26]+packet[27],base=16)
    filedes.write("\n	|-Sequence Number    : %u"%(sn));
    an=int(packet[28]+packet[29]+packet[30]+packet[31],base=16)
    filedes.write("\n	|-Acknowledge Number : %u"%(an));
    hlen=int(packet[32][0],base=16)
    
    filedes.write("\n	|-Header Length  : %d DWORDS or %d Bytes"%(hlen,hlen*4));
    flags=((bin(int(packet[33],base=16)))[2:])
    flags=('0'*(8-len(flags)))+flags
    filedes.write("\n	|-Urgent Flag          : %c"%(flags[2]));
    filedes.write("\n	|-Acknowledgement Flag : %c"%(flags[3]));
    filedes.write("\n	|-Push Flag            : %c"%(flags[4]));
    filedes.write("\n	|-Reset Flag           : %c"%(flags[5]));
    filedes.write("\n	|-Synchronise Flag     : %c"%(flags[6]));
    filedes.write("\n	|-Finish Flag          : %c"%(flags[7]));
    win=int(packet[34]+packet[35],base=16)
    filedes.write("\n	|-Window         : %d"%(win));
    cs=int(packet[36]+packet[37],base=16)
    filedes.write("\n	|-Checksum       : %d"%(cs));
    up=int(packet[38]+packet[39],base=16)
    filedes.write("\n	|-Urgent Pointer : %d"%(up));
    filedes.write("\n");
    filedes.write("\n                     DATA Dump                         \n");
    filedes.write("\nIP Header");
    PrintData2(packet,20);
    filedes.write("\n")
    filedes.write("\nTCP Header");
    PrintData2(packet[21:40],len(packet[21:40]));
         
    filedes.write("\nData Payload");  
    PrintData2(packet[40:],len(packet[40:]));
                         
    filedes.write("\n###########################################################\n");

This method will take IP packet as input and prints TCP headers
45 00 00 3C 0A 73 40 00 40 06 4C 54 AC 10 83 96 
D8 3A DC 13 C4 DA 00 50 95 9C 56 C9 00 00 00 00 
A0 02 72 10 E4 23 00 00 02 04 05 B4 04 02 08 0A 
DF 5B 79 7E 00 00 00 00 01 03 03
 
Hex data in green color represents TCP headers. Mapping of hex values to corresponding TCP packet header fields is mentioned below by using color coding.
C4 DA 00 50 95 9C 56 C9 00 00 00 00 A0 02 72 10 E4 23 00 00 

TCP Header
   |-Source Port: 0xC4DA
   |-Destination Port: 0x0050
   |-Sequence Number: 0x959C56C9
   |-Acknowledge Number: 0x00000000
   |-Header Length: 0xA  DWORDS or 40 BYTES
   0x02 ->b00000010
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







Sample RuN

Detailed information will be stored in dump.txt


