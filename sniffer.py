#!/usr/bin/python3
import socket
import os
import sys
framecount=-1
filedes=open("dump.txt","w+")

def PrintData2(data,size):
	lines=int(size/16);
	if(size%16>0):
		lines+=1
	index=0
	for i in range(0,lines):
		if(index+16 <= len(data)):
			hdata=" ".join(data[index:index+16])
			tdata="\n\t"+hdata.ljust(50)+"\t"
			filedes.write(tdata)
			k=[int(x,base=16) for x in data[index:index+16]]
			for i in range(0,len(k)):
				if(k[i]>=32 and k[i]<=127):
					k[i]=chr(k[i]);
				else:
					k[i]="."
			filedes.write("".join(k))
		else:
			hdata=" ".join(data[index:])
			tdata="\n\t"+hdata.ljust(50)+"\t"
			filedes.write(tdata)
			k=[int(x,base=16) for x in data[index:]]
			for i in range(0,len(k)):
				if(k[i]>=32 and k[i]<=127):
					k[i]=chr(k[i]);
				else:
					k[i]="."
			filedes.write("".join(k))
		index+=16


	
def ProcessIPv4Packet(buffers,size):
	protocol=int(buffers[9],base=16)
	if(protocol==1):
		print_icmp_packet(buffers ,size)
		print ("ICMP")
	elif(protocol==2):
		print ("IGMP")
	elif(protocol==6):
		print ("TCP")
		print_tcp_header(packet,size)
	elif(protocol==17):
		print ("UDP")
		print_udp_header(buffers,size)
	else:
		print ("Other")

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
    sip="%d.%d.%d.%d"%(int(Buffer[12],base=16),int(Buffer[13],base=16),int(Buffer[14],base=16),int(Buffer[15],base=16))
    filedes.write("\n	|-Source IP        : %s"%(sip));
    dip="%d.%d.%d.%d"%(int(Buffer[16],base=16),int(Buffer[17],base=16),int(Buffer[18],base=16),int(Buffer[19],base=16))
    filedes.write("\n	|-Destination IP   : %s"%(dip));

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
    PrintData2(Buffer[27:],len(Buffer[27:]));
                         
    filedes.write("\n###########################################################\n");
         

def print_icmp_packet(Buffer ,Size):
    filedes.write("\n***********************ICMP Packet*************************");   
    print_ip_header(Buffer , Size);   
    filedes.write("\n\n");
         
    filedes.write("\nICMP Header");
    itype=(int(Buffer[20],base=16))
    filedes.write("\n	|-Type : %d"%(itype));
             
    if(itype == 11):
        filedes.write("\n	(TTL Expired)");
    elif(itype==0):
        filedes.write("\n	(ICMP Echo Reply)");
    filedes.write("\n	|-Code : %d"%((int(Buffer[21],base=16))));
    filedes.write("\n	|-Checksum : %d"%((int(Buffer[22]+Buffer[23],base=16))));
    filedes.write("\n");
    filedes.write("\n                     DATA Dump                         \n");
    filedes.write("\nIP Header");
    PrintData2(Buffer,20);
    filedes.write("\n")
    filedes.write("\nUDP Header");
    PrintData2(Buffer[21:24],len(Buffer[21:24]));
         
    filedes.write("\nData Payload");  
    PrintData2(Buffer[24:],len(Buffer[24:]));
    filedes.write("\n###########################################################\n");

rsocket=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0003));
print(">>>>>>>> Packet sniffing Program <<<<<<<<<\n\
Please check dump.txt for detailed information of frames\n\n")
ether_types=['0800' , '0806' , '0842' , '22F3' , '22EA' , '6003' , '8035', '809B' , '80F3' , '8100' , '8137' , '8204' , '86DD' , '8808', '8809' , '8819' , '8847' , '8848' , '8863' , '8864' , '886D', '8870' , '887B' , '888E' , '8892' , '889A' , '88A2' , '88A4', '88A8' , '88AB' , '88B8' , '88B9' , '88BA' , '88CC' , '88CD', '88DC' , '88E1' , '88E3' , '88E5' , '88E7' , '88F7' , '88FB', '8902' , '8906' , '8914' , '8915' , '891D' , '892F' , '9000', '9100' ];
ether_type_names=["Internet Protocol version 4 (IPv4)", "Address Resolution Protocol (ARP)", "Wake-on-LAN[7]", "IETF TRILL Protocol", "Stream Reservation Protocol", "DECnet Phase IV", "Reverse Address Resolution Protocol", "AppleTalk (Ethertalk)", "AppleTalk Address Resolution Protocol (AARP)", "VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility[8]", "IPX", "QNX Qnet", "Internet Protocol Version 6 (IPv6)", "Ethernet flow control", "Ethernet Slow Protocols[9]", "CobraNet", "MPLS unicast", "MPLS multicast", "PPPoE Discovery Stage", "PPPoE Session Stage", "Intel Advanced Networking Services [10]", "Jumbo Frames (Obsoleted draft-ietf-isis-ext-eth-01)", "HomePlug 1.0 MME", "EAP over LAN (IEEE 802.1X)", "PROFINET Protocol", "HyperSCSI (SCSI over Ethernet)", "ATA over Ethernet", "EtherCAT Protocol", "Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq[8]", "Ethernet Powerlink[citation needed]", "GOOSE (Generic Object Oriented Substation event)", "GSE (Generic Substation Events) Management Services", "SV (Sampled Value Transmission)", "Link Layer Discovery Protocol (LLDP)", "SERCOS III", "WSMP, WAVE Short Message Protocol", "HomePlug AV MME[citation needed]", "Media Redundancy Protocol (IEC62439-2)", "MAC security (IEEE 802.1AE)", "Provider Backbone Bridges (PBB) (IEEE 802.1ah)", "Precision Time Protocol (PTP) over Ethernet (IEEE 1588)", "Parallel Redundancy Protocol (PRP)", "IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)", "Fibre Channel over Ethernet (FCoE)", "FCoE Initialization Protocol", "RDMA over Converged Ethernet (RoCE)", "TTEthernet Protocol Control Frame (TTE)", "High-availability Seamless Redundancy (HSR)", "Ethernet Configuration Testing Protocol[11]", "VLAN-tagged (IEEE 802.1Q) frame with double tagging"];
if(len(sys.argv)==1):
	print("""
Usage:
sudo ./sniffer.py <interface>""")
	exit(0)
os.system("ip link set %s promisc on"%(sys.argv[1]))
while(True):
	buffers=rsocket.recvfrom(65565)
	framecount+=1
	hexdump=["%02X"%(i) for i in buffers[0]]
	out=(str(len(buffers[0])),"bytes received","Frame",str(framecount),":".join(hexdump[0:6]),"<",":".join(hexdump[6:12]),ether_type_names[ether_types.index(hexdump[12]+hexdump[13])]);
	out=" ".join(out)
	print(out,end="")
	filedes.write("\n\n"+out)
	filedes.write("\n#######################Hex dump############################\n");
	filedes.write(" ".join(hexdump));
	filedes.write("\n###########################################################\n");
	packet=hexdump[14:]
	etype=hexdump[12]+hexdump[13];
	if(etype=="0800"):
		filedes.write("\nIPv4 Packet");
		ProcessIPv4Packet(packet, len(packet));
	else:
		print("");
		filedes.write("\n??????????? Skipping Packet ????????????????\n");


