# sniffer-python
Python based network sniffer. It works at Data Link Layer
T
his documentation is intended to explain a python based network tool called Packet Sniffer. This packet sniffer can be used legitimately by a network or system administrator to monitor and troubleshoot network traffic. It decodes the network traffic and makes sense of it. When somebody runs this packet sniffer on a computer, the selected network interface of that computer will be switched into promiscuous mode, listening to all the network traffic on the network rather than just those packets intended for it. It makes a copy of each packet flowing through that network interface and finds the source and destination MAC addresses of the packets. It decodes the protocols in the packets given below:
1. IP (Internet Protocol)
2. TCP (Transmission Control Protocol)
3. UDP (User Datagram Protocol)
4. ICMP 
The output is appended into a text file, so that the people can understand the network traffic and later analyze it.

Platform: Linux, Python3
This sniffer is implemented by using raw socket. A raw socket is used to receive raw packets. This means packets received at the Ethernet layer will directly pass to the raw socket. Following code is used to implement raw socket in python3.

import socket
import os
os.system("ip link set %s promisc on"%(sys.argv[1]))
rsocket=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0003));
while(True):
	buffers=rsocket.recvfrom(65565)

 os.system("ip link set %s promisc on"%(sys.argv[1])). This line will set the promiscuous mode on selected  network interface
