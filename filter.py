from scapy.all import * #sniff , send , sendp, IP,ARP,Ether,UDP,TCP,DNS,DNSQR
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.fields import Field

def filter_packets(packet):
	# print("Packet received:")
	# print(packet.show())
	
	#Scapy cannot distinguish between incoming and outgoing packets, so
	#to avoid infinite loop, let's change outgoing packet's MAC
	new_mac="00:11:22:33:44:55"
	if IP in packet:
		if(packet[0][1].dst != "192.168.2.101" and packet[0][0].src != new_mac):
			packet[0][0].src=new_mac
			
			### ------- HERE COMES ANY FILTERING --------- ###

			if packet.haslayer(DNS):
				if packet.qdcount > 0 and isinstance(packet.qd, DNSQR):
					print("DNS query")
					name = packet[DNSQR].qname
					print(name)

					if("index.hu" in str(name)):
						# DNS queries looking for index.hu will be dropped
						print("Query to index.hu")
					else:
						# FORWARD every other DNS queries
						sendp(packet, iface="eth0")			
			else:
				# FORWARD everything else
				sendp(packet, iface="eth0")			
			####============== FILTERING ENDS ============####
			
		elif(packet[0][1].dst == "192.168.2.101"):
			# This host was the destination
			# print("I was the destination")
			pass
		elif(packet[0][1].src == "192.168.2.101"):
			# Reply sent
			# print("Reply sent")
			pass
		else:
			#this is actually the same packet but outgoing...scapy still gets it as an incoming one
			# print("Packet sent out")
			pass

def filter_packets_2(packet):
	if IP in packet:
		print("Packet received:")
		print(packet.show())
		if(packet[0][1].dst != "10.10.10.101"):
			sendp(packet, iface="eth1")
			print("outgoing packet:")
			print(packet.show())
		elif(packet[0][1].dst == "192.168.2.101"):
			print("I was the destination")
		# elif(packet[0][1].src == "192.168.2.101"):
		else:
			print("Reply sent")
			

sniff(iface="eth0", prn=filter_packets)


