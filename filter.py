from scapy.all import * #sniff , send , sendp, IP,ARP,Ether,UDP,TCP,DNS,DNSQR
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.tls.all import TLS
import argparse


parser = argparse.ArgumentParser(description="Python-based DNS filter!")

parser.add_argument('-f', '--filter-dns', action="store_true", dest="filter_dns" , help="Enable pure DNS based filtering (Default: False)")
parser.set_defaults(filter_dns=False)

parser.add_argument('-d', '--domain', action="store", default="index.hu", type=str, dest="domain_to_filter" , help="Specify the domain to filter for with DNS (Default: index.hu)! Use only with -f/--filter-dns option!")

parser.add_argument('-g', '--filter-doh', action="store_true", dest="filter_doh" , help="Enable DoH-based filtering - This will drop all packets that looks like a DoH query (Default: False)")
parser.set_defaults(filter_doh=False)

results = parser.parse_args()

filter_dns=results.filter_dns
domain_to_filter=results.domain_to_filter
filter_doh=results.filter_doh

print("Configuration:")
if(not filter_dns):
    print("BLIND FORWARDING MODE")
else:
    print("The following domain will be blocked via pure DNS: {}".format(domain_to_filter))

if(not filter_doh):
    print("DNS-over-HTTPS is allowed")
else:
    print("DNS-over-HTTPS needs to be blocked")


##  ============ PURE DNS FILTERING ============
def filter_dns(packet):
    if packet.qdcount > 0 and isinstance(packet.qd, DNSQR):
        #print("DNS query")
        name = packet[DNSQR].qname
        #print(name)
        if(domain_to_filter in str(name)):
            # DNS queries looking for domain_to_filter will be dropped
            print("Gotcha {}  - DROP".format(domain_to_filter))
        else:
            # FORWARD every other DNS queries
            sendp(packet, iface="eth0")
            print("FORWARDING DNS query ({})...".format(name))
## ------- PURE DNS FILTERING END ------


## ============  DNS-over-HTTPS filtering ===========
def filter_doh(packet):
	sendp(packet, iface="eth0")
	print("DoH Filter not implemented...FORWARDING")
    
## ----- DNS-over-HTTPS filtering END ----------------




def filter_packets(packet):
	#Scapy cannot distinguish between incoming and outgoing packets, so
	#to avoid infinite loop, let's change outgoing packet's MAC
	new_mac="00:11:22:33:44:55"
	if IP in packet:
        #packets coming from the user
		if(packet[0][1].dst != "10.10.10.101" and packet[0][0].src != new_mac):
            #setting the source MAC to a pseudo-random one
			packet[0][0].src=new_mac

			### ------- HERE COMES ANY FILTERING --------- ###
			##------- NO FILTER ---------
			if(not filter_dns and not filter_doh):
				# FORWARD everything else
				sendp(packet, iface="eth0")
				print("FORWARDING...")
			## -------- FILTERING -------
			else:
				##  ============ PURE DNS FILTERING ============
				if(packet.haslayer(DNS) and filter_dns):
					filter_dns(packet)
				## ------- PURE DNS FILTERING END ------

				## ============  DNS-over-HTTPS filtering ===========
				elif(packet.haslayer(TLS) and filter_doh):
					filter_doh(packet)
				## ----- DNS-over-HTTPS filtering END ----------------
				else:
					sendp(packet, iface="eth0")
					print("FORWARDING...")
			####============== FILTERING ENDS ============####


		elif(packet[0][1].dst == "10.10.10.101"):
			# This host was the destination
			# print("I was the destination")
			pass
		elif(packet[0][1].src == "10.10.10.101"):
			# Reply sent
			# print("Reply sent")
			pass
		else:
			#this is actually the same packet but outgoing...scapy sniffer
			# print("Packet sent out")
			pass


#we cannot filter on anything, because then packets missing the filter will not
#be forwarded by default
sniff(iface="eth0", prn=filter_packets)
