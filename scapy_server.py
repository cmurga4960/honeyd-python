import os
import rstr
import time
import threading
import netifaces as ni
from scapy.all import *
from colorama import Fore, Back, Style

# Interacts with a client by going through the three-way handshake.
# Shuts down the connection immediately after the connection has been established.
# Akaljed Dec 2010, https://akaljed.wordpress.com/2010/12/12/scapy-as-webserver/

'''
Use expression from /usr/share/nmap/nmap-service-probes
For example from nmap-service-probes file....
--------------------------------------------------------------------------------------------------------------------
# NoMachine Network Server
# Announce client version 5.6.7 (could be anything)
Probe TCP NoMachine q|NXSH-5.6.7\n|
ports 4000
rarity 9

match nomachine-nx m|^NXD-([\d.]+)\n| p/NoMachine NX Server remote desktop/ v/$1/ cpe:/a:nomachine:nx_server:$1/
--------------------------------------------------------------------------------------------------------------------
set tcp_experssion = r'^NXD-([\d.]+)\n'

- Note, not all services will work due to the limitations of rstr.xeger and nmaps usage of perl's 'i' and 's' options
- Avoid services that have "|s" or "|i" in them.
- Nmap rules that use the response to print the version may also lead to warnings or bad results.
- Expressions with non-zero bytes may be ify?

See notes at the bottom for more details.
'''

#CUSTOMIZE ME
ifacee = 'eth0'
server_port = 3000
# set tcp/udp_experssion = None if not using
tcp_expression = r'^2;http://[\d.]+:\d+/;[\d.]+;\d+:\d+;\w+,[\d.]+,PLUGIN_LOADED' #r'^ok$'  #r'^BUSY$'
udp_expression = tcp_expression
tcp_expression = None
color = True
#CUSTOMIZE ME

#EXTRAS
tcp_color = Fore.LIGHTMAGENTA_EX if color else ''
udp_color = Fore.LIGHTBLUE_EX if color else ''
reset_color = Style.RESET_ALL if color else ''
red = Fore.RED if color else ''
green = Fore.GREEN if color else ''
#EXTRAS


def answerTCP(packet):
	print(tcp_color + 'New tcp client:')
	packet.summary()
	print(reset_color, end="") 

	ValueOfPort = packet.sport
	SeqNr = packet.seq
	AckNr = packet.seq+1
	victim_ip = packet['IP'].src
	
	# send syn ack
	ip = IP(src=ip_addr, dst=victim_ip)
	tcp_synack = TCP(sport=server_port, dport=ValueOfPort, flags="SA", seq=SeqNr, ack=AckNr, options=[('MSS', 1460)])
	handshake = ip/tcp_synack
	print(tcp_color,end="")
	ANSWER = sr1(handshake, timeout=8)
	print(reset_color, end="") 
	if not ANSWER:
		print(red + "TIMEOUT on syn ack" + reset_color)
		return ""	

	# Capture next TCP packet if the client talks first
	#GEThttp = sniff(filter="tcp and src host "+str(victim_ip)+" and port "+str(server_port),count=1)
	#GEThttp = GEThttp[0]
	#AckNr = AckNr+len(GEThttp['Raw'].load)
	
	# send psh ack (main tcp packet)
	SeqNr += 1
	#payload="HTTP/1.1 200 OK\x0d\x0aDate: Wed, 29 Sep 2010 20:19:05 GMT\x0d\x0aServer: Testserver\x0d\x0aConnection: Keep-Alive\x0d\x0aContent-Type: text/html; charset=UTF-8\x0d\x0aContent-Length: 291\x0d\x0a\x0d\x0a<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\"><html><head><title>Testserver</title></head><body bgcolor=\"black\" text=\"white\" link=\"blue\" vlink=\"purple\" alink=\"red\"><p><font face=\"Courier\" color=\"blue\">-Welcome to test server-------------------------------</font></p></body></html>"
	payload = rstr.xeger(tcp_expression)
	tcp_pshack = TCP(sport=server_port, dport=ValueOfPort, flags="PA", seq=SeqNr, ack=AckNr, options=[('MSS', 1460)])
	tcp_main = ip/tcp_pshack/payload
	print(tcp_color,end="")
	ACKDATA = sr1(tcp_main, timeout=5)
	print(reset_color, end="") 
	if not ACKDATA:
		print(red + "TIMEOUT data ack" + reset_color)
		return ""
	
	# send fin
	SeqNr=ACKDATA.ack
	Bye=TCP(sport=server_port, dport=ValueOfPort, flags="FA", seq=SeqNr, ack=AckNr, options=[('MSS', 1460)])
	print(tcp_color,end="")
	send(ip/Bye)
	print(tcp_color+'tcp client done' + reset_color)
	return ""

def answerUDP(packet):
	print(udp_color + 'New udp client:')
	packet.summary()
	print(reset_color, end="") 
	ValueOfPort = packet.sport
	victim_ip = packet['IP'].src
	
	ip = IP(src=ip_addr, dst=victim_ip)
	udp = UDP(sport=server_port, dport=ValueOfPort)
	payload = rstr.xeger(udp_expression)
	udp_main = ip/udp/payload
	print(udp_color, end="") 
	send(udp_main)
	print(udp_color + 'udp client done' + reset_color)
	return ""

def startTCP():
	print(tcp_color + 'tcp server starting:', ip_addr, ":", server_port)
	print(reset_color,end="") 
	sniff(filter="tcp[tcpflags] & tcp-syn != 0 and dst host "+ip_addr+" and port "+str(server_port), prn=answerTCP, iface=ifacee)

def startUDP():
	print(udp_color + 'udp server starting:', ip_addr, ":", server_port)
	print(reset_color,end="") 
	sniff(filter="udp and dst host "+ip_addr+" and port "+str(server_port), prn=answerUDP, iface=ifacee)


if __name__ == '__main__':
	
	# Get IP addr and set iptables (if needed)
	ni.ifaddresses(ifacee)
	ip_addr = ni.ifaddresses(ifacee)[ni.AF_INET][0]['addr']
	
	# Start "servers"
	if tcp_expression:
		set_iptable = 'iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport '+str(server_port)+' -j DROP'
		if not set_iptable in os.popen('iptables-save').read():
			os.system(set_iptable)
		tcp_thread = threading.Thread(target=startTCP)
		tcp_thread.daemon = True
		tcp_thread.start()
	if udp_expression:
		#TODO make port specific?
		set_iptable = 'iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP'
		if not set_iptable in os.popen('iptables-save').read():
			os.system(set_iptable)
		udp_thread = threading.Thread(target=startUDP)
		udp_thread.daemon = True
		udp_thread.start()
	print(reset_color+'threads started')

	# Wait till killed
	while 1:
		try:
			time.sleep(1)
		except KeyboardInterrupt:
			break
		except:
			break
	#TODO clean iptables - not super important for RST though on high ports
	print(green + "Done" +  reset_color)

'''
NOTES
- If nmap flags as tcpwrapped service, its likely you are not responding (or responding incorrectly) after handshake.  E.g. bad ack or seq #
- If nmap does not recognize the service, you may need to set --version-intensity 9  or --version-all   (default is 7)
- Nmap skips ports 9100-9107 for -sV scan, even upon adding "-p 9100".  Use --allports  to bypass this.  
- Note, not all services will work due to the limitations of rstr.xeger and nmaps usage of perl's 'i' and 's' options.  
  In general, dynamically generating string that fit regex is a hard problem
- Nmap -O (OS scan) and -sU (UDP scan) options require root (at least on Android's Termux).
- The -sV option will not send UDP packet at all unless -sU is specified. Jeez nmap, letting me down here xD


LINKS
- Scapy send vs sendp  http://abunchofbaloney.blogspot.com/2014/09/scapy-send-vs-sendp.html\
- Nmap version options   https://nmap.org/book/man-version-detection.html
- Nmap service detction file format  https://nmap.org/book/vscan-fileformat.html#vscan-fileformat-example
- Nmap os dection workings  https://nmap.org/book/osdetect-methods.html
- Linux routing  https://www.cyberciti.biz/faq/linux-route-add/
- BPF syntax http://biot.com/capstats/bpf.html
'''

