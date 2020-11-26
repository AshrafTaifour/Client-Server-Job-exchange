# JOBS:
# ONE TO ONE
# 1) given IP address/Hostname    IS ONLINE/ ARE THEY CONNECTED TO THE NETWORK?  --- JOB SEEKER FINDS THIS OUT NOTE: is this sniffing? must include IP
# 2) detect status of given port at an IP address (open/closed/filtered), can use UDP or TCP ports. MUST INCLUDE IP + port number
# 3) detect all live IP addresses on a given subet. target subnet is required  in a.b.c.d/x format?
# 4) detect status of all registered TCP-UDP ports on given IP address/subnet

# ONE-TO-MANY
# 1) execute an ICMP flood attack against a given IP or subnet
# 2) execute a TCP flood attack against an IP or port
# 3) UDP flood attack on IP/Port

# requirements know sniffing and sending packets I guess.

import socket  # socket object will be used to make the connection
from scapy.all import ARP, Ether, srp


# CONSTANTS
HEADER = 64  # wILL BE THE HEADER LENGTH
PORT = 5050  # Port that the socket will be using
FORMAT = 'utf-8'  # THIS WILL BE THE ENCODING FORMAT WHEN SENDING HEADER
# WHEN CLIENT DISCONNECTS OR TERMINATES CONNECTION
DISCONNECT_MESSAGE = "!disconnect"
# NOTE THIS IS LOCAL IP ADDRESS ON LAN, PLEASE ADJUST IT TO THE SERVER IP ADDRESS BY RUNNING ifconfig on linux or ipconfig /all on Windows
SERVER = "192.168.1.134"
ADDR = (SERVER, PORT)  # ADDRESS WILL BE TUPLE OF IP ADDRESS OF SERVER AND PORT#
# CREATE NEW VARIABLE CALLED CLIENT AND MAKE IT AN OBJECT OF THIS CONNECTION
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)  # CLIENT CONNECTS TO ABOVE IP ADDRESS


def send(msg):  # DEFINED FUNCTION TO SEND MSG FROM CLIENT
    message = msg.encode(FORMAT)  # TAKE MSG AND ENCOD IT
    msg_length = len(message)  # GET LENGTH OF ENCODED MESSAGE
    # SEND_length for header is equal to encoded message length
    send_length = str(msg_length).encode(FORMAT)
    # padd the message up to 124 bits adding b' ' byte of space
    send_length += b' ' * (HEADER - len(send_length))
    # send info to server first of the padded header message
    client.send(send_length)
    client.send(message)  # send encoded message to server
    

def greetingMsg(): #'[HELLO]' protocol establishes the connection
    return "[HELLO] Hello World!"


#def JobHandler():


def CheckIP(string, target_ip): #sends ARP request to an IP address followed by a broadcast packet, response will have a MAC address with all network users' IPs
	if string == '[IP#1]': #find if host is online by ip addr
		arp = ARP(pdst = target_ip) #create ARP packet
		ether = Ether(dst="ff:ff:ff:ff:ff:ff") #create ether broadcast packet
		packet = ether/arp #stacks ether and arp packets 
		result = srp(packet, timeout=3)[0] #sends the packet and receives them at the data link layer, times out in 3 secs
		#result contains sent and received packet in pairs
		clients = []
		for sent, received in result:
			#will append ip and MAC address to 'clients' list for every response received.
			 clients.append({'ip': received.psrc, 'mac': received.hwsrc})
		return clients

	#else: #find if host is online by hostname



send(greetingMsg())  # first message to send
input()
rcvd_msg = client.recv(2048).decode(FORMAT)
clients = CheckIP(rcvd_msg[0:6], rcvd_msg[10:26])
print(rcvd_msg)  # print receive message from
send("The Following Devices are currently connected to the network: ")
input()
for client in clients:
	client_str = str("{:16}    {}".format(client['ip'], client['mac']))
	print(client_str)
	#client_str = f"{client.ip}"
	#send(client_str)
input()  # when user hits enter or any input it will now disconnect
send("Disconnecting now!")  # disconnect message
send(DISCONNECT_MESSAGE)  # send disconnect message







# scapy
# SENDING
# send(IP(src="192.168.1.103",dst="192.168.1.1")/ICMP()/"HelloWorld")   the first / separates the protocol from the header data.
# SNIFFING
#sniff(iface="wlp4s0", prn=lambda x:x.summary)
# DOSSING
#send(IP(src="192.168.1.103", dst="192.168.1.1")/TCP(sport=80, dport=80), count=10000)
