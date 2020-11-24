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
# CONSTANTS
HEADER = 64  # wILL BE THE HEADER LENGTH
PORT = 5050  # Port that the socket will be using
FORMAT = 'utf-8'  # THIS WILL BE THE ENCODING FORMAT WHEN SENDING HEADER
# WHEN CLEINT DISCONNECTS OR TERMINATES CONNECTION
DISCONNECT_MESSAGE = "!disconnect"
# NOTE THIS IS LOCAL IP ADDRESS ON LAN, PLEASE ADJUST IT TO THE SERVER IP ADDRESS BY RUNNING IPCONFIG ON WINDOWS
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
    print(client.recv(2048).decode(FORMAT))  # print receive message from


send("Hello World!")  # first message to send

send("Computer Network is fun!")  # second message to send
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
