# JOBS:
# ONE TO ONE
# 1) given IP address/Hostname    IS ONLINE/ ARE THEY CONNECTED TO THE NETWORK?  --- JOB SEEKER FINDS THIS OUT NOTE: is this sniffing? must include IP
# LINUX: ip addr show
#WINDOWS: ipconfig /all


# 2) detect status of given port at an IP address (open/closed/filtered), can use UDP or TCP ports. MUST INCLUDE IP + port number
# 3) detect all live IP addresses on a given subet. target subnet is required  in a.b.c.d/x format?
# 4) detect status of all registered TCP-UDP ports on given IP address/subnet

# ONE-TO-MANY
# 1) execute an ICMP flood attack against a given IP or subnet
# 2) execute a TCP flood attack against an IP or port
# 3) UDP flood attack on IP/Port

# requirements know sniffing and sending packets I guess.

import socket
import threading

# Variables below are constants
HEADER = 64  # header describes the properties of the message that it comes with
PORT = 5050  # Port that the socket will be using
HOST_NAME = socket.gethostname()  # will obtain the name of the machine
# will obtain the IP address by using the machine name
SERVER = socket.gethostbyname(HOST_NAME)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((SERVER, PORT))  # passed as tuple
FORMAT = 'utf-8'
DISCONNECT_MSG = "!disconnect"


def ClientHandler(addr, conn):  # function takes in a socket object and an address
    print(f"Client {addr} has connected.")
    connected = True
    while connected:
        msg_length = conn.recv(HEADER).decode(FORMAT)
        if msg_length:  # will ignore any messages with are 0, usually connection a 0 message is sent
            msg_length = int(msg_length)  # convert message length to an int
            # code will stop here until a msg is received from the client, it will receive a HEADER number of bytes and it will decode the message from its bytes format to a string.

            msg = conn.recv(msg_length).decode(FORMAT)
            # displays message
            print(f"{addr}  has sent the following message: {msg}")
            if msg == DISCONNECT_MSG:  # if client asks to disconnect it will disconnect
                connected = False
    conn.close()


def Init():  # this function will be called to initilize the server
    server.listen()
    print(f"Job Creator is listening on + {SERVER}")
    while True:
        # will wait for a connection and store address in addr and a socket object in conn
        conn, addr = server.accept()
        # will start a thread where the function ClientHandler will be used to handle the upcoming connection.
        thread = threading.Thread(target=ClientHandler, args=(addr, conn))
        thread.start()

        # will display all active threads, we are subtracting 1 since we will always have 1 active thread at minimum even without connections
        print(
            f"THE NUMBER OF ACTIVE CONNECTIONS IS CURRENTLY  {threading.active_count() - 1}")


def CreateJob(string):
    if(string == 'IsIPOnline'):
        IsIPOnline()
    elif(string == 'LookupNetworkConn'):
        LookupNetworkConn()
    elif(string == 'TCPFlood'):
        TCPFlood()
    else:
        UDPFlood()


def IsIPOnline():
    print("BLANK IS ONLINE!")


def LookupNetworkConn():
    print("LOOKED UP!")


def TCPFlood():
    print("BLANK HAS BEEN TCP FLOODED!")


def UDPFlood():
    print("BLANK HAS BEEN UDP FLOODED!")

#test
# CreateJob('IsIPOnline')
# CreateJob('LookupNetworkConn')
# CreateJob('TCPFlood')
# CreateJob('UDPFlood')


print("initializing server...")
Init()

# scapy
# SENDING
# send(IP(src="192.168.1.103",dst="192.168.1.1")/ICMP()/"HelloWorld")   the first / separates the protocol from the header data.
# SNIFFING
#sniff(iface="wlp4s0", prn=lambda x:x.summary)
# DOSSING
#send(IP(src="192.168.1.103", dst="192.168.1.1")/TCP(sport=80, dport=80), count=10000)
