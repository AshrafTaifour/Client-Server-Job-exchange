# INSTRUCTIONS:
# 1) Change the SERVER const to match your machine's server
# 2) Change TARGET_IP to match the IP where you can detect the packets
# 3) run server.py first (send only one job at a time to test each one individually)
# 4) run client.py with administrator priviledges

# JOBS:
# ONE TO ONE
# 1) given IP address/Hostname    IS ONLINE/ ARE THEY CONNECTED TO THE NETWORK? NOTE: name of function is checkOneIP
# 3) detect all live IP addresses on a given subet. NOTE: name of function is checkAllIPs

# ONE-TO-MANY
# 1) execute an ICMP flood attack against a given IP or subnet NOTE: Name of function is ICMPFlood()
# 2) execute a TCP flood attack against an IP or port NOTE: Name of function is TCPFlood()


import socket
import threading
import time

# Variables below are constants
HEADER = 1024  # header describes the properties of the message that it comes with
PORT = 5050  # Port that the socket will be using
SERVER = '192.168.1.134'  # my machine's IP, obtained by ifconfig
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((SERVER, PORT))  # passed as tuple
FORMAT = 'utf-8'
DISCONNECT_MSG = "!disconnect"
# IP of my laptop so I can test on wireshark and see these packets
TARGET_IP = '192.168.1.144'
TARGET_IPBROADCAST = '192.168.1.144/24'  # will list all ips
TARGET_PORT = '5050'  # port num you're targeting
TARGET_HOSTNAME = 'nouriddin'  # name of machine you want to check if it's online

# function takes in a socket object and an address, this is unique to each client


def ClientHandler(addr, conn):
    print(f"Client {addr} has connected.")

    # variable is used to check if the connected client used the proper [HELLO] protocol
    HELO_PROTO = False

    connected = True
    while connected:
        msg_length = conn.recv(HEADER).decode(FORMAT)
        if msg_length:  # will ignore any messages with are 0, usually connection a 0 message is sent
            msg_length = int(msg_length)  # convert message length to an int
            # code will stop here until a msg is received from the client, it will receive a HEADER number of bytes and it will decode the message from its bytes format to a string.

            msg = conn.recv(msg_length).decode(FORMAT)
            # displays message
            print(f"{addr}  has sent the following message: {msg}")

            if(HELO_PROTO == False):
                # 0:7 is [HELLO] which is the first msg that is agreed on
                HELO_PROTO = EstablishConn(msg[0:7])
                connected = HELO_PROTO

            # Send only one job!

            # conn.send(LookupNetworkConn(TARGET_IPBROADCAST))  # WORKS!
            conn.send(IsIPOnline(TARGET_IP, 'none'))  # WORKS!
            # conn.send(IsIPOnline('none', TARGET_HOSTNAME))  # WORKS!
            # conn.send(TCPFlood(TARGET_IP, TARGET_PORT)) #WORKS!
            # conn.send(ICMPFlood(TARGET_IP))  # WORKS!
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


def EstablishConn(initMsg):  # ensures client is using correct protocol
    if(initMsg == "[HELLO]"):
        print("HELLO PROTOCOL SUCCESSFULL, CONNECTION ESTABLISHED")
        return True
    else:
        print("HELLO PROTOCOL FAILED, DISCONNECTING")
        return False


def LookupNetworkConn(ipaddr):  # THIS WORKS!
    return f"[IP#1] List all the connections on the subnet of {ipaddr} please".encode(FORMAT)

# asks client if an IP address or hostname are online on a network.


def IsIPOnline(ipaddr, hostname):
    if(hostname == "none"):
        return f"[IP#2] is {ipaddr} Online?".encode(FORMAT)
    else:
        return f"[IP#3] is {hostname} Online?".encode(FORMAT)


def TCPFlood(target_ip, port_num):
    return f"[TCPF] Please TCP Flood {target_ip} at Port number {port_num}".encode(FORMAT)


def ICMPFlood(target_ip):
    return f"[ICMP] Please ICMP Flood {target_ip}".encode(FORMAT)


print("initializing server...")
Init()
