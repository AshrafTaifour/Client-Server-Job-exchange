# INSTRUCTIONS:
# Make sure the TARGET_IP matches the IP of the machine that you want to test, and that it matches the TARGET_IP in the server.py file
# Make sure LIST_OFIPS matches the current live IPs on your subnet
# Make sure the Function/job you're testing is the function that the server.py is assigning to client.py
# RUN ONLY ONE TEST AT A TIME (the test should match the one job assigned by the server)
# run the server first 'python3 server.py'
# then run 'sudo python3 -m unittest test_client.py'

import scapy
import unittest
from client import checkOneIP, checkAllIPs, TCPFlood, ICMPFlood


TARGET_IP = '192.168.1.144'
# this should match the current devices that can be detected so you can test the function
LIST_OFIPS = ['DESKTOP-44HR2VL', 'Chromecast']
PORT_NUM = 5050

# one test at a time


def test_checkOneIP():
    exp_ret = f"{TARGET_IP} is connected to the network!"
    actual_ret = checkOneIP(TARGET_IP, 'none')

    assert exp_ret == actual_ret


# def test_checkALLIPs():
#    exp_ret = LIST_OFIPS
#    actual_ret = checkAllIPs(TARGET_IP)
#
#    assert exp_ret == actual_ret


# def test_TCPFlood():
#    exp_ret = f"Successfully Flooded IP Address {TARGET_IP} At Port Number {PORT_NUM}"
#    actual_ret = TCPFlood(TARGET_IP, PORT_NUM)
#    assert exp_ret == actual_ret


# def test_ICMPFlood():
#    exp_ret = f"I have flooded {TARGET_IP} with 10 ICMP Packets!"
#    actual_ret = ICMPFlood(TARGET_IP)
#
#    assert exp_ret == actual_ret
