# Client-Server-Job-exchange

# INSTRUCTIONS:
1) Change the SERVER const to match your machine's server
2) Change TARGET_IP to match the IP where you can detect the packets
3) run server.py first (send only one job at a time to test each one individually)
4) run client.py with administrator privileges

# JOBS:
# ONE TO ONE
1) given IP address/Hostname    IS ONLINE/ ARE THEY CONNECTED TO THE NETWORK? NOTE: name of function is checkOneIP
2) detect all live IP addresses on a given subet. NOTE: name of function is checkAllIPs

# ONE-TO-MANY
1) execute an ICMP flood attack against a given IP or subnet NOTE: Name of function is ICMPFlood()
2) execute a TCP flood attack against an IP or port NOTE: Name of function is TCPFlood()



# INSTRUCTIONS FOR test_client.py:
Make sure the TARGET_IP matches the IP of the machine that you want to test, and that it matches the TARGET_IP in the server.py file
Make sure LIST_OFIPS matches the current live IPs on your subnet
Make sure the Function/job you're testing is the function that the server.py is assigning to client.py
RUN ONLY ONE TEST AT A TIME (the test should match the one job assigned by the server)
run the server first 'python3 server.py'
then run 'sudo python3 -m unittest test_client.py'
