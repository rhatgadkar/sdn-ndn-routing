import argparse
import socket
import sys


contents = {
    1: ("content1_1", "content1_2", "10.0.1.100", 10001),
    2: ("content2_1", "content2_2", "10.0.2.100", 10002),
    3: ("content3_1", "content3_2", "10.0.3.100", 10003),
    4: ("content4_1", "content4_2", "10.0.4.100", 10004),
}

parser = argparse.ArgumentParser(description="Determine host.")
parser.add_argument(
    "host_num", type=int, help="integer representing host number"
)
args = parser.parse_args()

serving_contents = contents[args.host_num]

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the port
server_address = (serving_contents[2], serving_contents[3])
print "starting up on %s port %s" % server_address
sock.bind(server_address)

while True:
    print "\nwaiting to receive message"
    data, address = sock.recvfrom(4096)
    
    print "received %s bytes from %s" % (len(data), address)
    print data
    
    if data in serving_contents[:2]:
        sent = sock.sendto(data, address)
        print "sent %s bytes back to %s" % (sent, address)
