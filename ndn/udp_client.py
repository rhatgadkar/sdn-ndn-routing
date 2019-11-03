import argparse
from collections import Counter
import random
import socket
import sys
import time


contents = {
    1: ("content1_1", "content1_2", "10.0.1.100", 10001),
    2: ("content2_1", "content2_2", "10.0.2.100", 10002),
    3: ("content3_1", "content3_2", "10.0.3.100", 10003),
    4: ("content4_1", "content4_2", "10.0.4.100", 10004),
}
local_routers = {
    1: ("10.0.1.1", 10001),
    2: ("10.0.2.1", 10002),
    3: ("10.0.3.1", 10003),
    4: ("10.0.4.1", 10004),
}

parser = argparse.ArgumentParser(description="Determine host.")
parser.add_argument(
    "host_num", type=int, help="integer representing host num"
)
args = parser.parse_args()

content_counts = Counter()
contents_to_get = {}
for host_num in contents.keys():
    if host_num != args.host_num:
        contents_to_get[contents[host_num][0]] = (
            contents[host_num][2], contents[host_num][3]
        )
        contents_to_get[contents[host_num][1]] = (
            contents[host_num][2], contents[host_num][3]
        )

server_address = local_routers[args.host_num]
server_ip = server_address[0]
num_requests = 0
start_time = time.time()
while contents_to_get:
    content_to_get = random.choice(contents_to_get.keys())

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Send data
        num_requests += 1
        print "\nRequest %d" % num_requests
        print "requesting \"%s\" from %s" % (content_to_get, server_ip)
        sent = sock.sendto(content_to_get, server_address)

        # Receive response
        data, server = sock.recvfrom(4096)
        print "received \"%s\" from %s" % (data, server_ip)
        content_counts[content_to_get] += 1
        if content_counts[content_to_get] == 100:
            del contents_to_get[content_to_get]
    finally:
        sock.close()
end_time = time.time()
duration = end_time - start_time
print "\nDuration: %s" % str(duration)
