from collections import defaultdict

from pox.lib.addresses import IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ETHER_ANY, ETHER_BROADCAST, ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.udp import udp
import pox.openflow.libopenflow_01 as of

from lru_cache import LRUCache

CC_SIZE = 1
CP_RESP = "response"
CP_REQ = "request"
ROUTER_RESP_UDP_PORT = 4950
ROUTER_REQ_UDP_PORT = 4951
LOCAL_HOST_OUT_PORT = 1


class NDNRouter (object):
  """
  Contains the data structures that define and identify an NDN router.
  """

  def __init__ (
    self, name, ip, local_host, local_host_ip, local_host_server_udp_port,
    local_host_contents
  ):
    self.name = name
    self.arp_cache = {}
    self.arp_message_queue = defaultdict(list)
    self.ip = ip
    self.cc = LRUCache(CC_SIZE)
    self.crt = defaultdict(list)  # content name: rcvd to port
    self.local_host = local_host
    self.local_host_crt = {}  # content name: local hosts's UDP src port
    self.local_host_ip = local_host_ip
    self.local_host_server_udp_port = local_host_server_udp_port
    self.local_host_contents = local_host_contents


class NDNRouting (object):
  """
  Performs routing to retrieve a content from a network.
  """

  def __init__ (self, connection):
    self.connection = connection
    connection.addListeners(self)

  def port_to_mac (self, port_no):
    port = self.connection.ports[port_no]
    return port.hw_addr

  def send_packet (self, packet_in, out_port):
    msg = of.ofp_packet_out()
    msg.data = packet_in
    action = of.ofp_action_output(port=out_port)
    msg.actions.append(action)
    self.connection.send(msg)

  def handle_arp_pkt (self, packet, packet_in, dpid):
    arpp = packet.payload
    try:
      if arpp.protosrc != self.router[dpid].local_host_ip:
        raise Exception
    except Exception:
      # drop the packet because of invalid IP
      return
    if arpp.opcode == arp.REQUEST:
      # send port's MAC address to requester
      arp_reply = self.get_arp_reply_pkt(
        src_mac=self.port_to_mac(LOCAL_HOST_OUT_PORT), dst_mac=packet.src,
        src_ip=self.router[dpid].ip, dst_ip=arpp.protosrc,
      )
      self.send_packet(arp_reply.pack(), LOCAL_HOST_OUT_PORT)
    elif arpp.opcode == arp.REPLY:
      if arpp.protosrc in self.router[dpid].arp_message_queue:
        # send all messages from message queue that are satisfied by ARP reply
        self.router[dpid].arp_cache[arpp.protosrc] = arpp.hwsrc
        for to_send in self.router[dpid].arp_message_queue[arpp.protosrc]:
          to_send.src = self.port_to_mac(LOCAL_HOST_OUT_PORT)
          to_send.dst = arpp.hwsrc
          self.send_packet(to_send.pack(), LOCAL_HOST_OUT_PORT)
        del self.router[dpid].arp_message_queue[arpp.protosrc]

  def handle_ip_pkt (self, packet, packet_in, dpid):
    raise NotImplementedError("Abstract method")

  def handle_cp_pkt (self, packet, packet_in, dpid):
    raise NotImplementedError("Abstract method")

  def act_like_router (self, packet, packet_in, dpid):
    raise NotImplementedError("Abstract method")

  def process_crt(self, dpid, content):
    raise NotImplementedError("Abstract method")

  def send_udp_to_host (self, dpid, udp_pkt, dst_ip, out_port):
    if dst_ip in self.router[dpid].arp_cache:
      dst_mac = self.router[dpid].arp_cache[dst_ip]
      udp_pkt.dst = dst_mac
      self.send_packet(udp_pkt.pack(), out_port)
    else:
      arp_request = self.get_arp_request_pkt(
        self.port_to_mac(out_port), self.router[dpid].ip, dst_ip
      )
      self.router[dpid].arp_message_queue[dst_ip].append(udp_pkt)
      self.send_packet(arp_request.pack(), out_port)

  def get_content_loc (self, dpid, content):
    raise NotImplementedError("Abstract method")

  def get_arp_reply_pkt (self, src_mac, dst_mac, src_ip, dst_ip):
    arp_reply = arp()
    arp_reply.hwdst = dst_mac
    arp_reply.protodst = dst_ip
    arp_reply.hwsrc = src_mac
    arp_reply.protosrc = src_ip
    arp_reply.opcode = arp.REPLY
    ether = ethernet()
    ether.type = ethernet.ARP_TYPE
    ether.dst = dst_mac
    ether.src = src_mac
    ether.payload = arp_reply
    return ether

  def get_arp_request_pkt (self, src_mac, src_ip, dst_ip):
    arp_request = arp()
    arp_request.hwdst = ETHER_ANY
    arp_request.protodst = dst_ip
    arp_request.hwsrc = src_mac
    arp_request.protosrc = src_ip
    arp_request.opcode = arp.REQUEST
    ether = ethernet()
    ether.type = ethernet.ARP_TYPE
    ether.dst = ETHER_BROADCAST
    ether.src = src_mac
    ether.payload = arp_request
    return ether

  def get_content_pkt (self, type, content, src_mac):
    ether = ethernet()
    ether.type = ethernet.CP_TYPE
    ether.dst = ETHER_ANY
    ether.src = src_mac
    ether.payload = type + "," + content
    return ether

  def get_udp_resp (
    self, src_port, dst_port, src_ip, dst_ip, src_mac, dst_mac, content
  ):
    udp_resp = udp()
    udp_resp.srcport = src_port
    udp_resp.dstport = dst_port
    udp_resp.payload = content
    ipv4_pkt = ipv4()
    ipv4_pkt.srcip = src_ip
    ipv4_pkt.dstip = dst_ip
    ipv4_pkt.protocol = ipv4.UDP_PROTOCOL
    ipv4_pkt.payload = udp_resp
    ether = ethernet()
    ether.type = ethernet.IP_TYPE
    ether.dst = dst_mac
    ether.src = src_mac
    ether.payload = ipv4_pkt
    return ether
