from collections import defaultdict
import random

from pox.core import core
from pox.lib.addresses import IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ETHER_ANY, ETHER_BROADCAST, ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.udp import udp
import pox.openflow.libopenflow_01 as of

from lru_cache import LRUCache

CC_SIZE = 8
CP_RESP = "response"
CP_REQ = "request"
ROUTER_RESP_UDP_PORT = 4950
ROUTER_REQ_UDP_PORT = 4951
LOCAL_HOST_OUT_PORT = 1
log = core.getLogger()

"""
NDN 2:
1. if don't know how to route, send broadcast.
2. receive periodic advertisements from neighboring routers to know how to route.

CAMs:
contain comma-separated hosts/routers that the current router knows about.
"""


class Router (object):
  """
  Contains the data structures that define and identify a router.
  """

  def __init__ (
    self, name, ip, local_host, local_host_ip, local_host_server_udp_port,
    local_host_contents
  ):
    self.name = name
    self.arp_cache = {}
    self.arp_message_queue = defaultdict(list)
    self.cp_message_queue = defaultdict(list)
    self.ip = ip
    self.cc = LRUCache(CC_SIZE)
    self.rt = defaultdict(set)  # content name: out ports
    self.crt = defaultdict(list)  # content name: rcvd to port
    self.local_host = local_host
    self.local_host_crt = {}  # content name: local hosts's UDP src port
    self.local_host_ip = local_host_ip
    self.local_host_server_udp_port = local_host_server_udp_port
    self.local_host_contents = local_host_contents
    self.prev_cam = set()


class DistinctNDNRouting (object):
  """
  Performs routing to retrieve a content from a network, assuming distinct
  controller for each router.
  """

  def __init__ (self, connection):
    self.connection = connection
    connection.addListeners(self)
    self.router = {
      1: Router("r1", IPAddr("10.0.1.1"), "h1", IPAddr("10.0.1.100"), 10001, ("content1_1", "content1_2")),
      2: Router("r2", IPAddr("10.0.2.1"), "h2", IPAddr("10.0.2.100"), 10002, ("content2_1", "content2_2")),
      3: Router("r3", IPAddr("10.0.3.1"), "h3", IPAddr("10.0.3.100"), 10003, ("content3_1", "content3_2")),
      4: Router("r4", IPAddr("10.0.4.1"), "h4", IPAddr("10.0.4.100"), 10004, ("content4_1", "content4_2")),
    }

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
    ipp = packet.payload
    udpp = ipp.payload
    content = udpp.payload
    if udpp.srcport == self.router[dpid].local_host_server_udp_port:
      # response coming from server process of host
      self.process_crt(dpid, content)
    else:
      # request coming from client process of host
      # 1. check if CC contains content. If it does not, invoke RT.
      if self.router[dpid].cc.exists(content):
        udp_resp = self.get_udp_resp(
          src_port=ROUTER_RESP_UDP_PORT, dst_port=udpp.srcport,
          src_ip=self.router[dpid].ip,
          dst_ip=self.router[dpid].local_host_ip,
          src_mac=self.port_to_mac(LOCAL_HOST_OUT_PORT),
          dst_mac=ETHER_ANY, content=content,
        )
        self.send_udp_to_host(
          dpid=dpid, udp_pkt=udp_resp, dst_ip=self.router[dpid].local_host_ip,
          out_port=LOCAL_HOST_OUT_PORT,
        )
      else:
        out_port = self.get_content_loc(dpid, content)
        # add request for content to local CRT
        assert not self.router[dpid].local_host_crt
        self.router[dpid].local_host_crt[content] = udpp.srcport
        # create and send content request packet out of port
        if out_port:
          content_pkt = self.get_content_pkt(
            type=CP_REQ, content=content, src_mac=self.port_to_mac(out_port),
          )
          self.send_packet(content_pkt.pack(), out_port)
        else:
          content_pkt = self.get_content_pkt(
            type=CP_REQ, content=content, src_mac=ETHER_ANY,
          )
          if out_port:
            content_pkt.src = self.port_to_mac(out_port)
            self.send_packet(content_pkt.pack(), out_port)
          else:
            # doesn't know how to route, add to queue and wait for CAM
            self.router[dpid].cp_message_queue[content].append(content_pkt)

  def handle_cp_pkt (self, packet, packet_in, dpid):
    type, content = packet.payload.split(",")
    if type == CP_REQ:
      # 1. check if CC contains content. If it does not, invoke RT.
      if self.router[dpid].cc.exists(content):
        content_pkt = self.get_content_pkt(
          type=CP_RESP, content=content,
          src_mac=self.port_to_mac(packet_in.in_port),
        )
        self.send_packet(content_pkt.pack(), packet_in.in_port)
      else:
        out_port = self.get_content_loc(dpid, content)
        # add request for content to CRT
        self.router[dpid].crt[content].append(packet_in.in_port)
        if out_port == LOCAL_HOST_OUT_PORT:
          # send request to local host
          udp_req = self.get_udp_resp(
            src_port=ROUTER_REQ_UDP_PORT,
            dst_port=self.router[dpid].local_host_server_udp_port,
            src_ip=self.router[dpid].ip,
            dst_ip=self.router[dpid].local_host_ip,
            src_mac=self.port_to_mac(out_port), dst_mac=ETHER_ANY,
            content=content,
          )
          self.send_udp_to_host(
            dpid=dpid, udp_pkt=udp_req, dst_ip=self.router[dpid].local_host_ip,
            out_port=out_port
          )
        else:
          content_pkt = self.get_content_pkt(
            type=CP_REQ, content=content, src_mac=ETHER_ANY,
          )
          if out_port:
            content_pkt.src = self.port_to_mac(out_port)
            self.send_packet(content_pkt.pack(), out_port)
          else:
            # doesn't know how to route, add to queue and wait for CAM
            self.router[dpid].cp_message_queue[content].append(content_pkt)
    elif type == CP_RESP:
      if content in self.router[dpid].local_host_crt:
        # update cc
        self.router[dpid].cc.insert(content)
        # send response to local host
        local_host_client_udp_port = self.router[dpid].local_host_crt[content]
        udp_resp = self.get_udp_resp(
          src_port=ROUTER_RESP_UDP_PORT, dst_port=local_host_client_udp_port,
          src_ip=self.router[dpid].ip,
          dst_ip=self.router[dpid].local_host_ip,
          src_mac=self.port_to_mac(LOCAL_HOST_OUT_PORT), dst_mac=ETHER_ANY,
          content=content,
        )
        self.send_udp_to_host(
          dpid=dpid, udp_pkt=udp_resp, dst_ip=self.router[dpid].local_host_ip,
          out_port=LOCAL_HOST_OUT_PORT
        )
        # remove entry from local_host_crt
        del self.router[dpid].local_host_crt[content]
        assert not self.router[dpid].local_host_crt
      self.process_crt(dpid, content)

  def handle_cam_pkt (self, packet, packet_in, dpid):
    contents = packet.payload.split(",")
    # content_name:h1,content_name:r1, ...
    # update rt
    for content in contents:
      self.router[dpid].rt[content].add(packet_in.in_port)
      if content in self.router[dpid].cp_message_queue:
        for content_pkt in self.router[dpid].cp_message_queue[content]:
          content_pkt.src = self.port_to_mac(packet_in.in_port)
          self.send_packet(content_pkt.pack(), packet_in.in_port)
        del self.router[dpid].cp_message_queue[content]

  def act_like_router (self, packet, packet_in, dpid):
    if packet.type == packet.ARP_TYPE:
      self.handle_arp_pkt(packet, packet_in, dpid)
    elif packet.type == packet.IP_TYPE:
      self.handle_ip_pkt(packet, packet_in, dpid)
    elif packet.type == packet.CP_TYPE:
      self.handle_cp_pkt(packet, packet_in, dpid)
    elif packet.type == packet.CAM_TYPE:
      self.handle_cam_pkt(packet, packet_in, dpid)
    self.send_cam_to_neighs(dpid)

  def process_crt(self, dpid, content):
    if content in self.router[dpid].crt:
      # update cc
      self.router[dpid].cc.insert(content)
      for to_snd_port in self.router[dpid].crt[content]:
        # send response to preceding router
        content_pkt = self.get_content_pkt(
          type=CP_RESP, content=content,
          src_mac=self.port_to_mac(to_snd_port),
        )
        self.send_packet(content_pkt.pack(), to_snd_port)
      # remove entry from crt
      del self.router[dpid].crt[content]

  def send_cam_to_neighs (self, dpid):
    data = {
      self.router[dpid].local_host_contents[0],
      self.router[dpid].local_host_contents[1]
    }
    data.union(self.router[dpid].cc.items)
    data.update(self.router[dpid].rt.keys())
    if self.router[dpid].prev_cam != data:
      self.router[dpid].prev_cam = data
      payload = ",".join(list(data))
      ether = ethernet()
      ether.type = ethernet.CAM_TYPE
      ether.payload = payload
      ether.dst = ETHER_ANY
      ether.src = self.port_to_mac(2)
      self.send_packet(ether.pack(), 2)
      ether.src = self.port_to_mac(3)
      self.send_packet(ether.pack(), 3)

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
    if content in self.router[dpid].local_host_contents:
      return LOCAL_HOST_OUT_PORT
    out_ports = self.router[dpid].rt[content]
    if out_ports:
      return random.choice(list(out_ports))

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

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    dpid = event.connection.dpid
    packet = event.parsed
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return
    packet_in = event.ofp
    self.act_like_router(packet, packet_in, dpid)


def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    DistinctNDNRouting(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
