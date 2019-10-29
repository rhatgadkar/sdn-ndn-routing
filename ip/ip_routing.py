from collections import defaultdict
import random

from pox.core import core
from pox.lib.addresses import IPAddr
from pox.lib.packet.arp import arp
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ETHER_ANY, ETHER_BROADCAST, ethernet

log = core.getLogger()


class Router (object):
  """
  Contains the data structures that define and identify a router.
  """

  def __init__(self, name, routing_table, ip):
    self.name = name
    self.arp_cache = {}
    self.message_queue = defaultdict(list)
    self.routing_table = routing_table
    self.ip = ip


class IPRouting (object):
  """
  Performs routing to destination based on IP addresses.
  """

  def __init__ (self, connection):
    self.connection = connection
    connection.addListeners(self)
    self.router = {
      1: Router("r1", self.r1_routing_table, IPAddr("10.0.1.1")),
      2: Router("r2", self.r2_routing_table, IPAddr("10.0.2.1")),
      3: Router("r3", self.r3_routing_table, IPAddr("10.0.3.1")),
      4: Router("r4", self.r4_routing_table, IPAddr("10.0.4.1")),
    }

  def r1_routing_table (self, dst_ip):
    if dst_ip.in_network("10.0.1.0/24"):
      # host 1
      return ("r1-eth1", IPAddr("10.0.1.1"), 1)
    if dst_ip.in_network("10.0.2.0/24"):
      # host 2
      return ("r1-eth2", IPAddr("10.0.2.1"), 2)
    if dst_ip.in_network("10.0.3.0/24"):
      # host 3
      # randomly decide between port 2 and port 3
      if random.choice((2, 3)) == 2:
        return ("r1-eth2", IPAddr("10.0.2.1"), 2)
      return ("r1-eth3", IPAddr("10.0.4.1"), 3)
    if dst_ip.in_network("10.0.4.0/24"):
      # host 4
      return ("r1-eth3", IPAddr("10.0.4.1"), 3)
    raise Exception("Invalid dst_ip: %s." % str(dst_ip))

  def r2_routing_table (self, dst_ip):
    if dst_ip.in_network("10.0.2.0/24"):
      # host 2
      return ("r2-eth1", IPAddr("10.0.2.1"), 1)
    if dst_ip.in_network("10.0.1.0/24"):
      # host 1
      return ("r2-eth2", IPAddr("10.0.1.1"), 2)
    if dst_ip.in_network("10.0.3.0/24"):
      # host 3
      return ("r2-eth3", IPAddr("10.0.3.1"), 3)
    if dst_ip.in_network("10.0.4.0/24"):
      # host 4
      # randomly decide between port 2 and port 3
      if random.choice((2, 3)) == 2:
        return ("r2-eth2", IPAddr("10.0.1.1"), 2)
      return ("r2-eth3", IPAddr("10.0.3.1"), 3)
    raise Exception("Invalid dst_ip: %s." % str(dst_ip))

  def r3_routing_table (self, dst_ip):
    if dst_ip.in_network("10.0.3.0/24"):
      # host 3
      return ("r3-eth1", IPAddr("10.0.3.1"), 1)
    if dst_ip.in_network("10.0.1.0/24"):
      # host 1
      # randomly decide between port 2 and port 3
      if random.choice((2, 3)) == 2:
        return ("r3-eth2", IPAddr("10.0.2.1"), 2)
      return ("r3-eth3", IPAddr("10.0.4.1"), 3)
    if dst_ip.in_network("10.0.2.0/24"):
      # host 2
      return ("r3-eth2", IPAddr("10.0.2.1"), 2)
    if dst_ip.in_network("10.0.4.0/24"):
      # host 4
      return ("r3-eth3", IPAddr("10.0.4.1"), 3)
    raise Exception("Invalid dst_ip: %s." % str(dst_ip))

  def r4_routing_table (self, dst_ip):
    if dst_ip.in_network("10.0.4.0/24"):
      # host 4
      return ("r4-eth1", IPAddr("10.0.4.1"), 1)
    if dst_ip.in_network("10.0.1.0/24"):
      # host 1
      return ("r4-eth2", IPAddr("10.0.1.1"), 2)
    if dst_ip.in_network("10.0.2.0/24"):
      # host 2
      # randomly decide between port 2 and port 3
      if random.choice((2, 3)) == 2:
        return ("r4-eth2", IPAddr("10.0.1.1"), 2)
      return ("r4-eth3", IPAddr("10.0.3.1"), 3)
    if dst_ip.in_network("10.0.3.0/24"):
      # host 3
      return ("r4-eth3", IPAddr("10.0.3.1"), 3)
    raise Exception("Invalid dst_ip: %s." % str(dst_ip))

  def port_to_mac (self, port_no):
    port = self.connection.ports[port_no]
    return port.hw_addr

  def send_packet (self, packet_in, out_port):
    msg = of.ofp_packet_out()
    msg.data = packet_in
    action = of.ofp_action_output(port=out_port)
    msg.actions.append(action)
    self.connection.send(msg)

  def act_like_router (self, packet, packet_in, dpid):
    if packet.type == packet.ARP_TYPE:
      arpp = packet.payload
      try:
        _, dst_ip, out_port = self.router[dpid].routing_table(arpp.protosrc)
      except Exception:
        # drop the packet because of invalid IP
        return
      if arpp.opcode == arp.REQUEST:
        # send port's MAC address to requester
        arp_reply = self.get_arp_reply_pkt(
          src_mac=self.port_to_mac(out_port), dst_mac=packet.src,
          src_ip=self.router[dpid].ip, dst_ip=arpp.protosrc,
        )
        self.send_packet(arp_reply.pack(), out_port)
      elif arpp.opcode == arp.REPLY:
        if arpp.protosrc in self.router[dpid].message_queue:
          # send all messages from message queue that are satisfied by ARP reply
          self.router[dpid].arp_cache[arpp.protosrc] = arpp.hwsrc
          for to_send in self.router[dpid].message_queue[arpp.protosrc]:
            to_send.src = self.port_to_mac(out_port)
            to_send.dst = arpp.hwsrc
            self.send_packet(to_send.pack(), out_port)
          del self.router[dpid].message_queue[arpp.protosrc]
    elif packet.type == packet.IP_TYPE:
      ipp = packet.payload
      try:
        _, dst_ip, out_port = self.router[dpid].routing_table(ipp.dstip)
      except Exception:
        # drop the packet because of invalid IP
        return
      if ipp.dstip in self.router[dpid].arp_cache:
        # forward IP packet to next hop (destination host)
        packet.src = self.port_to_mac(out_port)
        packet.dst = self.router[dpid].arp_cache[ipp.dstip]
        self.send_packet(packet, out_port)
      elif self.router[dpid].ip == dst_ip:
        # inside the destination router
        # send ARP request to get MAC address, and add the message to queue
        arp_request = self.get_arp_request_pkt(
          self.port_to_mac(out_port), self.router[dpid].ip, ipp.dstip
        )
        self.router[dpid].message_queue[ipp.dstip].append(packet)
        self.send_packet(arp_request.pack(), out_port)
      elif self.router[dpid].ip != dst_ip:
        # not in the destination router
        packet.src = self.port_to_mac(out_port)
        self.send_packet(packet, out_port)

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
    IPRouting(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
