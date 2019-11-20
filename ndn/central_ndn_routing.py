import random

from pox.core import core
from pox.lib.addresses import IPAddr
from pox.lib.packet.ethernet import ETHER_ANY

from ndn_routing import (
  CP_RESP, CP_REQ, ROUTER_RESP_UDP_PORT, ROUTER_REQ_UDP_PORT,
  LOCAL_HOST_OUT_PORT, NDNRouter, NDNRouting
)

log = core.getLogger()

"""
Centralized NDN routing (centralized control plane):
Shortest path routing.
1. check if CC contains content. If it does not, invoke RT.
1. check if local host contains content
2. check if neighboring routers (1 hop) contain content.
3. check hosts 2 hops away for content
3. check router 2 hops away for content
4. last host will contain content
"""


class CentralNDNRouter (NDNRouter):
  """
  Contains the data structures that define and identify a router.
  """

  def __init__ (
    self, name, ip, local_host, local_host_ip, local_host_server_udp_port,
    local_host_contents, routing_table
  ):
    super(CentralNDNRouter, self).__init__(
      name, ip, local_host, local_host_ip, local_host_server_udp_port,
      local_host_contents
    )
    self.rt = routing_table


class CentralNDNRouting (NDNRouting):
  """
  Performs routing to retrieve a content from a network, assuming a centralized
  controller.
  """

  def __init__ (self, connection):
    super(CentralNDNRouting, self).__init__(connection)
    self.router = {
      1: CentralNDNRouter("r1", IPAddr("10.0.1.1"), "h1", IPAddr("10.0.1.100"),
         10001, ("content1_1", "content1_2"), self.r1_routing_table),
      2: CentralNDNRouter("r2", IPAddr("10.0.2.1"), "h2", IPAddr("10.0.2.100"),
         10002, ("content2_1", "content2_2"), self.r2_routing_table),
      3: CentralNDNRouter("r3", IPAddr("10.0.3.1"), "h3", IPAddr("10.0.3.100"),
         10003, ("content3_1", "content3_2"), self.r3_routing_table),
      4: CentralNDNRouter("r4", IPAddr("10.0.4.1"), "h4", IPAddr("10.0.4.100"),
         10004, ("content4_1", "content4_2"), self.r4_routing_table),
    }
    self.content_locs = {
      "content1_1": {"h1"},
      "content1_2": {"h1"},
      "content2_1": {"h2"},
      "content2_2": {"h2"},
      "content3_1": {"h3"},
      "content3_2": {"h3"},
      "content4_1": {"h4"},
      "content4_2": {"h4"},
    }
    self.content_hosts = {
      "content1_1": "h1",
      "content1_2": "h1",
      "content2_1": "h2",
      "content2_2": "h2",
      "content3_1": "h3",
      "content3_2": "h3",
      "content4_1": "h4",
      "content4_2": "h4",
    }
    self.host_hops = {
      "r1": ((), ("h1",), ("h2", "h4"), ("h3",)),
      "r2": ((), ("h2",), ("h1", "h3"), ("h4",)),
      "r3": ((), ("h3",), ("h2", "h4"), ("h1",)),
      "r4": ((), ("h4",), ("h1", "h3"), ("h2")),
    }
    self.router_hops = {
      "r1": ((), ("r2", "r4"), ("r3",)),
      "r2": ((), ("r1", "r3"), ("r4",)),
      "r3": ((), ("r2", "r4"), ("r1",)),
      "r4": ((), ("r1", "r3"), ("r2",)),
    }

  def r1_routing_table (self, dst):
    if dst in ("h2", "r2"):
      # host 2
      return ("r1-eth2", 2)
    if dst in ("h3", "r3"):
      # host 3
      # randomly decide between port 2 and port 3
      if random.choice((2, 3)) == 2:
        return ("r1-eth2", 2)
      return ("r1-eth3", 3)
    if dst in ("h4", "r4"):
      # host 4
      return ("r1-eth3", 3)
    raise Exception("Invalid dst: %s." % dst)

  def r2_routing_table (self, dst):
    if dst in ("h1", "r1"):
      # host 1
      return ("r2-eth2", 2)
    if dst in ("h3", "r3"):
      # host 3
      return ("r2-eth3", 3)
    if dst in ("h4", "r4"):
      # host 4
      # randomly decide between port 2 and port 3
      if random.choice((2, 3)) == 2:
        return ("r2-eth2", 2)
      return ("r2-eth3", 3)
    raise Exception("Invalid dst: %s." % dst)

  def r3_routing_table (self, dst):
    if dst in ("h1", "r1"):
      # host 1
      # randomly decide between port 2 and port 3
      if random.choice((2, 3)) == 2:
        return ("r3-eth2", 2)
      return ("r3-eth3", 3)
    if dst in ("h2", "r2"):
      # host 2
      return ("r3-eth2", 2)
    if dst in ("h4", "r4"):
      # host 4
      return ("r3-eth3", 3)
    raise Exception("Invalid dst: %s." % dst)

  def r4_routing_table (self, dst):
    if dst in ("h1", "r1"):
      # host 1
      return ("r4-eth2", 2)
    if dst in ("h2", "r2"):
      # host 2
      # randomly decide between port 2 and port 3
      if random.choice((2, 3)) == 2:
        return ("r4-eth2", 2)
      return ("r4-eth3", 3)
    if dst in ("h3", "r3"):
      # host 3
      return ("r4-eth3", 3)
    raise Exception("Invalid dst: %s." % dst)

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
      # TODO check if request for content exists in crt.
      #      If it does, don't need to send a new CP.
      #      Did not work when tried to implement in distinct NDN routing.
      else:
        out_port = self.get_content_loc(dpid, content)
        # add request for content to local CRT
        assert not self.router[dpid].local_host_crt
        self.router[dpid].local_host_crt[content] = udpp.srcport
        # create and send content request packet out of port
        content_pkt = self.get_content_pkt(
          type=CP_REQ, content=content, src_mac=self.port_to_mac(out_port),
        )
        self.send_packet(content_pkt.pack(), out_port)

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
      # TODO check if request for content exists in crt.
      #      If it does, don't need to send a new CP.
      #      Did not work when tried to implement in distinct NDN routing.
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
            type=CP_REQ, content=content,
            src_mac=self.port_to_mac(out_port),
          )
          self.send_packet(content_pkt.pack(), out_port)
    elif type == CP_RESP:
      if content in self.router[dpid].local_host_crt:
        # update cc and content_locs
        del_content = self.router[dpid].cc.insert(content)
        if del_content:
          self.content_locs[del_content].remove(self.router[dpid].name)
        self.content_locs[content].add(self.router[dpid].name)
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

  def act_like_router (self, packet, packet_in, dpid):
    if packet.type == packet.ARP_TYPE:
      self.handle_arp_pkt(packet, packet_in, dpid)
    elif packet.type == packet.IP_TYPE:
      self.handle_ip_pkt(packet, packet_in, dpid)
    elif packet.type == packet.CP_TYPE:
      self.handle_cp_pkt(packet, packet_in, dpid)

  def process_crt(self, dpid, content):
    if content in self.router[dpid].crt:
      # update cc and content_locs
      del_content = self.router[dpid].cc.insert(content)
      if del_content:
        self.content_locs[del_content].remove(self.router[dpid].name)
      self.content_locs[content].add(self.router[dpid].name)
      for to_snd_port in self.router[dpid].crt[content]:
        # send response to preceding router
        content_pkt = self.get_content_pkt(
          type=CP_RESP, content=content,
          src_mac=self.port_to_mac(to_snd_port),
        )
        self.send_packet(content_pkt.pack(), to_snd_port)
      # remove entry from crt
      del self.router[dpid].crt[content]

  def get_content_loc (self, dpid, content):
    _, _, host_hop2, _ = self.host_hops[self.router[dpid].name]
    _, router_hop1, router_hop2 = self.router_hops[self.router[dpid].name]
    # 1. check if local host contains content
    if self.content_hosts[content] == self.router[dpid].local_host:
      dst = self.router[dpid].local_host
    # 2. check if neighboring routers (1 hop) contain content.
    elif (
      router_hop1[0] in self.content_locs[content] and
      router_hop1[1] in self.content_locs[content]
    ):
      dst = random.choice((router_hop1[0], router_hop1[1]))
    elif router_hop1[0] in self.content_locs[content]:
      dst = router_hop1[0]
    elif router_hop1[1] in self.content_locs[content]:
      dst = router_hop1[1]
    # 3. check hosts 2 hops away for content
    elif (
      host_hop2[0] in self.content_locs[content] and
      host_hop2[1] in self.content_locs[content]
    ):
      dst = random.choice((host_hop2[0], host_hop2[1]))
    elif host_hop2[0] in self.content_locs[content]:
      dst = host_hop2[0]
    elif host_hop2[1] in self.content_locs[content]:
      dst = host_hop2[1]
    # 4. check router 2 hops away for content
    elif router_hop2[0] in self.content_locs[content]:
      dst = router_hop2[0]
    # 5. the last host (3 hops away) will contain the content
    else:
      dst = self.content_hosts[content]
    if dst == self.router[dpid].local_host:
      return LOCAL_HOST_OUT_PORT
    rt_res = self.router[dpid].rt(dst)
    return rt_res[1]  # out port

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
    CentralNDNRouting(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
