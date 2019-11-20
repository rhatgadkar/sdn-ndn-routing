Software-Defined Named Data Networking (NDN) Routing
----------------------------------------------------
This project implements software-defined NDN routing protocols using Mininet,
OpenFlow, and the POX controller. It implements a centralized controller and a
distinct controller version of the protocol.

Here is the organization of this directory:
- `cmds.txt`: contains important CLI commands for Mininet and the POX
              controller.
- `my_topo.py`: contains the Mininet topology used in the experiments of this
              project.
- `new_ethernet_format.patch`: a patch file for the
                             `pox/pox/lib/packet/ethernet.py` file.
                             The patch defines the `CP_TYPE` and `CAM_TYPE`
                             ethernet type fields, which are used in the NDN
                             controller programs.
- `ip/`: contains the IP routing controller program and the IP client and server
       programs.
- `ndn/`: contains the NDN routing controller programs and the NDN client and
       server programs.
