./pox.py log.level --DEBUG misc.ip_routing

sudo mn --custom mytopo.py --topo mytopo --mac --controller remote --switch ovsk --link tc,bw=10,delay=10ms

sudo mn -c
