"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the "topos" dict with a key/value pair to generate our newly defined
topology enables one to pass in "--topo=mytopo" from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        h1 = self.addHost(
            'h1', ip='10.0.1.100/24', defaultRoute='via 10.0.1.1',
        )
        h2 = self.addHost(
            'h2', ip='10.0.2.100/24', defaultRoute='via 10.0.2.1',
        )
        h3 = self.addHost(
            'h3', ip='10.0.3.100/24', defaultRoute='via 10.0.3.1',
        )
        h4 = self.addHost(
            'h4', ip='10.0.4.100/24', defaultRoute='via 10.0.4.1',
        )
        r1 = self.addSwitch( 'r1' )
        r2 = self.addSwitch( 'r2' )
        r3 = self.addSwitch( 'r3' )
        r4 = self.addSwitch( 'r4' )

        # Add links
        self.addLink( h1, r1 )
        self.addLink( h2, r2 )
        self.addLink( h3, r3 )
        self.addLink( h4, r4 )
        self.addLink( r1, r2 )
        self.addLink( r1, r4 )
        self.addLink( r2, r3 )
        self.addLink( r4, r3 )


topos = { 'mytopo': ( lambda: MyTopo() ) }
