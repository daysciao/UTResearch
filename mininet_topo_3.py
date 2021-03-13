from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController,CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections


class MyTopo(Topo):

    def __init__(self):

        # initilaize topology   
        Topo.__init__(self)
        
        hostConfig = {'cpu':1}
        linkConfig100M = {'bw':100m}
        linkConfig1G = {'bw':1g}
        
        # add hosts
        h1 = self.addHost('h1',**hostConfig)
        h2 = self.addHost('h2',**hostConfig)
        h3 = self.addHost('h3',**hostConfig)
        
        # add switchs
        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )
        s3 = self.addSwitch( 's3' )
            
        # add links
        
        self.addLink(h1,s1)
        self.addLink(h2,s2)
        self.addLink(h3,s3)
        
        self.addLink(s1,s2,**linkConfig100M)
        self.addLink(s3,s2,**linkConfig100M)
        self.addLink(s1,s3,**linkConfig100M)
        
        self.addLink(s3,s2,**linkConfig1G)
        self.addLink(s1,s3,**linkConfig1G)
        

topos = { 'mytopo': ( lambda: MyTopo() ) }
