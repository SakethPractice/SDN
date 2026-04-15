"""Custom Mininet topology for the SDN host discovery mini project."""

from mininet.topo import Topo


class HostDiscoveryTopo(Topo):
    """Single-switch topology with three end hosts."""

    def build(self):
        """Create hosts, switch, and host-to-switch links."""
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")

        s1 = self.addSwitch("s1")

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)


topos = {"mytopo": lambda: HostDiscoveryTopo()}
