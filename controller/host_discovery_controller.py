"""Ryu controller for dynamic host discovery on an OpenFlow 1.3 switch.

This application performs three main tasks:
1. Installs a table-miss flow entry so unknown traffic reaches the controller.
2. Learns host attachment information from PacketIn events.
3. Installs explicit forwarding rules to support normal switch behavior.
"""

from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3


class HostDiscoveryController(app_manager.RyuApp):
    """Simple host discovery and forwarding controller."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """Initialize MAC learning and host database structures."""
        super(HostDiscoveryController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.host_db = {}

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Install a flow entry using explicit OpenFlow match-action logic."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        instructions = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]

        if buffer_id is not None:
            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=instructions,
            )
        else:
            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=instructions,
            )

        datapath.send_msg(flow_mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install the default table-miss flow when a switch connects."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Send unmatched packets to the controller for inspection and learning.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

        self.logger.info(
            "Switch connected: datapath_id=%s, installed table-miss flow",
            format(datapath.id, "016x"),
        )

    def update_host_database(self, src_mac, dpid, in_port):
        """Create or refresh host details when traffic is seen from a host."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        known_host = self.host_db.get(src_mac)

        self.host_db[src_mac] = {
            "switch": dpid,
            "port": in_port,
            "last_seen": timestamp,
        }

        if known_host is None:
            self.logger.info(
                "New host detected: mac=%s, switch=%s, port=%s",
                src_mac,
                dpid,
                in_port,
            )
        elif known_host["port"] != in_port or known_host["switch"] != dpid:
            self.logger.info(
                "Host location updated: mac=%s, switch=%s, port=%s",
                src_mac,
                dpid,
                in_port,
            )

        self.logger.info("Current host database: %s", self.host_db)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle PacketIn events for host discovery and forwarding decisions."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = format(datapath.id, "016x")
        in_port = msg.match["in_port"]

        # Parse the incoming Ethernet frame.
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP to avoid polluting host discovery with control traffic.
        if eth is None or eth.ethertype == 0x88CC:
            return

        dst_mac = eth.dst
        src_mac = eth.src

        # Maintain per-switch MAC learning state.
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # Update the host database whenever a source host sends traffic.
        self.update_host_database(src_mac, dpid, in_port)

        self.logger.info(
            "PacketIn received: switch=%s, in_port=%s, src=%s, dst=%s",
            dpid,
            in_port,
            src_mac,
            dst_mac,
        )

        # Decide where to send the packet based on learned destination state.
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a unicast flow only after the destination has been learned.
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(
                    datapath,
                    priority=1,
                    match=match,
                    actions=actions,
                    buffer_id=msg.buffer_id,
                )
                self.logger.info(
                    "Installed flow: switch=%s, match(in_port=%s, src=%s, dst=%s), out_port=%s",
                    dpid,
                    in_port,
                    src_mac,
                    dst_mac,
                    out_port,
                )
                return

            self.add_flow(datapath, priority=1, match=match, actions=actions)
            self.logger.info(
                "Installed flow: switch=%s, match(in_port=%s, src=%s, dst=%s), out_port=%s",
                dpid,
                in_port,
                src_mac,
                dst_mac,
                out_port,
            )

        # Forward the current packet according to the selected action list.
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        packet_out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(packet_out)
