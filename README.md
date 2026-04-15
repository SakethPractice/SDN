# SDN Host Discovery Service using Mininet and Ryu

## Problem Statement

The goal of this mini project is to automatically detect hosts joining a Software Defined Network (SDN), maintain a dynamic host database, and install forwarding rules using an OpenFlow 1.3 controller. The project demonstrates controller-switch interaction, packet processing through `packet_in` events, and OpenFlow match-action based forwarding using Mininet and Ryu.

## Features

- Host join detection from live traffic
- Dynamic host database updates with `last_seen` timestamps
- Explicit OpenFlow 1.3 flow rule installation
- `packet_in` event handling in the Ryu controller
- Controller-switch communication through a remote OpenFlow controller
- Match-action forwarding logic using `OFPMatch` and `OFPActionOutput`
- Terminal logs showing host MAC address, switch datapath ID, and ingress port

## Repository Structure

```text
SDN/
├── controller/
│   └── host_discovery_controller.py
├── topology/
│   └── custom_topology.py
├── README.md
├── requirements.txt
└── run_demo.sh
```

## Setup Instructions

This project is designed for Ubuntu 20.04 with Mininet and Open vSwitch installed.

### 1. Install Python dependencies

```bash
pip3 install -r requirements.txt
```

### 2. Start the Ryu controller

```bash
ryu-manager controller/host_discovery_controller.py
```

### 3. Run the Mininet topology

```bash
sudo mn --custom topology/custom_topology.py --topo mytopo --controller remote,ip=127.0.0.1 --switch ovsk,protocols=OpenFlow13
```

### 4. Test connectivity using ping

Inside the Mininet CLI:

```bash
pingall
```

### 5. Dump the switch flow table

In another terminal:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

### 6. Run an iperf test

Inside the Mininet CLI:

```bash
iperf h1 h2
```

### 7. Optional quick start with the demo script

```bash
chmod +x run_demo.sh
./run_demo.sh
```

## Execution Commands

Use the following commands exactly from the project root:

```bash
ryu-manager controller/host_discovery_controller.py
```

```bash
sudo mn --custom topology/custom_topology.py --topo mytopo --controller remote,ip=127.0.0.1 --switch ovsk,protocols=OpenFlow13
```

Useful runtime commands:

```bash
pingall
```

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

```bash
iperf h1 h2
```

## Test Scenarios

### Scenario 1: Normal Host Discovery

1. Start the controller.
2. Launch the custom Mininet topology.
3. Run `pingall` from the Mininet CLI.
4. Observe the controller terminal.

Expected behavior:

- The controller receives `packet_in` events.
- New hosts are detected dynamically when they send traffic.
- The host database is updated with MAC address, switch DPID, port number, and timestamp.
- Flow rules are installed after host learning.
- `pingall` should complete successfully.

### Scenario 2: Failure / Blocked Communication

1. Start the controller and topology.
2. In the Mininet CLI, intentionally bring down one host interface or remove connectivity:

```bash
h3 ifconfig h3-eth0 down
```

3. Run:

```bash
pingall
```

Expected behavior:

- Communication involving `h3` should fail.
- Hosts `h1` and `h2` should still communicate normally.
- The controller will continue logging `packet_in` events for active hosts.
- Flow entries for reachable hosts can still be inspected using `ovs-ofctl`.

To restore connectivity:

```bash
h3 ifconfig h3-eth0 up
```

## Expected Output

When the project runs successfully, the following should be visible:

- Hosts detected dynamically in the Ryu controller terminal
- `packet_in` logs for incoming traffic
- Flow rules installed in the switch flow table
- Successful `pingall` output for the normal case
- `iperf` throughput results between selected hosts

Example controller log format:

```text
Switch connected: datapath_id=0000000000000001, installed table-miss flow
New host detected: mac=00:00:00:00:00:01, switch=0000000000000001, port=1
PacketIn received: switch=0000000000000001, in_port=1, src=00:00:00:00:00:01, dst=ff:ff:ff:ff:ff:ff
Installed flow: switch=0000000000000001, match(in_port=1, src=00:00:00:00:00:01, dst=00:00:00:00:00:02), out_port=2
Current host database: {
  '00:00:00:00:00:01': {'switch': '0000000000000001', 'port': 1, 'last_seen': '2026-04-15 10:00:00'}
}
```

## Proof of Execution

The following artifacts and observations can be used as proof that the project executed correctly:

- OpenFlow flow tables dumped using `ovs-ofctl`
- `pingall` results from the Mininet CLI
- Wireshark captures showing ARP, ICMP, and OpenFlow packets
- `iperf` results demonstrating host-to-host throughput

## Notes

- This controller behaves like a learning switch with added host discovery and tracking logic.
- Host discovery occurs when hosts generate traffic such as ARP or ICMP packets.
- OpenFlow 1.3 is enforced both in the Ryu controller and in the Mininet switch configuration.
