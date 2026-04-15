#!/bin/bash

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "[INFO] Starting Ryu controller in a new background process..."
ryu-manager "$PROJECT_ROOT/controller/host_discovery_controller.py" &
CONTROLLER_PID=$!

cleanup() {
    echo
    echo "[INFO] Cleaning up Mininet and controller process..."
    sudo mn -c >/dev/null 2>&1 || true
    kill "$CONTROLLER_PID" >/dev/null 2>&1 || true
}

trap cleanup EXIT

echo "[INFO] Waiting for the controller to initialize..."
sleep 3

echo "[INFO] Launching Mininet topology..."
sudo mn --custom "$PROJECT_ROOT/topology/custom_topology.py" \
    --topo mytopo \
    --controller remote,ip=127.0.0.1 \
    --switch ovsk,protocols=OpenFlow13
