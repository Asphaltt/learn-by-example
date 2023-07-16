#!/bin/bash -ex

NETNSCLI="nscli"
NETNSSRV="nssrv"

IPCLI="192.168.0.10"
IPSRV="192.168.0.11"

VETHCLI="vcli"
VETHSRV="vsrv"

ip link add dev ${VETHCLI} type veth peer name ${VETHSRV}

ip netns add ${NETNSCLI}
ip link set dev ${VETHCLI} netns ${NETNSCLI}
ip netns exec ${NETNSCLI} bash -c "
ip link set dev ${VETHCLI} up
ip addr add dev ${VETHCLI} ${IPCLI}/24
"

ip netns add ${NETNSSRV}
ip link set dev ${VETHSRV} netns ${NETNSSRV}
ip netns exec ${NETNSSRV} bash -c "
ip link set dev ${VETHSRV} up
ip addr add dev ${VETHSRV} ${IPSRV}/24

tc qdisc add dev ${VETHSRV} ingress
tc filter add dev ${VETHSRV} ingress pref 10 protocol all bpf da obj ./tcmd_bpfel.o sec tc

./xdpmetadata --dev ${VETHSRV}
"

echo "
Command to check bpf log:
cat /sys/kernel/debug/tracing/trace_pipe

Command to genenrate bpf log:
ip netns exec ${NETNSCLI} ping -c1 ${IPSRV}

Command to clear attached bpf prog:
rm -rf bpffs
"
