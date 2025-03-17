MAX_CAPTURE_TIME := 10
TCPDUMP_SLEEP    :=  2
TCPDUMP_FLAGS    := -leevn
ICMP_SIZE        := 1377

all: _create_scenario _print_scenario
	@echo "Note: link1 has matching MTU 1500"
_print_scenario:
	@cat scenario.txt

_create_scenario:
	@sudo ip netns add router
	@sudo ip netns add host1
	@sudo ip netns add host2
	@sudo ip netns exec router ip link add type veth
	@sudo ip netns exec router ip link add type veth
	@sudo ip netns exec router ip link set netns host1 dev veth0
	@sudo ip netns exec router ip link set netns host2 dev veth3
	@sudo ip netns exec host1 ip link set up dev lo
	@sudo ip netns exec host1 ip link set up dev veth0
	@sudo ip netns exec router ip link set up dev lo
	@sudo ip netns exec router ip link set up dev veth1
	@sudo ip netns exec router ip link set up dev veth2
	@sudo ip netns exec host2 ip link set up dev lo
	@sudo ip netns exec host2 ip link set up dev veth3
	@sudo ip netns exec host1 ip addr add 192.168.0.2/24 dev veth0
	@sudo ip netns exec router ip addr add 192.168.0.1/24 dev veth1
	@sudo ip netns exec router ip addr add 192.168.1.1/24 dev veth2
	@sudo ip netns exec host2 ip addr add 192.168.1.2/24 dev veth3
	@sudo ip netns exec host1 ip route add default via 192.168.0.1
	@sudo ip netns exec host2 ip route add default via 192.168.1.1
	@sudo ip netns exec router ip route add 192.168.11.0/24 via 192.168.0.2
	@sudo ip netns exec router ip route add 192.168.21.0/24 via 192.168.1.2

flush_cache:
	@sudo ip netns exec router ip route flush cache
	@sudo ip netns exec host1 ip route flush cache
	@sudo ip netns exec host2 ip route flush cache

set_link1_default mtus:
	@echo "Setting link1 MTUs to 1500"
	@sudo ip netns exec host1  ip link set mtu 1500 dev veth0
	@sudo ip netns exec router ip link set mtu 1500 dev veth1
	@$(MAKE) flush_cache

set_link1_mismatched_mtus:
	@echo "Lowering MTU ONLY on router's (veth1) to 1400, veth0 to 1500"
	@sudo ip netns exec host1  ip link set mtu 1500 dev veth0
	@sudo ip netns exec router ip link set mtu 1400 dev veth1
	@$(MAKE) flush_cache
set_link1_matching_mtus:
	@echo "Lowering MTU on link1 on both interfaces to 1400"
	@sudo ip netns exec host1  ip link set mtu 1400 dev veth0
	@sudo ip netns exec router ip link set mtu 1400 dev veth1
	@$(MAKE) flush_cache

_enable_disable_gso_tso_ufo:
	@sudo ip netns exec router ethtool -K veth1 tso $(OP) gso $(OP) ufo $(OP) || true
	@sudo ip netns exec router ethtool -K veth2 tso $(OP) gso $(OP) ufo $(OP) || true
	@sudo ip netns exec host1 ethtool -K veth0 tso $(OP) gso $(OP) ufo $(OP) || true
	@sudo ip netns exec host2 ethtool -K veth3 tso $(OP) gso $(OP) ufo $(OP) || true
	@$(MAKE) flush_cache

enable_gso_tso_ufo:
	@echo "Enabling GSO/TSO/UFO on all interface..."
	$(MAKE) _enable_disable_gso_tso_ufo OP=on

disable_gso_tso_ufo:
	@echo "Disabling GSO/TSO/UFO on all interface..."
	$(MAKE) _enable_disable_gso_tso_ufo OP=off

block_icmp:
	@echo "Blocking all outgoing ICMP from the router..."
	@sudo ip netns exec router iptables -I OUTPUT -p icmp -j DROP
	@sudo ip netns exec $(NS) ip route flush cache
	@$(MAKE) flush_cache
unblock_icmp_router:
	@echo "Unblocking all outgoing ICMP from the router..."
	@sudo ip netns exec router iptables -D OUTPUT -p icmp -j DROP || true
	@sudo ip netns exec $(NS) ip route flush cache
	@$(MAKE) flush_cache

enable_mtu_probing:
	@echo "Enabling TCP MTU probing (TCP PLPMTUD) on host2 (tcp_mtu_probing=2)..."
	@sudo ip netns exec host2 bash -c "echo 2 > /proc/sys/net/ipv4/tcp_mtu_probing"
	@sudo ip netns exec $(NS) ip route flush cache
	@$(MAKE) flush_cache
disable_mtu_probing:
	@echo "Disabling TCP MTU probing (TCP PLPMTUD) on host2 (tcp_mtu_probing=0)..."
	@sudo ip netns exec host2 bash -c "echo 0 > /proc/sys/net/ipv4/tcp_mtu_probing"
	@sudo ip netns exec $(NS) ip route flush cache
	@$(MAKE) flush_cache

## Test

test_large_icmp_request:
	@$(MAKE) _print_scenario
	@echo "TEST: Sending 3 ICMP requests maxing out MTU=1500 (-s $(ICMP_SIZE))"
	@echo ""
	@sudo ip netns exec host2 timeout $(MAX_CAPTURE_TIME) tcpdump -i veth3 $(TCPDUMP_FLAGS) icmp &
	@echo "Waiting for tcpdump in veth3 to be up and running..."
	@sleep $(TCPDUMP_SLEEP)
	@sudo ip netns exec host2 ping -s $(ICMP_SIZE) 192.168.0.2 -c 3

test_tcp:
	@echo "TEST: test a large TCP flow host2->host2"
	@echo ""
	@$(MAKE) -s _print_scenario
	@echo ""
	@echo 'Clear PMTUD cache (sudo ip route flush cache)'
	@sudo ip netns exec host1 ip route flush cache
	@sudo ip netns exec host2 ip route flush cache
	@sudo ip netns exec host1 timeout $(MAX_CAPTURE_TIME) nc -l 12345 > /dev/null &
	@sudo ip netns exec host2 timeout $(MAX_CAPTURE_TIME) tcpdump -i veth3 $(TCPDUMP_FLAGS) -c 100 tcp or icmp &
	@echo "Waiting for tcpdump in veth3 to be up and running (will sniff the first 100 TCP|ICMP pkts)..."
	@sleep $(TCPDUMP_SLEEP)
	@sudo ip netns exec host2 bash -c "dd if=/dev/zero bs=1M count=100 | nc 192.168.0.2 12345"

shell_router:
	@sudo ip netns exec router bash
shell_host1:
	@sudo ip netns exec host1 bash
shell_host2:
	@sudo ip netns exec host2 bash

clean:
	@sudo ip netns exec host1 ip link del lxc1 || true
	@sudo ip netns exec host2 ip link del lxc1 || true
	@sudo ip netns exec router ip link del veth1 || true
	@sudo ip netns exec router ip link del veth2 || true
	@sudo ip netns del router || true
	@sudo ip netns del host1 || true
	@sudo ip netns del host2 || true
