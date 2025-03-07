
#
# Scenario:
# ....................   .............................   ....................
# .            ----- .   , -----               ----- .   . -----            .
# . Server NS |veth0|-----|veth1|  Router NS  |veth2|-----|veth3| Client NS .
# .            ----- .   . -----               ----- .   . -----            .
# ....................   .............................   ....................
#
# Route tables:
#
# Server NS
# 192.168.0.2/32 local veth0
# 192.168.0.0/24 direct veth0
# default via 192.168.0.1
#
# Router NS
# 192.168.0.1/32 local veth1
# 192.168.1.1/32 local veth2
# 192.168.0.0/24 direct veth1
# 192.168.1.0/24 direct veth2
#
# Client NS
# 192.168.1.2/32 local veth3
# 192.168.1.0/24 direct veth3
# default via 192.168.1.1
#

MAX_CAPTURE_TIME := 10
TCPDUMP_SLEEP    :=  2
TCPDUMP_FLAGS    := -leevn

all:
	@echo "Use make <scenario>"
	@exit 1

_print_scenario:
	@echo "Scenario:"
	@echo "....................   .............................   ...................."
	@echo ".            ----- .   , -----               ----- .   . -----            ."
	@echo ". Server NS |veth0|-----|veth1|  Router NS  |veth2|-----|veth3| Client NS ."
	@echo ".            ----- .   . -----               ----- .   . -----            ."
	@echo "....................   .............................   ...................."

_create_scenario:
	sudo ip netns add server
	sudo ip netns add router
	sudo ip netns add client
	sudo ip netns exec router ip link add type veth
	sudo ip netns exec router ip link add type veth
	sudo ip netns exec router ip link set netns server dev veth0
	sudo ip netns exec router ip link set netns client dev veth3
	sudo ip netns exec server ip link set up dev veth0
	sudo ip netns exec router ip link set up dev veth1
	sudo ip netns exec router ip link set up dev veth2
	sudo ip netns exec client ip link set up dev veth3
	sudo ip netns exec server ip addr add 192.168.0.2/24 dev veth0
	sudo ip netns exec router ip addr add 192.168.0.1/24 dev veth1
	sudo ip netns exec router ip addr add 192.168.1.1/24 dev veth2
	sudo ip netns exec client ip addr add 192.168.1.2/24 dev veth3
	sudo ip netns exec server ip route add default via 192.168.0.1
	sudo ip netns exec client ip route add default via 192.168.1.1
_disable_gso_tso_ufo:
	@echo "Disabling GSO/TSO/UFO on all interface..."
	sudo ip netns exec server ethtool -K veth0 tso off gso off ufo off
	sudo ip netns exec router ethtool -K veth1 tso off gso off ufo off
	sudo ip netns exec router ethtool -K veth2 tso off gso off ufo off
	sudo ip netns exec client ethtool -K veth3 tso off gso off ufo off
_lower_mtu_server_router:
	@echo "Lowering MTU ONLY on server's (veth1) to 1400"
	sudo ip netns exec router ip link set mtu 1400 dev veth1
_block_router_icmp:
	@echo "Blocking all outgoing ICMP from the router..."
	@sudo ip netns exec router iptables -I OUTPUT -p icmp -j DROP

router_nogso: _create_scenario _lower_mtu_server_router _disable_gso_tso_ufo

router_nogso_icmp_blocked: _create_scenario _lower_mtu_server_router _disable_gso_tso_ufo _block_router_icmp

router_nogso_icmp_blocked_mtu_probing: _create_scenario _lower_mtu_server_router _disable_gso_tso_ufo _block_router_icmp
	@echo "Enabling TCP MTU probing (TCP PLPMTUD) on the client (tcp_mtu_probing=2)..."
	@sudo ip netns exec router bash -c "echo 2 > /proc/sys/net/ipv4/tcp_mtu_probing"

router_gso: _create_scenario _lower_mtu_server_router

test_large_icmp_request:
	@echo "TEST: Sending 3 ICMP requests maxing out MTU=1500 (-s 1472)"
	@echo ""
	@$(MAKE) -s _print_scenario
	@echo ""
	@sudo ip netns exec client timeout $(MAX_CAPTURE_TIME) tcpdump -i veth3 $(TCPDUMP_FLAGS) icmp &
	@echo "Waiting for tcpdump in veth3 to be up and running..."
	@sleep $(TCPDUMP_SLEEP)
	@sudo ip netns exec client ping -s 1472 192.168.0.2 -c 3 2>&1 > /dev/null

test_tcp:
	@echo "TEST: test a large TCP flow client->server"
	@echo ""
	@$(MAKE) -s _print_scenario
	@echo ""
	@echo 'Clear PMTUD cache (sudo ip route flush cache)'
	@sudo ip netns exec client ip route flush cache
	@sudo ip netns exec server timeout $(MAX_CAPTURE_TIME) nc -l 12345 > /dev/null &
	@sudo ip netns exec client timeout $(MAX_CAPTURE_TIME) tcpdump -i veth3 $(TCPDUMP_FLAGS) -c 100 tcp or icmp &
	@echo "Waiting for tcpdump in veth3 to be up and running (will sniff the first 100 TCP|ICMP pkts)..."
	@sleep $(TCPDUMP_SLEEP)
	@sudo ip netns exec client bash -c "dd if=/dev/zero bs=1M count=100 | nc 192.168.0.2 12345"

shell_client:
	sudo ip netns exec client bash
shell_router:
	sudo ip netns exec router bash
shell_server:
	sudo ip netns exec server bash

clean:
	sudo ip netns exec router ip link del veth1 || true
	sudo ip netns exec router ip link del veth2 || true
	sudo ip netns del server || true
	sudo ip netns del router || true
	sudo ip netns del client || true
