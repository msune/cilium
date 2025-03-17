MAX_CAPTURE_TIME := 10
TCPDUMP_SLEEP    :=  2
TCPDUMP_FLAGS    := -leevn

all:
	@echo "Use make <scenario>"
	@exit 1

_print_scenario_pods:
	@echo "Scenario:"
	@echo "....................   .............................   ...................."
	@echo ".            ----- .   , -----               ----- .   . -----            ."
	@echo ". Host1 NS  |veth0|-----|veth1|  Router NS  |veth2|-----|veth3| Host2 NS  ."
	@echo ".            ----- .   . -----               ----- .   . -----            ."
	@echo ".            XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX                 ."
	@echo "....................   .............................   ...................."
	@echo ""
	@echo "> Host1 NS route table"
	@echo "   192.168.0.2/32 local veth0"
	@echo "   192.168.0.0/24 direct veth0"
	@echo "   default via 192.168.0.1"
	@echo ""
	@echo "> Router NS route table"
	@echo "   192.168.0.1/32 local veth1"
	@echo "   192.168.1.1/32 local veth2"
	@echo "   192.168.0.0/24 direct veth1"
	@echo "   192.168.1.0/24 direct veth2"
	@echo ""
	@echo "> Host2 NS"
	@echo "   192.168.1.2/32 local veth3"
	@echo "   192.168.1.0/24 direct veth3"
	@echo "   default via 192.168.1.1"

_add_pods:
	sudo ip netns add host1_pod1
	sudo ip netns add host2_pod1
	sudo ip netns exec host1_pod1 ip link add eth0 type veth peer name lxc1
	sudo ip netns exec host2_pod1 ip link add eth0 type veth peer name lxc1
	sudo ip netns exec host1_pod1 ip link set netns host1 dev lxc1
	sudo ip netns exec host2_pod1 ip link set netns host2 dev lxc1
	sudo ip netns exec host1_pod1 ip link set up dev lo
	sudo ip netns exec host1_pod1 ip link set up dev eth0
	sudo ip netns exec host2_pod1 ip link set up dev lo
	sudo ip netns exec host2_pod1 ip link set up dev eth0
	sudo ip netns exec host1 ip link set up dev lxc1
	sudo ip netns exec host2 ip link set up dev lxc1
	sudo ip netns exec host1 ip addr add 192.168.11.1/24 dev lxc1
	sudo ip netns exec host2 ip addr add 192.168.21.1/24 dev lxc1
	sudo ip netns exec host1_pod1 ip addr add 192.168.11.2/24 dev eth0
	sudo ip netns exec host2_pod1 ip addr add 192.168.21.2/24 dev eth0
	sudo ip netns exec host1_pod1 ip route add default via 192.168.11.1
	sudo ip netns exec host2_pod1 ip route add default via 192.168.21.1
	sudo ip netns exec host1 ip link add vxlan0 type vxlan id 12345 dev veth0 remote 192.168.1.2 dstport 4789
	sudo ip netns exec host2 ip link add vxlan0 type vxlan id 12345 dev veth3 remote 192.168.0.2 dstport 4789
	sudo ip netns exec host1 ip link set up dev vxlan0
	sudo ip netns exec host2 ip link set up dev vxlan0
	sudo ip netns exec host1 ip addr add 192.168.254.1/24 dev vxlan0
	sudo ip netns exec host2 ip addr add 192.168.254.2/24 dev vxlan0

_create_scenario:
	sudo ip netns add router
	sudo ip netns add host1
	sudo ip netns add host2
	sudo ip netns exec router ip link add type veth
	sudo ip netns exec router ip link add type veth
	sudo ip netns exec router ip link set netns host1 dev veth0
	sudo ip netns exec router ip link set netns host2 dev veth3
	sudo ip netns exec host1 ip link set up dev veth0
	sudo ip netns exec router ip link set up dev veth1
	sudo ip netns exec router ip link set up dev veth2
	sudo ip netns exec host2 ip link set up dev veth3
	sudo ip netns exec host1 ip addr add 192.168.0.2/24 dev veth0
	sudo ip netns exec router ip addr add 192.168.0.1/24 dev veth1
	sudo ip netns exec router ip addr add 192.168.1.1/24 dev veth2
	sudo ip netns exec host2 ip addr add 192.168.1.2/24 dev veth3
	sudo ip netns exec host1 ip route add default via 192.168.0.1
	sudo ip netns exec host2 ip route add default via 192.168.1.1
	sudo ip netns exec router ip route add 192.168.11.0/24 via 192.168.0.2
	sudo ip netns exec router ip route add 192.168.21.0/24 via 192.168.1.2

router_nogso: _create_scenario _lower_mtu_host2_router _disable_gso_tso_ufo

router_nogso_icmp_blocked: _create_scenario _lower_mtu_host2_router _disable_gso_tso_ufo _block_router_icmp

add_pods: _add_pods

router_nogso_icmp_blocked_mtu_probing: _create_scenario _lower_mtu_host2_router _disable_gso_tso_ufo _block_router_icmp
	@echo "Enabling TCP MTU probing (TCP PLPMTUD) on the host2 (tcp_mtu_probing=2)..."
	@sudo ip netns exec host2 bash -c "echo 2 > /proc/sys/net/ipv4/tcp_mtu_probing"

router_gso: _create_scenario _lower_mtu_host2_router

_test_large_icmp_request:
	@echo "TEST: Sending 3 ICMP requests maxing out MTU=1500 (-s 1472)"
	@echo ""
	@sudo ip netns exec $(NS) timeout $(MAX_CAPTURE_TIME) tcpdump -i $(IFACE) $(TCPDUMP_FLAGS) icmp &
	@echo "Waiting for tcpdump in veth3 to be up and running..."
	@sleep $(TCPDUMP_SLEEP)
	@sudo ip netns exec $(NS) ping -s 1472 $(IP) -c 3 2>&1 > /dev/null

test_host_large_icmp_request:
	$(MAKE) _print_scenario
	$(MAKE) _test_large_icmp_request NS=host2 IFACE=veth3 IP=192.168.0.2

test_pods_large_icmp_request:
	$(MAKE) _print_scenario_pods
	$(MAKE) _test_large_icmp_request NS=host2_pod1 IFACE=eth0 IP=192.168.11.2

_test_tcp:
	@echo ""
	@echo 'Clear PMTUD cache (sudo ip route flush cache)'
	@sudo ip netns exec host2 ip route flush cache
	@sudo ip netns exec host2 timeout $(MAX_CAPTURE_TIME) nc -l 12345 > /dev/null &
	@sudo ip netns exec host2 timeout $(MAX_CAPTURE_TIME) tcpdump -i veth3 $(TCPDUMP_FLAGS) -c 100 tcp or icmp &
	@echo "Waiting for tcpdump in veth3 to be up and running (will sniff the first 100 TCP|ICMP pkts)..."
	@sleep $(TCPDUMP_SLEEP)
	@sudo ip netns exec host2 bash -c "dd if=/dev/zero bs=1M count=100 | nc 192.168.0.2 12345"

shell_router:
	sudo ip netns exec router bash
shell_host1:
	sudo ip netns exec host1 bash
shell_host1_pod1:
	sudo ip netns exec host1_pod1 bash
shell_host2:
	sudo ip netns exec host2 bash
shell_host2_pod1:
	sudo ip netns exec host2_pod1 bash

clean:
	sudo ip netns exec host1 ip link del lxc1 || true
	sudo ip netns exec host2 ip link del lxc1 || true
	sudo ip netns exec router ip link del veth1 || true
	sudo ip netns exec router ip link del veth2 || true
	sudo ip netns del router || true
	sudo ip netns del host1_pod1 || true
	sudo ip netns del host2_pod1 || true
	sudo ip netns del host1 || true
	sudo ip netns del host2 || true
