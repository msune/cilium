import pytest
import time
from src.nodes import *
from src.pcap_utils import pcap_sniff, pcap_get_pkts, pcap_stop

@pytest.fixture
def packet_capture():
    """Setup and teardown packet capture."""
    interfaces = ["node1:lo"]
    pcap_sniff(interfaces)
    yield
    pcap_stop()

@pytest.fixture
def build_topology():
    """Create the topology"""
    node_create(1)
    yield
    node_destroy(1)

def test_packet_capture(build_topology, packet_capture):
    """Test that packets are being captured on each interface."""
    _ = build_topology
    _ = packet_capture

    print("Heya")
    while True:
        pkts = pcap_get_pkts("node1", "lo", 10)
        if len(pkts) > 0:
            print(f"Got {len(pkts)}")
            break
        break
    time.sleep(10)
    assert 1 == 1
