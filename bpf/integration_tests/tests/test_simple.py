import pytest
import time
from src.pcap_utils import pcap_sniff, pcap_get_pkts, pcap_stop

@pytest.fixture
def packet_capture():
    """Setup and teardown packet capture."""
    interfaces = ["lo"]
    pcap_sniff(interfaces)
    yield
    pcap_stop()

def test_packet_capture(packet_capture):
    """Test that packets are being captured on each interface."""
    _ = packet_capture

    print("Heya")
    while True:
        pkts = pcap_get_pkts("lo", 10)
        if len(pkts) > 0:
            print(f"Got {len(pkts)}")
            break
    assert 1 == 1
