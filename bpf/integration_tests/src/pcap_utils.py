import threading
import queue
import time
from scapy.all import AsyncSniffer

keep_running = True
buffers = None
threads = []

def __capture_packets(interface, filter_expr):
    global buffers
    def packet_callback(pkt):
        buffers[interface].put(pkt)
    try:
        sniffer = AsyncSniffer(iface=interface, prn=packet_callback, filter=filter_expr)
        sniffer.start()
        while keep_running:
            time.sleep(0.2)
        sniffer.stop()
    except Exception as e:
        print(f"Error capturing packets on {interface}: {e}")

def pcap_sniff(interfaces, filter_expr=""):
    global threads, buffers
    buffers = {interface: queue.Queue() for interface in interfaces}
    threads = []
    for interface in interfaces:
        thread = threading.Thread(target=__capture_packets, args=(interface, filter_expr))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    # Make sure all sniffers are up and running

def pcap_stop():
    global threads
    keep_running = False
    for thread in threads:
        thread.join(timeout=1)

def pcap_get_pkts(interface, n_elements=1):
    """
    Dequeue up to n_elements from the queue
    """
    global buffers
    if interface not in buffers:
        return []
    q = buffers[interface] 
    return [q.get() for _ in range(min(q.qsize(), n_elements))]
