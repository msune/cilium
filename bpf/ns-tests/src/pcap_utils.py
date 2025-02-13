import threading
import queue
import time
import logging
import multiprocessing
import struct
from scapy.all import *

from src.netns import *

io_thread = None
mutex = threading.Lock()
keep_running = True
buffers = None

IO_KEEP_RUNNING_S=0.5
SYNC_ATTEMPTS=3
SYNC_ATTEMPTS_SLEEP_S=0.5
SYNC_READ_ATTEMPTS=5
SYNC_READ_SLEEP_S=0.05

def __sync_iface(ns:str, iface:str):
    cnt = 1

    # Get into the right NS
    netns_set(ns)

    # Base sentinel pkt
    p = Ether()/IP()/TCP(dport=47)

    for i in range(1, SYNC_ATTEMPTS):
        # Inject sentinel pkt
        #
        # Note: this might get lost if sniffer is not up, but at the same time
        #       read timeout could occurr _before_ the pkt is actually read,
        #       hence the counter in sport (we only care to have seen last sent)
        p["TCP"].sport = cnt
        sendp(p, iface=iface, verbose=False)

        for i in range(1, SYNC_READ_ATTEMPTS):
            pkts = pcap_get_pkts(ns, iface, 128)
            if len(pkts) == 0:
                time.sleep(SYNC_READ_SLEEP_S)
                continue
            for pkt in pkts:
                if "TCP" not in pkt:
                    continue
                if pkt["TCP"].dport != 47:
                    continue
                if pkt["TCP"].sport != cnt:
                    continue
                print(f"done")
                return
        time.sleep(SYNC_ATTEMPTS_SLEEP_S)
        cnt = cnt + 1
    raise Exception(f"Unable to sync '{iface}'!")

def _pcap_sniffer_ioloop(test_name:str, ns:str, iface:str, filter_expr:str, pipe):

    # Get into the right NS
    netns_set(ns)

    # Open pcap file
    fpath = f"output/{test_name}/{ns}_iface.pcap"
    pcap_writer = PcapWriter(fpath, append=False)

    def pkt_callback(pkt):
        hdr = struct.pack('I', len(pkt))
        pipe.send_bytes(hdr)
        pipe.send_bytes(raw(pkt))
        pcap_writer.write(pkt)
        pcap_writer.flush()
    try:
        sniffer = AsyncSniffer(iface=iface, prn=pkt_callback, filter=filter_expr)
        sniffer.start()
    except Exception as e:
        print(f"Error capturing packets on '{ns}:{iface}'. Exception: {e}")

    while True:
        time.sleep(1)

def _pcap_sniffer_spawn(test_name:str, ns:str, iface:str, filter_expr:str):
    global procs
    main_pipe, sniffer_pipe = multiprocessing.Pipe()
    args = (test_name, ns, iface, filter_expr, sniffer_pipe,)
    proc = multiprocessing.Process(target=_pcap_sniffer_ioloop, args=args)

    proc.start()

    ns_iface = ns+":"+iface
    procs[ns_iface] = {
        "ns_iface": ns_iface,
        "proc": proc,
        "main_pipe": main_pipe,
        "sniffer_pipe": sniffer_pipe
    }

def _pcap_thread_ioloop():
    global keep_running, procs
    fd_to_procs = {}

    epoll = select.epoll()
    for key, d in procs.items():
        fd_to_procs[d["main_pipe"].fileno()] = d
        epoll.register(d["main_pipe"], select.EPOLLIN)

    try:
        while keep_running:
            events = epoll.poll(IO_KEEP_RUNNING_S)
            for pipe_fd, event in events:
                if pipe_fd not in fd_to_procs:
                    raise Exception(f"Unknown pipe: {pipe}")

                d = fd_to_procs[pipe_fd]

                pipe = d["main_pipe"]
                pkt_len = struct.unpack("I", pipe.recv_bytes(4))[0]
                pkt = Ether(pipe.recv_bytes(pkt_len))
                if len(pkt) != pkt_len:
                    raise Exception(f"Pkt length mismatch: hdr: {pkt_len}, pkt: {len(pkt)}")

                if d["ns_iface"] not in buffers:
                    raise Exception(f"Unable to find buffer queue for '{ns_iface}'")

                with mutex:
                    buffers[d["ns_iface"]].put(pkt)
    except Exception as e:
        print(f"Exception while reading from pipes: {e}")
    finally:
        epoll.close()

def _pcap_thread_spawn():
    global io_thread
    io_thread = threading.Thread(target=_pcap_thread_ioloop)
    io_thread.start()

def pcap_sniff(test_name:str, ns_ifaces: list, filter_expr:str=""):
    """
    Start sniffers on the list of ns_ifaces using the pcap filter_expr

    @param ns_ifaces List of interfaces in the format `<ns>:<name>`.
                     Use "" for the default NS.
    """
    global procs, buffers
    buffers = {iface: queue.Queue() for iface in ns_ifaces}
    procs = {}
    pcap_files = {}

    # Create pcap output folder for this test
    os.makedirs(f"output/{test_name}/", exist_ok=True)

    #Add sentinel clause (TCP port 47 is reserved, no traffic should flow there)
    if filter_expr:
        filter_expr = f"({filter_expr}) or tcp port 47"

    # Start sniffer child procs
    for ns_iface in ns_ifaces:
        ns = ns_iface.split(":")[0]
        iface = ns_iface.split(":")[1]
        _pcap_sniffer_spawn(test_name, ns, iface, filter_expr)

    # Start I/O thread
    _pcap_thread_spawn()

    # Make sure sniffer is up and running
    for ns_iface in ns_ifaces:
        ns = ns_iface.split(":")[0]
        iface = ns_iface.split(":")[1]
        __sync_iface(ns, iface)

def pcap_stop():
    """
    Stop sniffers
    """
    global io_thread, keep_running, procs
    keep_running = False
    io_thread.join()

    for key, d in procs.items():
        print(f"Stopping {key}")
        d["proc"].terminate()
        d["proc"].join()

def pcap_get_pkts(ns:str, iface:str, n_elements:int=1):
    """
    Dequeue up to n_elements from the queue
    """
    global buffers
    key = ns+":"+iface
    if key not in buffers:
        return []
    q = buffers[key]
    with mutex:
        pkts = [q.get() for _ in range(min(q.qsize(), n_elements))]
    return pkts
