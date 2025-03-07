# MTU IP fragmentation short intro

## Introduction

[Maximum Transmission Unit](MTU) is the size of the largest protocol data unit (PDU)
that can be sent over an interface, **excluding the data link layer**.

In other words for IPv4/6 packets, the MTU is `sizeof(IPv4|6 + payload)`.

### MTU vs max packet size

See the details [here](mtu_vs_max_pkt_size.md)

### The effective MTU

End systems use the effective MTU for a given destination to decide how to
generate IP packets towards that destination. Simplified, the process is as
follows:

1. Do a route lookup in the Routing Information Base (RIB) to reach the destination
   IP. Note that in some routers this can be a recursive process (in Linux
   route tables are flattened to the next hope, so unrolled, closer to a FIB).
   This result is in a route with an adjacent next hop.
2. The effective MTU is the minimum value betweeni:
    * the route MTU
    * the next hop egress device MTU
    * the PMTUD discovered MTU (see below)

There are some differences on how packets are generated depending on the L4, see
the following specific sections for TCP and UDP.

### IPv4 fragmentation and MTU exceeded (v4/v6)

A quick summary on what happens when packets are exceeding the MTU is stubbed
[here](ip_frag.md).

Please note the specifics about Linux hosts with multiple namespaces.

### Path MTU Discovery (PMTUD). TL;DR it's broken.

In short, PMTUD adjusts the effective MTU for a given destination. It is
however not always reliable. The details have been stubbed [here](pmtud.md).

### Packetization Layer Path MTU Discovery (PLPMTUD)

In short, PLPMTUD can send probes, detect losses and adapt the MSS. Details
[here](plpmtud.md).

### TCP congestion control and MTU

TCP congestion control can interprete MTU losses as congestion.
Details [here](tcp_congcontrol.md).

### TCP

For `AF_STREAM` sockets, after a successful `connect()`, processes can `write()`
into the file descriptor of the socket. Data might be buffered by the kernel.

Buffered data needs to then be packed on top of an IPv4 or IPv6 packet:

```
IPvX(dst=IP_dst, src=IP_device)/TCP(dport=XX, sport=YY,...)/Raw(data)
``

In order to determine the size of the data portion to put on a packet - and in
absence of TSO/GSO -  the TCP state machine will use the **current and effective**
Maximum Segment Size (MSS) on the socket. The MSS is nothing but the number of
payload bytes that can be added on top of the TCP header without exceeding the
effective MTU size (or the MSS detected by PLPMTUD, see below). Note that the
maximum TCP MSS will always be upper bound by the effective MTU, yet the current
MSS can be lower than (PLPMTUD).


#### Packetization Layer Path MTU Discovery (PLPMTUD) RFC481

#### How and why MSS is aj

#### How MSS is 
simplify, this val
Thistake the effective MTU size
In order to det

is then packed on TCP segments. When a packet towards `IP_dest` In absence of TSO/GSO, the Maximum
Segment Size (that is the payload to the (see the the simpl
The Linux kernel will schedule
Buffered data (out of scope how this happens)
 is successful, if a `write()` is
issued, the Linux kernel will attempt to send the buffered data. For doing so
it will prepare  using IPT

#### TCP Segmentation Offload (TSO) and Generic Segmentation Offload (GSO)

* UDPow toHow packets are generated (in POSIX sockets)



