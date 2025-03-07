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
2. The effective MTU is the minimum value between:
    * the route MTU
    * the next hop egress device MTU
    * the PMTUD discovered MTU (see below)
    * for TCP, PLPMTUD can further constrain the MTU

There are some differences on how packets are generated depending on the L4, see
the following specific sections for TCP and UDP.

### IPv4 fragmentation and MTU exceeded (v4/v6)

A quick summary on general IP routing and MTU, fragmentation etc. is stubbed
[here](ip_frag.md).

Please note the specifics about Linux hosts with multiple namespaces.

### Path MTU Discovery (PMTUD). TL;DR it's mostly broken.

In short, PMTUD adjusts the effective MTU for a given destination. It is
however not always reliable. The details have been stubbed [here](pmtud.md).

### Packetization Layer Path MTU Discovery (PLPMTUD)

In short, In TCP PLPMTUD can send probes (tcp probing), detect losses and adapt
the MSS. Details [here](plpmtud.md).

### TCP congestion control and MTU

TCP congestion control can interprete MTU losses as congestion. Details
[here](tcp_congcontrol.md).

### [Linux] General considerations

Considerations:

1. In Linux every single network namespace - including the default
   one- acts as an IP router for IP frames.
1. Packets generated from a network namespace (from sockets on that NS) are
   routed using the Route table.
1. Packets entering a network namespace (e.g. via an veth) will be:
   * switched if attached to a bridge
   * routed - as a regular IP router - otherwise.
1. Packets tunneled in another IP packet (IPinIP, VXLAN, Geneve, Wireguard etc.)
   will be recirculated and routed again after encapsulation (same skb), using
   the new outer IP header. This is not the case for IPSEC.
1. Linux VRFs (!= namespaces) are out of scope of this doc.

### [Linux] TSO/GSO and USO

* TCP segmentation offload (TSO) and Generic Segmentation Offload (GSO) is stubbed [here](tso_gso.md).
  Note TSO/GSO is enabled by default in Linux for TCP.

## [Linux] End host packet generation

### TCP

This section is stubbed [here](tcp_gen.md)

### UDP

This section is stubbed [here](ud_gen.md)

## [Linux] Routing IP packets

This section is stubbed [here](linux_ip_routing.md)
