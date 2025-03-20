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

1. Do a route lookup in the Routing Information Base (RIB) to reach the
   destination IP. This is inherently a recursive process which, when the packet
   is routable, it results in an adjacent next hop. Note that in Linux the route
   table is already flattened (routes can only point to adjacent next hops).
2. The effective MTU is the minimum value between:
    * the route MTU
    * the next hop egress device MTU
    * the PMTUD discovered MTU (see below)
    * for TCP, PLPMTUD can further constrain the MTU

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

## [Linux] General considerations

This section has been stubbed [here](linux.md)

## [Linux] Demo

Take a look into the [demo](demo/) for seeing some of these mechanisms in
action.
