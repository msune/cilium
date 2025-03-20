# Linux

(Few things are common to POSIX systems).

XXX: TODO

## General considerations

Considerations:

1. In Linux every single network namespace - including the default
   one - acts as an IP router for IP frames.
1. Packets generated from a network namespace (from sockets on that NS) are
   routed using the Route table.
1. Packets entering a network namespace (e.g. via an veth) will be:
   * switched if attached to a bridge
   * routed - as a regular IP router - otherwise.
1. Packets tunneled in another IP packet (IPinIP, VXLAN, Geneve, Wireguard etc.)
   will be recirculated and routed again after encapsulation (same skb), using
   the new outer IP header. This is not the case for IPSEC.
1. Linux VRFs (!= namespaces) are out of scope of this doc.

## [Linux] TSO/GSO and USO

* TCP segmentation offload (TSO) and Generic Segmentation Offload (GSO) is stubbed
  [here](tso_gso.md). Note TSO/GSO is enabled by default in Linux for TCP.

## End host packet generation

### TCP

This section is stubbed [here](linux_tcp_gen.md)

### UDP

This section is stubbed [here](linux_udp_gen.md)

## Routing IP packets (acting as a router)

This section is stubbed [here](linux_ip_routing.md)
