# [Linux] Routing IP packets (summary)

A Linux host/namespace with the sysctl `ip_forward` flag will attempt incoming
packets from interfaces not attached to a bridge. The route lookup will result
in a route and next hop and an associated egress interface.

The behaviour is that of a regular IP router, except there are some nuances on
TSO/GSO.

For a packet which is NOT TSO/GSO, and assuming the default value in
`ip_forward_use_pmtu=0`sysctl, the Linux kernel will:

1. Deduce what is the effective forwarding MTU, min {route MTU,
   egress device MTU}
1. Check the size of the packet against the effective MTU. If the packet is
   bigger, the kernel will (IPv4 only):
    * If `DF=0` fragment the packet.
    * If `DF=1` will:
       * Drop the original packet
       * Generate an ICMP message, as described in the [PMTUD section](pmtud.md).


## The effect of TSO/GSO on PMTUD: where is MTU checked?

TBD

## The effect of tunneling

### Tunneling GSO offload

## Practical example: routing between namespaces



Assume this diagram:

```
  .............................     .........................
 ----                  -----  .     .  -----                .
|eth0|    Default NS  |veth0|---------|veth1|   Namespace X .
 ----                  -----  .     .  -----                .
  .............................     .........................

```

And assume the following simplified route table:

```
Default NS:
----------

10.0.0.0/24 dev veth0 proto kernel scope link src 10.0.0.1 metric 600
default via 192.168.1.1 dev eth0

NS X:
----

10.0.0.0/24 dev veth1 proto kernel scope link src 10.0.0.2 metric 600
default via 10.0.0.1 dev veth1
```

