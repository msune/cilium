# IPv4 fragmentation, ICMPv4/v6

## Basics

Assume this simplified network where packets flow from End Host 1 to End host 2
via two intermediate routers X and Y:

```
   ------------      A     ----------    B    ----------     C    -----------
  | End host 1 | -------- | Router X | ----- | Router Y | ------ | End host 2|
   ------------            ----------         ----------          -----------
```

If the MTUs match for links {A, B, C} there is no issue with MTU/fragmentation.
Let's assume now that the link B is now assume link B is constrained (assuming
MTUs on both interface match):

 * Link A: 1500 bytes
 * Link B: 1400 bytes
 * Link C: 1500 bytes

## IPv4

The [RFC 791, Internet Protocol](https://datatracker.ietf.org/doc/html/rfc791)
covers the basics of routing, fragmentation and reassembly.

Packets exceeding MTU 1400 bytes in the example above can't be TX "as is" in
link B, so two things can happen for IPv4:

1. If packets don't have the Don't Fragment flag, `DF=0`, Router X
   will fragment the packet.
1. If packets have Don't Fragment flag, `DF=1`, well behaved routers will send
   an ICMP message back to the originator with `SRC_IP=RouterX_IP` and
   `DST_IP=PKT_SRC_IP` ICMP message type=3 (`Destination Unreachable`), code=4
   (`Fragmentation required, and DF flag set`). This is allows [Path MTU Discovery](pmtud.md)
   to work, but it has its limitations.

### Fragmentation

Fragmentation and reassembly is covered in [RFC 791, section 2.3](https://datatracker.ietf.org/doc/html/rfc791#section-2.3),
but there are a number of other informational RFCs with recommendations on the
implementation (especially with regards to reassembly).

When an IP packet is fragmented, routers will split the packet into two or
more packets. In the simplest of the examples (following the example of mtu
1400), a packet like this (1500 bytes):

```
pkt=IP(src=endhost1, dst=endhost2, df=0, ip_proto=6, identification=12345, tot_len=1500)/TCP()/Payload(size=1460)
```

Will result in two packets:

```
pkt1=IP(src=endhost1, dst=endhost2, df=0, mf=1, ip_proto=6, identification=12345, fragment_offset=0, tot_len=1400)/TCP()/Payload(bytes=[0...1360])
pkt2=IP(src=endhost1, dst=endhost2, df=0, mf=0, ip_proto=6, identification=12345, fragment_offset=1360, tot_len=120)/Payload(bytes=[1361..1460])
```

Worth noting:

* The second packet does **NOT** contain a copy of the original L4 header, but
  the `ip_proto` still is 6 (TCP). Only the portion of the IP frame above the
  MTU is actually copied on the new fragment.
* The Identification field uniquely identifies the flow for the purpose of
  reassembly.
* More Fragments (mf) is set to 1 on all fragments but the last one.
* Fragment offset indicates where to put the portion of the data received in the
  resulting buffer during reassembly (more details below).

Fragmentation is expensive and a performance killer, especially during
reassembly. Most routers do that in HW, but they usually have limitations on
the number of packets they can fragment.

Fragmentation should be avoided at all cost. It's important to note, thoguth,
that while it should be actively avoided, there is no guarantee that some
intermediate links are misconfigured, constraining the effective MTU between two
end hosts resulting in fragmentation.

### Reassembly

Reassembly is an expensive operation, and is to some extent inherently vulnerable
to DoS attacks. For this reason reassembly is typically not done in transit,
except in rare cases (security appliances etc).

Packet networks are subject to:
 * Losses: examples are when a link goes down (e.g. laser failure), transitory
   blackholing of traffic (e.g. due to incorrect routing configurations or
   during reconvergences), transitory routing loops during reconvergences etc.
 * Reorderings: routing reconvergences, incorrect ECMP configuration etc.

End hosts can't assume any ordering, and therefore need to buffer fragments
during a certain period of time. This makes the system vulnerable to DoS, as
an attacker can send partial fragments without never sending the other pieces,
wasting memory CPU and potentially dropping valid fragments.

#### [Linux] sysctls related to IP reassembly

[Sysctls](https://docs.kernel.org/networking/ip-sysctl.html) related to
reassembly are:

* `ipfrag_high_thresh`: max memory to use
* `ipfrag_time`: time in seconds to keep an IP fragment i nmemory
* `ipfrag_max_dist`: maximum disorder allowed between fragments

## IPv6

TBD explain difference no fragmentation in transit, but PMTUD exists and frags
can be generated in source
