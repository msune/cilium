# Packetization Layer Path MTU Discovery (PLPMTUD)

Packetization Layer Path MTU Discovery (PLPMTUD) is defined in [RFC4821](https://datatracker.ietf.org/doc/html/rfc4821),
and it's an attempt to fix some of the limitations of [PMTUD](pmtud.md). PLPMTUD
is only possible for protocols that have explicit acknolwedgements, like TCP.

In TCP this is sometimes referred as TCP probing.

TCP PLPMTUD uses the TCP state machine information to craft probe packets
alongside of traffic to probe the effective MTU of the network between the two
TCP peers. It uses ACKs/SACKs to deduce losses and therefore be able to detect
the effective:

* Minimum Transfer Unit: some networks will drop packets, typically < 64 bytes.
* Maximum Transfer Unit (MTU).

Probes are sent between values `search_low` and `search_high`. `search_high` is
inherently bound by the MTU of the (egress) interface.

```
               search_low          eff_pmtu         search_high
                   |                   |                  |
           ...------------------------->

               non-probe size range
                   <-------------------------------------->
                               probe size range
```

## [Linux] Configuring PLPMTUD

### sysctl

There are a number of [sysctls](https://docs.kernel.org/networking/ip-sysctl.html#tcp-variables)
to control PLPMTUD or MTU probing:

* `tcp_mtu_probing`: possible values:
  * `0`: disabled. [Default in most linux distros]
  * `1`: disabled by default, enabled when an ICMP black hole is detected
  * `2`: always enabled, uses inital MSS of `tcp_base_mss`
* `tcp_base_mss`: initial value to use for MTU probing ir PLPMTUD (`search_low`).
* `tcp_mtu_probe_floor`: caps th minimum MSS used for (`search_low`).

### Code

Some pointers to "tcp probing":

* Some pointers [1](https://github.com/torvalds/linux/blob/00a7d39898c8010bfd5ff62af31ca5db34421b38/net/ipv4/tcp_output.c#L2434), [2]()
* A patchset improving base PLPMTUD for TCP:

```
commit f0fdc80bd9ced4de3eb165c9c408e83713a71104
Merge: aaa4e70404c7 fab427608437
Author: David S. Miller <davem@davemloft.net>
Date:   Fri Mar 6 14:57:46 2015 -0500

    Merge branch 'pmtu-probe'
    
    Fan Du says:
    
    ====================
    Improvements for TCP PMTU
    
    This patchset performs some improvements and enhancement
    for current TCP PMTU as per RFC4821 with the aim to find
    optimal mms size quickly, and also be adaptive to route
    changes like enlarged path MTU. Then TCP PMTU could be
    used to probe a effective pmtu in absence of ICMP message
    for tunnels(e.g. vxlan) across different networking stack.
    
    Patch1/4: Set probe mss base to 1024 Bytes per RFC4821
    Patch2/4: Do not double probe_size for each probing,
              use a simple binary search to gain maximum performance.
              mss for next probing.
    Patch3/4: Create a probe timer to detect enlarged path MTU.
    Patch4/4: Update ip-sysctl.txt for new sysctl knobs.
```

### PLPMTUD in action

:warning: Something is fishy in either the test or the kernel with PLPMTUD :warning:

You can check the [demo](demo/) for seeing how PLPMTUD discovery works. You must
use the `_nogso_icmp_blocked` variant:

```
cd demo
make router_nogso_icmp_blocked
```

The scenario has all veth MTUs set to 1500, except `veth1` that is set to 1400.

You can then test:

* ICMP large packets (technically this is not affected by GSO): `test_large_icmp_request`. 
* TCP large flow: `test_tcp`
