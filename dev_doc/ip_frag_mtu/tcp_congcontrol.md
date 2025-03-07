# TCP congestion control and MTU

:warning: this needs to be validated!

TCP congestion control [RFC2581](https://datatracker.ietf.org/doc/html/rfc2581)
adapts the rate of transmission based on packet loss and round trip times.

When TCP segments are lost due to MTU issues in transit, PLPMTUD is disabled
and PMTUD messages don't make it back to the sender, the TCP congestion control
may intereprete losses as a sign of congestion in the network.

As a result, it will temporally lower the effective transmission window and
retransmit frames. If lowered enough, packets may fall into an acceptable size
for the constrained MTU. It's important to mention that as packets make it to
the other end and are ACKed, the TX window will increase and the cycle will
repeat. As a result, TCP connections might be able to work but their performance
severly degraded.
