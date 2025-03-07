# [Linux] How end hosts generate TCP packets


## Basics

(note we will assume no special `setsockopt()`)


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




For `AF_STREAM` sockets, after a successful `connect()`, processes can `write()`
into the file descriptor of the socket. Data might be buffered by the kernel.


### Socket creation

### Transmitting data


