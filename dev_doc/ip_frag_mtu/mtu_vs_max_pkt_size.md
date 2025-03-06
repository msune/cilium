# MTU vs max packet size

The maximum size of the packet in the wire is the MTU + data link layer size. For
Ethernet II devices, the data link layer and maximum packet size can be:

| Pkt type   | Data Link Layer size   | MTU  | Maximum packet size  | Max. pkt size with FCS    |
|--------------------------|----------------------------------------------|------|-------|------|
| Untagged                 | Ethernet II (14 bytes)                       | 1500 | 1514  | 1518 |
| Single tagged (802.1Q)   | Ethernet II (14 bytes) + VLAN (4bytes)       | 1500 | 1518  | 1522 |
| Double tagged (802.1ad)  | Ethernet II (14 bytes) + 2 x VLAN (4bytes)   | 1500 | 1522  | 1526 |
