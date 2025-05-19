# Tunnels

Some notes on how to configure tunnel decapsulation on Linux backend
servers. Very much an empirical effort and not to be considered as
normative. It would be advisable to add packet filtering rules to only
allow tunnel traffic from expected hosts, and encapsulated packets to
VIPs only.

## IP-in-IP

### 4in4 (RFC 1853)

```
modprobe ipip
ip l set dev tunl0 up
tcpdump tunl0
sysctl -w net.ipv4.conf.tunl0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0
```

### 6in4 (SIT)

```
modprobe sit
ip l set dev sit0 up
```

### 4in6

```
modprobe ip6_tunnel
ip -6 tunnel change ip6tnl0 mode ip4ip6
ip l set dev ip6tnl0 up
sysctl -w net.ipv4.conf.ip6tnl0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0
```

### 6in6

```
modprobe ip6_tunnel
ip -6 tunnel change ip6tnl0 mode ip6ip6
ip l set dev ip6tnl0 up
```


## Generic Route Encapsulation (GRE)

### GRE over IPv4 (carries both IPv4 and IPv6 VIPs)

```
modprobe ip_gre
ip l set dev gre0 up
sysctl -w net.ipv4.conf.gre0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0
````


### GRE over IPv6 (carries both IPv4 and IPv6 VIPs)

```
modprobe ip6_gre
ip l set dev ip6gre0 up
sysctl -w net.ipv4.conf.ip6gre0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0
```


## Foo-over-UDP (FOU)

FOU has no indication of the encapsulated protcol, so a different
(arbitrary) port number must be used to bind each protocol.

### IPv4 in FOU (IPv4 backend)

```
modprobe fou
modprobe ipip
ip fou add port 9999 ipproto 4
ip link set dev tunl0 up
sysctl -w net.ipv4.conf.tunl0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0
```

### IPv6 in FOU (IPv4 backend)

```
modprobe fou
modprobe sit
ip l set dev sit0 up
ip fou add port 6666 ipproto 41
```

### FOU over IPv6

I couldn't find a way to bind a FOU endpoint to an IPv6 UDP port, so I
have been unable to find a working example. The XVS library does
support FOU over IPv6, so to terminate this a simple XDP decapsulator
could be employed. I will likely write one once the library is fully
developed, with options to filter by tunnel peer and VIP.


## Generic UDP Encapsulation ([draft-ietf-intarea-gue-09](https://datatracker.ietf.org/doc/html/draft-ietf-intarea-gue-09))

### IPv4 in GUE

```
modprobe fou
modprobe ipip
ip fou add port 9999 gue
ip link set dev tunl0 up
sysctl -w net.ipv4.conf.tunl0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0
```

### IPv6 in GUE4

```
modprobe fou
modprobe sit
ip l set dev sit0 up
ip fou add port 9999 gue
```


## To configure on boot

```
/etc/networkd-dispatcher/routable.d/50-ifup-hooks:
#!/bin/sh
ip fou add port 9999 ipproto 4
ip link set dev tunl0 up
sysctl -w net.ipv4.conf.tunl0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0
```

```
/etc/modules:
fou
ipip
```
