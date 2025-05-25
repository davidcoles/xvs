# XDP Virtual Server

An [XDP](https://en.wikipedia.org/wiki/Express_Data_Path)/[eBPF](https://en.wikipedia.org/wiki/EBPF)
load balancer and Go API for Linux.

I'm now moving the new IPv6/layer 3 tunneling branch to main. It's not
quite production ready yet, so continue to use the v0.1 branch/tags
for that. When it seems ready I'll tag with v0.2 and start migrating
vc5 for proper testing.

This code is originally from the
[vc5](https://github.com/davidcoles/vc5) load balancer, and has been
split out to be developed seperately.

XVS implements a layer 4 Direct Server Return (DSR) load
balancer with an eBPF data plane (that is loaded into the kernel), and a
supporting Go library to configure the balancer through the XDP
API.

IPv6 and [layer 3 tunnels](doc/tunnels.md) are now supported. Tunnel
types implemented are: IP-in-IP (all flavours), GRE, FOU and GUE. A
NAT system provides a mechanism to directly query services via the
virtual IP address on backends (using the appropriate tunnel type),
which allows a client to perform accurate health checks and so
enable/disable new connections to targets as necessary.

There is no requirement to use the same address family for virtual and
real server addresses; you can forward IPv6 VIPs to backends using an
IPv4 tunnel endpoint, and vice versa.

Some facilities may not have been implemented in the new code yet, but
will be added shortly.

A compiled BPF ELF object file is committed to this repository (tagged
versions) and is accessed via Go's embed feature, which means that it
can be used as a standard Go module without having to build the binary
as a separate step. [libbpf](https://github.com/libbpf/libbpf) is
still required for linking programs using the library (CGO_CFLAGS and
CGO_LDFLAGS environment variables may need to be used to specify the
location of the library - see the Makefile for an example of how to do
this).

# Portability

eBPF code is JITted to the native instruction set at runtime, so this
should run on any Linux architecture. Currently AMD64 and ARM
(Raspberry Pi) are confirmed to work.

Devices with constrained memory might have issues loading the default
size flow state tables. This can now be overriden with the MaxFlows
parameter on newer kernels.

## Documentation

Some notes about design are in the [doc/](doc/) directory, and the [Go
API is described here](https://pkg.go.dev/github.com/davidcoles/xvs).

The API is loosely modelled on the [Cloudflare IPVS
library](https://github.com/cloudflare/ipvs) [(Go
reference)](https://pkg.go.dev/github.com/cloudflare/ipvs).

## Sample application

A simple application in the `cmd/` directory will balance traffic
to a VIP (TCP port 80 by default, can be changed with flags) to a
number of backend servers on the same IP subnet.

Compile/run with, eg.:

* `make`
* `cmd/balancer -r 180 -t gre ens192 10.1.2.254/24 192.168.101.1 10.1.10.100 10.1.10.101`

where `180` is the number of seconds to run for, `gre` is the tunnel
type, `ens192` is the network card you wish to load the XDP program
onto, `10.1.2.254/24` is the IP address of the router that will handle
tunneled traffic (the `/24` allows the library to determine the local
IP address to use as the source for tunnel packets), `192.168.101.1`
is the VIP, and `10.1.10.100` & `10.1.10.101` are two real servers to
send the traffic to. Only port 80/tcp is forwarded by default, but
other ports can be added (-h for help).

On a separate client machine on the same subnet you should add a
static route for the VIP directed at the load balancer's own IP
address, eg.:

* `ip r add 192.168.101.1 via 10.1.2.3`

You should then be able to contact the service:

* `curl http://192.168.101.1/`

No healthchecking is done, so you'll have to make sure that a
webserver is running on the real servers and that the VIP has been
configured on the loopback address (`ip a add 192.168.101.1 dev lo`).

This is not intended to be a useful utility, more an example of using
the library.  A more complete example with health check and BGP route
health injection is currently available at
[vc5](https://github.com/davidcoles/vc5).


## Performance

This has mostly been tested using Icecast backend servers with clients
pulling a mix of low and high bitrate streams (48kbps - 192kbps).

A VMWare guest (4 core, 8GB) using the XDP generic driver was able to
support 100K concurrent clients, 380Mbps/700Kpps through the load
balancer and 8Gbps of traffic from the backends directly to the
clients. Going above 700Kpps cause connections to be dropped,
regardless of the number of cores or memory assigned to the VM, so I
suspect that there is a limit on the number of interrupts that the VM
is able to handle per second.

On a single (non-virtualised) Intel Xeon Gold 6314U CPU (2.30GHz 32
physical cores, with hyperthreading enabled for 64 logical cores) and
an Intel 10G 4P X710-T4L-t ethernet card, I was able to run 700K
streams with 2Gbps/3.8Mpps ingress traffic and 46.5Gbps egress. The
server was more than 90% idle. Unfortunately I did not have the
resources available to create more clients/servers. I realised that I
carried this out when the server's profile was set to performance
per-watt. Using the performance mode the CPU usage is barely 2% and
latency is less than 250 nanoseconds.

Above tests were done on the old layer 2 code, but will be broadly the
same. I'll do some updated tests soon.

On a Raspberry Pi (B+) ... don't get your hopes up!

## Recalcitrant cards

I initially had problems with the Intel X710 card, but some
combination of SFP+ module/optics replacement and moving to Ubuntu
24.04 seems to have fixed the issue.

The Intel X520 cards that I had previously used work flawlessly.

