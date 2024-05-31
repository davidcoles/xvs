# XDP Virtual Server

An XDP/eBPF load balancer and Go API for Linux.

This code is originally from the
[VC5](https://github.com/davidcoles/vc5) load balancer, and has been
split out to be developed seperately.

This code implements an IPv4 layer 2 Direct Server Return load
balancer with an eBPF data plane that is loaded into the kernel and a
supporting Go library to configure the balancer through the XDP
API. Backend servers need share a VLAN with the load balancer.
Multiple VLANs/interfaces are supported.

The ELF object file is committed to this repository (main branch) and
is accessed via Go's embed feature, which means that it can be used as a
standard Go module without having to build the binary as a seperate
step. [libbpf](https://github.com/libbpf/libbpf) is still required for
linking programs using the library (CGO_CFLAGS and CGO_LDFLAGS
environment variables may need to be used to specify the location of the
library - see the Makefile for an example of how to do this).

Support for layer 3 DSR and IPv6 is planned.

# Portability

eBPF code is JITted to the native instruction set at runtime, so this
should run on any Linux architecture. Currently AMD64 and ARM
(Raspberry Pi) are confirmed to work.

Devices with constrained memory might have issues loading in the
default size flow state tables, so you may have to rebuild the eBPF
object file overriding the defaults (see the `raspberrypi` target in
the Makefile).

Pi wi-fi load balancer:

`cmd/balancer wlan0 192.168.0.16 192.168.101.1 192.168.0.10 192.168.0.11`

## Documentation

https://pkg.go.dev/github.com/davidcoles/xvs

The API is loosely modelled on the [Cloudflare IPVS
library](https://github.com/cloudflare/ipvs) [(Go
reference)](https://pkg.go.dev/github.com/cloudflare/ipvs).

## Sample application

A simple application in the `cmd/` directory will balance traffic
to a VIP (TCP port 80 by default, can be changed with flags) to a
number of backend servers on the same IP subnet.

Compile/run with:
 
* `make example`
* `cmd/balancer ens192 10.1.2.3 192.168.101.1 10.1.2.10 10.1.2.11 10.1.2.12`

Replace `ens192` with your ethernet interface name, `10.1.2.3` with
the address of the machine you are running the program on,
`192.168.101.1` with the VIP you want to use and `10.1.2.10-12` with
any number of real server addresses.

On a seperate client machine on the same subnet you should add a static route for the VIP, eg.:

* `ip r add 192.168.101.1 via 10.1.2.3`

You should then be able to contact the service:

* `curl http://192.168.101.1/`

No healthchecking is done, so you'll have to make sure that a
webserver is running on the real servers and that the VIP has been
configured on the loopback address (`ip a add 192.168.101.1 dev lo`).

A more complete example with health check and BGP route health
injection is currently available at
[VC5](https://github.com/davidcoles/vc5).


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
streams at 2Gbps/3.8Mpps ingress traffic and 46.5Gbps egress. The
server was more than 90% idle. Unfortunately I did not have the
resources available to create more clients/servers. I realised that I
carried this out when the server's profile was set to performance
per-watt. Using the performance mode the CPU usage is barely 2% and
latencey is less than 250 nanoseconds.

On a Raspberry Pi (B+) ... don't get your hopes up!

