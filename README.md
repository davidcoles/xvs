# XDP Virtual Server

An XDP/eBPF load balancer and Go API for Linux.

This code is originally from the
[VC5](https://github.com/davidcoles/vc5) load balancer, and has been
split out to be developed seperately.

The eBPF object file is committed to this repository which means that
it can be used as a standard Go module without having to build the
binary as a seperate step. [libbpf](https://github.com/libbpf/libbpf)
is still required but this will be linked in the standard CGO manner
by setting the CGO_CFLAGS and CGO_LDFLAGS environment variables to the
location of the library (see the Makefile for an example of how to do
this).

The code implements an IPv4 Layer-2 Direct Server Return load
balancer. Backend servers need to be on the same VLAN as the load
balancer. Multiple VLANs/interfaces are supported.

Layer 3 DSR and IPv6 support is planned.

## Documentation

https://pkg.go.dev/github.com/davidcoles/xvs

## Sample application

A simple application in the `balancer/` directory will balance traffic
to a VIP (TCP port 80 by default, can be changed with flags) to a
number of backend servers on the same IP subnet.

Compile/run with:
 
* `make example`
* `balancer/balancer ens192 10.1.2.3 192.168.101.1 10.1.2.10 10.1.2.11 10.1.2.12`

Replace `ens192` with your ethernet interface name, `10.1.2.3` with
the address of the machine you are running the program on,
`192.168.101.1` with the VIP you want to use and `10.1.2.10-12` with
any number of real server addresses. For this simple example
everything needs to be on the same VLAN/subnet.

On a seperate client machine on the same subnet you should add a static route for the VIP, eg.:

* `ip r add 192.168.101.1 via 10.1.2.3`

You should then be able to contact the service:

* `curl http://192.168.101.1/`

No healthchecking is done, so you'll have to make sure that a
webserver is running on the real servers and that the VIP has been
configured on the loopback address on them (`ip a add 192.168.101.1 dev lo`).


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
resources available to create more clients/servers.
