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

