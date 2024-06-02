BPFVER  ?= v1.3.0
LIBBPF  := $(PWD)/libbpf
INCLUDE ?= 

# MAX_CPU_SUPPORT defines the size of a map which is an array of 32bit
# pointers to LRU hash maps - one for each CPU core. The size should
# be set to something that is larger than the number of cores that are
# expected in any machine that this might run on. Setting it to
# something absuredly high is not a problem because the storage used
# is very small (in the order of 4 bytes x value). Memory usage will,
# of course, scale with the number of cores you actually have. My
# servers have 32 cores, with 64 threads on single socket on a
# motherboard that supports two processors, so 128 is already a
# commodity configuration! I've found a maximum NR_CPU of 8192 in the
# kernel source, so it probably wouldn't hurt to set it to that
# (although you'd need a lot of memory - which you probably do)
MAX_CPU_SUPPORT ?= 8192
FLOW_STATE_SIZE ?= 1000000
FLOW_QUEUE_SIZE ?= 10000

default: balancer

balancer: libbpf/bpf/libbpf.a blob
	cd cmd && CGO_CFLAGS="-I$(LIBBPF)" CGO_LDFLAGS="-L$(LIBBPF)/bpf" go build -o $@ balancer.go

blob: bpf/bpf.o.gz

clean:
	rm -f cmd/balancer

distclean: clean
	rm -rf libbpf

pristine: clean
	rm -f bpf/bpf.o.gz

bpf/bpf.o.gz: bpf/bpf.c bpf/*.h
	$(MAKE) bpf/bpf.o
	rm -f bpf/bpf.o.gz
	gzip bpf/bpf.o

%.o: %.c libbpf/bpf
	clang -S \
	    -target bpf \
	    -D FLOW_STATE_SIZE=$(FLOW_STATE_SIZE) \
	    -D FLOW_QUEUE_SIZE=$(FLOW_QUEUE_SIZE) \
	    -D MAX_CPU_SUPPORT=$(MAX_CPU_SUPPORT) \
	    -D __BPF_TRACING__ \
	    -I$(LIBBPF) $(INCLUDE) \
	    -Wall \
	    -Werror \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -g -O2 -emit-llvm -c -o $*.ll $*.c
	llc -march=bpf -filetype=obj -o $@ $*.ll
	rm $*.ll

libbpf:
	git clone -b $(BPFVER) https://github.com/libbpf/libbpf

libbpf/bpf: libbpf
	cd libbpf && ln -s src bpf

libbpf/bpf/libbpf.a: libbpf/bpf
	cd libbpf/bpf && $(MAKE)

cloc:
	cloc *.go bpf/*.go maglev/*.go xdp/*.go  bpf/*.c bpf/*.h xdp/*.c xdp/*.h

# For Raspberry Pi (I'm using "Raspberry Pi OS Lite (32 bit): Debian Bookworm"),
# to rebuild the eBPF object with lower memory use:	
#   make bpf/bpf.o.gz FLOW_STATE_SIZE=1000 INCLUDE=-I/usr/arm-linux-gnueabi/include
raspberrypi:
	apt install -y golang-1.19 libelf-dev clang llvm libc6-dev-armel-cross
	ln -s /usr/lib/go-1.19/bin/go /usr/local/bin/go || true

bookworm-amd64:
	apt install -y golang-1.19 libelf-dev clang llvm libc6-dev-i386
	ln -s /usr/lib/go-1.19/bin/go /usr/local/bin/go || true

jammy-amd64:
	apt install -y golang-1.21 libelf-dev clang llvm libc6-dev-i386
	ln -s /usr/lib/go-1.21/bin/go /usr/local/bin/go
