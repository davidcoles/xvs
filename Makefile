BPFVER  ?= v1.3.0
LIBBPF  := $(PWD)/libbpf
INCLUDE ?= 

FLOW_STATE_SIZE ?= 1000000
FLOW_QUEUE_SIZE ?= 10000

default: balancer

balancer: libbpf/bpf/libbpf.a blob
	cd cmd && CGO_CFLAGS="-I$(LIBBPF)" CGO_LDFLAGS="-L$(LIBBPF)/bpf" go build -o $@ balancer.go

blob: bpf/bpf.o.gz

clean:
	rm -f cmd/balancer

distclean: clean
	rm -rf libbpf bpf/bpf.o.gz

bpf/bpf.o.gz: bpf/bpf.c bpf/*.h
	$(MAKE) bpf/bpf.o
	rm -f bpf/bpf.o.gz
	gzip bpf/bpf.o

%.o: %.c libbpf/bpf
	clang -S \
	    -target bpf \
	    -D FLOW_STATE_SIZE=$(FLOW_STATE_SIZE) \
	    -D FLOW_QUEUE_SIZE=$(FLOW_QUEUE_SIZE) \
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

# For Raspberry Pi (I'm using "Raspberry Pi OS Lite (32 bit): Debian Bookworm")
# to rebuild the eBPF object with lower memory use:
#   make bpf/bpf.o.gz FLOW_STATE_SIZE=100000 INCLUDE=-I/usr/arm-linux-gnueabi/include
raspberrypi:
	apt install -y golang-1.19 libelf-dev           # needed to build the example binary
	ln -s /usr/lib/go-1.19/bin/go /usr/local/bin/go # put Go in the path
	apt install -y clang libc6-dev-armel-cross llvm # needed to rebuild the eBPF object


