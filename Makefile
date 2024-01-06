LIBBPF := $(PWD)/libbpf/src
#BPFVER ?= v0.6.1
#BPFVER ?= v0.8.1
BPFVER ?= v1.3.0

export CGO_CFLAGS  = -I$(LIBBPF)
export CGO_LDFLAGS = -L$(LIBBPF)

FLOW_STATE_TYPE ?= BPF_MAP_TYPE_LRU_PERCPU_HASH
FLOW_STATE_SIZE ?= 1000000  # 1M
FLOW_SHARE_SIZE ?= 1000000  # 1M
FLOW_QUEUE_SIZE ?= 10000

default:
	test -f bpf/bpf.o.gz || $(MAKE) bpf/bpf.o.gz

example: bpf/bpf.o.gz
	cd balancer && $(MAKE)

bpf/bpf.o.gz: bpf/bpf.o
	gzip -9 bpf/bpf.o

%.o: %.c libbpf
	clang -S \
	    -target bpf \
	    -D FLOW_STATE_TYPE=$(FLOW_STATE_TYPE) \
	    -D FLOW_STATE_SIZE=$(FLOW_STATE_SIZE) \
	    -D FLOW_SHARE_SIZE=$(FLOW_SHARE_SIZE) \
	    -D FLOW_QUEUE_SIZE=$(FLOW_QUEUE_SIZE) \
	    -D __BPF_TRACING__ \
	    -I$(LIBBPF) \
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

libbpf/src/libbpf.a: libbpf
	cd libbpf/src && $(MAKE)

clean:
	rm -f bpf/bpf.o bpf/bpf.o.gz
	cd balancer && $(MAKE) clean

distclean: clean
	rm -rf libbpf
	cd balancer && $(MAKE) distclean

debian-dependencies:
	apt-get install build-essential libelf-dev clang libc6-dev llvm

wc:
	wc *.go */*.go
	wc xdp/*.h xdp/*.c bpf/*.c bpf/*.h

test: libbpf/src/libbpf.a
	#cd maglev/ && go test -v
	#cd nat/    && go test -v
	env
	go test -v

