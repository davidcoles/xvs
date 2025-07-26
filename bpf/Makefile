BPFVER  ?= v1.5.0
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
ICMP_QUEUE_SIZE ?= 1000

default: layer3.o.gz

clean:
	rm -f *.o

distclean: clean
	rm -f *.gz

pristine: distclean
	rm -rf libbpf

%.o.gz: %.o
	gzip -f $*.o

%.o: %.c %.h libbpf/bpf
	clang -S \
	    -target bpf \
	    -D FLOW_STATE_SIZE=$(FLOW_STATE_SIZE) \
	    -D FLOW_QUEUE_SIZE=$(FLOW_QUEUE_SIZE) \
	    -D MAX_CPU_SUPPORT=$(MAX_CPU_SUPPORT) \
	    -D ICMP_QUEUE_SIZE=$(ICMP_QUEUE_SIZE) \
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
