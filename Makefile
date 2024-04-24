BPFVER ?= v1.3.0
LIBBPF := $(PWD)/libbpf

default: balancer

balancer: libbpf/src/libbpf.a blob
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

libbpf/bpf: libbpf
	cd libbpf && ln -s src bpf

libbpf/src/libbpf.a: libbpf
	cd libbpf/src && $(MAKE)

cloc:
	cloc *.go bpf/*.go maglev/*.go xdp/*.go  bpf/*.c bpf/*.h xdp/*.c xdp/*.h
