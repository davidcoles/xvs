LIBBPF := $(PWD)/libbpf
BPFVER ?= v1.3.0

balancer: libbpf/bpf/libbpf.a
	CGO_CFLAGS="-I$(LIBBPF)" CGO_LDFLAGS="-L$(LIBBPF)/bpf" go build -o balancer -race

libbpf:
	git clone -b $(BPFVER) https://github.com/libbpf/libbpf

libbpf/bpf: libbpf
	cd libbpf && ln -s src bpf

libbpf/bpf/libbpf.a: libbpf/bpf
	cd libbpf/bpf && $(MAKE)

clean:
	rm -f balancer

distclean: clean
	rm -rf libbpf
