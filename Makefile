BPFVER  ?= v1.5.0
LIBBPF  := $(PWD)/bpf/libbpf
INCLUDE ?= 

default: cmd/balancer

cmd/balancer: cmd/balancer.go *.go
	cd bpf && $(MAKE) libbpf/bpf/libbpf.a layer3.o.gz
	cd cmd && CGO_CFLAGS="-I$(LIBBPF)" CGO_LDFLAGS="-L$(LIBBPF)/bpf" go build -race -o balancer balancer.go

clean:
	rm -f cmd/balancer

distclean: clean
	cd bpf && $(MAKE) distclean

pristine:
	cd bpf && $(MAKE) pristine

cloc:
	cloc  $$(ls -1 *.go */*.go */*.c */*.h | grep -v _test.go)

bpf_printk:
	if `egrep -v '^\s*//' bpf/*.h bpf/*.c | grep bpf_printk >/dev/null 2>&1`; then echo uncommented bpf_printk; exit 1; fi
	echo passed

tests:
	(cd bpf/ && go test -v)
	(cd maglev/ && go test -v -cover)
	CGO_CFLAGS="-I$(LIBBPF)" CGO_LDFLAGS="-L$(LIBBPF)/bpf" go test -v -cover

prerelease: bpf_printk tests

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
	apt install -y golang-1.23 libelf-dev clang llvm libc6-dev-i386
	ln -s /usr/lib/go-1.23/bin/go /usr/local/bin/go
