BPFVER  ?= v1.5.0
LIBBPF  := $(PWD)/bpf/libbpf
INCLUDE ?= 

default: cmd/balancer

stuff:
	cd bpf && $(MAKE) layer3.o.gz

cmd/balancer:
	cd bpf && $(MAKE) libbpf/bpf/libbpf.a bpf.o.gz
	cd cmd && CGO_CFLAGS="-I$(LIBBPF)" CGO_LDFLAGS="-L$(LIBBPF)/bpf" go build -o balancer balancer.go

cmd/balancer3:
	cd bpf && $(MAKE) libbpf/bpf/libbpf.a bpf.o.gz
	cd cmd && CGO_CFLAGS="-I$(LIBBPF)" CGO_LDFLAGS="-L$(LIBBPF)/bpf" go build -o balancer3 balancer3.go

clean:
	rm -f cmd/balancer

distclean: clean
	cd bpf && $(MAKE) distclean

pristine:
	cd bpf && $(MAKE) pristine

cloc:
	ls -1 */*_test.go > tests.txt
	cloc --exclude-list-file=tests.txt *.go bpf/*.go maglev/*.go xdp/*.go  bpf/*.c bpf/*.h xdp/*.c xdp/*.h

tests:
	(cd bpf/ && go test -v)
	(cd maglev/ && go test -v)

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
