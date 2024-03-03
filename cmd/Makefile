# To use this code as a standalone example:
# Copy the go file and the Makefile to a new directory
# Initialise a go module in the new directory
# (eg.: go mod init balancer && go mod tidy)
# Run make. Done.

# If you already have libbpf installed elsewhere on your system then,
# after inialsing the moudule, you can simply:
# CGO_CFLAGS=-I/path/to/libbpf CGO_LDFLAGS=-L/path/to/libbpf go build

LIBBPF := $(PWD)/libbpf/src
BPFVER ?= v1.3.0

export CGO_CFLAGS  = -I$(LIBBPF)
export CGO_LDFLAGS = -L$(LIBBPF)

build: libbpf/src/libbpf.a
	go build -race

libbpf:
	git clone -b $(BPFVER) https://github.com/libbpf/libbpf

libbpf/src/libbpf.a: libbpf
	cd libbpf/src && $(MAKE)

clean:
	rm -f balancer

distclean: clean
	rm -rf libbpf
