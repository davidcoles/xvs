LIBBPF := $(PWD)/cmd/libbpf

FLOW_STATE_TYPE ?= BPF_MAP_TYPE_LRU_PERCPU_HASH
FLOW_STATE_SIZE ?= 1000000  # 1M
FLOW_SHARE_SIZE ?= 1000000  # 1M
FLOW_QUEUE_SIZE ?= 10000

example: bpfblob
	cd cmd && $(MAKE)

default: bpfblob

bpfblob:
	test -f bpf/bpf.o.gz || $(MAKE) bpf/bpf.o.gz

bpf/bpf.o.gz: bpf/bpf.o
	gzip -9 bpf/bpf.o

%.o: %.c cmd/libbpf/bpf
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

cmd/libbpf/bpf:
	cd cmd && $(MAKE) libbpf/bpf

clean:
	cd cmd && $(MAKE) clean

distclean: clean
	cd cmd && $(MAKE) distclean

debian-dependencies:
	apt-get install build-essential libelf-dev clang libc6-dev llvm

cloc:
	cloc *.go */*.go */*.h */*.c

tests:
	cd maglev/ && go test -v

# to be run before pushing back to origin
release-checks:
	output="$$(git status --untracked-files=no --porcelain)"; echo "$$output"; test -z "$$output"
	rm -f bpf/bpf.o bpf/bpf.o.gz
	$(MAKE) distclean
	$(MAKE) tests
	$(MAKE) example
	$(MAKE) distclean
	git reset --hard
	git status
