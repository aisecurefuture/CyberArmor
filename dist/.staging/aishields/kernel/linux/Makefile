# AIShields Protect - Linux eBPF Monitor Build System
# Requires: clang, llvm, libbpf-dev, linux-headers

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool

KERN_HEADERS ?= /usr/include
BPF_CFLAGS := -O2 -target bpf -D__TARGET_ARCH_x86 \
	-I$(KERN_HEADERS) \
	-I/usr/include/bpf \
	-Wall -Werror

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

SRC := aishields_monitor.bpf.c
OBJ := aishields_monitor.bpf.o
SKEL := aishields_monitor.skel.h

.PHONY: all clean install check-deps

all: check-deps $(OBJ)

$(OBJ): $(SRC)
	$(CLANG) $(BPF_CFLAGS) -g -c $< -o $@
	@echo "Built eBPF object: $@"

# Generate BPF skeleton header (optional, for C userspace)
$(SKEL): $(OBJ)
	$(BPFTOOL) gen skeleton $< > $@
	@echo "Generated skeleton: $@"

skeleton: $(SKEL)

check-deps:
	@which $(CLANG) > /dev/null 2>&1 || (echo "ERROR: clang not found. Install with: apt install clang" && exit 1)
	@test -f /usr/include/bpf/bpf_helpers.h || test -f /usr/include/linux/bpf.h || \
		(echo "WARNING: BPF headers may be missing. Install with: apt install libbpf-dev linux-headers-$$(uname -r)" && exit 0)
	@echo "Dependencies OK"

install: $(OBJ)
	install -d /opt/aishields/ebpf
	install -m 644 $(OBJ) /opt/aishields/ebpf/
	install -m 755 aishields_loader.py /opt/aishields/ebpf/
	@echo "Installed to /opt/aishields/ebpf/"

clean:
	rm -f $(OBJ) $(SKEL)

# Verify the BPF object
verify: $(OBJ)
	$(BPFTOOL) prog load $(OBJ) /sys/fs/bpf/aishields_test && \
		$(BPFTOOL) prog show pinned /sys/fs/bpf/aishields_test && \
		rm /sys/fs/bpf/aishields_test
	@echo "BPF object verification passed"

# Show BPF map info
info: $(OBJ)
	@echo "=== Programs ==="
	@llvm-objdump -d $(OBJ) | head -50
	@echo ""
	@echo "=== Sections ==="
	@llvm-readelf -S $(OBJ)
