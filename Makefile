# SPDX-License-Identifier: GPL-2.0
#
# Per-Packet Load Balancer (PPLB) Makefile
#

CC = gcc
CLANG = clang

# Directories
SRC_DIR = src
XDP_DIR = xdp
INC_DIR = include
CFG_DIR = config

# Compiler flags
CFLAGS = -Wall -Wextra -O2 -g -I$(INC_DIR)
LDFLAGS = -lbpf -lxdp -lpthread -lelf -lz

# BPF flags
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86
BPF_CFLAGS += -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types

# Targets
XDP_OBJ = $(XDP_DIR)/xdp_redirect.o
PPLB = pplb

.PHONY: all clean help install-deps run detach

all: $(XDP_OBJ) $(PPLB)
	@echo ""
	@echo "====================================="
	@echo "  Build Complete!"
	@echo "====================================="
	@echo ""
	@echo "  XDP Program: $(XDP_OBJ)"
	@echo "  PPLB:        $(PPLB)"
	@echo ""
	@echo "  Usage: sudo ./$(PPLB) <config_file> [xdp.o]"
	@echo "  Example: sudo ./$(PPLB) $(CFG_DIR)/server1.conf"
	@echo ""

# XDP BPF Program
$(XDP_OBJ): $(XDP_DIR)/xdp_redirect.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[OK] Built XDP program: $@"

# PPLB userspace program
$(PPLB): $(SRC_DIR)/pplb.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	@echo "[OK] Built pplb: $@"

clean:
	rm -f $(XDP_OBJ) $(PPLB)
	@echo "[OK] Cleaned build artifacts"

# Install dependencies (Ubuntu/Debian)
install-deps:
	@echo "Installing dependencies..."
	sudo apt-get update
	sudo apt-get install -y clang llvm libbpf-dev libxdp-dev \
		linux-headers-$$(uname -r) build-essential pkg-config \
		libelf-dev zlib1g-dev
	@echo "[OK] Dependencies installed"

# Run with default config
run: all
	sudo ./$(PPLB) $(CFG_DIR)/server1.conf $(XDP_OBJ)

# Detach XDP from all interfaces
detach:
	@echo "Detaching XDP from interfaces..."
	-sudo ip link set dev enp4s0 xdp off 2>/dev/null
	-sudo ip link set dev enp5s0 xdp off 2>/dev/null
	-sudo ip link set dev enp6s0 xdp off 2>/dev/null
	-sudo ip link set dev enp7s0 xdp off 2>/dev/null
	@echo "[OK] XDP detached"

help:
	@echo ""
	@echo "====================================="
	@echo "  Per-Packet Load Balancer (PPLB)"
	@echo "====================================="
	@echo ""
	@echo "Build:"
	@echo "  make all          - Build everything"
	@echo "  make clean        - Clean build files"
	@echo "  make install-deps - Install dependencies"
	@echo ""
	@echo "Run:"
	@echo "  make run          - Run with default config"
	@echo "  make detach       - Detach XDP from all interfaces"
	@echo ""
	@echo "Manual run:"
	@echo "  sudo ./pplb <config_file> [xdp.o]"
	@echo ""
	@echo "Config file format:"
	@echo "  local <interface>              # Local interface"
	@echo "  remote <network>/<prefix>      # Remote network to tunnel"
	@echo "  wan <interface> <gateway_ip>   # WAN interface + gateway"
	@echo ""
	@echo "Example config:"
	@echo "  local enp7s0"
	@echo "  remote 192.168.182.0/24"
	@echo "  wan enp4s0 192.168.11.2"
	@echo "  wan enp5s0 192.168.131.2"
	@echo "  wan enp6s0 192.168.203.2"
	@echo ""
	@echo "Architecture:"
	@echo ""
	@echo "  ┌─────────────────────────────────────────────────────────┐"
	@echo "  │                      SERVER                             │"
	@echo "  │                                                         │"
	@echo "  │   LOCAL (enp7s0)        SLIDING WINDOW         WANs    │"
	@echo "  │        │              (flow-based 1MB)           │      │"
	@echo "  │        ▼                                         ▼      │"
	@echo "  │   ┌─────────┐         ┌──────────────┐    ┌──────────┐ │"
	@echo "  │   │   XDP   │────────▶│  Userspace   │───▶│ enp4s0   │ │"
	@echo "  │   │  Filter │  AF_XDP │    Load      │raw │ enp5s0   │ │"
	@echo "  │   │(by dest)│         │  Balancer    │sock│ enp6s0   │ │"
	@echo "  │   └─────────┘         └──────────────┘    └──────────┘ │"
	@echo "  │        ▲                     │                  │      │"
	@echo "  │        │                     │                  │      │"
	@echo "  │        └─────────────────────┴──────────────────┘      │"
	@echo "  │              (Inbound: WAN → LOCAL)                    │"
	@echo "  └─────────────────────────────────────────────────────────┘"
	@echo ""
