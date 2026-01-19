/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PPLB_COMMON_H__
#define __PPLB_COMMON_H__

/*
 * Per-Packet Load Balancer (PPLB) - Common Definitions
 *
 * Architecture:
 *   Client -> Server1 (LOCAL) -> XDP -> Userspace LB -> WANs
 *                                                         |
 *   Client <- Server2 (LOCAL) <- XDP <- Userspace LB <- WANs
 *
 * Features:
 *   - XDP redirect to userspace with IP network filtering
 *   - Raw socket TX for stability
 *   - MAC address handling for proper routing
 *   - Flow-based sliding window load balancing
 *   - Config file support
 *
 * Config file format:
 *   local <interface>              # Local interface
 *   remote <network>/<prefix>      # Remote network to tunnel
 *   wan <interface> <gateway_ip>   # WAN interface + gateway
 */

/* Maximum WAN interfaces */
#define MAX_WAN         3

/* AF_XDP configuration */
#define NUM_FRAMES      4096
#define FRAME_SIZE      4096
#define BATCH_SIZE      64

/* Sliding window configuration */
#define WINDOW_SIZE     (1024 * 1024)  /* 1MB sliding window */

/* Flow table for load balancing */
#define FLOW_TABLE_SIZE 65536

#endif /* __PPLB_COMMON_H__ */
