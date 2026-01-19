/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Per-Window Load Balancer (PPLB)
 *
 * Load balance packets across multiple WAN interfaces per-window
 * to avoid reordering issues.
 *
 * Usage: sudo ./pplb <config_file> [xdp_redirect.o]
 */

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>

/* ============ Configuration ============ */
#define MAX_WAN             3
#define NUM_FRAMES          4096
#define FRAME_SIZE          XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE          64
#define WINDOW_SIZE         (1024 * 1024)  /* 1MB window */
#define FLOW_TABLE_SIZE     65536

/* ============ Data Structures ============ */
struct flow_entry {
    uint32_t bytes;
    int wan_idx;
};

/* ============ Global State ============ */
static volatile int running = 1;

/* Config */
static char local_if[32];
static int local_ifindex;
static uint32_t remote_net, remote_mask;
static int num_wan = 0;
static char wan_if[MAX_WAN][32];
static int wan_ifindex[MAX_WAN];
static uint8_t local_mac[6];
static uint8_t wan_src_mac[MAX_WAN][6];
static uint8_t wan_dst_mac[MAX_WAN][6];

/* Raw sockets for TX */
static int local_raw_fd;
static int wan_raw_fd[MAX_WAN];

/* BPF objects */
static struct bpf_object *local_bpf_obj;
static struct bpf_object *wan_bpf_obj[MAX_WAN];

/* AF_XDP for LOCAL */
static struct xsk_socket *local_xsk;
static struct xsk_ring_cons local_rx;
static struct xsk_ring_prod local_fq;
static struct xsk_umem *local_umem;
static void *local_buffer;

/* AF_XDP for WANs */
static struct xsk_socket *wan_xsk[MAX_WAN];
static struct xsk_ring_cons wan_rx[MAX_WAN];
static struct xsk_ring_prod wan_fq[MAX_WAN];
static struct xsk_umem *wan_umem[MAX_WAN];
static void *wan_buffer[MAX_WAN];

/* Flow table */
static struct flow_entry flow_table[FLOW_TABLE_SIZE];

/* Statistics */
static uint64_t rx_local = 0, tx_local = 0;
static uint64_t rx_wan[MAX_WAN] = {0}, tx_wan[MAX_WAN] = {0};
static uint64_t window_switches = 0;

/* ============ Utility Functions ============ */
static void die(const char *msg)
{
    fprintf(stderr, "ERROR: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
}

static int get_mac(const char *ifname, uint8_t *mac)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }

    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

static int get_peer_mac(const char *ifname, const char *ip, uint8_t *mac)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ping -c1 -W1 -I %s %s >/dev/null 2>&1", ifname, ip);
    system(cmd);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct arpreq arp = {0};
    struct sockaddr_in *sin = (struct sockaddr_in *)&arp.arp_pa;
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sin->sin_addr);
    strncpy(arp.arp_dev, ifname, 15);

    if (ioctl(fd, SIOCGARP, &arp) < 0) {
        close(fd);
        return -1;
    }

    close(fd);
    memcpy(mac, arp.arp_ha.sa_data, 6);
    return 0;
}

/* ============ Config ============ */
static int load_config(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Cannot open config: %s\n", path);
        return -1;
    }

    char line[256], key[32], val1[64], val2[64];

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        val2[0] = 0;
        int n = sscanf(line, "%31s %63s %63s", key, val1, val2);
        if (n < 2) continue;

        if (strcmp(key, "local") == 0) {
            strncpy(local_if, val1, sizeof(local_if) - 1);
            local_ifindex = if_nametoindex(val1);
            if (!local_ifindex) {
                fprintf(stderr, "Interface not found: %s\n", val1);
                fclose(f);
                return -1;
            }
            get_mac(val1, local_mac);
            printf("  LOCAL: %s\n", local_if);

        } else if (strcmp(key, "remote") == 0) {
            char *slash = strchr(val1, '/');
            int prefix = 24;
            if (slash) {
                *slash = 0;
                prefix = atoi(slash + 1);
            }
            remote_net = ntohl(inet_addr(val1));
            remote_mask = (prefix == 0) ? 0 : (0xFFFFFFFF << (32 - prefix));
            printf("  REMOTE: %s/%d\n", val1, prefix);

        } else if (strcmp(key, "wan") == 0 && num_wan < MAX_WAN) {
            strncpy(wan_if[num_wan], val1, sizeof(wan_if[num_wan]) - 1);
            wan_ifindex[num_wan] = if_nametoindex(val1);
            if (!wan_ifindex[num_wan]) {
                fprintf(stderr, "Interface not found: %s\n", val1);
                fclose(f);
                return -1;
            }
            get_mac(val1, wan_src_mac[num_wan]);

            if (val2[0]) {
                get_peer_mac(val1, val2, wan_dst_mac[num_wan]);
            }

            printf("  WAN%d: %s", num_wan + 1, wan_if[num_wan]);
            if (val2[0]) printf(" -> %s", val2);
            printf("\n");

            num_wan++;
        }
    }

    fclose(f);

    if (!local_ifindex || num_wan == 0) {
        fprintf(stderr, "Config incomplete\n");
        return -1;
    }

    return 0;
}

/* ============ Raw Socket ============ */
static int create_raw_socket(int ifindex)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;

    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/* ============ XDP/AF_XDP ============ */
static int attach_xdp(const char *bpf_path, int ifindex, uint32_t direction,
                      struct bpf_object **obj_out, int *xsk_map_fd)
{
    struct bpf_object *obj = bpf_object__open_file(bpf_path, NULL);
    if (libbpf_get_error(obj)) return -1;

    if (bpf_object__load(obj)) {
        bpf_object__close(obj);
        return -1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_redirect_prog");
    if (!prog) {
        bpf_object__close(obj);
        return -1;
    }

    int cfg_map_fd = bpf_object__find_map_fd_by_name(obj, "config");
    *xsk_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");

    if (cfg_map_fd < 0 || *xsk_map_fd < 0) {
        bpf_object__close(obj);
        return -1;
    }

    uint32_t key = 0, val = remote_net;
    bpf_map_update_elem(cfg_map_fd, &key, &val, BPF_ANY);
    key = 1; val = remote_mask;
    bpf_map_update_elem(cfg_map_fd, &key, &val, BPF_ANY);
    key = 2; val = direction;
    bpf_map_update_elem(cfg_map_fd, &key, &val, BPF_ANY);

    int prog_fd = bpf_program__fd(prog);
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL) < 0) {
        if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
            bpf_object__close(obj);
            return -1;
        }
    }

    *obj_out = obj;
    return 0;
}

static int setup_xsk(const char *ifname, int xsk_map_fd,
                     struct xsk_socket **xsk,
                     struct xsk_ring_cons *rx,
                     struct xsk_ring_prod *fq,
                     struct xsk_umem **umem,
                     void **buffer)
{
    if (posix_memalign(buffer, getpagesize(), NUM_FRAMES * FRAME_SIZE))
        return -1;

    struct xsk_umem_config ucfg = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0
    };

    struct xsk_ring_prod fill_ring;
    struct xsk_ring_cons comp_ring;

    if (xsk_umem__create(umem, *buffer, NUM_FRAMES * FRAME_SIZE,
                         &fill_ring, &comp_ring, &ucfg)) {
        free(*buffer);
        return -1;
    }

    *fq = fill_ring;

    struct xsk_socket_config xcfg = {
        .rx_size = NUM_FRAMES,
        .tx_size = NUM_FRAMES,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = 0,
        .bind_flags = XDP_COPY
    };

    struct xsk_ring_prod tx_ring;
    if (xsk_socket__create(xsk, ifname, 0, *umem, rx, &tx_ring, &xcfg)) {
        xsk_umem__delete(*umem);
        free(*buffer);
        return -1;
    }

    int fd = xsk_socket__fd(*xsk);
    uint32_t idx = 0;
    bpf_map_update_elem(xsk_map_fd, &idx, &fd, BPF_ANY);

    uint32_t fidx;
    if (xsk_ring_prod__reserve(fq, NUM_FRAMES, &fidx) == NUM_FRAMES) {
        for (uint32_t i = 0; i < NUM_FRAMES; i++)
            *xsk_ring_prod__fill_addr(fq, fidx + i) = i * FRAME_SIZE;
        xsk_ring_prod__submit(fq, NUM_FRAMES);
    }

    return 0;
}

/* ============ Load Balancing ============ */
static inline uint32_t calc_flow_hash(uint8_t *pkt)
{
    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
    return (ip->saddr ^ ip->daddr) % FLOW_TABLE_SIZE;
}

static int select_wan(uint8_t *pkt, uint32_t len)
{
    uint32_t hash = calc_flow_hash(pkt);
    struct flow_entry *flow = &flow_table[hash];

    int current_wan = flow->wan_idx;

    flow->bytes += len;

    if (flow->bytes >= WINDOW_SIZE) {
        flow->wan_idx = (flow->wan_idx + 1) % num_wan;
        flow->bytes = 0;
        window_switches++;
    }

    return current_wan;
}

/* ============ Packet Processing ============ */

/* LOCAL -> WANs */
static void process_local_rx(void)
{
    uint32_t idx = 0;
    uint32_t rcvd = xsk_ring_cons__peek(&local_rx, BATCH_SIZE, &idx);
    if (rcvd == 0) return;

    for (uint32_t i = 0; i < rcvd; i++) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&local_rx, idx + i);
        uint64_t addr = desc->addr;
        uint32_t len = desc->len;
        uint8_t *pkt = xsk_umem__get_data(local_buffer, addr);

        rx_local++;

        int w = select_wan(pkt, len);

        /* Set MAC */
        memcpy(pkt, wan_dst_mac[w], 6);
        memcpy(pkt + 6, wan_src_mac[w], 6);

        /* Send */
        struct sockaddr_ll sll = {0};
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = wan_ifindex[w];
        sll.sll_halen = 6;
        memcpy(sll.sll_addr, wan_dst_mac[w], 6);

        if (sendto(wan_raw_fd[w], pkt, len, 0,
                   (struct sockaddr *)&sll, sizeof(sll)) > 0) {
            tx_wan[w]++;
        }

        /* Return buffer */
        uint32_t fidx;
        if (xsk_ring_prod__reserve(&local_fq, 1, &fidx)) {
            *xsk_ring_prod__fill_addr(&local_fq, fidx) = addr;
            xsk_ring_prod__submit(&local_fq, 1);
        }
    }

    xsk_ring_cons__release(&local_rx, rcvd);
}

/* WAN -> LOCAL */
static void process_wan_rx(int w)
{
    uint32_t idx = 0;
    uint32_t rcvd = xsk_ring_cons__peek(&wan_rx[w], BATCH_SIZE, &idx);
    if (rcvd == 0) return;

    for (uint32_t i = 0; i < rcvd; i++) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&wan_rx[w], idx + i);
        uint64_t addr = desc->addr;
        uint32_t len = desc->len;
        uint8_t *pkt = xsk_umem__get_data(wan_buffer[w], addr);

        rx_wan[w]++;

        /* Forward to LOCAL */
        struct sockaddr_ll sll = {0};
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = local_ifindex;

        if (sendto(local_raw_fd, pkt, len, 0,
                   (struct sockaddr *)&sll, sizeof(sll)) > 0) {
            tx_local++;
        }

        /* Return buffer */
        uint32_t fidx;
        if (xsk_ring_prod__reserve(&wan_fq[w], 1, &fidx)) {
            *xsk_ring_prod__fill_addr(&wan_fq[w], fidx) = addr;
            xsk_ring_prod__submit(&wan_fq[w], 1);
        }
    }

    xsk_ring_cons__release(&wan_rx[w], rcvd);
}

/* ============ Statistics ============ */
static void print_stats(void)
{
    printf("\n=== PPLB Stats ===\n");
    printf("LOCAL: RX %lu, TX %lu\n", rx_local, tx_local);
    for (int i = 0; i < num_wan; i++) {
        printf("WAN%d:  RX %lu, TX %lu\n", i + 1, rx_wan[i], tx_wan[i]);
    }
    printf("Window switches: %lu\n", window_switches);
    printf("==================\n");
}

/* ============ Cleanup ============ */
static void cleanup(void)
{
    printf("\nShutting down...\n");
    print_stats();

    if (local_ifindex) {
        bpf_xdp_detach(local_ifindex, XDP_FLAGS_DRV_MODE, NULL);
        bpf_xdp_detach(local_ifindex, XDP_FLAGS_SKB_MODE, NULL);
    }
    if (local_xsk) xsk_socket__delete(local_xsk);
    if (local_umem) xsk_umem__delete(local_umem);
    if (local_buffer) free(local_buffer);
    if (local_bpf_obj) bpf_object__close(local_bpf_obj);
    if (local_raw_fd > 0) close(local_raw_fd);

    for (int i = 0; i < num_wan; i++) {
        if (wan_ifindex[i]) {
            bpf_xdp_detach(wan_ifindex[i], XDP_FLAGS_DRV_MODE, NULL);
            bpf_xdp_detach(wan_ifindex[i], XDP_FLAGS_SKB_MODE, NULL);
        }
        if (wan_xsk[i]) xsk_socket__delete(wan_xsk[i]);
        if (wan_umem[i]) xsk_umem__delete(wan_umem[i]);
        if (wan_buffer[i]) free(wan_buffer[i]);
        if (wan_bpf_obj[i]) bpf_object__close(wan_bpf_obj[i]);
        if (wan_raw_fd[i] > 0) close(wan_raw_fd[i]);
    }

    printf("Done.\n");
}

/* ============ Main ============ */
int main(int argc, char **argv)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    printf("=== Per-Window Load Balancer ===\n");
    printf("Window size: %d bytes\n\n", WINDOW_SIZE);

    if (argc < 2) {
        printf("Usage: %s <config> [xdp.o]\n", argv[0]);
        return 1;
    }

    if (setrlimit(RLIMIT_MEMLOCK, &r)) die("setrlimit");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    libbpf_set_print(NULL);

    printf("[CONFIG]\n");
    if (load_config(argv[1]) < 0) return 1;

    const char *bpf_path = (argc >= 3) ? argv[2] : "xdp/xdp_redirect.o";

    /* Raw sockets */
    local_raw_fd = create_raw_socket(local_ifindex);
    if (local_raw_fd < 0) die("local raw socket");

    for (int i = 0; i < num_wan; i++) {
        wan_raw_fd[i] = create_raw_socket(wan_ifindex[i]);
        if (wan_raw_fd[i] < 0) die("wan raw socket");
    }

    /* Setup LOCAL */
    int local_xsk_map;
    if (attach_xdp(bpf_path, local_ifindex, 0, &local_bpf_obj, &local_xsk_map) < 0)
        die("attach xdp local");
    if (setup_xsk(local_if, local_xsk_map, &local_xsk, &local_rx, &local_fq,
                  &local_umem, &local_buffer) < 0)
        die("setup xsk local");
    printf("[OK] LOCAL ready\n");

    /* Setup WANs */
    for (int i = 0; i < num_wan; i++) {
        int wan_xsk_map;
        if (attach_xdp(bpf_path, wan_ifindex[i], 1, &wan_bpf_obj[i], &wan_xsk_map) < 0)
            die("attach xdp wan");
        if (setup_xsk(wan_if[i], wan_xsk_map, &wan_xsk[i], &wan_rx[i], &wan_fq[i],
                      &wan_umem[i], &wan_buffer[i]) < 0)
            die("setup xsk wan");
        printf("[OK] WAN%d ready\n", i + 1);
    }

    printf("\n[RUNNING] Press Ctrl+C to stop\n");

    /* Main loop */
    time_t last_stats = 0;
    while (running) {
        process_local_rx();

        for (int i = 0; i < num_wan; i++) {
            process_wan_rx(i);
        }

        usleep(10);

        time_t now = time(NULL);
        if (now - last_stats >= 5) {
            print_stats();
            last_stats = now;
        }
    }

    cleanup();
    return 0;
}
