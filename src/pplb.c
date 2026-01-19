#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <poll.h>
#include <net/if.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#define MAX_WAN      3
#define NUM_FRAMES   4096
#define FRAME_SIZE   XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE   64
#define TX_FRAMES    256

static volatile int running = 1;

/* Config */
static char local_if[32];
static int num_wan = 0;
static char wan_if[MAX_WAN][32];
static uint8_t local_mac[6];
static uint8_t client_mac[6];
static uint8_t wan_src_mac[MAX_WAN][6];
static uint8_t wan_dst_mac[MAX_WAN][6];
static uint32_t remote_net = 0;
static uint32_t remote_mask = 0;
static uint32_t local_net = 0;
static uint32_t local_mask = 0;

/* BPF objects */
static struct bpf_object *local_bpf_obj;
static struct bpf_object *wan_bpf_obj;
static int local_prog_fd = -1;
static int wan_prog_fd = -1;

/* XSK for LOCAL */
static struct xsk_socket *local_xsk;
static struct xsk_ring_cons local_rx;
static struct xsk_ring_prod local_tx;
static struct xsk_ring_prod local_fq;
static struct xsk_ring_cons local_cq;
static struct xsk_umem *local_umem;
static void *local_buf;
static __u32 local_tx_idx = 0;

/* XSK for WAN */
static struct xsk_socket *wan_xsk;
static struct xsk_ring_cons wan_rx;
static struct xsk_ring_prod wan_tx;
static struct xsk_ring_prod wan_fq;
static struct xsk_ring_cons wan_cq;
static struct xsk_umem *wan_umem;
static void *wan_buf;
static __u32 wan_tx_idx = 0;

static int selected_wan = 0;
static uint64_t local_rx_cnt = 0, local_tx_cnt = 0;
static uint64_t wan_rx_cnt = 0, wan_tx_cnt = 0;

static void die(const char *m) { perror(m); exit(1); }
static void sig_handler(int s) { (void)s; running = 0; }

static int get_mac(const char *ifname, uint8_t *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

static int parse_mac(const char *str, uint8_t *mac) {
    unsigned int m[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = m[i];
    return 0;
}

/* Parse CIDR: 192.168.182.0/24 */
static int parse_cidr(const char *str, uint32_t *net, uint32_t *mask) {
    char ip[32];
    int prefix = 24;
    strncpy(ip, str, sizeof(ip)-1);
    char *slash = strchr(ip, '/');
    if (slash) {
        *slash = 0;
        prefix = atoi(slash + 1);
    }
    struct in_addr addr;
    if (inet_aton(ip, &addr) == 0) return -1;
    *net = ntohl(addr.s_addr);
    *mask = prefix ? (~0U << (32 - prefix)) : 0;
    return 0;
}

static int load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256], key[32], v1[64], v2[64], v3[32];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        v1[0] = v2[0] = v3[0] = 0;
        sscanf(line, "%s %s %s %s", key, v1, v2, v3);
        if (!strcmp(key, "local")) {
            strcpy(local_if, v1);
            get_mac(v1, local_mac);
            /* Get local network from interface */
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            struct ifreq ifr = {0};
            strncpy(ifr.ifr_name, v1, IFNAMSIZ-1);
            if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
                struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
                uint32_t ip = ntohl(addr->sin_addr.s_addr);
                /* Assume /24 */
                local_net = ip & 0xFFFFFF00;
                local_mask = 0xFFFFFF00;
            }
            close(fd);
        } else if (!strcmp(key, "client")) {
            parse_mac(v1, client_mac);
        } else if (!strcmp(key, "remote")) {
            parse_cidr(v1, &remote_net, &remote_mask);
        } else if (!strcmp(key, "wan") && num_wan < MAX_WAN) {
            strcpy(wan_if[num_wan], v1);
            get_mac(v1, wan_src_mac[num_wan]);
            if (v3[0]) parse_mac(v3, wan_dst_mac[num_wan]);
            num_wan++;
        }
    }
    fclose(f);
    return (local_if[0] && num_wan > 0 && remote_net) ? 0 : -1;
}

/* Load BPF, attach XDP, configure maps */
static int setup_bpf(const char *ifname, const char *bpf_path,
                     struct bpf_object **obj, int *prog_fd,
                     int *xsks_map_fd, uint32_t filter_net, uint32_t filter_mask,
                     uint32_t direction) {

    /* Load BPF object */
    *obj = bpf_object__open_file(bpf_path, NULL);
    if (!*obj) {
        fprintf(stderr, "Failed to open BPF: %s\n", bpf_path);
        return -1;
    }
    if (bpf_object__load(*obj)) {
        fprintf(stderr, "Failed to load BPF: %s\n", bpf_path);
        return -1;
    }

    /* Find program */
    struct bpf_program *prog = bpf_object__find_program_by_name(*obj, "xdp_redirect_prog");
    if (!prog) {
        fprintf(stderr, "XDP program 'xdp_redirect_prog' not found\n");
        return -1;
    }
    *prog_fd = bpf_program__fd(prog);

    /* Find maps */
    *xsks_map_fd = bpf_object__find_map_fd_by_name(*obj, "xsks_map");
    int config_fd = bpf_object__find_map_fd_by_name(*obj, "config");

    if (*xsks_map_fd < 0) {
        fprintf(stderr, "xsks_map not found\n");
        return -1;
    }

    /* Configure filter */
    if (config_fd >= 0) {
        __u32 key, val;
        key = 0; val = filter_net;
        bpf_map_update_elem(config_fd, &key, &val, 0);
        key = 1; val = filter_mask;
        bpf_map_update_elem(config_fd, &key, &val, 0);
        key = 2; val = direction;
        bpf_map_update_elem(config_fd, &key, &val, 0);
        printf("    Filter: net=0x%08x mask=0x%08x dir=%u\n", filter_net, filter_mask, direction);
    }

    /* Attach XDP using older API */
    int ifindex = if_nametoindex(ifname);
    if (bpf_set_link_xdp_fd(ifindex, *prog_fd, XDP_FLAGS_SKB_MODE) < 0) {
        fprintf(stderr, "Failed to attach XDP to %s\n", ifname);
        return -1;
    }

    return 0;
}

/* Setup XSK socket */
static int setup_xsk(const char *ifname, int xsks_map_fd,
                     struct xsk_socket **xsk,
                     struct xsk_ring_cons *rx, struct xsk_ring_prod *tx,
                     struct xsk_ring_prod *fq, struct xsk_ring_cons *cq,
                     struct xsk_umem **umem, void **buf) {

    /* Allocate UMEM */
    if (posix_memalign(buf, getpagesize(), NUM_FRAMES * FRAME_SIZE))
        die("memalign");

    struct xsk_umem_config ucfg = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = FRAME_SIZE,
    };
    if (xsk_umem__create(umem, *buf, NUM_FRAMES * FRAME_SIZE, fq, cq, &ucfg))
        die("umem create");

    /* Fill ring */
    __u32 idx;
    __u32 rx_frames = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    if (xsk_ring_prod__reserve(fq, rx_frames, &idx) != rx_frames)
        die("fill ring reserve");
    for (__u32 i = 0; i < rx_frames; i++)
        *xsk_ring_prod__fill_addr(fq, idx + i) = (TX_FRAMES + i) * FRAME_SIZE;
    xsk_ring_prod__submit(fq, rx_frames);

    /* Create XSK socket - XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD để không auto-attach */
    struct xsk_socket_config cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = 0,
        .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP,
    };

    int ret = xsk_socket__create(xsk, ifname, 0, *umem, rx, tx, &cfg);
    if (ret) {
        fprintf(stderr, "xsk_socket__create failed: %d\n", ret);
        return -1;
    }

    /* Update XSKMAP */
    int fd = xsk_socket__fd(*xsk);
    __u32 key = 0;
    if (bpf_map_update_elem(xsks_map_fd, &key, &fd, 0)) {
        fprintf(stderr, "Failed to update xsks_map\n");
        return -1;
    }

    return 0;
}

/* Send packet via LOCAL */
static int send_pkt_local(uint8_t *pkt, uint32_t len) {
    __u32 comp_idx;
    unsigned int done = xsk_ring_cons__peek(&local_cq, TX_FRAMES, &comp_idx);
    if (done > 0) xsk_ring_cons__release(&local_cq, done);

    __u32 tx_slot;
    if (xsk_ring_prod__reserve(&local_tx, 1, &tx_slot) != 1)
        return -1;

    __u64 addr = (local_tx_idx % TX_FRAMES) * FRAME_SIZE;
    local_tx_idx++;

    uint8_t *frame = xsk_umem__get_data(local_buf, addr);
    memcpy(frame, pkt, len);

    struct xdp_desc *d = xsk_ring_prod__tx_desc(&local_tx, tx_slot);
    d->addr = addr;
    d->len = len;

    xsk_ring_prod__submit(&local_tx, 1);

    if (xsk_ring_prod__needs_wakeup(&local_tx))
        sendto(xsk_socket__fd(local_xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    return 0;
}

/* Send packet via WAN */
static int send_pkt_wan(uint8_t *pkt, uint32_t len) {
    __u32 comp_idx;
    unsigned int done = xsk_ring_cons__peek(&wan_cq, TX_FRAMES, &comp_idx);
    if (done > 0) xsk_ring_cons__release(&wan_cq, done);

    __u32 tx_slot;
    if (xsk_ring_prod__reserve(&wan_tx, 1, &tx_slot) != 1)
        return -1;

    __u64 addr = (wan_tx_idx % TX_FRAMES) * FRAME_SIZE;
    wan_tx_idx++;

    uint8_t *frame = xsk_umem__get_data(wan_buf, addr);
    memcpy(frame, pkt, len);

    struct xdp_desc *d = xsk_ring_prod__tx_desc(&wan_tx, tx_slot);
    d->addr = addr;
    d->len = len;

    xsk_ring_prod__submit(&wan_tx, 1);

    if (xsk_ring_prod__needs_wakeup(&wan_tx))
        sendto(xsk_socket__fd(wan_xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    return 0;
}

/* LOCAL RX → WAN TX */
static void process_local_rx(void) {
    __u32 rx_idx = 0;
    unsigned int n = xsk_ring_cons__peek(&local_rx, BATCH_SIZE, &rx_idx);
    if (!n) return;

    for (__u32 i = 0; i < n; i++) {
        const struct xdp_desc *d = xsk_ring_cons__rx_desc(&local_rx, rx_idx + i);
        uint8_t *pkt = xsk_umem__get_data(local_buf, d->addr);
        uint32_t len = d->len;

        local_rx_cnt++;

        struct ethhdr *eth = (struct ethhdr *)pkt;
        memcpy(eth->h_dest, wan_dst_mac[selected_wan], 6);
        memcpy(eth->h_source, wan_src_mac[selected_wan], 6);

        if (send_pkt_wan(pkt, len) == 0)
            wan_tx_cnt++;

        __u32 fq_idx;
        if (xsk_ring_prod__reserve(&local_fq, 1, &fq_idx) == 1) {
            *xsk_ring_prod__fill_addr(&local_fq, fq_idx) = d->addr;
            xsk_ring_prod__submit(&local_fq, 1);
        }
    }
    xsk_ring_cons__release(&local_rx, n);
}

/* WAN RX → LOCAL TX */
static void process_wan_rx(void) {
    __u32 rx_idx = 0;
    unsigned int n = xsk_ring_cons__peek(&wan_rx, BATCH_SIZE, &rx_idx);
    if (!n) return;

    for (__u32 i = 0; i < n; i++) {
        const struct xdp_desc *d = xsk_ring_cons__rx_desc(&wan_rx, rx_idx + i);
        uint8_t *pkt = xsk_umem__get_data(wan_buf, d->addr);
        uint32_t len = d->len;

        wan_rx_cnt++;

        struct ethhdr *eth = (struct ethhdr *)pkt;

        if (wan_rx_cnt <= 3) {
            printf("WAN RX #%lu: len=%u\n", wan_rx_cnt, len);
            printf("  BEFORE: dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                   eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        }

        memcpy(eth->h_dest, client_mac, 6);
        memcpy(eth->h_source, local_mac, 6);

        if (wan_rx_cnt <= 3) {
            printf("  AFTER:  dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                   eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        }

        if (send_pkt_local(pkt, len) == 0)
            local_tx_cnt++;

        __u32 fq_idx;
        if (xsk_ring_prod__reserve(&wan_fq, 1, &fq_idx) == 1) {
            *xsk_ring_prod__fill_addr(&wan_fq, fq_idx) = d->addr;
            xsk_ring_prod__submit(&wan_fq, 1);
        }
    }
    xsk_ring_cons__release(&wan_rx, n);
}

static void cleanup(void) {
    printf("\nShutdown...\n");
    printf("LOCAL: RX=%lu TX=%lu\n", local_rx_cnt, local_tx_cnt);
    printf("WAN:   RX=%lu TX=%lu\n", wan_rx_cnt, wan_tx_cnt);

    int ifindex;
    ifindex = if_nametoindex(local_if);
    if (ifindex > 0) bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);
    ifindex = if_nametoindex(wan_if[selected_wan]);
    if (ifindex > 0) bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);

    if (local_xsk) xsk_socket__delete(local_xsk);
    if (local_umem) xsk_umem__delete(local_umem);
    if (local_buf) free(local_buf);
    if (local_bpf_obj) bpf_object__close(local_bpf_obj);

    if (wan_xsk) xsk_socket__delete(wan_xsk);
    if (wan_umem) xsk_umem__delete(wan_umem);
    if (wan_buf) free(wan_buf);
    if (wan_bpf_obj) bpf_object__close(wan_bpf_obj);
}

int main(int argc, char **argv) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    printf("=== Tunnel 2 chiều (với IP filter) ===\n\n");

    if (argc < 3) {
        printf("Usage: %s <config> <wan_index> [xdp_redirect.o]\n", argv[0]);
        return 1;
    }

    selected_wan = atoi(argv[2]);
    const char *bpf_path = (argc >= 4) ? argv[3] : "xdp/xdp_redirect.o";

    if (setrlimit(RLIMIT_MEMLOCK, &r)) die("setrlimit");
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[CONFIG]\n");
    if (load_config(argv[1]) < 0) die("config");

    if (selected_wan >= num_wan) {
        fprintf(stderr, "Invalid WAN %d\n", selected_wan);
        return 1;
    }

    printf("  LOCAL: %s (%02x:%02x:%02x:%02x:%02x:%02x)\n", local_if,
           local_mac[0], local_mac[1], local_mac[2],
           local_mac[3], local_mac[4], local_mac[5]);
    printf("  LOCAL net: %u.%u.%u.%u/%u\n",
           (local_net >> 24) & 0xFF, (local_net >> 16) & 0xFF,
           (local_net >> 8) & 0xFF, local_net & 0xFF,
           __builtin_popcount(local_mask));
    printf("  REMOTE net: %u.%u.%u.%u/%u\n",
           (remote_net >> 24) & 0xFF, (remote_net >> 16) & 0xFF,
           (remote_net >> 8) & 0xFF, remote_net & 0xFF,
           __builtin_popcount(remote_mask));
    printf("  CLIENT: %02x:%02x:%02x:%02x:%02x:%02x\n",
           client_mac[0], client_mac[1], client_mac[2],
           client_mac[3], client_mac[4], client_mac[5]);
    printf("  WAN: %s -> %02x:%02x:%02x:%02x:%02x:%02x\n", wan_if[selected_wan],
           wan_dst_mac[selected_wan][0], wan_dst_mac[selected_wan][1],
           wan_dst_mac[selected_wan][2], wan_dst_mac[selected_wan][3],
           wan_dst_mac[selected_wan][4], wan_dst_mac[selected_wan][5]);

    printf("\n[SETUP LOCAL - filter: packets TO remote net]\n");
    int local_xsks_fd;
    if (setup_bpf(local_if, bpf_path, &local_bpf_obj, &local_prog_fd,
                  &local_xsks_fd, remote_net, remote_mask, 0) < 0)
        die("setup_bpf local");

    if (setup_xsk(local_if, local_xsks_fd, &local_xsk, &local_rx, &local_tx,
                  &local_fq, &local_cq, &local_umem, &local_buf) < 0)
        die("setup_xsk local");
    printf("  %s: OK\n", local_if);

    printf("\n[SETUP WAN - filter: packets FROM remote net (to local)]\n");
    int wan_xsks_fd;
    if (setup_bpf(wan_if[selected_wan], bpf_path, &wan_bpf_obj, &wan_prog_fd,
                  &wan_xsks_fd, local_net, local_mask, 0) < 0)
        die("setup_bpf wan");

    if (setup_xsk(wan_if[selected_wan], wan_xsks_fd, &wan_xsk, &wan_rx, &wan_tx,
                  &wan_fq, &wan_cq, &wan_umem, &wan_buf) < 0)
        die("setup_xsk wan");
    printf("  %s: OK\n", wan_if[selected_wan]);

    printf("\n[RUNNING]\n");
    printf("  LOCAL: redirect packets dst=%u.%u.%u.%u/%u\n",
           (remote_net >> 24) & 0xFF, (remote_net >> 16) & 0xFF,
           (remote_net >> 8) & 0xFF, remote_net & 0xFF,
           __builtin_popcount(remote_mask));
    printf("  WAN: redirect packets dst=%u.%u.%u.%u/%u\n",
           (local_net >> 24) & 0xFF, (local_net >> 16) & 0xFF,
           (local_net >> 8) & 0xFF, local_net & 0xFF,
           __builtin_popcount(local_mask));
    printf("  Other traffic: XDP_PASS (normal kernel)\n");
    printf("  Ctrl+C to stop\n\n");

    struct pollfd fds[2];
    fds[0].fd = xsk_socket__fd(local_xsk);
    fds[0].events = POLLIN;
    fds[1].fd = xsk_socket__fd(wan_xsk);
    fds[1].events = POLLIN;

    time_t last = 0;
    while (running) {
        poll(fds, 2, 10);
        process_local_rx();
        process_wan_rx();

        time_t now = time(NULL);
        if (now - last >= 3) {
            printf("LOCAL RX=%lu TX=%lu | WAN RX=%lu TX=%lu\n",
                   local_rx_cnt, local_tx_cnt, wan_rx_cnt, wan_tx_cnt);
            last = now;
        }
    }

    cleanup();
    printf("Done.\n");
    return 0;
}

