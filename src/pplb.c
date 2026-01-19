#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <net/if.h>
#include <net/if_arp.h>
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

#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif

#define MAX_WAN      3
#define NUM_FRAMES   4096
#define FRAME_SIZE   XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE   64

static volatile int running = 1;

/* Config */
static char local_if[32];
static int local_ifindex;
static int num_wan = 0;
static char wan_if[MAX_WAN][32];
static int wan_ifindex[MAX_WAN];
static uint8_t local_mac[6];
static uint8_t wan_src_mac[MAX_WAN][6];
static uint8_t wan_dst_mac[MAX_WAN][6];

/* LOCAL - giống recv.c */
static struct bpf_object *local_bpf_obj;
static int local_xsks_map_fd;
static struct xsk_socket *local_xsk;
static struct xsk_ring_cons local_rx;
static struct xsk_ring_prod local_tx;
static struct xsk_ring_prod local_fq;
static struct xsk_ring_cons local_cq;
static struct xsk_umem *local_umem;
static void *local_buf;

/* WAN - giống sender.c */
static struct xsk_socket *wan_xsk[MAX_WAN];
static struct xsk_ring_cons wan_rx[MAX_WAN];
static struct xsk_ring_prod wan_tx[MAX_WAN];
static struct xsk_ring_prod wan_fq[MAX_WAN];
static struct xsk_ring_cons wan_cq[MAX_WAN];
static struct xsk_umem *wan_umem[MAX_WAN];
static void *wan_buf[MAX_WAN];

static int selected_wan = 0;
static uint64_t rx_count = 0, tx_count = 0;

static void die(const char *m) { perror(m); exit(1); }
static void sig_handler(int s) { (void)s; running = 0; }

static int silent_print(enum libbpf_print_level l, const char *f, va_list a) {
    (void)l; (void)f; (void)a; return 0;
}

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

static int load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256], key[32], v1[64], v2[64], v3[32];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        v2[0] = v3[0] = 0;
        sscanf(line, "%s %s %s %s", key, v1, v2, v3);
        if (!strcmp(key, "local")) {
            strcpy(local_if, v1);
            local_ifindex = if_nametoindex(v1);
            get_mac(v1, local_mac);
        } else if (!strcmp(key, "wan") && num_wan < MAX_WAN) {
            strcpy(wan_if[num_wan], v1);
            wan_ifindex[num_wan] = if_nametoindex(v1);
            get_mac(v1, wan_src_mac[num_wan]);
            if (v3[0]) parse_mac(v3, wan_dst_mac[num_wan]);
            num_wan++;
        }
    }
    fclose(f);
    return (local_ifindex && num_wan > 0) ? 0 : -1;
}

/* ========== LOCAL SETUP - giống recv.c ========== */
static int setup_local(const char *bpf_path) {
    libbpf_set_print(silent_print);

    /* Load BPF object - giống recv.c */
    local_bpf_obj = bpf_object__open_file(bpf_path, NULL);
    if (!local_bpf_obj || bpf_object__load(local_bpf_obj)) {
        fprintf(stderr, "Failed to load BPF: %s\n", bpf_path);
        return -1;
    }

    local_xsks_map_fd = bpf_object__find_map_fd_by_name(local_bpf_obj, "xsks_map");
    if (local_xsks_map_fd < 0) {
        fprintf(stderr, "xsks_map not found\n");
        return -1;
    }

    /* Allocate UMEM */
    if (posix_memalign(&local_buf, getpagesize(), NUM_FRAMES * FRAME_SIZE))
        die("memalign");

    struct xsk_umem_config ucfg = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
    };
    if (xsk_umem__create(&local_umem, local_buf, NUM_FRAMES * FRAME_SIZE,
                         &local_fq, &local_cq, &ucfg))
        die("umem");

    /* Fill ring init */
    __u32 idx;
    xsk_ring_prod__reserve(&local_fq, NUM_FRAMES, &idx);
    for (__u32 i = 0; i < NUM_FRAMES; i++)
        *xsk_ring_prod__fill_addr(&local_fq, idx + i) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&local_fq, NUM_FRAMES);

    /* Create XSK socket - giống recv.c dùng create_shared */
    struct xsk_socket_config xcfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .bind_flags = XDP_COPY,
    };

    int ret = xsk_socket__create_shared(&local_xsk, local_if, 0, local_umem,
                                        &local_rx, &local_tx, &local_fq, &local_cq, &xcfg);
    if (ret) {
        if (-ret == ENOTSUPP) return 0;
        errno = -ret;
        die("xsk_socket local");
    }

    /* Update XSKMAP - giống recv.c */
    int fd = xsk_socket__fd(local_xsk);
    __u32 key = 0;
    if (bpf_map_update_elem(local_xsks_map_fd, &key, &fd, 0))
        die("map_update");

    printf("LOCAL %s: XSK ready\n", local_if);
    return 0;
}

/* ========== WAN SETUP - giống sender.c ========== */
static int setup_wan(int w) {
    const char *ifname = wan_if[w];

    /* Allocate UMEM */
    if (posix_memalign(&wan_buf[w], getpagesize(), NUM_FRAMES * FRAME_SIZE))
        die("memalign wan");

    struct xsk_umem_config ucfg = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0
    };

    if (xsk_umem__create(&wan_umem[w], wan_buf[w], NUM_FRAMES * FRAME_SIZE,
                         &wan_fq[w], &wan_cq[w], &ucfg))
        die("umem wan");

    /* Fill ring init */
    __u32 idx;
    if (xsk_ring_prod__reserve(&wan_fq[w], NUM_FRAMES, &idx) == NUM_FRAMES) {
        for (__u32 i = 0; i < NUM_FRAMES; i++)
            *xsk_ring_prod__fill_addr(&wan_fq[w], idx + i) = i * FRAME_SIZE;
        xsk_ring_prod__submit(&wan_fq[w], NUM_FRAMES);
    }

    /* Create XSK socket - giống sender.c */
    struct xsk_socket_config cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = 0,  /* libbpf tự attach XDP */
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .bind_flags = XDP_USE_NEED_WAKEUP | XDP_COPY,
    };

    int ret = xsk_socket__create(&wan_xsk[w], ifname, 0, wan_umem[w],
                                 &wan_rx[w], &wan_tx[w], &cfg);
    if (ret) {
        /* Fallback to SKB mode */
        cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
        ret = xsk_socket__create(&wan_xsk[w], ifname, 0, wan_umem[w],
                                 &wan_rx[w], &wan_tx[w], &cfg);
        if (ret) {
            errno = -ret;
            die("xsk_socket wan");
        }
        printf("WAN%d %s: XSK ready (SKB)\n", w+1, ifname);
    } else {
        printf("WAN%d %s: XSK ready (DRV)\n", w+1, ifname);
    }

    return 0;
}

/* ========== TX to WAN - giống sender.c ========== */
static int send_wan(int w, uint8_t *pkt, uint32_t len) {
    /* Clean up completed TX - QUAN TRỌNG */
    __u32 comp_idx;
    unsigned int done = xsk_ring_cons__peek(&wan_cq[w], NUM_FRAMES, &comp_idx);
    if (done > 0) xsk_ring_cons__release(&wan_cq[w], done);

    /* Reserve TX slot */
    __u32 tx_idx;
    if (xsk_ring_prod__reserve(&wan_tx[w], 1, &tx_idx) != 1)
        return -1;

    /* Copy packet to frame 0 */
    uint8_t *frame = xsk_umem__get_data(wan_buf[w], 0);
    memcpy(frame, pkt, len);

    /* Fill descriptor */
    struct xdp_desc *d = xsk_ring_prod__tx_desc(&wan_tx[w], tx_idx);
    d->addr = 0;
    d->len = len;

    xsk_ring_prod__submit(&wan_tx[w], 1);

    /* Wakeup kernel */
    if (xsk_ring_prod__needs_wakeup(&wan_tx[w]))
        sendto(xsk_socket__fd(wan_xsk[w]), NULL, 0, MSG_DONTWAIT, NULL, 0);

    return 0;
}

/* ========== Process LOCAL RX ========== */
static void process_rx(void) {
    __u32 rx_idx = 0;
    unsigned int n = xsk_ring_cons__peek(&local_rx, BATCH_SIZE, &rx_idx);
    if (!n) return;

    __u32 fq_idx;
    if (xsk_ring_prod__reserve(&local_fq, n, &fq_idx) == n) {
        for (__u32 i = 0; i < n; i++) {
            struct xdp_desc *d = (struct xdp_desc *)xsk_ring_cons__rx_desc(&local_rx, rx_idx + i);
            uint8_t *pkt = xsk_umem__get_data(local_buf, d->addr);
            uint32_t len = d->len;

            rx_count++;

            /* Đổi MAC cho WAN đã chọn */
            memcpy(pkt, wan_dst_mac[selected_wan], 6);
            memcpy(pkt + 6, wan_src_mac[selected_wan], 6);

            /* Gửi ra WAN */
            if (send_wan(selected_wan, pkt, len) == 0)
                tx_count++;

            /* Return buffer */
            *xsk_ring_prod__fill_addr(&local_fq, fq_idx + i) = d->addr & ~(FRAME_SIZE - 1);
        }
        xsk_ring_cons__release(&local_rx, n);
        xsk_ring_prod__submit(&local_fq, n);
    } else {
        xsk_ring_cons__release(&local_rx, n);
        usleep(10);
    }
}

static void cleanup(void) {
    printf("\nShutdown...\n");
    printf("RX: %lu, TX: %lu\n", rx_count, tx_count);

    if (local_xsk) xsk_socket__delete(local_xsk);
    if (local_umem) xsk_umem__delete(local_umem);
    if (local_buf) free(local_buf);
    if (local_bpf_obj) bpf_object__close(local_bpf_obj);

    for (int i = 0; i < num_wan; i++) {
        if (wan_xsk[i]) xsk_socket__delete(wan_xsk[i]);
        if (wan_umem[i]) xsk_umem__delete(wan_umem[i]);
        if (wan_buf[i]) free(wan_buf[i]);
    }
}

int main(int argc, char **argv) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    printf("=== Tunnel (1 chiều: LOCAL -> WAN) ===\n\n");

    if (argc < 2) {
        printf("Usage: %s <config> [wan_index] [xdp_kern.o]\n", argv[0]);
        printf("  wan_index: 0, 1, 2 (default: 0)\n");
        return 1;
    }

    if (argc >= 3 && argv[2][0] >= '0' && argv[2][0] <= '9')
        selected_wan = atoi(argv[2]);

    if (setrlimit(RLIMIT_MEMLOCK, &r)) die("setrlimit");
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[CONFIG]\n");
    if (load_config(argv[1]) < 0) die("config");

    if (selected_wan >= num_wan) {
        fprintf(stderr, "Invalid WAN %d\n", selected_wan);
        return 1;
    }

    printf("  LOCAL: %s\n", local_if);
    for (int i = 0; i < num_wan; i++) {
        printf("  WAN%d: %s %s\n", i+1, wan_if[i],
               i == selected_wan ? "<-- selected" : "");
    }

    const char *bpf = (argc >= 4) ? argv[3] : "xdp_kern.o";

    printf("\n[SETUP]\n");

    /* QUAN TRỌNG: Phải attach XDP vào LOCAL trước */
    printf("Attaching XDP to %s...\n", local_if);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set dev %s xdp obj %s 2>/dev/null || "
             "ip link set dev %s xdpgeneric obj %s 2>/dev/null",
             local_if, bpf, local_if, bpf);
    system(cmd);

    if (setup_local(bpf) < 0) die("setup local");

    for (int i = 0; i < num_wan; i++) {
        if (setup_wan(i) < 0) die("setup wan");
    }

    printf("\n[RUNNING]\n");
    printf("  %s -> %s (bypass kernel)\n", local_if, wan_if[selected_wan]);
    printf("  Static route không ảnh hưởng!\n");
    printf("  Ctrl+C to stop\n\n");

    time_t last = 0;
    while (running) {
        process_rx();
        usleep(10);

        time_t now = time(NULL);
        if (now - last >= 3) {
            printf("RX: %lu, TX: %lu\n", rx_count, tx_count);
            last = now;
        }
    }

    /* Detach XDP khi thoát */
    snprintf(cmd, sizeof(cmd), "ip link set dev %s xdp off 2>/dev/null", local_if);
    system(cmd);

    cleanup();
    printf("XDP detached. Traffic back to kernel.\n");
    return 0;
}
