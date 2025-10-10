#ifndef __COMMON_DEFINES_H
#define __COMMON_DEFINES_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <sys/statfs.h>  /* statfs */
#include <sys/stat.h>    /* stat(2) + S_IRWXU */
#include <sys/mount.h>   /* mount(2) */

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h> /* TC_H_MAJ + TC_H_MIN */
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <getopt.h>
#include "linux/bpf.h"

#define MACLEN 14
#define IPLEN 20
#define UDPLEN 8
#define TCPLEN 20
#define VXLANLEN 8

#define bpf_printkm(fmt, ...)                                    \
({                                                              \
    char ____fmt[] = fmt;                                   \
    bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

#define MAX_IFINDEX 4096

struct bpf_elf_map {
        __u32 type;
        __u32 size_key;
        __u32 size_value;
        __u32 max_elem;
        __u32 flags;
        __u32 id;
        __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

// Must pad the struct to avoid eBPf verifier
// think the stack boundary is iligal.
// #pragma pack(1)
struct fivetuple {
    __be32 laddr;
    __be32 raddr;
    __be16 lport;
    __be16 rport;
    __u32 protocol;
};

struct egressinfo {
    unsigned char outer_header[64];
    __u32 ifidx;
};

struct action {
    __u16 ingress;
    __u16 egress;
};

struct devinfo {
    __be32 ip;
    unsigned char mac[ETH_ALEN];
};

struct rule {
    struct fivetuple fivetuple_;
    int isIngress;
};

// Should write dmac to a map forahead becuase pod mac is not carried in VXLAN
struct ingressinfo {
    __u32 ifidx;
    unsigned char dmac[ETH_ALEN];
    unsigned char smac[ETH_ALEN];
};

#define PORT_AVAILABLE 1024

static int verbose = 0;

#define EXIT_OK   0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL  1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP  3
#define EXIT_FAIL_MAP  20
#define EXIT_FAIL_MAP_KEY 21
#define EXIT_FAIL_MAP_FILE 22
#define EXIT_FAIL_MAP_FS 23
#define EXIT_FAIL_IP  30
#define EXIT_FAIL_CPU  31
#define EXIT_FAIL_BPF  40
#define EXIT_FAIL_BPF_ELF 41
#define EXIT_FAIL_BPF_RELOCATE 42

#endif
