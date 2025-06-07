#include "common_kern.h"

#define PIN_GLOBAL_NS 2
#define PORT_MIN 49152
#define PORT_MAX 65535
#define ENABLENP

struct bpf_elf_map SEC("maps") ingress_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .size_key = sizeof(__be32),
    .size_value = sizeof(struct ingressinfo),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem = 1024,
};

struct bpf_elf_map SEC("maps") egressip_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .size_key = sizeof(__be32),
    .size_value = sizeof(__be32),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem = 4096
};

struct bpf_elf_map SEC("maps") egress_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .size_key = sizeof(__be32),
    .size_value = sizeof(struct egressinfo),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem = 1024,
};

struct bpf_elf_map SEC("maps") policy_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .size_key = sizeof(struct fivetuple),
    .size_value = sizeof(struct action),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem = 4096,
};

struct bpf_elf_map SEC("maps") devmap = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .size_key = sizeof(int),
    .size_value = sizeof(struct devinfo),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem = 8,
};

SEC("tc_init_e")
int tc_init_e_func(struct __sk_buff *skb) {
    int err;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    ////////////////// Check if the packet is a VXLAN packet ////////////////////
    if (data_end < data + MACLEN * 2 + IPLEN * 2 + UDPLEN + VXLANLEN) goto out;
    struct ethhdr *outer_eth = data;

    // Check if Ethernet frame has IP packet and set IP hdr ptr
    if (outer_eth->h_proto != bpf_htons(ETH_P_IP)) goto out;
    struct iphdr *outer_iph = (struct iphdr *)(outer_eth + 1);
    // Check if IP packet is UDP and set UDP hdr ptr
    if (outer_iph->protocol != IPPROTO_UDP) goto out;
    struct udphdr *udph = (struct udphdr *)(outer_iph + 1);

    // Check if UDP packet is VXLAN/Geneve and set VXLAN/Geneve hdr ptr
    if (!is_encap(udph)) goto out;
    // UDP hdr = vxlan/geneve header = 8 bytes
    struct ethhdr * inner_eth = (struct ethhdr *)((void*)udph + UDPLEN + VXLANLEN);

    // Check if Ethernet frame has IP packet and set IP hdr ptr
    if (inner_eth->h_proto != bpf_htons(ETH_P_IP)) goto out;
    struct iphdr *inner_iph = (struct iphdr *)(inner_eth + 1);
    // Make sure both egress_prog required to and is in established state
    if ((inner_iph->tos & 0xc) != 0xc) goto out;
    /////////////////////////// Policy Learning ///////////////////////////
#ifdef ENABLENP
    struct fivetuple tuple_;
    if (parse_5tuple_e(inner_iph, data_end, &tuple_)) goto out;
    struct action eaction_ = {
        .egress = 1,
        .ingress = 0
    };
    if(bpf_map_update_elem(&policy_cache, &tuple_, &eaction_, BPF_NOEXIST)) {
        struct action* action_ = bpf_map_lookup_elem(&policy_cache, &tuple_);
        if (!action_) {
            bpf_printkm("(tc_init_e)ERROR: Can not lookup policy_cache. goto out");
        } else {
            action_->egress = 1;
            // bpf_printkm("(tc_init_e)INFO: Added an policy_cache element. tuple_ is %x %x", tuple_.laddr, tuple_.raddr);
        }
    // } else {
        // bpf_printkm("(tc_init_e)INFO: Added an policy_cache element. tuple_ is %x %x", tuple_.laddr, tuple_.raddr);
    }
#endif
    ///////////////////////// Header cache learning ///////////////////////////////
    // Make sure there is elem in the map
    struct egressinfo tmpnodeegressinfo_;
    initegressinfo(&tmpnodeegressinfo_, data, skb->ifindex);
    err = bpf_map_update_elem(&egress_cache, &outer_iph->daddr, &tmpnodeegressinfo_, BPF_NOEXIST);
    // if(!err) {
        // bpf_printkm("(tc_init_e)INFO: Updated an nodeegressinfo element");
    // }

    err = bpf_map_update_elem(&egressip_cache, &inner_iph->daddr, &outer_iph->daddr, BPF_NOEXIST);
    // if(!err) {
        // bpf_printkm("(tc_init_e)INFO: Added an podip element. RemoteIP is %x", inner_iph->daddr);
    // }
    set_ip_tos(skb, 50, 0);
out:
    return TC_ACT_OK;
}

SEC("tc_masq")
int tc_masq_func(struct __sk_buff *ctx) {
    int action = TC_ACT_OK, err;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (data_end < data + MACLEN + IPLEN) goto out;
    struct ethhdr *eth = data;

    // Check if Ethernet frame has IP packet and set IP hdr ptr
    if (eth->h_proto != bpf_htons(ETH_P_IP)) goto out;
    struct iphdr *iphdr = (struct iphdr *)(eth + 1);
    // Read for udp source port and policy check
    __u32 hash = bpf_get_hash_recalc(ctx);
#ifdef ENABLENP
    ///////////////////////// Check for Policy /////////////////////////
    struct fivetuple tuple_;
    if (parse_5tuple_e(iphdr, data_end, &tuple_)) goto out;
    struct action *action_ = bpf_map_lookup_elem(&policy_cache, &tuple_);
    // Must the ingress and egress both allow the flow, or will cause conntrack problem
    if (!action_ || !(action_->ingress & action_->egress)) {
        // bpf_printkm("(tc_masq)INFO: Cannot masq because of policy. tuple_ is %x %x", tuple_.laddr, tuple_.raddr);
        set_ip_tos(ctx, 0, 0x4);
        goto out;
    }
#endif
    ///////////////////////// Check for header cache ///////////////////////////////
    __be32* nodeip_ = bpf_map_lookup_elem(&egressip_cache, &iphdr->daddr);
    if (!nodeip_) {
        bpf_printkm("(tc_masq)WARNING: Can not find nodeip, RemoteIP is %x", iphdr->daddr);
        set_ip_tos(ctx, 0, 0x4);
        goto out;
    } 

    // Use the nodeip to look up the egressinfo for masq
    struct egressinfo* egressinfo_ = bpf_map_lookup_elem(&egress_cache, nodeip_);
    if (!egressinfo_) {
        bpf_printkm("(tc_masq)WARNING: Can not find egressinfo. nodedip is %x", &nodeip_);
        set_ip_tos(ctx, 0, 0x4);
        goto out;
    }

    // Check for restore cache
    struct ingressinfo* ingressinfo_ = bpf_map_lookup_elem(&ingress_cache, &iphdr->saddr);
    if (!ingressinfo_ || ingressinfo_->smac[0] == 0x0) {
        bpf_printkm("(tc_masq)WARNING: Not ready for restore. LocalIP is %x", iphdr->saddr);
        goto out;
    }
    ///////////////////////// Start Masqurade /////////////////////////
    // Adjust the head pointer to the start of the inner IP header
    // The skb->inner protocol must be htons(ETH_P_TEB), thus we need BPF_F_ADJ_ROOM_ENCAP_L2(14)|BPF_F_ADJ_ROOM_ENCAP_L2_ETH flags.
    // The other flags are used to adjust some fild in the skb. Need kernel with d01b59c commit, at least 5.13.
    err = bpf_skb_adjust_room(ctx, 50, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP|BPF_F_ADJ_ROOM_ENCAP_L2(14)|BPF_F_ADJ_ROOM_ENCAP_L2_ETH);
    if (err) {
        bpf_printkm("(tc_masq)ERROR: Can not change head. goto out");
        goto out;
    }
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if (data_end < data + 64) goto out;
    // Append the outer header
    __builtin_memcpy(data, egressinfo_->outer_header, 64);
    set_new_length_outerhdr(ctx, ctx->len);
    // Set the UDP source port
    hash ^= hash << 16;
    __be16 sport = htons((((__u64) hash * (PORT_MAX - PORT_MIN)) >> 32) + PORT_MIN);
    bpf_skb_store_bytes(ctx, UDP_PORT_OFF, &sport, sizeof(sport), 0);

    ///////////////////////// Redirect to Node NIC /////////////////////////
    // action = bpf_redirect_rpeer(egressinfo_->ifidx, 0);
    action = bpf_redirect(egressinfo_->ifidx, 0);
    goto out;
out:
    return action;
}

SEC("tc_restore")
int tc_restore_func(struct __sk_buff *ctx) {
    int action = TC_ACT_OK;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (data_end < data + MACLEN * 2 + IPLEN * 2 + UDPLEN + VXLANLEN) goto out;
    struct ethhdr *outer_eth = data;

    // Check if Ethernet frame has IP packet and set IP hdr ptr
    if (outer_eth->h_proto != bpf_htons(ETH_P_IP)) goto out;
    struct iphdr *outer_iph = (struct iphdr *)(outer_eth + 1);

    // Check if IP packet is UDP and set UDP hdr ptr
    if (outer_iph->protocol != IPPROTO_UDP) goto out;
    struct udphdr *udph = (struct udphdr *)(outer_iph + 1);

    // Check if UDP packet is VXLAN/Geneve and set VXLAN/Geneve/OTV hdr ptr
    if (!is_encap(udph)) goto out;
    // UDP hdr = vxlan/geneve header = 8 bytes
    struct ethhdr * inner_eth = (struct ethhdr *)((void*)udph + UDPLEN + VXLANLEN);

    // Check if Ethernet frame has IP packet and set IP hdr ptr
    if (inner_eth->h_proto != bpf_htons(ETH_P_IP)) goto out;
    struct iphdr *inner_iph = (struct iphdr *)(inner_eth + 1);
    
    int ifindex = ctx->ifindex;
    struct devinfo *devinfo_ = bpf_map_lookup_elem(&devmap, &ifindex);
    if (!devinfo_ || maccmp(outer_eth->h_dest, devinfo_->mac, ETH_ALEN)) {
        bpf_printkm("(tc_restore)ERROR: Can not find devinfo or mac wrong.");
        goto out;
    }
    if (!devinfo_ || outer_iph->daddr != devinfo_->ip) {
        bpf_printkm("(tc_restore)ERROR: IP wrong.");
        goto out;
    }
    ///////////////////////// Policy Checking /////////////////////////
#ifdef ENABLENP
    struct fivetuple tuple_;
    if (parse_5tuple_in(inner_iph, data_end, &tuple_)) goto out;
    struct action *action_ = bpf_map_lookup_elem(&policy_cache, &tuple_);
    if (!action_ || !(action_->ingress & action_->egress)) {
        // bpf_printkm("(tc_restore)INFO: Cannot restore because of policy. tuple_ is %x %x", tuple_.laddr, tuple_.raddr);
        set_ip_tos(ctx, 50, 0x4);
        goto out;
    }
#endif
    ///////////////////////// Restore the Packet /////////////////////////
    struct ingressinfo* ingressinfo_ = bpf_map_lookup_elem(&ingress_cache, &inner_iph->daddr);
    if (!ingressinfo_ || ingressinfo_->smac[0] == 0x0) {
        bpf_printkm("(tc_restore)ERROR: pod info not ready, LocalIP is %x", inner_iph->daddr);
        set_ip_tos(ctx, 50, 0x4);
        goto out;
    }
    if (!bpf_map_lookup_elem(&egressip_cache, &inner_iph->saddr)) {
        bpf_printkm("(tc_restore)WARNING: Not ready for masq. RemoteIP is %x", inner_iph->saddr);
        goto out;
    }

    if (bpf_skb_adjust_room(ctx, -50, BPF_ADJ_ROOM_MAC, 0)) {
        bpf_printkm("(tc_restore)ERROR: Can not adjust room. goto out");
        goto out;
    }
    // Check bounds
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if (data_end < data + MACLEN + IPLEN) goto out;
    // Change MAC to masqed MAC
    outer_eth = data;
    __builtin_memcpy(outer_eth->h_dest, ingressinfo_->dmac, ETH_ALEN);
    __builtin_memcpy(outer_eth->h_source, ingressinfo_->smac, ETH_ALEN);
    action = bpf_redirect_peer(ingressinfo_->ifidx, 0);
out:
    return action;
}

SEC("tc_init_in")
int tc_init_in_func(struct __sk_buff *ctx) {
    int action = TC_ACT_OK;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (data_end < data + MACLEN + IPLEN) goto out;
    struct ethhdr *eth = data;
    // Check if Ethernet frame has IP packet and set IP hdr ptr
    if (eth->h_proto != bpf_htons(ETH_P_IP)) goto out;
    struct iphdr *iphdr = (struct iphdr *)(eth + 1);

    unsigned int src_ip = iphdr->saddr;
    src_ip = ntohl(src_ip);
    unsigned int last_octet = src_ip & 0xFF;
    if (last_octet == 1 || last_octet == 0) {
        goto out;
    }

    // We only learn the flow that is marked as 0x4
    if ((iphdr->tos & 0xc) != 0xc) goto out;
    ///////////////////////// Header/ifidx Learning ////////////////////
    struct ingressinfo* ingressinfo_ = bpf_map_lookup_elem(&ingress_cache, &iphdr->daddr);
    if (!ingressinfo_) {
        bpf_printkm("(tc_init_in)ERROR: No pod info found, LocalIP is %x", iphdr->daddr);
        goto out;
    } else {
        __builtin_memcpy(ingressinfo_->dmac, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(ingressinfo_->smac, eth->h_source, ETH_ALEN);
    }

#ifdef ENABLENP
    ///////////////////////// Policy Learning /////////////////////////
    struct fivetuple tuple_;
    if (parse_5tuple_in(iphdr, data_end, &tuple_)) goto out;
    struct action eaction_ = {
        .egress = 0,
        .ingress = 1
    };
    if(bpf_map_update_elem(&policy_cache, &tuple_, &eaction_, BPF_NOEXIST)) {
        struct action* action_ = bpf_map_lookup_elem(&policy_cache, &tuple_);
        if (!action_) {
            bpf_printkm("(tc_init_in)ERROR: Can not lookup policy_cache. goto out");
        } else {
            action_->ingress = 1;
            // bpf_printkm("(tc_init_in)INFO: Added an policy_cache element. tuple_ is %x %x", tuple_.laddr, tuple_.raddr);
        }
    // } else {
        // bpf_printkm("(tc_init_in)INFO: Added an policy_cache element. tuple_ is %x %x", tuple_.laddr, tuple_.raddr);
    }
#endif
    set_ip_tos(ctx, 0, 0);
out:
    return action;
}

char _license[] SEC("license") = "GPL";
