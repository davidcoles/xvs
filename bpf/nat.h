struct addr_port_time {
    addr_t nat;
    addr_t src;
    __u64 time;
    __be16 port;
    __be16 pad[3];
};

struct vip_rip {
    tunnel_t tunnel;
    addr_t vip;
    addr_t ext;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, addr_t); // nat
    __type(value, struct vip_rip); // vip/rip    
    __uint(max_entries, 4096);
} nat_to_vip_rip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fivetuple);
    __type(value, struct addr_port_time);
    __uint(max_entries, 65556);
} reply SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fivetuple);
    __type(value, struct addr_port_time);
    __uint(max_entries, 1);
} reply_dummy SEC(".maps");


static __always_inline
int xdp_request_v6(struct xdp_md *ctx) {
   
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    
    if (eth + 1 > data_end)
        return XDP_DROP;
    
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
       	return XDP_PASS;
    
    struct ip6_hdr *ip6 = (void *)(eth + 1);
    
    if (ip6 + 1 > data_end)
        return XDP_DROP;
    

    if ((ip6->ip6_ctlun.ip6_un2_vfc >> 4) != 6)
        return XDP_DROP;
    
    if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6)
	//return XDP_DROP;
	return XDP_PASS;

    if (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim <= 1)
    	return XDP_DROP;
    
    (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim)--;

    addr_t src = { .addr6 = ip6->ip6_src };
    addr_t nat = { .addr6 = ip6->ip6_dst };
    struct vip_rip *vip_rip = bpf_map_lookup_elem(&nat_to_vip_rip, &nat);
    
    if (!vip_rip)
        return XDP_PASS;

    __u8 proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    addr_t vip = vip_rip->vip;
    addr_t ext = vip_rip->ext;
    __be16 eph = 0;
    __be16 svc = 0;

    // check that external address is set - should probably set vlan to 0 in userspace if this is the case
    // maybe audit code and do belt & braces for each place that this could happen
    //if (nul6(&(vip.addr6)) || nul6(&(ext.addr6)))
    //	return XDP_DROP;

    struct l4 ft = { .saddr = src.addr4.addr, .daddr = nat.addr4.addr, .sport = eph, .dport = svc };
    struct tunnel *destinfo = (void *) vip_rip;

    tunnel_t t = *destinfo;
    t.sport = t.sport ? t.sport : (0x8000 | (l4_hash_(&ft) & 0x7fff));

    struct tcphdr *tcp = (void *) (ip6 + 1);
    struct udphdr *udp = (void *) (ip6 + 1);
    struct icmp6_hdr *icmp = (void *) (ip6 + 1);

    void *reply_map = &reply;
    
    switch(proto) {
    case IPPROTO_TCP:
	if (tcp + 1 > data_end)
	    return XDP_DROP;
	eph = tcp->source;
	svc = tcp->dest;
	break;
    case IPPROTO_UDP:
	if (udp + 1 > data_end)
	    return XDP_DROP;
	eph = udp->source;
	svc = udp->dest;
	break;
    case IPPROTO_ICMPV6:
	reply_map = &reply_dummy;
	if (icmp + 1 > data_end)
	    return XDP_DROP;
	if (icmp->icmp6_type == ICMP6_PACKET_TOO_BIG) {
	    ip6->ip6_dst = vip.addr6; // switch VIP back in
	    break;
	}
	return XDP_DROP;
    default:
	return XDP_DROP;
    }
    
    int overhead = 0;

    switch (t.method) {
    case T_GRE:  overhead = sizeof(struct ip6_hdr) + GRE_OVERHEAD; break;
    case T_FOU:  overhead = sizeof(struct ip6_hdr) + FOU_OVERHEAD; break;
    case T_GUE:  overhead = sizeof(struct ip6_hdr) + GUE_OVERHEAD; break;
    case T_IPIP: overhead = sizeof(struct ip6_hdr);  break;
    case T_NONE: break;
    default: return XDP_DROP;
    }

    if ((data_end - (void *) ip6) + overhead > MTU)
	return XDP_DROP;

    if (t.method == T_NONE && ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim > 2)
        ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = 2;
    
    struct l4v6 o = {.saddr = ip6->ip6_src, .daddr = ip6->ip6_dst, .sport = eph, .dport = svc };
    struct l4v6 n = o;

    if (IPPROTO_ICMPV6 != proto) {
	n.saddr = ip6->ip6_src = ext.addr6; // the source address of the NATed packet needs to be the LB's external IP
	n.daddr = ip6->ip6_dst = vip.addr6; // the destination needs to the that of the VIP that we are probing
    }
    
    switch(proto) {
    case IPPROTO_TCP:
	tcp->check = l4v6_checksum_diff(~(tcp->check), &n, &o);
	break;
    case IPPROTO_UDP:
	udp->check = l4v6_checksum_diff(~(udp->check), &n, &o);
	break;
    case IPPROTO_ICMPV6:
	// FIXME needs testing
	icmp->icmp6_cksum = l4v6_checksum_diff(~(icmp->icmp6_cksum), &n, &o);
	break;
    }
    
    /**********************************************************************/
    
    int action = 0;
    __u8 gue_protocol = 0;

    switch (t.method) {
    case T_NONE: action = send_l2_(ctx, &t); break;
    case T_IPIP: action = send_ipip_(ctx, &t, 1); break;
    case T_GRE:  action = send_gre_(ctx, &t, 1); break;
    case T_GUE:  gue_protocol = IPPROTO_IPV6; // fallthrough
    case T_FOU:  action = send_fou_gue(ctx, &t, gue_protocol); break;
    }

    if (action < 0 || !t.vlanid) // verifier shenanigans if I check for !t.vlanid earlier!
        return XDP_DROP;

    // to match returning packet
    fivetuple_t rep = { .sport = svc, .dport = eph, .proto = proto, .saddr = vip, .daddr = ext };
    struct addr_port_time map = { .port = eph, .time = bpf_ktime_get_ns(), .nat = nat, .src = src };

    // ICMP will use the dummy reply map - avoiding another conditional keeps the verifier happy
    bpf_map_update_elem(reply_map, &rep, &map, BPF_ANY);
    
    return is_ipv4_addr(t.daddr) ?
	bpf_redirect_map(&redirect_map4, t.vlanid, XDP_DROP) :
	bpf_redirect_map(&redirect_map6, t.vlanid, XDP_DROP);
}

static __always_inline
int xdp_request_v4(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    
    if (eth + 1 > data_end)
        return XDP_DROP;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
	return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    
    if (ip + 1 > data_end)
	return XDP_DROP;

    if (ip->version != 4)
	return XDP_DROP;
    
    if (ip->ihl != 5)
        return XDP_DROP;
    
    // ignore evil bit and DF, drop if more fragments flag set, or fragent offset is not 0
    if ((ip->frag_off & bpf_htons(0x3fff)) != 0)
        return XDP_DROP;

    if (ip->ttl <= 1)
	return XDP_DROP;

    ip_decrease_ttl(ip); // forwarding, so decrement TTL

    
    addr_t src = { .addr4.addr = ip->saddr };
    addr_t nat = { .addr4.addr = ip->daddr };
    struct vip_rip *vip_rip = bpf_map_lookup_elem(&nat_to_vip_rip, &nat);

    if (!vip_rip)
    	return XDP_PASS;
    
    __u8 proto = ip->protocol;
    addr_t vip = vip_rip->vip;
    addr_t ext = vip_rip->ext;
    __be16 eph = 0;
    __be16 svc = 0;

    struct l4 ft = { .saddr = ip->saddr, .daddr = ip->daddr, .sport = eph, .dport = svc };
    struct tunnel *destinfo = (void *) vip_rip;
    
    tunnel_t t = *destinfo;
    t.sport = t.sport ? t.sport : ( 0x8000 | (l4_hash_(&ft) & 0x7fff));

    struct tcphdr *tcp = (void *)(ip + 1);
    struct udphdr *udp = (void *)(ip + 1);
    struct icmphdr *icmp = (void *)(ip + 1);

    void *reply_map = &reply;
    
    switch(proto) {
    case IPPROTO_TCP:
	if (tcp + 1 > data_end)
	    return XDP_DROP;
	eph = tcp->source;
	svc = tcp->dest;
	break;
    case IPPROTO_UDP:
	if (udp + 1 > data_end)
	    return XDP_DROP;
	eph = udp->source;
	svc = udp->dest;
	break;
    case IPPROTO_ICMP:
	reply_map = &reply_dummy;
	if (icmp + 1 > data_end)
	    return XDP_DROP;
	if (icmp->type == ICMP_DEST_UNREACH && icmp->code == ICMP_FRAG_NEEDED) {
	    ip->daddr = vip.addr4.addr; // switch VIP back in
	    __u8 *d = (void *) &(ip->daddr);
	    bpf_printk("DST %d.%d.%d", d[1], d[2], d[3]);
	    break;
	}
	return XDP_DROP;
    default:
	return XDP_DROP;
    }

    int overhead = 0;

    switch (t.method) {
    case T_GRE:  overhead = sizeof(struct iphdr) + GRE_OVERHEAD; break;
    case T_FOU:  overhead = sizeof(struct iphdr) + FOU_OVERHEAD; break;
    case T_GUE:  overhead = sizeof(struct iphdr) + GUE_OVERHEAD; break;
    case T_IPIP: overhead = sizeof(struct iphdr);  break;
    case T_NONE: break;
    default: return XDP_DROP;
    }

    if ((data_end - (void *) ip) + overhead > MTU)
	return XDP_DROP;

    if (t.method == T_NONE && ip->ttl > 2)
        ip4_set_ttl(ip, 2);
    
    /*
    if ((data_end - (void *) ip) + overhead > mtu) {
	bpf_printk("IPv4 FRAG_NEEDED\n");
	__be32 internal = vlaninfo->source_ipv4;
	return send_frag_needed4(ctx, internal, mtu - overhead);
    }
    */

    // save l3/l4 parameters for checksum diffs
    struct l4 o = { .saddr = ip->saddr, .daddr = ip->daddr, .sport = eph, .dport = svc };    
    struct l4 n = o;
    struct iphdr old = *ip;
    
    // update l3 addresses if not ICMP
    if (proto != IPPROTO_ICMP) {
	n.saddr = ip->saddr = ext.addr4.addr;
	n.daddr = ip->daddr = vip.addr4.addr;
    }

    // calculate new l3 checksum
    ip->check = ip4_csum_diff(ip, &old);

    // calculate new l4 checksum
    switch(proto) {
    case IPPROTO_TCP:
	tcp->check = l4_csum_diff(&n, &o, tcp->check);
	break;
    case IPPROTO_UDP:
	udp->check = l4_csum_diff(&n, &o, udp->check);
	break;
    case IPPROTO_ICMP:
	// IPv4 ICMP does not use a pseudo header, so no change
	break;
    }

    /**********************************************************************/

    int action = 0;
    __u8 gue_protocol = 0;
    
    switch (t.method) {
    case T_NONE: action = send_l2_(ctx, &t); break;
    case T_IPIP: action = send_ipip_(ctx, &t, 0); break;
    case T_GRE:	 action = send_gre_(ctx, &t, 0); break;
    case T_GUE:  gue_protocol = IPPROTO_IPIP; // fallthrough
    case T_FOU:  action = send_fou_gue(ctx, &t, gue_protocol); break;
    }

    if (action < 0 || !t.vlanid) // verifier shenanigans if I check for !t.vlanid earlier!
	return XDP_DROP;

    // to match returning packet
    fivetuple_t rep = { .sport = svc, .dport = eph, .proto = proto, .saddr = vip, .daddr = ext };
    struct addr_port_time map = { .port = eph, .time = bpf_ktime_get_ns(), .nat = nat, .src = src };

    // ICMP will use the dummy reply map - avoiding another conditional keeps the verifier happy
    bpf_map_update_elem(reply_map, &rep, &map, BPF_ANY);
    
    return is_ipv4_addr(t.daddr) ?
	bpf_redirect_map(&redirect_map4, t.vlanid, XDP_DROP) :
	bpf_redirect_map(&redirect_map6, t.vlanid, XDP_DROP);
}

static __always_inline
int xdp_reply_v6(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    
    if (eth + 1 > data_end)
        return XDP_DROP;
    
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
       	return XDP_PASS;
    
    struct ip6_hdr *ip6 = (void *)(eth + 1);
    
    if (ip6 + 1 > data_end)
        return XDP_DROP;
    
    if ((ip6->ip6_ctlun.ip6_un2_vfc >> 4) != 6)
        return XDP_DROP;
    
    if(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6) {
        //return XDP_PASS;
	return XDP_DROP;
    }

    if (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim <= 1)
	return XDP_DROP;

        
    __u8 proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    addr_t saddr = { .addr6 = ip6->ip6_src };
    addr_t daddr = { .addr6 = ip6->ip6_dst };    
    
    fivetuple_t rep = { .proto = proto, .saddr = saddr, .daddr = daddr };

    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
	
    switch(proto) {
    case IPPROTO_TCP:
	tcp = (void *) (ip6 + 1);
	if (tcp + 1 > data_end)
	    return XDP_DROP;
	rep.sport = tcp->source;
	rep.dport = tcp->dest;
	break;
    case IPPROTO_UDP:
	udp = (void *) (ip6 + 1);
	if (udp + 1 > data_end)
	    return XDP_DROP;
	rep.sport = udp->source;
	rep.dport = udp->dest;
	break;
    default:
	return XDP_DROP;
    }

    struct addr_port_time *match = bpf_map_lookup_elem(&reply, &rep);
    
    if (!match)
	return XDP_DROP;
    
    (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim)--;

    __u64 time = bpf_ktime_get_ns();
    
    if (time < match->time)
	return XDP_DROP;
    
    if ((time - match->time) > (5 * SECOND_NS))
	return XDP_DROP;

    struct l4v6 o = {.saddr = ip6->ip6_src, .daddr = ip6->ip6_dst, .sport = rep.sport, .dport = rep.dport };
    struct l4v6 n = o;
    
    n.saddr = ip6->ip6_src = match->nat.addr6; // reply comes from the NAT addr
    n.daddr = ip6->ip6_dst = match->src.addr6; // to the internal NETNS address
    
    switch(proto) {
    case IPPROTO_TCP:
	tcp->check = l4v6_csum_diff(&n, &o, tcp->check);
	break;
    case IPPROTO_UDP:
	udp->check = l4v6_csum_diff(&n, &o, udp->check);
	break;
    }
    
    return XDP_PASS;
}

static __always_inline
int xdp_reply_v4(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = (void *)(long)ctx->data;
    
    if (eth + 1 > data_end)
        return XDP_DROP;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
	return XDP_DROP;
    
    struct iphdr *ip = (void *)(eth + 1);
    
    if (ip + 1 > data_end)
	return XDP_DROP;
        
    if (ip->version != 4)
        return XDP_DROP;
    
    if (ip->ihl != 5)
        return XDP_DROP;
    
    if (ip->ttl <= 1)
        return XDP_DROP;
    
    // ignore evil bit and DF, drop if more fragments flag set, or fragent offset is not 0
    if ((ip->frag_off & bpf_htons(0x3fff)) != 0)
        return XDP_DROP;
    
    __u8 proto = ip->protocol;
    addr_t saddr = { .addr4.addr = ip->saddr };
    addr_t daddr = { .addr4.addr = ip->daddr };    

    fivetuple_t rep = { .proto = proto, .saddr = saddr, .daddr = daddr };

    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;    

    switch(proto) {
    case IPPROTO_TCP:
	tcp = (void *)(ip + 1);
	if (tcp + 1 > data_end)
	    return XDP_DROP;
	rep.sport = tcp->source;
	rep.dport = tcp->dest;
	break;
    case IPPROTO_UDP:
	udp = (void *)(ip + 1);
	if (udp + 1 > data_end)
	    return XDP_DROP;
	rep.sport = udp->source;
	rep.dport = udp->dest;
	break;
    default:
	return XDP_DROP;    
    }

    struct addr_port_time *match = bpf_map_lookup_elem(&reply, &rep);
    
    if (!match)
	return XDP_DROP;
    
    ip_decrease_ttl(ip); // forwarding, so decrement TTL
    
    struct l4 o = { .saddr = ip->saddr, .daddr = ip->daddr };
    struct l4 n = o;
    struct iphdr old = *ip;

    __u64 time = bpf_ktime_get_ns();
    
    if (time < match->time)
	return XDP_DROP;
    
    if ((time - match->time) > (5 * SECOND_NS))
	return XDP_DROP;
    
    n.saddr = ip->saddr = match->nat.addr4.addr; // reply comes from the NAT addr
    n.daddr = ip->daddr = match->src.addr4.addr; // to the internal NETNS address
    
    ip->check = ip4_csum_diff(ip, &old);
    
    switch(proto) {
    case IPPROTO_TCP:
	tcp->check = l4_csum_diff(&n, &o, tcp->check);
	break;
    case IPPROTO_UDP:
	udp->check = l4_csum_diff(&n, &o, udp->check);
	break;
    }
    
    return XDP_PASS;
}
