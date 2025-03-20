

/*

static __always_inline
void *is_ipv4(void *data, void *data_end)
{
    struct iphdr *iph = data;
    __u32 nh_off = sizeof(struct iphdr);

    if (data + nh_off > data_end)
        return NULL;

    if (iph->version != 4)
	return NULL;
    
    if (iph->ihl < 5)
        return NULL;

    if (iph->ihl == 5)
        return data + nh_off;

    return NULL; // remove to allow IPv4 options - needs testing first and probably not advisable

    nh_off = (iph->ihl) * 4;

    if (data + nh_off > data_end)
        return NULL;

    return data + nh_off;
}



struct iphdr *xparse(struct xdp_md *ctx, struct ethhdr *eth, struct vlan_hdr *vlan,  struct iphdr *ip)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *e = data;
    struct vlan_hdr *v = NULL;
    struct iphdr *i = NULL;
    
    if (e + 1 > data_end)
	return NULL;

    *eth = *e;

    if (e->h_proto == bpf_htons(ETH_P_8021Q)) {
	v = (void *)(eth + 1);
	
	if (v + 1 > data_end)
	    return NULL;
	
	*vlan = *v;
	
	i = (void *)(v + 1);
    } else {
	i = (void *)(e + 1);
    }
    
    if (i + 1 > data_end)
	return NULL;

    *ip = *i;

    return i;
}
*/

    /*
    if (eth + 1 > data_end)
	return XDP_ABORTED;
    
    if(vlan) {
	vlan = (struct vlan_hdr *)(eth + 1);
	
	if (vlan + 1 > data_end)
	    return XDP_ABORTED;
	
	ip = (void *) (vlan + 1);
    } else {
	ip = (void *) (eth + 1);
    }
    
    if (ip + 1 > data_end)
        return XDP_ABORTED;
    */


/*
#define PARSE_FRAME(eth, vlan, ip, data_end) ((eth + 1 > data_end) ? -1 : \
        (vlan ? \
        (((vlan = (struct vlan_hdr *)(eth + 1)) + 1 > data_end) ? -1 : \
         (((ip = (void *)(vlan + 1)) + 1 > data_end) ? -1 : 0)) : (((ip = (void *)(eth + 1)) + 1 > data_end) ? -1 : 0))) \


int parse_frame1(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    struct vlan_hdr *vlan = NULL;
    struct iphdr *ip = NULL;
    
    if (eth + 1 > data_end)
	return -1;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
	vlan = (void *)(eth + 1);

	if (vlan + 1 > data_end)
            return -1;

	ip = (void *)(vlan + 1);
    } else {
	ip = (void *)(eth + 1);
    }

    if (ip + 1 > data_end)
	return -1;

    return 0;
}

int parse_frame2(struct xdp_md *ctx, struct pointers *p)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    p->eth = data;
    
    if (p->eth + 1 > data_end)
        return -1;
    
    if (p->eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        p->vlan = (void *)(p->eth + 1);
	
	if (p->vlan + 1 > data_end)
	    return -1;
	
	p->ip = (void *)(p->vlan + 1);
    } else {
        p->ip = (void *)(p->eth + 1);
    }

    if (p->ip + 1 > data_end)
	return -1;

    p->eth_copy = *(p->eth);
    if (p->vlan) p->vlan_copy = *(p->vlan);
    p->ip_copy = *(p->ip);
    
     return 0;
}


int reparse_frame1(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    struct vlan_hdr *vlan = NULL;
    struct iphdr *ip = NULL;
    
    if (eth + 1 > data_end)
        return -1;
    
    if(vlan) {
        vlan = (void *)(eth + 1);

	if (vlan + 1 > data_end)
            return -1;
	
	ip = (void *)(vlan + 1);
    } else {
	ip = (void *)(eth + 1);
    }
    
    if (ip + 1 > data_end)
	return -1;
    
    return 0;
}

int reparse_frame2(struct xdp_md *ctx, struct pointers *p)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    p->eth = data;
    
    if (p->eth + 1 > data_end)
        return -1;
    
    if(p->vlan) {
        p->vlan = (void *)(p->eth + 1);

	if (p->vlan + 1 > data_end)
            return -1;
	
	p->ip = (void *)(p->vlan + 1);
    } else {
	p->ip = (void *)(p->eth + 1);
    }
    
    if (p->ip + 1 > data_end)
	return -1;

    // *(p->eth) = p->eth_copy;
    // if (p->vlan) *(p->vlan) = p->vlan_copy;
    // *(p->ip) = p->ip_copy;
    
    return 0;
}
*/

/*
static __always_inline
int adjust_head(struct xdp_md *ctx, struct pointers *p, int overhead)
//int adjust_head(struct xdp_md *ctx, struct pointers *p, int overhead, int payload_header_len)
{
    if (preserve_headers(ctx, p) < 0)
	return -1;

    // could be calculated from overhead
    //int payload_len = payload_header_len + ((void *)(long)ctx->data_end - ((void *) p->ip));

    if (sizeof(struct iphdr) > overhead)
	return -1;
    
    int payload_len = (overhead - sizeof(struct iphdr)) + ((void *)(long)ctx->data_end - ((void *) p->ip));

    // Insert space for new headers at the start of the packet
    if (bpf_xdp_adjust_head(ctx, 0 - overhead))
	return -1;
    
    // After bpf_xdp_adjust_head we need to re-calculate all of the header pointers  and restore contents
    if (restore_headers(ctx, p) < 0)
	return -1;

    return payload_len;
}
*/

/*
static __always_inline
int adjust_head_fou4(struct xdp_md *ctx, struct pointers *p)
{
    //return adjust_head(ctx, p, FOU4_OVERHEAD, sizeof(struct udphdr));
    return adjust_head(ctx, p, FOU4_OVERHEAD);
}

static __always_inline
int adjust_head_ipip4(struct xdp_md *ctx, struct pointers *p)
{
    //return adjust_head(ctx, p, IPIP_OVERHEAD, 0);
    return adjust_head(ctx, p, IPIP_OVERHEAD);
}
*/

/*
static __always_inline
int xipip_push(struct xdp_md *ctx, char *router, __be32 saddr, __be32 daddr)
{
    struct pointers p = {};

    if (!saddr || !daddr)
	return -1;
    
    // adjust the packet to add the FOU header - pointers to new header fields will be in p
    int payload_len = adjust_head_ipip4(ctx, &p);
    
    if (payload_len < 0)
	return -1;
    
    // Update the outer IP header to send to the IPIP target
    p.ip->saddr = saddr;
    p.ip->daddr = daddr;
    sanitise_iphdr(p.ip, sizeof(struct iphdr) + payload_len, IPPROTO_IPIP);    
    
    if (!nulmac(router)) {
	// If a router is explicitly indicated then direct the frame there
	memcpy(p.eth->h_source, p.eth->h_dest, 6);
	memcpy(p.eth->h_dest, router, 6);
    } else {
	// Otherwise return it to the device that it came from
	reverse_ethhdr(p.eth);
    }
    
    // some final sanity checks on ethernet addresses
    if (nulmac(p.eth->h_source) || nulmac(p.eth->h_dest))
	return -1;

    // Layer 3 services are only received on the same interface/VLAN as recieved, so we can simply TX
    return 0;
}
*/

/*
static __always_inline
int fou4_push(struct xdp_md *ctx, char *router, __be32 saddr, __be32 daddr, __u16 sport, __u16 dport)
{
    struct pointers p = {};

    if (!saddr || !daddr || !sport || !dport)
	return -1;
    
    // adjust the packet to add the FOU header - pointers to new header fields will be in p
    int udp_len = adjust_head_fou4(ctx, &p);
    
    if (udp_len < 0)
	return -1;

    struct udphdr udp_new = { .source = bpf_htons(sport), .dest = bpf_htons(dport), .len = bpf_htons(udp_len) };
    struct udphdr *udp = (void *) (p.ip + 1);
    
    if (udp + 1 > (void *)(long)ctx->data_end)
	return -1;

    *udp = udp_new;
    
    // Update the outer IP header to send to the FOU target
    p.ip->saddr = saddr;
    p.ip->daddr = daddr;
    sanitise_iphdr(p.ip, sizeof(struct iphdr) + udp_len, IPPROTO_UDP);
    
    if (!nulmac(router)) {
	// If a router is explicitly indicated then direct the frame there
	memcpy(p.eth->h_source, p.eth->h_dest, 6);
	memcpy(p.eth->h_dest, router, 6);
    } else {
	// Otherwise return it to the device that it came from
	reverse_ethhdr(p.eth);
    }
    
    // some final sanity checks on ethernet addresses
    if (nulmac(p.eth->h_source) || nulmac(p.eth->h_dest))
	return -1;

    // Layer 3 services are only received on the same interface/VLAN as recieved, so we can simply TX
    return 0;
}
*/

/*
static __always_inline
__u16 l4_hashx(struct iphdr *ip, void *l4)
{
    // UDP, TCP and SCTP all have src and dst port in 1st 32 bits, so use shortest type (UDP)
    struct udphdr *udp = (struct udphdr *) l4;
    struct {
	__be32 src;
	__be32 dst;
	__be16 sport;
	__be16 dport;
    } h = { .src = ip->saddr, .dst = ip->daddr};
    if (udp) {
	h.sport = udp->source;
	h.dport = udp->dest;
    }
    return sdbm((unsigned char *)&h, sizeof(h));
}
*/

/*
static __always_inline
int xxipip_push(struct xdp_md *ctx, char *router, __be32 saddr, __be32 daddr)
{
    struct pointers p = {};

    if (!saddr || !daddr)
	return -1;
    
    // adjust the packet to add the FOU header - pointers to new header fields will be in p 
    int payload_len = adjust_head_ipip4(ctx, &p);
    
    if (payload_len < 0)
	return -1;
    
    // Update the outer IP header to send to the IPIP target 
    p.ip->saddr = saddr;
    p.ip->daddr = daddr;
    sanitise_iphdr(p.ip, sizeof(struct iphdr) + payload_len, IPPROTO_IPIP);    
    
    if (!nulmac(router)) {
	// If a router is explicitly indicated then direct the frame there
	memcpy(p.eth->h_source, p.eth->h_dest, 6);
	memcpy(p.eth->h_dest, router, 6);
    } else {
	// Otherwise return it to the device that it came from
	reverse_ethhdr(p.eth);
    }
    
    // some final sanity checks on ethernet addresses
    if (nulmac(p.eth->h_source) || nulmac(p.eth->h_dest))
	return -1;

    // Layer 3 services are only received on the same interface/VLAN as recieved, so we can simply TX
    return 0;
}
*/



static __always_inline
int xxpush_gre4(struct xdp_md *ctx, unsigned char *router, __be32 saddr, __be32 daddr, __u16 protocol)
{
    struct pointers p = {};
    
    if (!saddr || !daddr)
	return -1;
    
    /* adjust the packet to add the FOU header - pointers to new header fields will be in p */
    int orig_len = adjust_head_gre4(ctx, &p);

    if (orig_len < 0)
	return -1;

    if (p.vlan) {
	p.vlan->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IP);
    } else {
	p.eth->h_proto = bpf_htons(ETH_P_IP);
    }

    int gre_len = sizeof(struct gre_hdr) + orig_len;
    
    struct gre_hdr gre_new = { .crv = 0, .protocol = bpf_htons(protocol) };
    struct gre_hdr *gre = (void *) (p.ip + 1);
    
    if (gre + 1 > (void *)(long)ctx->data_end)
	return -1;

    *gre = gre_new;

    /* Update the outer IP header to send to the FOU target */
    int tot_len = sizeof(struct iphdr) + gre_len;
    new_iphdr(p.ip, tot_len, IPPROTO_GRE, saddr, daddr);

    if (!nulmac(router)) {
	/* If a router is explicitly indicated then direct the frame there */
	memcpy(p.eth->h_source, p.eth->h_dest, 6);
	memcpy(p.eth->h_dest, router, 6);
    } else {
	/* Otherwise return it to the device that it came from */
	reverse_ethhdr(p.eth);
    }

    /* some final sanity checks on ethernet addresses */
    if (nulmac(p.eth->h_source) || nulmac(p.eth->h_dest))
	return -1;

    /* Layer 3 services are only received on the same interface/VLAN as recieved, so we can simply TX */
    return 0;
}


/*
static __always_inline
void sanitise_iphdr(struct iphdr *ip, __u16 tot_len, __u8 protocol)
{
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 64;
    ip->tot_len = bpf_htons(tot_len);
    ip->protocol = protocol;
    ip->check = 0;
    ip->check = ipv4_checksum(ip);
}
*/


/*
static __always_inline
int xxxadjust_head_fou4(struct xdp_md *ctx, struct pointers *p)
{
    return adjust_head(ctx, p, FOU4_OVERHEAD);
}
*/
/*
static __always_inline
int xxxadjust_head_fou6(struct xdp_md *ctx, struct pointers *p)
{
    return adjust_head(ctx, p, FOU6_OVERHEAD);
}
*/

/*
static __always_inline
int xxxadjust_head_ipip4(struct xdp_md *ctx, struct pointers *p)
{
    //return adjust_head(ctx, p, IPIP_OVERHEAD, 0);
    return adjust_head(ctx, p, IPIP_OVERHEAD);
}
*/


/*
static __always_inline
int xxxfou4_push(struct xdp_md *ctx, unsigned char *router, __be32 saddr, __be32 daddr, __u16 sport, __u16 dport)
{
    struct pointers p = {};

    if (!saddr || !daddr || !sport || !dport)
	return -1;
    
    // adjust the packet to add the FOU header - pointers to new header fields will be in p
    int orig_len = adjust_head_fou4(ctx, &p);

    if (orig_len < 0)
	return -1;


    if (p.vlan) {
	p.vlan->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IP);
    } else {
	p.eth->h_proto = bpf_htons(ETH_P_IP);
    }

    int udp_len = sizeof(struct udphdr) + orig_len;
    
    struct udphdr udp_new = { .source = bpf_htons(sport), .dest = bpf_htons(dport), .len = bpf_htons(udp_len) };
    struct udphdr *udp = (void *) (p.ip + 1);
    
    if (udp + 1 > (void *)(long)ctx->data_end)
	return -1;

    *udp = udp_new;

    // Update the outer IP header to send to the FOU target
    int tot_len = sizeof(struct iphdr) + udp_len;
    new_iphdr(p.ip, tot_len, IPPROTO_UDP, saddr, daddr);

    if (!nulmac(router)) {
	// If a router is explicitly indicated then direct the frame there
	memcpy(p.eth->h_source, p.eth->h_dest, 6);
	memcpy(p.eth->h_dest, router, 6);
    } else {
	// Otherwise return it to the device that it came from
	reverse_ethhdr(p.eth);
    }

    // some final sanity checks on ethernet addresses
    if (nulmac(p.eth->h_source) || nulmac(p.eth->h_dest))
	return -1;

    // Layer 3 services are only received on the same interface/VLAN as recieved, so we can simply TX
    return 0;
}
*/



/*
static __always_inline
int xin4_push(struct xdp_md *ctx, char *router, __be32 saddr, __be32 daddr, __u8 inner)
{
    struct pointers p = {};

    if (!saddr || !daddr)
	return -1;
    
    // adjust the packet to add the FOU header - pointers to new header fields will be in p
    int orig_len = adjust_head2_ipip4(ctx, &p);

    if (orig_len < 0)
	return -1;

    if (p.vlan) {
	p.vlan->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IP);
    } else {
	p.eth->h_proto = bpf_htons(ETH_P_IP);
    }
    
    // Update the outer IP header to send to the IPIP target
    int tot_len = sizeof(struct iphdr) + orig_len;
    new_iphdr(p.ip, tot_len, inner, saddr, daddr);
    
    if (!nulmac(router)) {
	// If a router is explicitly indicated then direct the frame there
	memcpy(p.eth->h_source, p.eth->h_dest, 6);
	memcpy(p.eth->h_dest, router, 6);
    } else {
	// Otherwise return it to the device that it came from 
	reverse_ethhdr(p.eth);
    }
    
    // some final sanity checks on ethernet addresses
    if (nulmac(p.eth->h_source) || nulmac(p.eth->h_dest))
	return -1;

    // Layer 3 services are only received on the same interface/VLAN as recieved, so we can simply TX
    return 0;
}
*/

/*
static __always_inline
int push_6in4(struct xdp_md *ctx, char *router, __be32 saddr, __be32 daddr)
{
    return xin4_push(ctx, router, saddr, daddr, IPPROTO_IPV6);
}
*/

/*
static __always_inline
int ipip_push(struct xdp_md *ctx, char *router, __be32 saddr, __be32 daddr)
{
    return xin4_push(ctx, router, saddr, daddr, IPPROTO_IPIP);
}
*/

/*

// struct in6_addr
static __always_inline
int fou6_push(struct xdp_md *ctx, unsigned char *router, struct in6_addr saddr, struct in6_addr daddr, __u16 sport, __u16 dport)
{
    struct pointers p = {};

    //if (!saddr || !daddr || !sport || !dport)
    if (!sport || !dport) // FIXME
	return -1;
    
    // adjust the packet to add the FOU header - pointers to new header fields will be in p
    int orig_len = adjust_head2_fou6(ctx, &p);

    if (orig_len < 0)
	return -1;

    struct ip6_hdr *new = (void *) p.ip;

    if (new + 1 > (void *)(long)ctx->data_end)
	return -1;
    
    
    if (p.vlan) {
	p.vlan->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IPV6);
    } else {
	p.eth->h_proto = bpf_htons(ETH_P_IPV6);
    }

    int udp_len = sizeof(struct udphdr) + orig_len;
    
    struct udphdr udp_new = { .source = bpf_htons(sport), .dest = bpf_htons(dport), .len = bpf_htons(udp_len), .check = 0 };
    struct udphdr *udp = (void *) (new + 1);
    
    if (udp + 1 > (void *)(long)ctx->data_end)
	return -1;

    *udp = udp_new;

    // Update the outer IP header to send to the FOU target
    //int tot_len = sizeof(struct ip6_hdr) + udp_len;
    new_ip6hdr(new, udp_len, IPPROTO_UDP, saddr, daddr);
    
    udp->check = udp6_checksum(new, udp, (void *)(long)ctx->data_end);

    bpf_printk("fou6 %d\n", udp_len);
    
    if (!nulmac(router)) {
	// If a router is explicitly indicated then direct the frame there
	memcpy(p.eth->h_source, p.eth->h_dest, 6);
	memcpy(p.eth->h_dest, router, 6);
    } else {
	// Otherwise return it to the device that it came from
	reverse_ethhdr(p.eth);
    }

    // some final sanity checks on ethernet addresses
    if (nulmac(p.eth->h_source) || nulmac(p.eth->h_dest))
	return -1;

    // Layer 3 services are only received on the same interface/VLAN as recieved, so we can simply TX
    return 0;
}
*/



/*
static __always_inline
int xin6_push(struct xdp_md *ctx, char *router, struct in6_addr saddr, struct in6_addr daddr, __u8 inner)
{
    struct pointers p = {};

    if (nul6(&saddr) || nul6(&daddr))
	return -1;
    
    // adjust the packet to add the FOU header - pointers to new header fields will be in p
    int orig_len = adjust_head_xin6(ctx, &p);

    if (orig_len < 0)
	return -1;

    if (p.vlan) {
	p.vlan->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IPV6);
    } else {
	p.eth->h_proto = bpf_htons(ETH_P_IPV6);
    }

    struct ip6_hdr *new = (void *) p.ip;

    if (new + 1 > (void *)(long)ctx->data_end)
	return -1;
    
    new_ip6hdr(new, orig_len, inner, saddr, daddr);
    
    if (!nulmac(router)) {
	// If a router is explicitly indicated then direct the frame there
	memcpy(p.eth->h_source, p.eth->h_dest, 6);
	memcpy(p.eth->h_dest, router, 6);
    } else {
	// Otherwise return it to the device that it came from
	reverse_ethhdr(p.eth);
    }
    
    // some final sanity checks on ethernet addresses
    if (nulmac(p.eth->h_source) || nulmac(p.eth->h_dest))
	return -1;
    
    // Layer 3 services are only received on the same interface/VLAN as recieved, so we can simply TX
    return 0;
}
*/



//static __always_inline
int xdp_fwd_func6(struct xdp_md *ctx, struct ethhdr *eth, struct vlan_hdr *vlan, struct ip6_hdr *ip6)
{
    struct destination dest = {};
    enum lookup_result result = NOT_A_VIP;

    /*
    void *data_end = (void *)(long)ctx->data_end;

    if (ip6 + 1 > data_end)
	return XDP_PASS;
    
    if ((ip6->ip6_ctlun.ip6_un2_vfc >> 4) != 6)
	return XDP_PASS;

    if(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6) {
	bpf_printk("IPv6 ICMP!\n");
	return XDP_PASS;
    }
    
    if(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP)
	return XDP_PASS;

    struct tcphdr *tcp = (void *) (ip6 + 1);

    if (tcp + 1 > data_end)
        return XDP_PASS;

    int x = bpf_ntohs(tcp->dest);
    
    bpf_printk("IPv6 TCP %d\n", x);
    
    result = lookup6(ip6, tcp, &dest);
    bpf_printk("HERE %d\n", result);
    */
    result = lookup6_(ctx, ip6, &dest);
    
    
    int overhead = is_ipv4_addr(dest.daddr) ? sizeof(struct iphdr) : sizeof(struct ip6_hdr);
    
    switch (result) {
    case LAYER3_GRE: overhead += GRE_OVERHEAD; break;
    case LAYER3_FOU: overhead += FOU_OVERHEAD; break;
    case LAYER3_GUE: overhead += GUE_OVERHEAD; break;
    case LAYER3_IPIP:
	break;
    case LAYER2_DSR:
	break;
    case NOT_A_VIP:
	return XDP_PASS;
    case NOT_FOUND:
        return XDP_DROP;
    }

    switch (result) {
    case LAYER3_GRE:
    case LAYER3_FOU:
    case LAYER3_GUE:
    case LAYER3_IPIP:
	
	if (check_ingress_interface(ctx->ingress_ifindex, vlan, dest.vlanid) < 0)
            return XDP_DROP;
	
	//if ((data_end - ((void *) ip)) + overhead > mtu)
        //    return send_frag_needed(ctx, dest.saddr.addr4.addr, mtu - overhead);
	
	break;

    default:
	break;
    }
    
    if (is_ipv4_addr(dest.daddr)) {
	switch (result) {
	case LAYER3_FOU:  return send_fou4(ctx, &dest); // IPv6 in FOU in IPv4 - works
	case LAYER3_IPIP: return send_6in4(ctx, &dest); // IPv6 in IPv4 - works
	case LAYER3_GRE:  return send_gre4(ctx, &dest, ETH_P_IPV6);
	case LAYER3_GUE:  return send_gue4(ctx, &dest, IPPROTO_IPV6);
	default:
	    break;
	}
    } else {	
	switch (result) {
	case LAYER3_FOU:  return send_fou6(ctx, &dest); // IPv6 in FOU in IPv6 - can't see how to decap this
	case LAYER3_IPIP: return send_6in6(ctx, &dest); // IPv6 in IPv6 - works
	case LAYER3_GRE:  return send_gre6(ctx, &dest, ETH_P_IPV6);
	case LAYER3_GUE:  return send_gue6(ctx, &dest, IPPROTO_IPV6);	    
	default:
	    break;
	}
    }
    

    return XDP_DROP;
}



// lookup request(192.168.0.3, 8889, tcp) -> { nat:10.255.0.4, eph:23456, time: 5s }
// does not match our nat addr/eph and is only 3s old - next
// ext_port = lock_xadd(rec->tcp, 1) (8890)
// lookup request(192.168.0.3, 8890, tcp) -> { nat:10.255.0.4, eph:23499, time: 65s }
// old connection - reuse

// lookup active(192.168.0.3, 8889, tcp) -> { nat:10.255.0.3, eph:12345, time: 3s }
// matches our nat addr/eph and is relatively recent - probably our keepalive conn
// ext_port = lock_xadd(rec->tcp, 1) (8890)

// not found at all - port is free to use

// write {192.168.0.3:80:tcp->a.b.c.d:8890} -> {10.255.0.4:80->10.255.255.254:12345 } to LRU reply map

// reply from 192.168.0.3:80:tcp -> a.b.c.d:8890
// reply(192.168.0.3:80:tcp->a.b.c.d:8890) -> { 10.255.0.4:80->10.255.255.254:12345 }

static __always_inline
int tunnel_request(addr_t ext_addr, __be16 ext_port, __u8 protocol, addr_t rip, __be16 service_port) {
    return 0;
}

int netns_side(addr_t *veth_, __be16 eph_port, __u8 protocol, addr_t *nat_, __be16 service_port) {

    //addr_t veth = *veth_;
    addr_t nat = *nat_;
    
    // check that veth is what we expect amd that nat is in the correct range ...
    
    addr_t *vip_rip = bpf_map_lookup_elem(&nat_to_vip_rip, &nat);
    
    if (!vip_rip)
	return -1;

    addr_t vip = vip_rip[0];
    addr_t rip = vip_rip[1];

    addr_t ext_addr = {}; // look this up
    __u64 ext_port = 0;

    for (int n = 0; n < 10; n++) {
    
	struct next_ports *ports = bpf_map_lookup_elem(&vip_port, &vip);
	
	if (!ports)
	    return -1;

	bpf_spin_lock(&(ports->semaphore));
	if((ext_port = ports->tcp++) < 2048)
	    ext_port = ports->tcp = 2048;
	bpf_spin_unlock(&(ports->semaphore));
	
	__u64 now = bpf_ktime_get_ns();

	struct three_tuple req = { .addr = vip, .port = ext_port, .protocol = protocol };
	struct addrport_time *foo = bpf_map_lookup_elem(&request, &req);

	if (!foo) {
	    // insert record - done
	    struct addrport_time fizz = {
					 .nat = nat,
					 .eph = eph_port,
					 .time = now,
	    };

	    if(bpf_map_update_elem(&request, &req, &fizz, BPF_NOEXIST) != 0)
		continue; // try again 
	    
	    break;
	}
	
	int ok = 0;
	
	{ 
	    bpf_spin_lock(&(foo->semaphore)); // start of critical section
	    
	    
	    if ((now - foo->time) > (60 * SECOND_NS)) {
		// lease expired
		ok = 1;
		
		foo->nat = nat;
		foo->eph = eph_port;
		foo->time = now;
		
	    } else if (0) { // if (nat == foo->nat && eph == foo->eph)
		// our connection - update lease
		ok = 1;
		foo->time = now;
	    } else {
		// not today - try again
	    }
	    
	    bpf_spin_unlock(&(foo->semaphore)); // end of critical section
	}
	
	if (ok)
	    break;
    }

    // store reply mapping

    // write {192.168.0.3:80:tcp->a.b.c.d:8890} -> {10.255.0.4:80->10.255.255.254:12345 } to LRU reply m 
    
    struct five_tuple bar = {
			     .saddr = vip,
			     .sport = service_port,
			     .protocol = protocol,
			     .daddr = ext_addr,
			     .dport = ext_port,
    };

    struct addr_port_time baz = {
			    .addr = nat,
			    .port = eph_port,
    };

    bpf_map_update_elem(&reply, &bar, &baz, BPF_ANY);

    // send request
    return tunnel_request(ext_addr, bpf_htons(ext_port), protocol, rip, service_port);
}

/*
int netns_side3(addr_t *veth_, __be16 eph_port, __u8 protocol, addr_t *nat_, __be16 service_port) {

    //addr_t veth = *veth_;
    addr_t nat = *nat_;
    
    // check that veth is what we expect amd that nat is in the correct range ...
    
    addr_t *vip_rip = bpf_map_lookup_elem(&nat_to_vip_rip, &nat);
    
    if (!vip_rip)
	return -1;

    addr_t vip = vip_rip[0];
    addr_t rip = vip_rip[1];

    addr_t ext_addr = {}; // look this up
    __u64 ext_port = eph_port;

    
    struct five_tuple bar = {
			     .saddr = vip,
			     .sport = service_port,
			     .protocol = protocol,
			     .daddr = ext_addr,
			     .dport = ext_port,
    };

    struct addr_port baz = {
			    .addr = nat,
			    .port = eph_port,
    };

    bpf_map_update_elem(&reply, &bar, &baz, BPF_ANY);
    
}
*/

// nat:nport:vip:vport:protocol -> ext-port (external addr is fixed)

/*
  PROCEDURE:
  
  Outgoing:
  * map from VIP/RIP to NAT address (userspace)
  * open connection to NAT/service-port/protocol from 10.255.255.254/::0aff:fffe in netns("outside")
  * "inside" XDP sees request from ns-addr:ephemeral-port:protocol to nat-addr:service-port:protocol
  * lookup (ns-addr:ephemeral-port:nat-addr:service-port:protocol) -> (vip:ext-port)
  *   not-found: * lookup vip_port(vip)->{ext-port}, lock, test vip:extport:protocol-> naddr:eph-port:vport:time match ephemeral-port
  *              * increment proto-port try again, 100x, if fail then drop
  *              * write vip:extport:protocol-> ephemeral-port:now
  
  Incoming:
  * check vip matches our ext addr (dest of packet)
  * lookup vip_port(vip:extport:protocol) if not found then drop, otheriwse:
  * * ephemeral-port:vport:time -> rewrite as src-addr->nat-addr, src-port unchanged, dst-addr->ns-addr, dst-port->eph-port

  */


/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)

#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

lock_xadd(&rec->rx_packets, 1);

 */


// netns: 10.255.255.254:12345:tcp -> 10.255.0.3:80 (for vip 192.168.0.3/10.1.2.3)
// lookup vip: nat_to_vip(10.255.0.3) -> {  vip:192.168.0.3, rip:10.1.2.3 }
// lookup vip_port(192.168.0.3)->{ tcp:8888, udp:3333 }
// ext_port = lock_xadd(rec->tcp, 1) (8889)

struct addrport_time {
    struct bpf_spin_lock semaphore;
    addr_t nat;
    __be16 eph;
    __u64 time;
};

struct next_ports {
    struct bpf_spin_lock semaphore;
    uint64_t tcp;
    uint64_t udp;
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // physical NIC
    __type(value, __u32); // VLAN ID
    __uint(max_entries, 4096);
} nic_to_vlanid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct addr); // NAT address
    __type(value, struct nat_info); // has VLAN ID to use to send probe, dst MAC for L2
    __uint(max_entries, 65536);
} nat_info SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct addr); // VIP
    __type(value, struct next_ports); // ports
    __uint(max_entries, 4096); // maximum number of VIPs
} vip_port SEC(".maps");




/*
https://datatracker.ietf.org/doc/html/draft-ietf-nvo3-geneve-08#section-3.1

Basically everything can be zeo except for protocol and VNI

      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |        Virtual Network Identifier (VNI)       |    Reserved   |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                    Variable Length Options                    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

inside UDP, followed payload described by Protocol Type

   Protocol Type (16 bits):  The type of the protocol data unit
      appearing after the Geneve header.  This follows the EtherType
      [ETYPES] convention with Ethernet itself being represented by the
      value 0x6558.

https://www.redhat.com/en/blog/what-geneve
https://developers.redhat.com/blog/2019/05/17/an-introduction-to-linux-virtual-interfaces-tunnels#geneve
# ip link add name geneve0 type geneve id VNI remote REMOTE_IPv4_ADDR

*/


// very experimental - likely not useful just yet
//static __always_inline
int push_geneve4(struct xdp_md *ctx, unsigned char *router, tunnel_t *t, __u16 protocol)
{
    struct pointers p = {};
    //int orig_len = push_xin4(ctx, &p, router, t->saddr.addr4.addr, t->daddr.addr4.addr, IPPROTO_UDP, GENEVE_OVERHEAD);
    int orig_len = push_xin4_(ctx, &p, router, t->saddr, t->daddr, IPPROTO_UDP, GENEVE_OVERHEAD);

    if (orig_len < 0)
	return -1;

    struct udphdr *udp = (void *) (p.ip + 1);

    if (udp + 1 > (void *)(long)ctx->data_end)
        return -1;

    udp->source = bpf_htons(t->sport);
    udp->dest = bpf_htons(t->dport); // registered port is 6801
    udp->len = bpf_htons(GENEVE_OVERHEAD + orig_len);
    udp->check = 0;

    __u32 vni = 9999;
    
    struct geneve_hdr geneve = { .vni = bpf_htonl((vni & 0x00ffffff)<<8),  .protocol = bpf_htons(0x6558) };
    struct geneve_hdr *g = (void *) (udp + 1);
    
    if (g + 1 > (void *)(long)ctx->data_end)
	return -1;

    *g = geneve;

    struct ethhdr *eth = (void *) (g + 1);

    if (eth + 1 > (void *)(long)ctx->data_end)
        return -1;

    // just copy the same hw addrs into the inner frame, bit of a fudge
    memcpy(eth->h_dest, p.eth->h_dest, 6);
    memcpy(eth->h_source, p.eth->h_source, 6);
    eth->h_proto = bpf_htons(protocol);
    
    if (! t->nochecksum)
	udp->check = udp4_checksum((void *) p.ip, udp, (void *)(long)ctx->data_end);

    return 0;
}

static __always_inline
int send_geneve(struct xdp_md *ctx, tunnel_t *t, __u16 protocol)
{
    if (is_addr4(&(t->daddr)))
	return push_geneve4(ctx, t->hwaddr, t, protocol) < 0 ? XDP_ABORTED : XDP_TX;
    
    return XDP_ABORTED;
}

