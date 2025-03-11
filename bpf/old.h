

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

