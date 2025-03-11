struct pointers {
    struct ethhdr *eth, eth_copy;
    struct vlan_hdr *vlan, vlan_copy;
    struct iphdr *ip, ip_copy;
};




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

int preserve_headers(struct xdp_md *ctx, struct pointers *p)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    p->vlan = NULL;
    
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



int restore_headers(struct xdp_md *ctx, struct pointers *p)
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

    *(p->eth) = p->eth_copy;
    if (p->vlan) *(p->vlan) = p->vlan_copy;
    *(p->ip) = p->ip_copy;
    
    return 0;
}


static __always_inline
__u16 csum_fold_helper(__u32 csum)
{
    __u32 sum;
    sum = (csum >> 16) + (csum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

static __always_inline
int ip_decrease_ttl(struct iphdr *ip)
{
    __u32 check = ip->check;
    check += bpf_htons(0x0100);
    ip->check = (__u16)(check + (check >= 0xFFFF));
    return --(ip->ttl);
}

static __always_inline
__u16 ipv4_checksum(struct iphdr *ip)
{
    __u32 size = sizeof(struct iphdr);
    __u32 csum = bpf_csum_diff((__be32 *) ip, 0, (__be32 *) ip, size, 0);
    return csum_fold_helper(csum);
}


static __always_inline
__u16 icmp_checksum(struct icmphdr *icmp, __u16 size)
{
    __u32 csum = bpf_csum_diff((__be32 *) icmp, 0, (__be32 *) icmp, size, 0);
    return csum_fold_helper(csum);
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

static __always_inline
void new_iphdr(struct iphdr *ip, __u16 tot_len, __u8 protocol, __be32 saddr, __be32 daddr)
{
    struct iphdr i = {};
    //*ip = i;

    memcpy(ip, &i, sizeof(struct iphdr));
    
    ip->version = 4;
    ip->ihl = 5;
    // DSCP ECN leave as 0
    ip->tot_len = bpf_htons(tot_len);

    ip->id = bpf_ktime_get_ns() & 0xffff;
    // flags - DF?
    // fragmentation offset - 0
    
    ip->ttl = 64;
    ip->protocol = protocol;
    ip->check = 0;
    
    ip->saddr = saddr;
    ip->daddr = daddr;
    
    ip->check = ipv4_checksum(ip);
}

static __always_inline
void reverse_ethhdr(struct ethhdr *eth)
{
    char temp[6];
    memcpy(temp, eth->h_dest, 6);
    memcpy(eth->h_dest, eth->h_source, 6);
    memcpy(eth->h_source, temp, 6);
}

static __always_inline
int nulmac(unsigned char *mac)
{
    return (!mac[0] && !mac[1] && !mac[2] && !mac[3] && !mac[4] && !mac[5]);
}




const __u8 FOU4_OVERHEAD = sizeof(struct iphdr) + sizeof(struct udphdr);
const __u8 IPIP_OVERHEAD = sizeof(struct iphdr);

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


static __always_inline
int frag_needed_trim(struct xdp_md *ctx, struct pointers *p)
{
    const int max = 128;
    void *data_end = (void *)(long)ctx->data_end;
        
    if (preserve_headers(ctx, p) < 0)
	return -1;

    /* if DF is not set then drop */
    if (!IS_DF(p->ip->frag_off))
	return -1;
    
    int iplen = data_end - (void *)(p->ip);

    /* if a packet was smaller than "max" bytes then it should not have been too big - drop */
    if (iplen < max)
      return -1;
    
    // DELIBERATE BREAKAGE
    p->ip->daddr = 0; // prevent the ICMP from changing the path MTU whilst testing
    
    /* truncate the packet if > max bytes (it could of course be exactly max bytes) */
    if (iplen > max && bpf_xdp_adjust_tail(ctx, 0 - (int)(iplen - max)))
	return -1;
    
    /* extend header - extra ip and icmp needed*/
    if (bpf_xdp_adjust_head(ctx, 0 - (int)(sizeof(struct iphdr) + sizeof(struct icmphdr))))	
	return -1;

    if (restore_headers(ctx, p) < 0)	
        return -1;

    return max;
}



static __always_inline
int frag_needed(struct xdp_md *ctx, __be32 saddr, __u16 mtu, __u8 *buffer)
{
    // FIXME: checksum doesn't work for much larger packets, unsure why - keep the size down for now
    // maybe the csum_diff helper has a bounded loop and needs to be invoked mutiple times?
    struct pointers p = {};
    int iplen;
    
    //if ((iplen = frag_needed_trim(ctx, &p, max)) < 0)
    if ((iplen = frag_needed_trim(ctx, &p)) < 0)	
	return -1;

    void *data_end = (void *)(long)ctx->data_end;
    struct icmphdr *icmp = (void *)(p.ip + 1);
    
    if (icmp + 1 > data_end)
	return -1;

    reverse_ethhdr(p.eth);

    // reply to client with LB's address
    // FIXME - how will the above work behind NAT?
    // 1) 2nd address stored only used for replying to client
    // 2) static NAT entry for LB -> outside world
    // 3) dynamic NAT pool
    // 4) larger internal MTU
    // ensure DEST_UNREACH/FRAG_NEEDED is allowed out
    // ensure DEST_UNREACH/FRAG_NEEDED is also allowed in to prevent MTU blackholes
    // respond to every occurence or keep a record of recent notifications?

    //p.ip->daddr = p.ip->saddr;
    //p.ip->saddr = saddr;
    //sanitise_iphdr(p.ip, sizeof(struct iphdr) + sizeof(struct icmphdr) + iplen, IPPROTO_ICMP);
    int tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + iplen;
    new_iphdr(p.ip, tot_len, IPPROTO_ICMP, saddr, p.ip->saddr); // source becomes LB's IP, destination is theclient

    struct icmphdr fou = { .type = ICMP_DEST_UNREACH, .code = ICMP_FRAG_NEEDED, .checksum = 0, .un.frag.mtu = bpf_htons(mtu) };
    *icmp = fou;

    ((__u8 *) icmp)[5] = ((__u8)(iplen >> 2)); // struct icmphdr lacks a length field

    //if (!(buffer = bpf_map_lookup_elem(&buffers, &ZERO)))
    //return -1;
    
    for (__u16 n = 0; n < sizeof(struct icmphdr) + iplen; n++) {
	if (((void *) icmp) + n >= data_end)
            break;
	((__u8 *) buffer)[n] = ((__u8 *) icmp)[n]; // copy original IP packet to buffer
    }

    /* calulate checksum over the entire icmp packet + payload (copied to buffer) */
    icmp->checksum = icmp_checksum((struct icmphdr *) buffer, sizeof(struct icmphdr) + iplen);

    return 0;
}


static __always_inline
__u16 sdbm(unsigned char *ptr, __u8 len)
{
    unsigned long hash = 0;
    unsigned char c;
    unsigned int n;

    for(n = 0; n < len; n++) {
        c = ptr[n];
        hash = c + (hash << 6) + (hash << 16) - hash;
    }

    return hash & 0xffff;
}


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

int preserve_l2_headers(struct xdp_md *ctx, struct pointers *p)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    p->vlan = NULL;
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
    //p->ip_copy = *(p->ip);
    
     return 0;
}

int restore_l2_headers(struct xdp_md *ctx, struct pointers *p)
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

    *(p->eth) = p->eth_copy;
    if (p->vlan) *(p->vlan) = p->vlan_copy;
    //*(p->ip) = p->ip_copy;
    
    return 0;
}

static __always_inline
int adjust_head2(struct xdp_md *ctx, struct pointers *p, int overhead)
//int adjust_head(struct xdp_md *ctx, struct pointers *p, int overhead, int payload_header_len)
{
    if (preserve_l2_headers(ctx, p) < 0)
	return -1;

    void *data_end = (void *)(long)ctx->data_end;
    int orig_len = data_end - (void *) p->ip;
    
    //if (sizeof(struct iphdr) > overhead)
    //return -1;
    
    /* Insert space for new headers at the start of the packet */
    if (bpf_xdp_adjust_head(ctx, 0 - overhead))
	return -1;
    
    /* After bpf_xdp_adjust_head we need to re-calculate all of the header pointers  and restore contents */
    if (restore_l2_headers(ctx, p) < 0)
	return -1;

    return orig_len;
}

static __always_inline
int adjust_head2_fou4(struct xdp_md *ctx, struct pointers *p)
{
    //return adjust_head(ctx, p, FOU4_OVERHEAD, sizeof(struct udphdr));
    return adjust_head2(ctx, p, FOU4_OVERHEAD);
}

static __always_inline
int adjust_head2_ipip4(struct xdp_md *ctx, struct pointers *p)
{
    //return adjust_head(ctx, p, IPIP_OVERHEAD, 0);
    return adjust_head2(ctx, p, IPIP_OVERHEAD);
}




static __always_inline
int fou4_push2(struct xdp_md *ctx, unsigned char *router, __be32 saddr, __be32 daddr, __u16 sport, __u16 dport)
{
    struct pointers p = {};

    if (!saddr || !daddr || !sport || !dport)
	return -1;
    
    /* adjust the packet to add the FOU header - pointers to new header fields will be in p */
    int orig_len = adjust_head2_fou4(ctx, &p);

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

    /* Update the outer IP header to send to the FOU target */
    int tot_len = sizeof(struct iphdr) + udp_len;
    new_iphdr(p.ip, tot_len, IPPROTO_UDP, saddr, daddr);

    //*udp = udp_new;

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





static __always_inline
int xin4_push(struct xdp_md *ctx, char *router, __be32 saddr, __be32 daddr, __u8 inner)
{
    struct pointers p = {};

    if (!saddr || !daddr)
	return -1;
    
    /* adjust the packet to add the FOU header - pointers to new header fields will be in p */
    int orig_len = adjust_head2_ipip4(ctx, &p);

    if (orig_len < 0)
	return -1;

    if (p.vlan) {
	p.vlan->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IP);
    } else {
	p.eth->h_proto = bpf_htons(ETH_P_IP);
    }
    
    /* Update the outer IP header to send to the IPIP target */
    int tot_len = sizeof(struct iphdr) + orig_len;
    new_iphdr(p.ip, tot_len, inner, saddr, daddr);
    
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
int sit_push(struct xdp_md *ctx, char *router, __be32 saddr, __be32 daddr)
{
    return xin4_push(ctx, router, saddr, daddr, IPPROTO_IPV6);
}

static __always_inline
int ipip_push(struct xdp_md *ctx, char *router, __be32 saddr, __be32 daddr)
{
    return xin4_push(ctx, router, saddr, daddr, IPPROTO_IPIP);
}




