struct pointers {
    struct ethhdr *eth, eth_copy;
    struct vlan_hdr *vlan, vlan_copy;
    struct iphdr *ip, ip_copy;
};


struct gre_hdr {
    __be16 crv;
    __be16 protocol;
    //__be16 checksum;
    //__be16 reserved;
};

struct gue_hdr {
    __u8 variant : 1;
    __u8 control : 1;
    __u8 hlen    : 6;
    __u8 protocol;
    __be16 flags;
};


struct geneve_hdr {
    __u8 ver : 2;
    __u8 opt_len : 6;
    
    __u8 oam : 1;
    __u8 critical : 1;
    __u8 resvd : 6;

    __be16 protocol;

    __be32 vni;// : 24;
    //__be32 reserved : 8;
};

const __u8 GRE_OVERHEAD = sizeof(struct gre_hdr);
const __u8 FOU_OVERHEAD = sizeof(struct udphdr);
const __u8 GUE_OVERHEAD = sizeof(struct udphdr) + sizeof(struct gue_hdr);
const __u8 GENEVE_OVERHEAD = sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct geneve_hdr);

static __always_inline
int nul6(struct in6_addr *a) 
{
    __u32 *p = (void*) a;
    if (*(p++) != 0) return 0;
    if (*(p++) != 0) return 0;
    if (*(p++) != 0) return 0;
    if (*(p++) != 0) return 0;
    return 1;
}

#define CRV 0x0080 // NBO

static __always_inline
__u16 csum_fold_helper(__u32 csum)
{
    __u32 sum;
    sum = (csum >> 16) + (csum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

static __always_inline
__u16 ipv4_checksum_diff(__u16 seed, struct iphdr *new, struct iphdr *old)
{
    __u32 csum, size = sizeof(struct iphdr);   
    csum = bpf_csum_diff((__be32 *)old, size, (__be32 *)new, size, seed);
    return csum_fold_helper(csum);
}


struct l4 {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};

static __always_inline __u16
l4_checksum_diff(__u16 seed, struct l4 *new, struct l4 *old) {
    __u32 csum, size = sizeof(struct l4);
    csum = bpf_csum_diff((__be32 *)old, size, (__be32 *)new, size, seed);
    return csum_fold_helper(csum);
}


static __always_inline
__u16 internet_checksum(void *data, void *data_end, __u32 csum)
{
    __u16 *p = data;
    
    for (int n = 0; n < MTU; n += 2) {
	if (p + 1 > data_end)
	    break;
	csum += *p;
	p++;
    }

    if (((void *) p) + 1 <= data_end) {
	csum += *((__u8 *) p);
    }

    return csum_fold_helper(csum);
}

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
    
    return 0;
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


/*
static __always_inline
__u16 icmp_checksum(struct icmphdr *icmp, __u16 size)
{
    __u32 csum = bpf_csum_diff((__be32 *) icmp, 0, (__be32 *) icmp, size, 0);
    return csum_fold_helper(csum);
}
*/

static __always_inline
void new_iphdr(struct iphdr *ip, __u16 tot_len, __u8 protocol, __be32 saddr, __be32 daddr)
{
    struct iphdr i = {};
    *ip = i;
    
    ip->version = 4;
    ip->ihl = 5;
    // DSCP ECN leave as 0
    ip->tot_len = bpf_htons(tot_len);

    ip->id = bpf_ktime_get_ns() & 0xffff;
    ip->frag_off = bpf_htons(0x4000); // only DF flag set, fragmentation offset to 0
    
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

static __always_inline
int frag_needed_trim(struct xdp_md *ctx, struct pointers *p)
{
    const int max = 128;
    void *data_end = (void *)(long)ctx->data_end;
        
    if (preserve_l2_headers(ctx, p) < 0)
	return -1;

    // if DF is not set then drop
    if (!IS_DF(p->ip->frag_off))
	return -1;
    
    int iplen = data_end - (void *)(p->ip);

    // if a packet was smaller than "max" bytes then it should not have been too big - drop
    if (iplen < max)
      return -1;
    
    // DELIBERATE BREAKAGE
    p->ip->daddr = 0; // prevent the ICMP from changing the path MTU whilst testing
    
    // truncate the packet if > max bytes (it could of course be exactly max bytes)
    if (iplen > max && bpf_xdp_adjust_tail(ctx, 0 - (int)(iplen - max)))
	return -1;
    
    // extend header - extra ip and icmp needed
    if (bpf_xdp_adjust_head(ctx, 0 - (int)(sizeof(struct iphdr) + sizeof(struct icmphdr))))	
	return -1;

    if (restore_l2_headers(ctx, p) < 0)	
        return -1;

    return max;
}



static __always_inline
int frag_needed4(struct xdp_md *ctx, __be32 saddr, __u16 mtu, __u8 *buffer)
{
    struct pointers p = {};
    int iplen;
    
    if ((iplen = frag_needed_trim(ctx, &p)) < 0)	
	return -1;

    void *data_end = (void *)(long)ctx->data_end;
    struct icmphdr *icmp = (void *)(p.ip + 1);
    
    if (icmp + 1 > data_end)
	return -1;

    reverse_ethhdr(p.eth);

    int tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + iplen;
    new_iphdr(p.ip, tot_len, IPPROTO_ICMP, saddr, p.ip->saddr); // source becomes LB's IP, destination is the client

    // reply to client with LB's address
    // ensure DEST_UNREACH/FRAG_NEEDED is allowed out
    // ensure DEST_UNREACH/FRAG_NEEDED is also allowed in to prevent MTU blackholes
    // respond to every occurence or keep a record of recent notifications?
    
    struct icmphdr fou = { .type = ICMP_DEST_UNREACH, .code = ICMP_FRAG_NEEDED, .checksum = 0, .un.frag.mtu = bpf_htons(mtu) };
    *icmp = fou;

    ((__u8 *) icmp)[5] = ((__u8)(iplen >> 2)); // struct icmphdr lacks a length field

    icmp->checksum = internet_checksum(icmp, data_end, 0);

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





static __always_inline
int redirect_eth(struct xdp_md *ctx, __u8 *dest)
{
    struct pointers p = {};
    
    if (preserve_l2_headers(ctx, &p) < 0)
	return -1;
    
    memcpy(p.eth->h_source, p.eth->h_dest, 6);
    memcpy(p.eth->h_dest, dest, 6);

    if (nulmac(p.eth->h_source) || nulmac(p.eth->h_dest))
	return -1;

    return 0;
}


static __always_inline
int adjust_head(struct xdp_md *ctx, struct pointers *p, int overhead)
{
    if (preserve_l2_headers(ctx, p) < 0)
	return -1;

    void *data_end = (void *)(long)ctx->data_end;
    int orig_len = data_end - (void *) p->ip;
    
    // Insert space for new headers before the start of the packet
    if (bpf_xdp_adjust_head(ctx, 0 - overhead))
	return -1;
    
    // After bpf_xdp_adjust_head we need to re-calculate the header pointers and restore contents
    if (restore_l2_headers(ctx, p) < 0)
	return -1;

    return orig_len;
}

static __always_inline
__u16 udp4_checksum(struct iphdr *ip, struct udphdr *udp, void *data_end)
{
    __u32 csum = 0;
    struct {
	__be32 saddr;
	__be32 daddr;
	__u8 pad;
	__u8 protocol;
	__be16 len;
    } ph = { .saddr = ip->saddr, .daddr = ip->daddr, .protocol = IPPROTO_UDP, .len = udp->len};

    __u16 *p = (void *) &ph;
    for (int n = 0; n < 6; n++) {
        csum += *(p++);
    }
    
    return internet_checksum(udp, data_end, csum);
}

static __always_inline
__u16 udp6_checksum(struct ip6_hdr *ip6, void *l4, void *data_end) {
    __u32 csum = 0;
    __u16 *p = (void *) &(ip6->ip6_src);

    for (int n = 0; n < 16; n++) {
	csum += *(p++);
    }

    csum += bpf_htons(data_end - l4); // upper 16 bits are zero so a no-op
    csum += bpf_htons(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt); // also a no-op
    csum = internet_checksum(l4, data_end, csum);

    // https://www.ietf.org/rfc/rfc2460.txt 8.1 - if csum is 0 then 0xffff must be used
    return csum ? csum : 0xffff;
}

static __always_inline
void new_ip6hdr(struct ip6_hdr *ip, __u16 payload_len, __u8 protocol, struct in6_addr saddr, struct in6_addr daddr)
{
    struct ip6_hdr i = {};
    *ip = i;
    
    ip->ip6_ctlun.ip6_un2_vfc = 0x6 << 4; // empty TC and flow label for now
    ip->ip6_ctlun.ip6_un1.ip6_un1_plen =  bpf_htons(payload_len);
    ip->ip6_ctlun.ip6_un1.ip6_un1_nxt = protocol;
    ip->ip6_ctlun.ip6_un1.ip6_un1_hlim = 64;
    
    ip->ip6_src = saddr;
    ip->ip6_dst = daddr;
}

static __always_inline
//int push_xin4(struct xdp_md *ctx, tunnel_t *t, struct pointers *p, unsigned char *router, __be32 saddr, __be32 daddr, __u8 protocol, int overhead)
int push_xin4(struct xdp_md *ctx, tunnel_t *t, struct pointers *p, __u8 protocol, int overhead)
{

    __be32 saddr = t->saddr.addr4.addr;
    __be32 daddr = t->daddr.addr4.addr;
    unsigned char *router = t->h_dest;
    
    if (!saddr || !daddr)
	return -1;
    
    // adjust the packet to add the FOU header - pointers to new header fields will be in p
    int orig_len = adjust_head(ctx, p, sizeof(struct iphdr) + overhead);
    
    if (orig_len < 0)
	return -1;

    if (p->vlan) {
	p->vlan->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IP);
    } else {
	p->eth->h_proto = bpf_htons(ETH_P_IP);
    }

    void *payload = (void *) (p->ip + 1);
    
    if (payload + overhead > (void *)(long)ctx->data_end)
	return -1;
    
    // Update the outer IP header to send to the FOU target
    int tot_len = sizeof(struct iphdr) + overhead + orig_len;
    new_iphdr(p->ip, tot_len, protocol, saddr, daddr);

    if (!nulmac(router)) {
	// If a router is explicitly indicated then direct the frame there
	memcpy(p->eth->h_source, p->eth->h_dest, 6);
	memcpy(p->eth->h_dest, router, 6);
    } else {
	// Otherwise return it to the device that it came from
	reverse_ethhdr(p->eth);
    }

    // some final sanity checks on ethernet addresses
    if (nulmac(p->eth->h_source) || nulmac(p->eth->h_dest))
	return -1;

    // Layer 3 services are only received on the same interface/VLAN as recieved, so we can simply TX
    return orig_len;
}


static __always_inline
int push_gre4(struct xdp_md *ctx,  tunnel_t *t, __u16 protocol)
{
    struct pointers p = {};
    
    //if (push_xin4(ctx,t,  &p, router, t->saddr.addr4.addr, t->daddr.addr4.addr, IPPROTO_GRE, sizeof(struct gre_hdr)) < 0)
    if (push_xin4(ctx,t,  &p, IPPROTO_GRE, sizeof(struct gre_hdr)) < 0)	
	return -1;

    struct gre_hdr *gre = (void *) (p.ip + 1);

    if (gre + 1 > (void *)(long)ctx->data_end)
        return -1;
    
    gre->crv = 0;
    gre->protocol = bpf_htons(protocol);
        
    return 0;
}

static __always_inline
int push_ipip(struct xdp_md *ctx, tunnel_t *t)
{
    struct pointers p = {};
    //return push_xin4(ctx, t, &p, router, t->saddr.addr4.addr, t->daddr.addr4.addr, IPPROTO_IPIP, 0);
    return push_xin4(ctx, t, &p, IPPROTO_IPIP, 0);
}


static __always_inline
//int push_6in4(struct xdp_md *ctx, char *router, tunnel_t *t)
int push_6in4(struct xdp_md *ctx, tunnel_t *t)    
{
    struct pointers p = {};
    //return push_xin4(ctx, t, &p, router, t->saddr.addr4.addr, t->daddr.addr4.addr, IPPROTO_IPV6, 0);
    return push_xin4(ctx, t, &p, IPPROTO_IPV6, 0);
}


static __always_inline
//int push_xin6(struct xdp_md *ctx, struct pointers *p, unsigned char *router, struct in6_addr saddr, struct in6_addr daddr, __u8 protocol, unsigned int overhead)
int push_xin6(struct xdp_md *ctx, tunnel_t *t, struct pointers *p, __u8 protocol, unsigned int overhead)
{

    struct in6_addr saddr = t->saddr.addr6;
    struct in6_addr daddr = t->daddr.addr6;
    unsigned char *router = t->h_dest;
    
    if (nul6(&saddr) || nul6(&daddr))
    	return -1;
    
    // adjust the packet to add the FOU header - pointers to new header fields will be in p
    int orig_len = adjust_head(ctx, p, sizeof(struct ip6_hdr) + overhead);
    
    if (orig_len < 0)
	return -1;

    if (p->vlan) {
	p->vlan->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IPV6);
    } else {
	p->eth->h_proto = bpf_htons(ETH_P_IPV6);
    }

    struct ip6_hdr *new = (void *) p->ip;

    void *data_end = (void *)(long)ctx->data_end;
    
    if (new + 1 > data_end)
        return -1;
    
    // Update the outer IP header to send to the FOU target
    int payload_len = overhead + orig_len;
    new_ip6hdr(new, payload_len, protocol, saddr, daddr);

    if (!nulmac(router)) {
	// If a router is explicitly indicated then direct the frame there
	memcpy(p->eth->h_source, p->eth->h_dest, 6);
	memcpy(p->eth->h_dest, router, 6);
    } else {
	// Otherwise return it to the device that it came from
	reverse_ethhdr(p->eth);
    }

    // some final sanity checks on ethernet addresses
    if (nulmac(p->eth->h_source) || nulmac(p->eth->h_dest))
	return -1;

    // Layer 3 services are only received on the same interface/VLAN as recieved, so we can simply TX
    return orig_len;
}


//static __always_inline
int push_6in6(struct xdp_md *ctx, tunnel_t *t)
{
    struct pointers p = {};
    //return push_xin6(ctx, &p, router, t->saddr.addr6, t->daddr.addr6, IPPROTO_IPV6, 0);
    return push_xin6(ctx, t, &p, IPPROTO_IPV6, 0);
}

//static __always_inline
int push_4in6(struct xdp_md *ctx, tunnel_t *t)
{
    //struct pointers p = {};
    //return push_xin6(ctx, &p, router, t->saddr.addr6, t->daddr.addr6, IPPROTO_IPIP, 0);
    return -1;
}


//static __always_inline
int push_gre6(struct xdp_md *ctx,  tunnel_t *t, __u16 protocol)
{
    struct pointers p = {};
    
    //int orig_len = push_xin6(ctx, &p, router, t->saddr.addr6, t->daddr.addr6, IPPROTO_GRE, sizeof(struct gre_hdr));
    int orig_len = push_xin6(ctx, t, &p, IPPROTO_GRE, sizeof(struct gre_hdr));

    if (orig_len < 0)
	return -1;

    struct gre_hdr *gre = (void *) ((struct ip6_hdr *) p.ip + 1);

    if (gre + 1 > (void *)(long)ctx->data_end)
    	return -1;

    gre->crv = 0;
    gre->protocol = bpf_htons(protocol);
    
    return 0;
}

//static __always_inline
int push_fou6(struct xdp_md *ctx,  tunnel_t *t)
{
    struct pointers p = {};
    
    //int orig_len = push_xin6(ctx, &p, router, t->saddr.addr6, t->daddr.addr6, IPPROTO_UDP, sizeof(struct udphdr));
    int orig_len = push_xin6(ctx, t, &p, IPPROTO_UDP, sizeof(struct udphdr));
    
    if (orig_len < 0)
        return -1;

    struct udphdr *udp = (void *) ((struct ip6_hdr *) p.ip + 1);

    if (udp + 1 > (void *)(long)ctx->data_end)
        return -1;

    udp->source = bpf_htons(t->sport);
    udp->dest = bpf_htons(t->dport);
    udp->len = bpf_htons(sizeof(struct udphdr) + orig_len);
    udp->check = 0;
    
    if (! t->nochecksum)
	udp->check = udp6_checksum((void *) p.ip, udp, (void *)(long)ctx->data_end);
    
    return 0;
}


//static __always_inline
int push_fou4(struct xdp_md *ctx,  tunnel_t *t)
{
    struct pointers p = {};
    //int orig_len = push_xin4(ctx, t, &p, router, t->saddr.addr4.addr, t->daddr.addr4.addr, IPPROTO_UDP, sizeof(struct udphdr));
    int orig_len = push_xin4(ctx, t, &p, IPPROTO_UDP, sizeof(struct udphdr));

    if (orig_len < 0)
	return -1;

    struct udphdr *udp = (void *) (p.ip + 1);

    if (udp + 1 > (void *)(long)ctx->data_end)
        return -1;

    udp->source = bpf_htons(t->sport);
    udp->dest = bpf_htons(t->dport);
    udp->len = bpf_htons(sizeof(struct udphdr) + orig_len);
    udp->check = 0;
    
    if (! t->nochecksum)
	udp->check = udp4_checksum((void *) p.ip, udp, (void *)(long)ctx->data_end);

    return 0;
}

//static __always_inline
int push_gue6(struct xdp_md *ctx,  tunnel_t *t, __u8 protocol)
{
    struct pointers p = {};
    
    //int orig_len = push_xin6(ctx, &p, router, t->saddr.addr6, t->daddr.addr6, IPPROTO_UDP, sizeof(struct udphdr) + sizeof(struct gue_hdr));
    int orig_len = push_xin6(ctx, t, &p, IPPROTO_UDP, sizeof(struct udphdr) + sizeof(struct gue_hdr));
    
    if (orig_len < 0)
        return -1;

    struct udphdr *udp = (void *) ((struct ip6_hdr *) p.ip + 1);

    if (udp + 1 > (void *)(long)ctx->data_end)
        return -1;

    udp->source = bpf_htons(t->sport);
    udp->dest = bpf_htons(t->dport);
    udp->len = bpf_htons(sizeof(struct udphdr) + sizeof(struct gue_hdr) + orig_len);
    udp->check = 0;

     struct gue_hdr *gue = (void *) (udp + 1);

    if (gue + 1 > (void *)(long)ctx->data_end)
        return -1;

    *((__be32 *) gue) = 0;

    //bpf_printk("GUE6 %d\n", protocol);

    gue->protocol = protocol;
    
    if (! t->nochecksum)
	udp->check = udp6_checksum((void *) p.ip, udp, (void *)(long)ctx->data_end);
    
    return 0;
}


//static __always_inline
int push_gue4(struct xdp_md *ctx,  tunnel_t *t, __u8 protocol)
{
    struct pointers p = {};
    //int orig_len = push_xin4(ctx, t, &p, router, t->saddr.addr4.addr, t->daddr.addr4.addr, IPPROTO_UDP, sizeof(struct udphdr) + sizeof(struct gue_hdr));
    int orig_len = push_xin4(ctx, t, &p, IPPROTO_UDP, sizeof(struct udphdr) + sizeof(struct gue_hdr));

    if (orig_len < 0)
	return -1;

    struct udphdr *udp = (void *) (p.ip + 1);

    if (udp + 1 > (void *)(long)ctx->data_end)
        return -1;

    udp->source = bpf_htons(t->sport);
    udp->dest = bpf_htons(t->dport);
    udp->len = bpf_htons(sizeof(struct udphdr) + sizeof(struct gue_hdr) + orig_len);
    udp->check = 0;

    struct gue_hdr *gue = (void *) (udp + 1);
    
    if (gue + 1 > (void *)(long)ctx->data_end)
	return -1;

    *((__be32 *) gue) = 0;

    //bpf_printk("GUE4 %d\n", protocol);
    
    gue->protocol = protocol;
    
    if (! t->nochecksum)
	udp->check = udp4_checksum((void *) p.ip, udp, (void *)(long)ctx->data_end);

    return 0;
}

