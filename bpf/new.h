struct pointers {
    struct ethhdr *eth, eth_copy;
    struct vlan_hdr *vlan, vlan_copy;
    struct iphdr *ip;
    struct ip6_hdr *ip6;
    void *data;
    void *data_end;    
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

const __u8 GRE_OVERHEAD = sizeof(struct gre_hdr);
const __u8 FOU_OVERHEAD = sizeof(struct udphdr);
const __u8 GUE_OVERHEAD = sizeof(struct udphdr) + sizeof(struct gue_hdr);


static __always_inline
void *ipptr(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    
    if (eth + 1 > data_end)
	return NULL;
    
    struct iphdr *ip = (void *)(eth + 1);

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
	ip = ip + sizeof(struct vlan_hdr); // don't do ip += ... otherwise we get a verifier issue
    }

    if (ip + 1 > data_end)
	return NULL;
    
    return ip;
}

static __always_inline
void *ip6ptr(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    
    if (eth + 1 > data_end)
	return NULL;
    
    struct ip6_hdr *ip6 = (void *)(eth + 1);

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
	ip6 = ip6 + sizeof(struct vlan_hdr);
    }

    if (ip6 + 1 > data_end)
	return NULL;
    
    return ip6;
}

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

struct l4v6 {
    struct in6_addr saddr;
    struct in6_addr daddr;
    __be16 sport;
    __be16 dport;
};

static __always_inline
__u16 l4v6_checksum_diff(__u16 seed, struct l4v6 *new, struct l4v6 *old) {
    __u32 csum, size = sizeof(struct l4v6);
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

static __always_inline
__u16 icmp_checksum_diff(__u16 seed, struct icmphdr *new, struct icmphdr *old)
{
    __u32 csum, size = sizeof(struct icmphdr);
    csum = bpf_csum_diff((__be32 *)old, size, (__be32 *)new, size, seed);
    return csum_fold_helper(csum);
}

static __always_inline
__u16 checksum_diff(__u16 seed, void *new, void *old, __u16 size)
{
    __u32 csum = 0;
    csum = bpf_csum_diff((__be32 *)old, size, (__be32 *)new, size, seed);
    return csum_fold_helper(csum);
}

static __always_inline
__u16 checksum_diff2(__u16 seed, void *new, void *old, __u16 size)
{
    __u32 csum = 0;
    csum = bpf_csum_diff((__be32 *)old, size, (__be32 *)new, size, ~seed);
    return csum_fold_helper(csum);
}

static __always_inline
__u16 icmp4_csum_diff(struct icmphdr *new, struct icmphdr *old)
{
    return checksum_diff2(old->checksum, new, old, sizeof(struct icmphdr));
}

static __always_inline
__u16 ip4_csum_diff(struct iphdr *new, struct iphdr *old)
{
    return checksum_diff2(old->check, new, old, sizeof(struct iphdr));
}

static __always_inline
__u16 l4_csum_diff(struct l4 *new, struct l4 *old, __u16 seed)
{
    return checksum_diff2(seed, new, old, sizeof(struct l4));
}

static __always_inline
__u16 icmp6_csum_diff(struct icmp6_hdr *new, struct icmp6_hdr *old)
{
    return checksum_diff2(old->icmp6_cksum, new, old, sizeof(struct icmp6_hdr));
}


static __always_inline
__u16 l4v6_csum_diff(struct l4v6 *new, struct l4v6 *old, __u16 seed) {
    return checksum_diff2(seed, new, old, sizeof(struct l4v6));
}

static __always_inline
void ip4_reply(struct iphdr *ip, __u8 ttl) {
    __u16 old_csum = ip->check;
    ip->check = 0;
    struct iphdr old = *ip;
    __be32 tmp = ip->daddr;
    ip->daddr = ip->saddr;
    ip->saddr = tmp;
    ip->ttl = ttl;
    ip->check = ipv4_checksum_diff(~old_csum, ip, &old);
}

static __always_inline
void ip4_set_ttl(struct iphdr *ip, __u8 ttl) {
    __u16 old_csum = ip->check;
    ip->check = 0;
    struct iphdr old = *ip;
    ip->ttl = ttl;
    ip->check = ipv4_checksum_diff(~old_csum, ip, &old);
}

static __always_inline
void ip6_reply(struct ip6_hdr *ip6, __u8 hlim) {
    struct in6_addr tmp = ip6->ip6_src;
    ip6->ip6_src = ip6->ip6_dst;
    ip6->ip6_dst = tmp;
    ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = hlim;
}

static __always_inline
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
	p->ip6 = (void *)(p->vlan + 1);
    } else {
        p->ip = (void *)(p->eth + 1);
        p->ip6 = (void *)(p->eth + 1);
    }

    //if (p->ip + 1 > data_end)
    //	return -1;

    p->eth_copy = *(p->eth);
    if (p->vlan) p->vlan_copy = *(p->vlan);
    
     return 0;
}

static __always_inline
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
	p->ip6 = (void *)(p->vlan + 1);
    } else {
	p->ip = (void *)(p->eth + 1);
	p->ip6 = (void *)(p->eth + 1);
    }
    
    //if (p->ip + 1 > data_end)
    //return -1;

    *(p->eth) = p->eth_copy;
    if (p->vlan) *(p->vlan) = p->vlan_copy;

    p->data = data;
    p->data_end = data_end;
    
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

//static __always_inline
void new_ip6hdr(struct ip6_hdr *ip, __u16 payload_len, __u8 protocol, struct in6_addr *saddr, struct in6_addr *daddr)
{
    struct ip6_hdr i = {};
    *ip = i;
    
    ip->ip6_ctlun.ip6_un2_vfc = 0x6 << 4; // empty TC and flow label for now
    ip->ip6_ctlun.ip6_un1.ip6_un1_plen =  bpf_htons(payload_len);
    ip->ip6_ctlun.ip6_un1.ip6_un1_nxt = protocol;
    ip->ip6_ctlun.ip6_un1.ip6_un1_hlim = 64;
    
    ip->ip6_src = *saddr;
    ip->ip6_dst = *daddr;
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
int nulmac(const unsigned char *mac)
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

    if (p->ip + 1 > data_end)
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
int frag_needed_trim6(struct xdp_md *ctx, struct pointers *p)
{
    const int max = 128;
    void *data_end = (void *)(long)ctx->data_end;
        
    if (preserve_l2_headers(ctx, p) < 0)
	return -1;

    if (p->ip6 + 1 > data_end)
	return -1;
    
    int iplen = data_end - (void *)(p->ip6);

    // if a packet was smaller than "max" bytes then it should not have been too big - drop
    if (iplen < max)
      return -1;
    
    // DELIBERATE BREAKAGE
    //struct in6_addr nul = {};  p->ip6->ip6_dst = nul; // prevent the ICMP from changing the path MTU whilst testing
    
    // truncate the packet if > max bytes (it could of course be exactly max bytes)
    if (iplen > max && bpf_xdp_adjust_tail(ctx, 0 - (int)(iplen - max)))
	return -1;
    
    // extend header - extra ip and icmp needed
    if (bpf_xdp_adjust_head(ctx, 0 - (int)(sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr))))
	return -1;

    if (restore_l2_headers(ctx, p) < 0)	
        return -1;

    return max;
}



static __always_inline
int frag_needed4(struct xdp_md *ctx, __be32 saddr, __u16 mtu)
{
    struct pointers p = {};
    int iplen;
    
    if ((iplen = frag_needed_trim(ctx, &p)) < 0)	
	return -1;
    
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *ip = ipptr(data, data_end);

    if (!ip)
        return -1;

    struct icmphdr *icmp = (void *) (ip + 1);
    
    if (icmp + 1 > data_end)
	return -1;

    reverse_ethhdr(p.eth);

    int tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + iplen;
    new_iphdr(p.ip, tot_len, IPPROTO_ICMP, saddr, p.ip->saddr); // source becomes LB's IP, destination is the client

    // reply to client with LB's address
    // ensure DEST_UNREACH/FRAG_NEEDED is allowed out
    // ensure DEST_UNREACH/FRAG_NEEDED is also allowed in to prevent MTU blackholes
    // respond to every occurence or keep a record of recent notifications?
    
    struct icmphdr msg = { .type = ICMP_DEST_UNREACH, .code = ICMP_FRAG_NEEDED, .checksum = 0, .un.frag.mtu = bpf_htons(mtu) };
    *icmp = msg;

    ((__u8 *) icmp)[5] = ((__u8)(iplen >> 2)); // struct icmphdr lacks a length field

    icmp->checksum = internet_checksum(icmp, data_end, 0);

    return 0;
}

static __always_inline
__u16 icmp6_checksum(struct ip6_hdr *ip6, void *l4, void *data_end) {
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


// "static __always_inline" needs commenting on 20.24 and uncommenting on 24.04
static __always_inline 
int icmp6_too_big(struct xdp_md *ctx, struct in6_addr *saddr, struct in6_addr *daddr, __u16 mtu)
{
    struct pointers p = {};
    int iplen;

    if ((iplen = frag_needed_trim6(ctx, &p)) < 0)
	return -1;
    
    struct icmp6_hdr *icmp = (void *) (p.ip6 + 1);

    if (icmp + 1 > p.data_end)
	return -1;
    
    reverse_ethhdr(p.eth);

    new_ip6hdr(p.ip6, sizeof(struct icmp6_hdr) + iplen, IPPROTO_ICMPV6, saddr, daddr);
    
    struct icmp6_hdr msg = { .icmp6_type = ICMP6_PACKET_TOO_BIG };
    msg.icmp6_dataun.icmp6_un_data32[0] = bpf_htonl(mtu);
    *icmp = msg;

    icmp->icmp6_cksum = icmp6_checksum(p.ip6, icmp, p.data_end);    
    
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
    struct ethhdr *eth = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (eth + 1 > data_end)
	return -1;

    memcpy(eth->h_source, eth->h_dest, 6);
    memcpy(eth->h_dest, dest, 6);

    if (nulmac(eth->h_source) || nulmac(eth->h_dest))
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
int push_xin4(struct xdp_md *ctx, tunnel_t *t, struct pointers *p, __u8 protocol, int overhead)
{
    __be32 saddr = t->saddr.addr4.addr;
    __be32 daddr = t->daddr.addr4.addr;
    
    if (!saddr || !daddr)
	return -1;
    
    int orig_len = adjust_head(ctx, p, sizeof(struct iphdr) + overhead);
    
    if (orig_len < 0)
	return -1;

    if (p->vlan) {
	p->vlan->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IP);
    } else {
	p->eth->h_proto = bpf_htons(ETH_P_IP);
    }

    void *payload = (void *) (p->ip + 1);
    
    if (payload + overhead > p->data_end)
    	return -1;
    
    // Update the outer IP header to send to the FOU target
    int tot_len = sizeof(struct iphdr) + overhead + orig_len;
    new_iphdr(p->ip, tot_len, protocol, saddr, daddr);

    memcpy(p->eth->h_dest, t->h_dest, 6);
    memcpy(p->eth->h_source, t->h_source,6);

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
    
    if (push_xin4(ctx,t,  &p, IPPROTO_GRE, sizeof(struct gre_hdr)) < 0)	
	return -1;

    struct gre_hdr *gre = (void *) (p.ip + 1);
    
    if (gre + 1 > p.data_end)
        return -1;
    
    gre->crv = 0;
    gre->protocol = bpf_htons(protocol);
        
    return 0;
}

static __always_inline
int push_xin6(struct xdp_md *ctx, tunnel_t *t, struct pointers *p, __u8 protocol, unsigned int overhead)
{
    if (nul6(&(t->saddr.addr6)) || nul6(&(t->daddr.addr6)))
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
    
    if (new + 1 > p->data_end)
        return -1;
    
    int payload_len = overhead + orig_len;
    new_ip6hdr(new, payload_len, protocol, &(t->saddr.addr6), &(t->daddr.addr6));

    memcpy(p->eth->h_dest, t->h_dest, 6);
    memcpy(p->eth->h_source, t->h_source,6);

    // some final sanity checks on ethernet addresses
    if (nulmac(p->eth->h_source) || nulmac(p->eth->h_dest))
	return -1;

    return orig_len;
}


/*
static __always_inline
int push_ipip(struct xdp_md *ctx, tunnel_t *t)
{
    struct pointers p = {};
    return push_xin4(ctx, t, &p, IPPROTO_IPIP, 0);
}


static __always_inline
int push_6in4(struct xdp_md *ctx, tunnel_t *t)    
{
    struct pointers p = {};
    return push_xin4(ctx, t, &p, IPPROTO_IPV6, 0);
}

static __always_inline
int push_6in6(struct xdp_md *ctx, tunnel_t *t)
{
    struct pointers p = {};
    return push_xin6(ctx, t, &p, IPPROTO_IPV6, 0);
}

static __always_inline
int push_4in6(struct xdp_md *ctx, tunnel_t *t)
{
    struct pointers p = {};
    return push_xin6(ctx, t, &p, IPPROTO_IPIP, 0);
}
*/

static __always_inline
int push_gre6(struct xdp_md *ctx,  tunnel_t *t, __u16 protocol)
{
    struct pointers p = {};
    
    int orig_len = push_xin6(ctx, t, &p, IPPROTO_GRE, sizeof(struct gre_hdr));

    if (orig_len < 0)
	return -1;

    struct gre_hdr *gre = (void *) ((struct ip6_hdr *) p.ip + 1);
    
    if (gre + 1 > p.data_end)
    	return -1;

    gre->crv = 0;
    gre->protocol = bpf_htons(protocol);
    
    return 0;
}

static __always_inline
int push_fou6(struct xdp_md *ctx,  tunnel_t *t)
{
    struct pointers p = {};
    
    int orig_len = push_xin6(ctx, t, &p, IPPROTO_UDP, sizeof(struct udphdr));
    
    if (orig_len < 0)
        return -1;

    struct udphdr *udp = (void *) ((struct ip6_hdr *) p.ip + 1);
    
    if (udp + 1 > p.data_end)
        return -1;

    udp->source = bpf_htons(t->sport);
    udp->dest = bpf_htons(t->dport);
    udp->len = bpf_htons(sizeof(struct udphdr) + orig_len);
    udp->check = 0;
    
    if (! (t->flags & F_CHECKSUM_DISABLE))
	udp->check = udp6_checksum((void *) p.ip, udp, p.data_end);
    
    return 0;
}


static __always_inline
int push_fou4(struct xdp_md *ctx,  tunnel_t *t)
{
    struct pointers p = {};
    int orig_len = push_xin4(ctx, t, &p, IPPROTO_UDP, sizeof(struct udphdr));

    if (orig_len < 0)
	return -1;

    struct iphdr *ip = p.ip;
    
    if (!ip)
        return -1;
    
    struct udphdr *udp = (void *) (ip + 1);
     
    if (udp + 1 > p.data_end)
        return -1;

    udp->source = bpf_htons(t->sport);
    udp->dest = bpf_htons(t->dport);
    udp->len = bpf_htons(sizeof(struct udphdr) + orig_len);
    udp->check = 0;
    
    if (! (t->flags & F_CHECKSUM_DISABLE))
	udp->check = udp4_checksum((void *) ip, udp, p.data_end);

    return 0;
}

static __always_inline
int push_gue6(struct xdp_md *ctx,  tunnel_t *t, __u8 protocol)
{
    struct pointers p = {};
    
    int orig_len = push_xin6(ctx, t, &p, IPPROTO_UDP, sizeof(struct udphdr) + sizeof(struct gue_hdr));
    
    if (orig_len < 0)
        return -1;

    struct udphdr *udp = (void *) ((struct ip6_hdr *) p.ip + 1);
    
    if (udp + 1 > p.data_end)
        return -1;

    udp->source = bpf_htons(t->sport);
    udp->dest = bpf_htons(t->dport);
    udp->len = bpf_htons(sizeof(struct udphdr) + sizeof(struct gue_hdr) + orig_len);
    udp->check = 0;

     struct gue_hdr *gue = (void *) (udp + 1);

    if (gue + 1 > p.data_end)
        return -1;

    *((__be32 *) gue) = 0;

    gue->protocol = protocol;
    
    if (! (t->flags & F_CHECKSUM_DISABLE))
	udp->check = udp6_checksum((void *) p.ip, udp, p.data_end);
    
    return 0;
}

static __always_inline
int push_gue4(struct xdp_md *ctx,  tunnel_t *t, __u8 protocol)
{
    struct pointers p = {};
    int orig_len = push_xin4(ctx, t, &p, IPPROTO_UDP, sizeof(struct udphdr) + sizeof(struct gue_hdr));

    if (orig_len < 0)
	return -1;
    
    struct udphdr *udp = (void *) (p.ip + 1);
    
    if (udp + 1 > p.data_end)
        return -1;
    
    udp->source = bpf_htons(t->sport);
    udp->dest = bpf_htons(t->dport);
    udp->len = bpf_htons(sizeof(struct udphdr) + sizeof(struct gue_hdr) + orig_len);
    udp->check = 0;
    
    struct gue_hdr *gue = (void *) (udp + 1);
    
    if (gue + 1 > p.data_end)
	return -1;

    *((__be32 *) gue) = 0;
    
    gue->protocol = protocol;
    
    if (! (t->flags & F_CHECKSUM_DISABLE))
	udp->check = udp4_checksum((void *) p.ip, udp, p.data_end);

    return 0;
}









/**********************************************************************/

static __always_inline
__u16 l3_hash(fourtuple_t *ft)
{
    return sdbm((unsigned char *) ft, sizeof(addr_t) * 2);
}

static __always_inline
__u16 l4_hash(fourtuple_t *ft)
{
    return sdbm((unsigned char *) ft, sizeof(fourtuple_t));
}

static __always_inline
__u16 l4_hash_(struct l4 *ft)
{
    return sdbm((unsigned char *) ft, sizeof(*ft));
}

static __always_inline
int is_ipv4_addr(struct addr a) {
    return (!a.addr4.pad1 && !a.addr4.pad2 && !a.addr4.pad3) ? 1 : 0;
}

//static __always_inline
int is_ipv4_addr_p(struct addr *a) {
    return (!a->addr4.pad1 && !a->addr4.pad2 && !a->addr4.pad3) ? 1 : 0;
}

/**********************************************************************/

static __always_inline
int send_l2(struct xdp_md *ctx, tunnel_t *t)
{
    return redirect_eth(ctx, t->h_dest) < 0 ? XDP_ABORTED : XDP_TX;
}

static __always_inline
int send_ipip(struct xdp_md *ctx, tunnel_t *t, int is_ipv6)
{
    struct pointers p = {};

    if (is_addr4(&(t->daddr)))
	return push_xin4(ctx, t, &p, is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP, 0) < 0 ? XDP_ABORTED : XDP_TX;

    return push_xin6(ctx, t, &p, is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP, 0) < 0 ? XDP_ABORTED : XDP_TX;
}

static __always_inline
int send_gre(struct xdp_md *ctx, tunnel_t *t, int is_ipv6)
{
    if (is_addr4(&(t->daddr)))
	return push_gre4(ctx, t, is_ipv6 ? ETH_P_IPV6 : ETH_P_IP) < 0 ? XDP_ABORTED : XDP_TX;
    
    return push_gre6(ctx, t, is_ipv6 ? ETH_P_IPV6 : ETH_P_IP) < 0 ? XDP_ABORTED : XDP_TX;
}

static __always_inline
int send_fou(struct xdp_md *ctx, tunnel_t *t)
{
    if (is_addr4(&(t->daddr)))
	return push_fou4(ctx, t) < 0 ? XDP_ABORTED : XDP_TX;

    return push_fou6(ctx, t) < 0 ? XDP_ABORTED : XDP_TX;    
}

static __always_inline
int send_gue(struct xdp_md *ctx, tunnel_t *t, int is_ipv6)
{
    if (is_addr4(&(t->daddr)))
	return push_gue4(ctx, t, is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP) < 0 ? XDP_ABORTED : XDP_TX;
    
    return push_gue6(ctx, t, is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP) < 0 ? XDP_ABORTED : XDP_TX;
}


/**********************************************************************/

static __always_inline
int send_l2_(struct xdp_md *ctx, tunnel_t *t)
{
    return redirect_eth(ctx, t->h_dest);
}

static __always_inline
int send_ipip_(struct xdp_md *ctx, tunnel_t *t, int is_ipv6)
{
    struct pointers p = {};

    if (is_addr4(&(t->daddr)))
	return push_xin4(ctx, t, &p, is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP, 0);

    return push_xin6(ctx, t, &p, is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP, 0);
}

static __always_inline
int send_gre_(struct xdp_md *ctx, tunnel_t *t, int is_ipv6)
{
    if (is_addr4(&(t->daddr)))
	return push_gre4(ctx, t, is_ipv6 ? ETH_P_IPV6 : ETH_P_IP);
    
    return push_gre6(ctx, t, is_ipv6 ? ETH_P_IPV6 : ETH_P_IP);
}

static __always_inline
int send_fou_(struct xdp_md *ctx, tunnel_t *t)
{
    if (is_addr4(&(t->daddr)))
	return push_fou4(ctx, t);

    return push_fou6(ctx, t);
}

static __always_inline
int send_gue_(struct xdp_md *ctx, tunnel_t *t, int is_ipv6)
{
    if (is_addr4(&(t->daddr)))
	return push_gue4(ctx, t, is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP);
    
    return push_gue6(ctx, t, is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP);
}
