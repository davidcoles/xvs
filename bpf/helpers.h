/*
 * vc5/xvs load balancer. Copyright (C) 2021-present David Coles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

struct l4ports {
    __be16 source;
    __be16 dest;
};

enum destination_result {
    DEST_NOT_FOUND = 0,
    DEST_NOT_AVAILABLE,
    DEST_FOUND
};

struct destination {
    __be32 rip;
    __u16 vlanid;
    char mac[6];
    int result;
    int new;
    struct state *state;
};

static __always_inline
void maccpy(void *dst, void *src)
{
    __builtin_memcpy(dst, src, 6);
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
__u16 ipv4_checksum_diff(__u16 seed, struct iphdr *new, struct iphdr *old)
{
    __u32 csum, size = sizeof(struct iphdr);   
    csum = bpf_csum_diff((__be32 *)old, size, (__be32 *)new, size, seed);
    return csum_fold_helper(csum);
}

static __always_inline
__u16 icmp_checksum_diff(__u16 seed, struct icmphdr *new, struct icmphdr *old)
{
    __u32 csum, size = sizeof(struct icmphdr);   
    csum = bpf_csum_diff((__be32 *)old, size, (__be32 *)new, size, seed);
    return csum_fold_helper(csum);
}

struct l4 {
    __be32 saddr;
    __be32 daddr;
};

static __always_inline __u16
l4_checksum_diff(__u16 seed, struct l4 *new, struct l4 *old) {
    __u32 csum, size = sizeof(struct l4);
    csum = bpf_csum_diff((__be32 *)old, size, (__be32 *)new, size, seed);
    return csum_fold_helper(csum);
}

static __always_inline
int nulmac(unsigned char *mac)
{
    return (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0);
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

struct hash_s {
    __be32 src;
    __be32 dst;
    __be16 sport;
    __be16 dport;
};

static __always_inline
__u16 l4_hash(struct iphdr *ipv4, struct l4ports l4)
{
    struct hash_s h = { .src = ipv4->saddr, .dst = ipv4->daddr, .sport = l4.source, .dport = l4.dest };
    return sdbm((unsigned char *)&h, sizeof(h));
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
int nat_ok(struct iphdr *ipv4, void *data_end, __be32 src, __be32 dst)
{
    void *data = ipv4;
    int nh_off = sizeof(struct iphdr);
    
    if(data + nh_off > data_end)
	return 0;
    
    struct l4 o = {.saddr = ipv4->saddr, .daddr = ipv4->daddr};
    struct l4 n = {.saddr = src, .daddr = dst };
    struct tcphdr *tcp = data + nh_off;
    struct udphdr *udp = data + nh_off;
    
    switch(ipv4->protocol) {
    case IPPROTO_TCP:
	nh_off += sizeof(struct tcphdr);
	if (data + nh_off > data_end)
	    return 0;
	tcp->check = l4_checksum_diff(~(tcp->check), &n, &o);
	break;
    case IPPROTO_UDP:
	nh_off += sizeof(struct udphdr);
	if (data + nh_off > data_end)
	    return 0;
	udp->check = l4_checksum_diff(~(udp->check), &n, &o);
	break;
    }    
    
    __u16 old_csum = ipv4->check;
    ipv4->check = 0;
    struct iphdr old = *ipv4;
    ipv4->saddr = src;
    ipv4->daddr = dst;
    ipv4->check = ipv4_checksum_diff(~old_csum, ipv4, &old);
    return 1;
}

static __always_inline
void ip_reply(struct iphdr *ip) {
    __u16 old_csum = ip->check;
    ip->check = 0;
    struct iphdr old = *ip;
    __be32 tmp = ip->daddr;
    ip->daddr = ip->saddr;
    ip->saddr = tmp;
    ip->ttl = 64;
    ip->check = ipv4_checksum_diff(~old_csum, ip, &old);
}
