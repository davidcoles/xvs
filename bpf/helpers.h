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


/*
// perl -e 'foreach(0..63) { printf "case %2d: return x & %016x;\n", $_, 2**$_ }'
static __always_inline
__u64 pow64(__u8 n)
{
    switch(n) {
    case  0: return 0x0000000000000001;
    case  1: return 0x0000000000000002;
    case  2: return 0x0000000000000004;
    case  3: return 0x0000000000000008;
    case  4: return 0x0000000000000010;
    case  5: return 0x0000000000000020;
    case  6: return 0x0000000000000040;
    case  7: return 0x0000000000000080;
    case  8: return 0x0000000000000100;
    case  9: return 0x0000000000000200;
    case 10: return 0x0000000000000400;
    case 11: return 0x0000000000000800;
    case 12: return 0x0000000000001000;
    case 13: return 0x0000000000002000;
    case 14: return 0x0000000000004000;
    case 15: return 0x0000000000008000;
    case 16: return 0x0000000000010000;
    case 17: return 0x0000000000020000;
    case 18: return 0x0000000000040000;
    case 19: return 0x0000000000080000;
    case 20: return 0x0000000000100000;
    case 21: return 0x0000000000200000;
    case 22: return 0x0000000000400000;
    case 23: return 0x0000000000800000;
    case 24: return 0x0000000001000000;
    case 25: return 0x0000000002000000;
    case 26: return 0x0000000004000000;
    case 27: return 0x0000000008000000;
    case 28: return 0x0000000010000000;
    case 29: return 0x0000000020000000;
    case 30: return 0x0000000040000000;
    case 31: return 0x0000000080000000;
    case 32: return 0x0000000100000000;
    case 33: return 0x0000000200000000;
    case 34: return 0x0000000400000000;
    case 35: return 0x0000000800000000;
    case 36: return 0x0000001000000000;
    case 37: return 0x0000002000000000;
    case 38: return 0x0000004000000000;
    case 39: return 0x0000008000000000;
    case 40: return 0x0000010000000000;
    case 41: return 0x0000020000000000;
    case 42: return 0x0000040000000000;
    case 43: return 0x0000080000000000;
    case 44: return 0x0000100000000000;
    case 45: return 0x0000200000000000;
    case 46: return 0x0000400000000000;
    case 47: return 0x0000800000000000;
    case 48: return 0x0001000000000000;
    case 49: return 0x0002000000000000;
    case 50: return 0x0004000000000000;
    case 51: return 0x0008000000000000;
    case 52: return 0x0010000000000000;
    case 53: return 0x0020000000000000;
    case 54: return 0x0040000000000000;
    case 55: return 0x0080000000000000;
    case 56: return 0x0100000000000000;
    case 57: return 0x0200000000000000;
    case 58: return 0x0400000000000000;
    case 59: return 0x0800000000000000;
    case 60: return 0x1000000000000000;
    case 61: return 0x2000000000000000;
    case 62: return 0x4000000000000000;
    case 63: return 0x8000000000000000;
    }
    return 0;
}
*/
