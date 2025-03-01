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

#ifdef __BPF__ // Skip all of this with CGO
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define memcpy(d, s, n) __builtin_memcpy((d), (s), (n));

#define VERSION 1
#define SECOND_NS 1000000000l


struct info {
    __be32 vip;
    __be32 saddr;
    __be32 daddr;
    __u16 port;
    char h_dest[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, struct info);
    __uint(max_entries, 1);
} infos SEC(".maps");

static __always_inline
__u16 csum_fold_helper(__u32 csum)
{
    __u32 sum;
    sum = (csum >> 16) + (csum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

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

static __always_inline
int ip_decrease_ttl(struct iphdr *ip)
{
    __u32 check = ip->check;
    check += bpf_htons(0x0100);
    ip->check = (__u16)(check + (check >= 0xFFFF));
    return --(ip->ttl);
}

static __always_inline
int nulmac(unsigned char *mac)
{
    return (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0);
}

static __always_inline
__u16 ipv4_checksum_diff(__u16 seed, struct iphdr *new, struct iphdr *old)
{
    __u32 csum, size = sizeof(struct iphdr);
    csum = bpf_csum_diff((__be32 *)old, size, (__be32 *)new, size, seed);
    return csum_fold_helper(csum);
}

static __always_inline
__u16 ipv4_checksum(struct iphdr *ip)
{
    struct iphdr nil = {};
    return ipv4_checksum_diff(0, ip, &nil);
    
}

static __always_inline
int fou_push(struct xdp_md *ctx, char *router, __be32 saddr, __be32 daddr, __u16 port)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = (void *)(long)ctx->data;
    
    if (eth + 1 > data_end)
        return -1;

    struct ethhdr eth_new = *eth;
    
    memcpy(eth_new.h_source, eth_new.h_dest, 6);
    memcpy(eth_new.h_dest, router, 6);    
    
    if (nulmac(eth_new.h_dest) || nulmac(eth_new.h_source))
	return -1;

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    if (ip + 1 > data_end)
        return -1;

    ip_decrease_ttl(ip);
    
    struct iphdr ip_new = *ip;

    int udp_len = sizeof(struct udphdr) + (data_end - ((void *) ip));
    
    ip_new.check = 0;

    ip_new.version = 4;
    ip_new.ihl = 5;    
    ip_new.saddr = saddr;
    ip_new.daddr = daddr;
    ip_new.tot_len = bpf_htons(sizeof(struct iphdr) + udp_len);
    ip_new.protocol = IPPROTO_UDP;
    ip_new.check = ipv4_checksum(&ip_new);    
    
    int extra = sizeof(struct iphdr) + sizeof(struct udphdr);

    __be16 source =  bpf_htons(1234); // hash of orig ip src/dst, udp src/dst
    __be16 dest   =  bpf_htons(port);
    

    struct udphdr udp_new = { .source = source, .dest = dest, .len = bpf_htons(udp_len) };
    
    if (bpf_xdp_adjust_head(ctx, 0 - extra))
	return -1;
    
    data     = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    eth = (void *)(long)ctx->data;
    
    if (eth + 1 > data_end)
	return -1;
    
    __builtin_memcpy(eth, &eth_new, sizeof(*eth));
    
    ip = data + sizeof(struct ethhdr);
    
    if (ip + 1 > data_end)
        return -1;
    
    __builtin_memcpy(ip, &ip_new, sizeof(*ip));
    
    struct udphdr *udp = (void *) ip + sizeof(*ip);
    
    if (udp + 1 > data_end)
	return -1;
    
    __builtin_memcpy(udp, &udp_new, sizeof(*udp));
    
    return 0;
}

const __u32 ZERO = 0;

SEC("xdp")
int xdp_fwd_func(struct xdp_md *ctx)
{
    //__u64 start = bpf_ktime_get_ns();
    //__u64 start_s = start / SECOND_NS;

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    //int octets = data_end - data;

    struct info *info = bpf_map_lookup_elem(&infos, &ZERO);
    
    if (!info)
	return XDP_PASS;

    struct ethhdr *eth = data;
    __u32 nh_off = sizeof(struct ethhdr);
    
    if (data + nh_off > data_end)
        return XDP_DROP;

    void *next_header = data + nh_off;
    
    /* We don't deal wih any traffic that is not IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = next_header;
    
    if (!(next_header = is_ipv4(ip, data_end)))
	return XDP_DROP;

    if (ip->daddr != info->vip)
	return XDP_PASS;
    
    if (ip->ttl <= 1)
	return XDP_DROP;

    if (fou_push(ctx, info->h_dest, info->saddr, info->daddr, info->port) != 0)	
	return XDP_ABORTED;
    
    return XDP_TX; 
}
    
SEC("xdp")
int  xdp_pass_func(struct xdp_md *ctx)
{
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

#endif

