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

/*

 bpf_printk: cat /sys/kernel/debug/tracing/trace_pipe

/etc/networkd-dispatcher/routable.d/50-ifup-hooks:
#!/bin/sh
ip fou add port 9999 ipproto 4
ip link set dev tunl0 up
sysctl -w net.ipv4.conf.tunl0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0

/etc/modules:
fou
ipip

*/

#ifdef __BPF__ // Skip all of this with CGO
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#define memcpy(d, s, n) __builtin_memcpy((d), (s), (n));

#define VERSION 1
#define SECOND_NS 1000000000l

const __u8 FOU4_OVERHEAD = sizeof(struct iphdr) + sizeof(struct udphdr);
const __u32 ZERO = 0;
const __u16 MTU = 1500;


struct info {
    __be32 vip;
    __be32 saddr;
    char h_dest[6];
    char pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, struct info);
    __uint(max_entries, 1);
} infos SEC(".maps");

struct dest4 {
    __be32 addr;
    __u16 vid;
    __u8 mac[6];
    __u8 flag[4];
};

struct dest6 {
    __u8 addr[16];
};
    
struct dest {
    union {
        struct dest4 dest4;
        struct dest6 dest6;
    };
};

const __u8 F_L2  = 0x00;
const __u8 F_FOU = 0x01;

struct service {
    __u8 flag[256]; // flag[0] - global flags for service; sticky, leastconns
    __be16 port[256]; // port[0] - high byte leastons score, low byte destination index to use
    struct dest dest[256];
    __u8 hash[8192];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, struct service);
    __uint(max_entries, 4096);
} services SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, __u8[2048]);
    __uint(max_entries, 1);
} buffers SEC(".maps");

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
__u16 l4_hash(__be32 saddr, __be32 daddr, __be16 source, __be16 dest)
{
    struct {
	__be32 src;
	__be32 dst;
	__be16 sport;
	__be16 dport;
    } h = { .src = saddr, .dst = daddr, .sport = source, .dport = dest };
    return sdbm((unsigned char *)&h, sizeof(h));
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
    
    ip_new.version = 4;
    ip_new.ihl = 5;    
    ip_new.saddr = saddr;
    ip_new.daddr = daddr;
    ip_new.tot_len = bpf_htons(sizeof(struct iphdr) + udp_len);
    ip_new.protocol = IPPROTO_UDP;
    ip_new.check = 0;
    ip_new.check = ipv4_checksum(&ip_new);    
    
    __be16 source =  bpf_htons(1234); // hash of orig ip src/dst, udp src/dst
    __be16 dest   =  bpf_htons(port);
    

    struct udphdr udp_new = { .source = source, .dest = dest, .len = bpf_htons(udp_len) };
    
    if (bpf_xdp_adjust_head(ctx, 0 - FOU4_OVERHEAD))
	return -1;
    
    data     = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    eth = (void *)(long)ctx->data;
    
    if (eth + 1 > data_end)
	return -1;
    
    memcpy(eth, &eth_new, sizeof(*eth));
    
    ip = data + sizeof(struct ethhdr);
    
    if (ip + 1 > data_end)
        return -1;
    
    memcpy(ip, &ip_new, sizeof(*ip));
    
    struct udphdr *udp = (void *) ip + sizeof(*ip);
    
    if (udp + 1 > data_end)
	return -1;
    
    memcpy(udp, &udp_new, sizeof(*udp));
    
    return 0;
}

static __always_inline
int frag_needed(struct xdp_md *ctx, __be32 saddr, __u16 mtu)
{
    // FIXME - checksum doesn't work for much larger packets, no sure why - keep the size down for now
    const int max = 128;

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    
    if (eth + 1 > data_end)
	return -1;
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    
    if (ip + 1 > data_end)
	return -1;
    
    int iplen = data_end - (void *) ip;

    /* if a packet was smaller than "max" bytes then it should not have been too big - drop */
    if (iplen < max)
      return -1;
    
    struct ethhdr eth_copy = *eth;
    struct iphdr ip_copy = *ip;

    // DELIBERATE BREAKAGE
    //ip->daddr = saddr; // prevent the ICMP from changing the path MTU whilst testing
    //ip->check = 0;
    //ip->check = ipv4_checksum(ip);
    
    int adjust = 0;
    
    /* truncate the packet if > max bytes (it could of course be exactly max bytes) */
    if (iplen > max) {
	adjust = iplen - max;
	
	if(bpf_xdp_adjust_tail(ctx, 0 - adjust))
	    return -1;
	
	iplen = max;
    }
    
    /* extend header - extra ip and icmp needed*/
    adjust = sizeof(struct iphdr) + sizeof(struct icmphdr);
    
    if (bpf_xdp_adjust_head(ctx, 0 - adjust))
	return -1;

    data     = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    
    eth = data;
    
    if (eth + 1 > data_end)
	return -1;
    
    ip = (struct iphdr *)(eth + 1);

    if (ip + 1 > data_end)
	return -1;

    struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
    
    if (icmp + 1 > data_end)
	return -1;
    
    *eth = eth_copy;
    *ip = ip_copy;

    memcpy(eth->h_dest, eth_copy.h_source, 6);
    memcpy(eth->h_source, eth_copy.h_dest, 6);

    ip->daddr = ip_copy.saddr;
    ip->saddr = saddr;

    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 64;
    ip->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + iplen);
    ip->protocol = IPPROTO_ICMP;
    ip->check = 0;
    ip->check = ipv4_checksum(ip);

    struct icmphdr fou = { .type = ICMP_DEST_UNREACH, .code = ICMP_FRAG_NEEDED, .checksum = 0 };

    fou.un.frag.mtu = bpf_htons(mtu);

    *icmp = fou;

    ((__u8 *) icmp)[5] = ((__u8)(iplen) >> 2); // struct icmphdr lacks a length field


    __u8 *buffer = bpf_map_lookup_elem(&buffers, &ZERO);

    if (!buffer)
	return -1;
    
    for (__u16 n = 0; n < sizeof(struct icmphdr) + max; n++) {
	if (((void *) icmp) + n >= data_end)
            break;
	((__u8 *) buffer)[n] = ((__u8 *) icmp)[n]; // copy original IP packet to buffer
    }

    /* calulate checksum over the entire icmp packet + payload (copied to buffer) */
    icmp->checksum = icmp_checksum((struct icmphdr *) buffer, sizeof(struct icmphdr) + iplen);    

    return 0;
}

SEC("xdp")
int xdp_fwd_func(struct xdp_md *ctx)
{
    //__u64 start = bpf_ktime_get_ns();
    //__u64 start_s = start / SECOND_NS;

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    //int octets = data_end - data;

    struct info *info = bpf_map_lookup_elem(&infos, &ZERO);
    struct service *service = bpf_map_lookup_elem(&services, &ZERO);
    
    if (!info || !service)
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
    
    if (ip->protocol != IPPROTO_TCP)
	return XDP_DROP;

    if (next_header + sizeof(struct tcphdr) > data_end)
	return XDP_DROP;

    struct tcphdr *tcp = next_header;

    __u16 hash = l4_hash(ip->saddr, ip->daddr, tcp->source, tcp->dest) & 0x1fff; // limit to 0-8191
    //__u16 hash = tcp->source & 0x1fff; // limit to 0-8191
    __u8 index = service->hash[hash];
    __u16 port = service->port[index];
    __u8 flag = service->flag[index];

    struct dest dest = service->dest[index];
    __be32 daddr = dest.dest4.addr;

    if (index == 0 || daddr == 0 | flag != 0)
	return XDP_DROP;

    int mtu = MTU;

    if ((data_end - ((void *) ip)) + FOU4_OVERHEAD > mtu) { // testing
	
	__u16 flags = bpf_ntohs(ip->frag_off) >> 13;
	if (!(flags & 0x02)) // DF bit not set
	    return XDP_DROP;
	
	if (frag_needed(ctx, info->saddr, mtu - FOU4_OVERHEAD) < 0)
	    return XDP_DROP;
	
	bpf_printk("XDP_TX\n");	
	
	return XDP_TX;
    }
    
    if (fou_push(ctx, info->h_dest, info->saddr, daddr, port) != 0)
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

