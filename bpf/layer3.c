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
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "vlan.h"

#define IS_DF(f) (((f) & bpf_htons(0x02<<13)) ? 1 : 0)
#define memcpy(d, s, n) __builtin_memcpy((d), (s), (n));

#define VERSION 1
#define SECOND_NS 1000000000l

const __u8 FOU4_OVERHEAD = sizeof(struct iphdr) + sizeof(struct udphdr);
const __u32 ZERO = 0;
const __u16 MTU = 1500;

const __u8 F_STICKY = 0x01;

const __u8 F_LAYER2_DSR  = 0x00;
const __u8 F_LAYER3_FOU4 = 0x01;
const __u8 F_LAYER3_FOU6 = 0x02;

enum lookup_result {
		    NOT_FOUND = 0,
		    LAYER2_DSR,
		    LAYER3_FOU4, // FOU to IPv4 host
		    LAYER3_FOU6, // FOU to IPv6 host
};

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

struct addr4 {
    __u16 vid;   // L2DSR only
    __u8 mac[6]; // L2DSR only
    __u8 pad[4];
    __be32 addr;
};

struct addr6 {
    __u8 addr[16];
};

struct addr {
    union {
        struct addr4 addr4;
        struct addr6 addr6;
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, __u8[2048]);
    __uint(max_entries, 1);
} buffers SEC(".maps");

struct servicekey {
    struct addr addr;    
    __be16 port;
    __u16 proto;
};

struct fookey {
    struct addr saddr;    
    __be16 sport;
    __u16 proto;
    struct addr daddr;
    __be16 dport;
};

struct destination {
    struct addr daddr;
    struct addr saddr;
    __u16 sport; // FOU
    __u16 dport; // FOU
    __u8 h_dest[6]; // router MAC
};

struct destinations {
    __u8 hash[8192];
    __u8 flag[256];    // flag[0] - global flags for service; sticky, leastconns
    __u16 dport[256];  // port[0] - high byte leastconns score, low byte destination index to use
    struct addr daddr[256];
    struct addr saddr; // source address to use with tunnels
    __u8 h_dest[6];    // router MAC address to send encapsulated packets to
    __u16 vlanid;      // VLAN ID which encapsulated packets should be sent on
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct servicekey);
    __type(value, struct destinations);
    __uint(max_entries, 4096);
} destinations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8[16]);
    __type(value, __u32);
    __uint(max_entries, 4096);
} vips SEC(".maps");

/**********************************************************************/

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
    return (!mac[0] && !mac[1] && !mac[2] && !mac[3] && !mac[4] && !mac[5]);
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
__u16 l4_hash(struct iphdr *ip, void *l4)
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


static __always_inline
int fou_push(struct xdp_md *ctx, char *router, __be32 saddr, __be32 daddr, __u16 sport, __u16 dport)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data, eth_new = {};
    struct vlan_hdr *vlan = NULL, vlan_new = {};
    struct iphdr *ip = NULL, ip_new = {};
    
    if (eth + 1 > data_end)
        return -1;

    eth_new = *eth;    
    
    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
	vlan = (void *) (eth + 1);
	
	if (vlan + 1 > data_end)
	    return -1;
	
	vlan_new = *vlan;
	
	ip = (void *) (vlan + 1);
    } else {
	ip = (void *) (eth + 1);
    }
    
    if (ip + 1 > data_end)
        return -1;
    
    memcpy(eth_new.h_source, eth_new.h_dest, 6);
    memcpy(eth_new.h_dest, router, 6);    
    
    if (nulmac(eth_new.h_dest) || nulmac(eth_new.h_source))
	return -1;
    
    ip_decrease_ttl(ip);
    
    ip_new = *ip;

    int udp_len = sizeof(struct udphdr) + (data_end - ((void *) ip));
    struct udphdr udp_new = { .source = bpf_htons(sport), .dest = bpf_htons(dport), .len = bpf_htons(udp_len) };
    
    ip_new.version = 4;
    ip_new.ihl = 5;    
    ip_new.saddr = saddr;
    ip_new.daddr = daddr;
    ip_new.tot_len = bpf_htons(sizeof(struct iphdr) + udp_len);
    ip_new.protocol = IPPROTO_UDP;
    ip_new.check = 0;
    ip_new.check = ipv4_checksum(&ip_new);    
    
    if (bpf_xdp_adjust_head(ctx, 0 - FOU4_OVERHEAD))
	return -1;
    
    data     = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    eth = data;
    
    if (eth + 1 > data_end)
	return -1;
    
    *eth = eth_new;   

    if(vlan) {
	vlan = (struct vlan_hdr *)(eth + 1);
	
	if (vlan + 1 > data_end)
	    return -1;
	
	*vlan = vlan_new;
	
	ip = (void *) (vlan + 1);
    } else {
	ip = (void *) (eth + 1);
    }
    
    if (ip + 1 > data_end)
        return -1;
    
    *ip = ip_new;
    
    struct udphdr *udp = (void *) (ip + 1);
    
    if (udp + 1 > data_end)
	return -1;
    
    *udp = udp_new;
    
    return 0;
}


static __always_inline
int send_fou4(struct xdp_md *ctx, struct destination *dest)
{
    return (fou_push(ctx, dest->h_dest, dest->saddr.addr4.addr, dest->daddr.addr4.addr, dest->sport, dest->dport) != 0) ? XDP_ABORTED : XDP_TX;
}

static __always_inline
enum lookup_result lookup(struct iphdr *ip, void *l4, struct destination *r) // flags arg?
{
    // lookup flow in state map?
    
    struct udphdr *udp = l4;
    struct addr daddr = { .addr4.addr =  ip->daddr };
    struct servicekey key = { .addr = daddr, .port = bpf_ntohs(udp->dest), .proto = ip->protocol }; 
    struct destinations *service = bpf_map_lookup_elem(&destinations, &key);

    if (!service)
	return NOT_FOUND;

    __u8 sticky = service->flag[0] & F_STICKY;
    __u16 hash3 = l4_hash(ip, NULL);
    __u16 hash4 = l4_hash(ip, l4);
    __u8 index = service->hash[(sticky ? hash3 : hash4) & 0x1fff]; // limit to 0-8191

    if (!index)
	return NOT_FOUND;
    
    r->daddr = service->daddr[index];      // backend's address, inc. MAC and VLAN for L2
    r->saddr = service->saddr;             // source address to send L3 tunnel traffic from
    r->dport = service->dport[index];      // destination port for L3 tunnel (eg. FOU)
    r->sport = 0x8000 | (hash4 & 0x7fff);  // source port for L3 tunnel (eg. FOU)
    memcpy(r->h_dest, service->h_dest, 6); // router MAC for L3 tunnel
    
    __u8 flag = service->flag[index];

    // store flow?
    
    switch (flag) {
    case F_LAYER2_DSR:  return LAYER2_DSR;
    case F_LAYER3_FOU4:	return LAYER3_FOU4;
    case F_LAYER3_FOU6: return LAYER3_FOU6;
    }

   return NOT_FOUND;
}

static __always_inline
enum lookup_result lookup4(struct iphdr *ip, void *l4, struct destination *r) // flags arg?
{
    return lookup(ip, l4, r);
}

static __always_inline
int frag_needed(struct xdp_md *ctx, __be32 saddr, __u16 mtu)
{
    // FIXME: checksum doesn't work for much larger packets, unsure why - keep the size down for now
    // maybe the csum_diff helper has a bounded loop and needs to be invoked mutiple times?
    const int max = 128;

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data, eth_new = {};
    struct vlan_hdr *vlan = NULL, vlan_new = {};
    struct iphdr *ip = NULL, ip_copy ={};
    
    if (eth + 1 > data_end)
	return -1;

    eth_new = *eth;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
	vlan = (void *)(eth + 1);
	
	if (vlan + 1 > data_end)
	    return -1;
	
	vlan_new = *vlan;
	
	ip = (void *)(vlan + 1);
    } else {
	ip = (void *)(eth + 1);
    }
    
    if (ip + 1 > data_end)
	return -1;

    ip_copy = *ip;

    /* if DF is not set then drop */
    if (!IS_DF(ip->frag_off))
	return -1;
    
    int iplen = data_end - (void *)ip;

    /* if a packet was smaller than "max" bytes then it should not have been too big - drop */
    if (iplen < max)
      return -1;
    
    // DELIBERATE BREAKAGE
    //ip->daddr = saddr; // prevent the ICMP from changing the path MTU whilst testing
    
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

    *eth = eth_new;
    
    if(vlan) {
	vlan = (void *)(eth + 1);
	
	if (vlan + 1 > data_end)
	    return -1;
	
	*vlan = vlan_new;
	
	ip = (void *)(vlan + 1);
    } else {
	ip = (void *)(eth + 1);
    }

    if (ip + 1 > data_end)
	return -1;
    
    struct icmphdr *icmp = (void *)(ip + 1);
    
    if (icmp + 1 > data_end)
	return -1;
    
    *ip = ip_copy;

    // reverse HW addresses to send ICMP message to client
    memcpy(eth->h_dest, eth_new.h_source, 6);
    memcpy(eth->h_source, eth_new.h_dest, 6);

    // reply to client with LB's address
    ip->daddr = ip_copy.saddr;
    ip->saddr = saddr; // FIXME - how will this work behimd NAT?

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


static __always_inline
int send_frag_needed(struct xdp_md *ctx, __be32 saddr, __u16 mtu)
{
    return (frag_needed(ctx, saddr, mtu) < 0) ? XDP_ABORTED : XDP_TX;
}

SEC("xdp")
int xdp_fwd_func(struct xdp_md *ctx)
{
    //__u64 start = bpf_ktime_get_ns();
    //__u64 start_s = start / SECOND_NS;

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    //int ingress    = ctx->ingress_ifindex;
    //int octets = data_end - data;

    //struct info *info = bpf_map_lookup_elem(&infos, &ZERO);
    //if (!info)
    //return XDP_PASS;

    struct ethhdr *eth = data;
    //__u32 nh_off = sizeof(struct ethhdr);
    
    //if (data + nh_off > data_end)
    //  return XDP_PASS;
    
    if (eth + 1 > data_end)
        return XDP_PASS;

    __be16 next_proto = eth->h_proto;
    void *next_header = eth + 1;
    
    struct vlan_hdr *vlan = NULL;
    
    if (next_proto == bpf_htons(ETH_P_8021Q)) {
	return XDP_PASS; // not yet fully implmented
	vlan = next_header;
	
	if (vlan + 1 > data_end)
	    return XDP_PASS;
	
	next_proto = vlan->h_vlan_encapsulated_proto;
	next_header = vlan + 1;
    }

    if (next_proto != bpf_htons(ETH_P_IP))
	return XDP_PASS;
    
    struct iphdr *ip = next_header;
    
    if (!(next_header = is_ipv4(ip, data_end)))
	return XDP_PASS;

    struct addr daddr = { .addr4.addr = ip->daddr };

    if (!bpf_map_lookup_elem(&vips, &daddr))
    	return XDP_PASS;

    if (ip->ttl <= 1)
	return XDP_DROP;
    
    if (ip->protocol != IPPROTO_TCP)
	return XDP_DROP;

    if (next_header + sizeof(struct tcphdr) > data_end)
	return XDP_DROP;

    struct tcphdr *tcp = next_header;
    struct destination dest = {};

    int mtu = MTU;

    switch (lookup4(ip, tcp, &dest)) {

    case LAYER3_FOU4:
	/* Will the packet and FOU headers exceed the MTU? Send ICMP ICMP_UNREACH/FRAG_NEEDED */
	if ((data_end - ((void *) ip)) + FOU4_OVERHEAD > mtu)
	    return send_frag_needed(ctx, dest.saddr.addr4.addr, mtu - FOU4_OVERHEAD);
	
	/* Encapsulate and send the packet */
	return send_fou4(ctx, &dest);

    case LAYER2_DSR:  /* not implemented yet */
    case LAYER3_FOU6: /* not implemented yet */
    case NOT_FOUND:
	break;
    }
    
    return XDP_DROP; 
}
    
SEC("xdp")
int  xdp_pass_func(struct xdp_md *ctx)
{
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

#endif

