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
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#define IS_DF(f) (((f) & bpf_htons(0x02<<13)) ? 1 : 0)
#define memcpy(d, s, n) __builtin_memcpy((d), (s), (n))
//#define memcmp(d, s, n) __builtin_memcmp((d), (s), (n))
//#define memcmp(d, s, n) (1)

const __u8 F_CALCULATEX_CHECKSUM = 1;
const __u8 F_NOT_LOCAL = 0x80;

#include "imports.h"
#include "vlan.h"


#define VERSION 1
#define SECOND_NS 1000000000l

//const __u32 NETNS = 4095;
const __u32 ZERO = 0;
const __u16 MTU = 1500;

//const __u8 F_STICKY = 0x01;

const __u8 F_CHECKSUM_DISABLE = 0x01;

// https://developers.redhat.com/blog/2019/05/17/an-introduction-to-linux-virtual-interfaces-tunnels

enum lookup_result {
		    NOT_FOUND = 0,
		    NOT_A_VIP,
		    PROBE_REPLY,
		    BOUNCE_ICMP,
		    LAYER2_DSR,
		    LAYER3_GRE,
		    LAYER3_FOU,
		    LAYER3_IPIP,
		    LAYER3_GUE,
};

struct addr4 {
    __be32 pad1;
    __be32 pad2;
    __be32 pad3;
    __be32 addr;
};

//struct addr6 {
//    __u8 addr[16];
//};

struct addr {
    union {
        struct addr4 addr4;
        struct in6_addr addr6;
    };
};

typedef struct addr addr_t;

struct fourtuple {
    struct addr saddr;
    struct addr daddr;
    __be16 sport;
    __be16 dport;
};
typedef struct fourtuple fourtuple_t;

struct fivetuple {
    struct addr saddr;
    struct addr daddr;
    __be16 sport;
    __be16 dport;
    __u16 proto;
};
typedef struct fivetuple fivetuple_t;

// will replace tunnel type
struct destinfo {
    addr_t daddr;
    addr_t saddr;
    __u16 dport;
    __u16 sport;
    __u16 vlanid;
    __u8 method;
    __u8 flags; // no_udp_checksum
    __u8 h_dest[6];   // backend (l2) or router hw address (or nul to return to sender?)
    __u8 h_source[6]; // local hw address
    __u8 pad[12]; // round this up to 64 bytes - the size of a cache line
};

typedef struct destinfo tunnel_t;

static __always_inline
int is_addr4(struct addr *a) {
    return (!(a->addr4.pad1) && !(a->addr4.pad2) && !(a->addr4.pad3)) ? 1 : 0;
}

#include "new.h"



struct vip_rip {
    struct destinfo destinfo;
    addr_t vip;
    addr_t ext;
};

struct servicekey {
    addr_t addr;
    __be16 port;
    __u16 proto;
};

typedef __u8 mac[6];

struct destinations {
    struct destinfo destinfo[256];
    __u8 hash[8192];
};

struct flow {
    tunnel_t tunnel; // contains real IP of server, etc
    
    __u32 time;   // time of last update
    __u16 vlanid; // either VLAN ID for ETH_P_8021Q of index to redirect map for untagged NICs
    __u8 mac[6];

    __u8 finrst;
    __u8 era;
    __u8 version;
};


/**********************************************************************/

struct vrpp {
    addr_t vaddr; // virtual service IP
    addr_t raddr; // real server IP
    __be16 vport; // virtual service port
    __be16 protocol;
};

struct counters {
    __u64 packets;
    __u64 octets;
    __u64 flows;
    __u64 errors;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct vrpp);
    __type(value, struct counters);
    __uint(max_entries, 4095);
} stats SEC(".maps");


/**********************************************************************/

struct netns {
    __u8 a[6];
    __u8 b[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct netns);
    __uint(max_entries, 1);
} netns SEC(".maps");
    
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, addr_t); // nat
    __type(value, struct vip_rip); // vip/rip    
    __uint(max_entries, 4096);
} nat_to_vip_rip SEC(".maps");

struct five_tuple {
    addr_t saddr;
    addr_t daddr;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
};

struct addr_port_time {
    __u64 time;
    addr_t nat;
    addr_t src;
    __be16 port;
    __be16 pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct five_tuple);
    __type(value, struct addr_port_time);
    __uint(max_entries, 65556);
} reply SEC(".maps");


/**********************************************************************/

struct settings {
    __u64 ticker;
    __u8 vetha[6];
    __u8 vethb[6];
    __u8 multi;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct settings);
    __uint(max_entries, 1);
} settings SEC(".maps");


struct vlaninfo {
    __be32 ip4;
    __be32 gw4;
    addr_t ip6;
    addr_t gw6;
    __u8 hw4[6];
    __u8 hw6[6];
    __u8 gh4[6];
    __u8 gh6[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct vlaninfo);
    __uint(max_entries, 4096);
} vlaninfo SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fourtuple);
    __type(value, struct flow);
    __uint(max_entries, 100);
} flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, addr_t);
    __type(value, __u32); // value no longer used
    __uint(max_entries, 4096);
} vips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct servicekey);
    __type(value, struct destinations);
    __uint(max_entries, 4096);
} destinations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4096);
} redirect_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4096);
} redirect_map6 SEC(".maps");

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

static __always_inline
int is_ipv4_addr_p(struct addr *a) {
    return (!a->addr4.pad1 && !a->addr4.pad2 && !a->addr4.pad3) ? 1 : 0;
}

//static __always_inline
int lookup_flow(fourtuple_t *ft, __u8 protocol)
{
    struct flow *flow = bpf_map_lookup_elem(&flows, ft);

    if (flow)
	return 1;
    
    return 0;
}


//static __always_inline
int store_tcp_flow(fourtuple_t *ft, tunnel_t *t, struct flow *f)
{

    if (f) {

	// update existing record - just modify f->
	// updating on a syn does leave open to tcp sniping, but will only affect long lived conns

	// I shall treat this naively, iterating as I learn more - assume not an atta
	
	return 0;
    }

    
    struct flow flow = { .tunnel = *t };
    bpf_map_update_elem(&flows, ft, &flow, BPF_ANY);

    return 0;
}


static __always_inline
enum lookup_result lookup(fivetuple_t *ft, __u8 protocol, tunnel_t *t)
{
    struct servicekey key = { .addr = ft->daddr, .port = bpf_ntohs(ft->dport), .proto = protocol };
    struct destinations *service = bpf_map_lookup_elem(&destinations, &key);

    if (!service)
	return NOT_FOUND;;
    
    __u8 sticky = service->destinfo[0].flags & F_STICKY;
    __u16 hash3 = l3_hash((fourtuple_t *) ft);
    __u16 hash4 = l4_hash((fourtuple_t *) ft);
    __u8 index = service->hash[(sticky ? hash3 : hash4) & 0x1fff]; // limit to 0-8191

    if (!index)
	return NOT_FOUND;
    
    *t = service->destinfo[index];
    t->sport = t->sport ? t->sport : 0x8000 | (hash4 & 0x7fff);

    __u32 vlanid = t->vlanid;

    if (!vlanid)
	return NOT_FOUND;
    
    struct vlaninfo *vlan = bpf_map_lookup_elem(&vlaninfo, &vlanid);

    if (!vlan)
	return NOT_FOUND;

    if (0) {
	addr_t saddr = {};
	__u8 h_source[6];
	__u8 h_gw[6];
	
	// migrate to using per-VLAN details for the tunnel source params - why?
	// oh, yeah, to allow failover from one LB to another rather than store LB local params
	// don't need to do this - just need this unless copying session from shared table
	// useful to test here though
	if (is_ipv4_addr_p(&(t->daddr))) {
	    saddr.addr4.addr = vlan->ip4;
	    memcpy(h_source, vlan->hw4, 6);
	    memcpy(h_gw, vlan->gh4, 6);
	} else {
	    saddr = vlan->ip6;
	    memcpy(h_source, vlan->hw6, 6);
	    memcpy(h_gw, vlan->gh6, 6);
	}
	
	t->saddr = saddr;
	memcpy(t->h_source, h_source, 6);
	
	if ((t->method != T_NONE) && (t->flags & F_NOT_LOCAL)) {
	    bpf_printk("F_NOT_LOCAL\n");
	    memcpy(t->h_dest, h_gw, 6); // send packet to router
	}
    }
	
    if (nulmac(t->h_dest))
	return NOT_FOUND;
    
    switch ((enum tunnel_type) t->method) {
    case T_FOU:  return LAYER3_FOU;
    case T_GRE:  return LAYER3_GRE;
    case T_GUE:  return LAYER3_GUE;
    case T_IPIP: return LAYER3_IPIP;
    case T_NONE: return LAYER2_DSR;
    }
    
   return NOT_FOUND;
}

static __always_inline
enum lookup_result lookup6(struct xdp_md *ctx, struct ip6_hdr *ip6, fivetuple_t *ft, tunnel_t *t)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = (void *)(long)ctx->data;

    if (eth + 1 > data_end)
        return NOT_FOUND;
    
    if (ip6 + 1 > data_end)
        return NOT_FOUND;

    if ((ip6->ip6_ctlun.ip6_un2_vfc >> 4) != 6)
        return NOT_FOUND;

    struct addr saddr = { .addr6 = ip6->ip6_src };
    struct addr daddr = { .addr6 = ip6->ip6_dst };

    if (!bpf_map_lookup_elem(&vips, &daddr)) {
	if (!bpf_map_lookup_elem(&vips, &saddr))
            return NOT_A_VIP;
	
	// source was a VIP - send to netns via veth interface
	struct netns *ns = bpf_map_lookup_elem(&netns, &ZERO);

	if (!ns || nulmac(ns->a) || nulmac(ns->b))
	    return NOT_FOUND;
	
	memcpy(eth->h_dest, ns->b, 6);
	memcpy(eth->h_source, ns->a, 6);
	
        return PROBE_REPLY;
    }

    ft->saddr = saddr;
    ft->daddr = daddr;
    ft->proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

    if (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim <= 1)
	return NOT_FOUND; // FIXME - new enum

    (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim)--;
    
    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    struct icmp6_hdr *icmp = NULL;
    
    switch (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
    case IPPROTO_TCP:
	tcp = (void *) (ip6 + 1);
	if (tcp + 1 > data_end)
	    return NOT_FOUND;
	ft->sport = tcp->source;
	ft->dport = tcp->dest;
	break;
	
    case IPPROTO_UDP:
	udp = (void *) (ip6 + 1);
	if (udp + 1 > data_end)
	    return NOT_FOUND;
	ft->sport = udp->source;
	ft->dport = udp->dest;
	break;
	
    case IPPROTO_ICMPV6:
	icmp = (void *)(ip6 + 1);
        if (icmp + 1 > data_end)
            return NOT_FOUND;
	if (icmp->icmp6_type == ICMP6_ECHO_REQUEST && icmp->icmp6_code == 0) {
	    bpf_printk("ICMPv6\n");
            ip6_reply(ip6, 64); // swap saddr/daddr, set TTL
	    struct icmp6_hdr old = *icmp;
            icmp->icmp6_type = ICMP6_ECHO_REPLY;
	    icmp->icmp6_cksum = icmp6_csum_diff(icmp, &old);
            reverse_ethhdr(eth);
	    return BOUNCE_ICMP;
	}
	return NOT_FOUND;
	
    default:
	return NOT_FOUND;
    }

    enum lookup_result r = lookup(ft, ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt, t);

    //if (LAYER2_DSR == r && ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim > 1)
    //	ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = 1;

    if (LAYER2_DSR == r && ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim > 1)
	ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = 1;

    return r;
}

static __always_inline
enum lookup_result lookup4(struct xdp_md *ctx, struct iphdr *ip, fivetuple_t *ft, tunnel_t *t)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = (void *)(long)ctx->data;

    if (eth + 1 > data_end)
        return NOT_FOUND;
    
    if (ip + 1 > data_end)
	return NOT_FOUND;
    
    if (ip->version != 4)
	return NOT_FOUND;
    
    if (ip->ihl != 5)
        return NOT_FOUND;
    
    if (ip->ttl <= 1)
	return NOT_FOUND; // FIXME - new enum
    
    // ignore evil bit and DF, drop if more fragments flag set, or fragent offset is not 0
    if ((ip->frag_off & bpf_htons(0x3fff)) != 0)
        return NOT_FOUND; // FIXME - new enum;
    
    struct addr saddr = { .addr4.addr = ip->saddr };
    struct addr daddr = { .addr4.addr = ip->daddr };
    
    if (!bpf_map_lookup_elem(&vips, &daddr)) {
	
	if (!bpf_map_lookup_elem(&vips, &saddr))
	    return NOT_A_VIP;
	
	// source was a VIP - send to netns via veth interface
	struct netns *ns = bpf_map_lookup_elem(&netns, &ZERO);
	
        if (!ns || nulmac(ns->a) || nulmac(ns->b))
            return NOT_FOUND;
	
        memcpy(eth->h_dest, ns->b, 6);
        memcpy(eth->h_source, ns->a, 6);
	
	return PROBE_REPLY;
    }

    ft->saddr = saddr;
    ft->daddr = daddr;
    ft->proto = ip->protocol;
	
    /* We're going to forward the packet, so we should decrement the time to live */
    ip_decrease_ttl(ip);    

    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    struct icmphdr *icmp = NULL;
    
    switch (ip->protocol) {
    case IPPROTO_TCP:
	tcp = (void *)(ip + 1);
	if (tcp + 1 > data_end)
	    return NOT_FOUND;
	ft->sport = tcp->source;
	ft->dport = tcp->dest;
	break;
	
    case IPPROTO_UDP:
	udp = (void *)(ip + 1);
	if (udp + 1 > data_end)
	    return NOT_FOUND;
	ft->sport = udp->source;
	ft->dport = udp->dest;
	break;
	
    case IPPROTO_ICMP:
	icmp = (void *)(ip + 1);
	if (icmp + 1 > data_end)
            return NOT_FOUND;
	if (icmp->type == ICMP_ECHO && icmp->code == 0) {
	    bpf_printk("ICMPv4\n");
	    ip4_reply(ip, 64); // swap saddr/daddr, set TTL
	    struct icmphdr old = *icmp;
	    icmp->type = ICMP_ECHOREPLY;
            icmp->checksum = icmp4_csum_diff(icmp, &old);
	    reverse_ethhdr(eth);
	    return BOUNCE_ICMP;
	}
	return NOT_FOUND;	

    default:
	return NOT_FOUND;
    }
    
    enum lookup_result r = lookup(ft, ip->protocol, t);

    if (LAYER2_DSR == r && ip->ttl > 1)
	ip4_set_ttl(ip, 1);
    
    return r;
}

static __always_inline
int xdp_fwd_func_(struct xdp_md *ctx, fivetuple_t *ft, tunnel_t *t)
{

    int mtu = MTU;
    int overhead = 0;
    enum lookup_result result = NOT_A_VIP;
    int vip_is_ipv6 = 0;
    
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    //int ingress    = ctx->ingress_ifindex;
    //int octets = data_end - data;

    struct ethhdr *eth = data;
    
    if (eth + 1 > data_end)
        return XDP_PASS; // or drop?
    
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

    //__builtin_memset(t, 0, sizeof(tunnel_t)); // was a temp fix
    
    switch (next_proto) {
    case bpf_htons(ETH_P_IPV6):
	vip_is_ipv6 = 1;
	overhead = sizeof(struct ip6_hdr);
	result = lookup6(ctx, next_header, ft, t);
	break;
    case bpf_htons(ETH_P_IP):
	vip_is_ipv6 = 0;
	overhead = sizeof(struct iphdr);
	result = lookup4(ctx, next_header, ft, t);
	break;
    default:
	return XDP_PASS;
    }

    overhead = is_ipv4_addr(t->daddr) ? sizeof(struct iphdr) : sizeof(struct ip6_hdr);

    // no default here - handle all cases explicitly
    switch (result) {
    case LAYER2_DSR: break; //return send_l2(ctx, t);
    case LAYER3_GRE: overhead += GRE_OVERHEAD; break;
    case LAYER3_FOU: overhead += FOU_OVERHEAD; break;
    case LAYER3_GUE: overhead += GUE_OVERHEAD; break;
    case LAYER3_IPIP: break;
    case NOT_A_VIP: return XDP_PASS;
    case NOT_FOUND: return XDP_DROP;
    case BOUNCE_ICMP: return XDP_TX;
    case PROBE_REPLY:
	if (vlan && vlan_pop(ctx) < 0) return XDP_DROP;
	//return bpf_redirect_map(&redirect_map, NETNS, XDP_DROP);
	return bpf_redirect_map(&redirect_map, 0, XDP_DROP);	
    }

    switch (result) {
    case LAYER3_GRE: // fallthough
    case LAYER3_FOU: // fallthough
    case LAYER3_GUE: // fallthough
    case LAYER3_IPIP:
	if ((data_end - next_header) + overhead > mtu) {
	    if (vip_is_ipv6) {
		bpf_printk("IPv6 FRAG_NEEDED - FIXME\n");
		return icmp6_too_big(ctx, &(ft->daddr.addr6),  &(ft->saddr.addr6), mtu - overhead) < 0 ? XDP_ABORTED : XDP_TX;
		
	    } else {
		bpf_printk("IPv4 FRAG_NEEDED - FIXME\n");
		return frag_needed4(ctx, ft->saddr.addr4.addr, mtu) < 0 ? XDP_ABORTED : XDP_TX;
	    }
	}
	break;
    default:
	break;
    }

    // update VLAN ID to that of the target if packet is tagged
    if (vlan)
	vlan->h_vlan_TCI = (vlan->h_vlan_TCI & bpf_htons(0xf000)) | (bpf_htons(t->vlanid) & bpf_htons(0x0fff));
    
    switch (result) {
    case LAYER2_DSR:  return send_l2(ctx, t);	
    case LAYER3_IPIP: return send_ipip(ctx, t, vip_is_ipv6);
    case LAYER3_GRE:  return send_gre(ctx, t, vip_is_ipv6);
    case LAYER3_FOU:  return send_fou(ctx, t);
    case LAYER3_GUE:  return send_gue(ctx, t, vip_is_ipv6); // TODO - breaks verifier on 22.04
    default:
	break;
    }
    return XDP_DROP; 
}

//static __always_inline
void update(fourtuple_t *key, tunnel_t *t)
{
    /*
    //struct fourtuple key = { .sport = sport, .dport = dport };
    struct flow val = { .tunnel = *t };
    
    if (bpf_map_update_elem(&flows, key, &val, BPF_ANY)) {
	bpf_printk("ERR\n");
    } else {
	bpf_printk("OK\n");
    }
    */
}



static __always_inline
int xdp_request_v6(struct xdp_md *ctx) {
   
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    
    if (eth + 1 > data_end)
        return XDP_DROP;
    
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
       	return XDP_PASS;
    
    struct ip6_hdr *ip6 = (void *)(eth + 1);
    
    if (ip6 + 1 > data_end)
        return XDP_DROP;
    

    if ((ip6->ip6_ctlun.ip6_un2_vfc >> 4) != 6)
        return XDP_DROP;
    

    bpf_printk("PRIOR %d %d\n", ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim, ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);

    if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6)
	//return XDP_DROP;
	return XDP_PASS;

    bpf_printk("AFTER %d\n", ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);

    if (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim <= 1)
    	return XDP_DROP;
    

    (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim)--;

    addr_t src = { .addr6 = ip6->ip6_src };
    addr_t nat = { .addr6 = ip6->ip6_dst };
    struct vip_rip *vip_rip = bpf_map_lookup_elem(&nat_to_vip_rip, &nat);
    
    if (!vip_rip)
        return XDP_PASS;

    bpf_printk("AAAARSE\n");


    __u8 proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    addr_t vip = vip_rip->vip;
    addr_t ext = vip_rip->ext;
    __be16 eph = 0;
    __be16 svc = 0;

    struct l4 ft = { .saddr = src.addr4.addr, .daddr = nat.addr4.addr, .sport = eph, .dport = svc };
    struct destinfo *destinfo = (void *) vip_rip;

    tunnel_t t = *destinfo;
    t.sport = t.sport ? t.sport : (0x8000 | (l4_hash_(&ft) & 0x7fff));

    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    
    switch(proto) {
    case IPPROTO_TCP:
	tcp = (void *) (ip6 + 1);
	if (tcp + 1 > data_end)
	    return XDP_DROP;
	eph = tcp->source;
	svc = tcp->dest;
	break;
    case IPPROTO_UDP:
	udp = (void *) (ip6 + 1);
	if (udp + 1 > data_end)
	    return XDP_DROP;
	eph = udp->source;
	svc = udp->dest;
	break;
    default:
	return XDP_DROP;
    }
    
    struct l4v6 o = {.saddr = ip6->ip6_src, .daddr = ip6->ip6_dst, .sport = eph, .dport = svc };
    struct l4v6 n = o;
    
    n.saddr = ip6->ip6_src = ext.addr6; // the source address of the NATed packet needs to be the LB's external IP
    n.daddr = ip6->ip6_dst = vip.addr6; // the destination needs to the that of the VIP that we are probing
    
     switch(proto) {
     case IPPROTO_TCP:
	 tcp->check = l4v6_checksum_diff(~(tcp->check), &n, &o);
	 break;
     case IPPROTO_UDP:
	 udp->check = l4v6_checksum_diff(~(udp->check), &n, &o);
	 break;
     }

    int action = XDP_DROP;

    switch (t.method) {
    case T_NONE: action = send_l2(ctx, &t); break;
    case T_IPIP: action = send_ipip(ctx, &t, 1); break;
    case T_GRE:  action = send_gre(ctx, &t, 1); break;
    case T_FOU:  action = send_fou(ctx, &t); break;
    case T_GUE:  action = send_gue(ctx, &t, 1); break;
    }

    if (action != XDP_TX || !t.vlanid) // verifier shenanigans if I check for !t.vlanid earlier!
        return XDP_DROP;


    // to match returning packet
    struct five_tuple rep = { .sport = svc, .dport = eph, .protocol = proto };
    rep.saddr = vip; // ???? upsets verifier if in declaration above
    rep.daddr = ext; // ???? upsets verifier if in declaration above

    struct addr_port_time map = { .port = eph, .time = bpf_ktime_get_ns() };
    map.nat = nat; // ??? upsets verifier if in declaration above
    map.src = src; // ??? upsets verifier if in declaration above    

    bpf_map_update_elem(&reply, &rep, &map, BPF_ANY);
    
    //return bpf_redirect(vlaninfo->ifindex, 0);
    return is_ipv4_addr(t.daddr) ?
	bpf_redirect_map(&redirect_map, t.vlanid, XDP_DROP) :
	bpf_redirect_map(&redirect_map6, t.vlanid, XDP_DROP);
}

static __always_inline
int xdp_request_v4(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    
    if (eth + 1 > data_end)
        return XDP_DROP;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
	return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    
    if (ip + 1 > data_end)
	return XDP_DROP;

    if (ip->version != 4)
	return XDP_DROP;
    
    if (ip->ihl != 5)
        return XDP_DROP;
    
    // ignore evil bit and DF, drop if more fragments flag set, or fragent offset is not 0
    if ((ip->frag_off & bpf_htons(0x3fff)) != 0)
        return XDP_DROP;

    if (ip->ttl <= 1)
	return XDP_DROP;

    ip_decrease_ttl(ip); // forwarding, so decrement TTL

    
    addr_t src = { .addr4.addr = ip->saddr };
    addr_t nat = { .addr4.addr = ip->daddr };
    struct vip_rip *vip_rip = bpf_map_lookup_elem(&nat_to_vip_rip, &nat);

    if (!vip_rip)
    	return XDP_PASS;

    
    __u8 proto = ip->protocol;
    addr_t vip = vip_rip->vip;
    addr_t ext = vip_rip->ext;
    __be16 eph = 0;
    __be16 svc = 0;

    struct l4 ft = { .saddr = ip->saddr, .daddr = ip->daddr, .sport = eph, .dport = svc };
    struct destinfo *destinfo = (void *) vip_rip;
    
    tunnel_t t = *destinfo;
    t.sport = t.sport ? t.sport : ( 0x8000 | (l4_hash_(&ft) & 0x7fff));

    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;

    switch(proto) {
    case IPPROTO_TCP:
	tcp = (void *)(ip + 1);
	if (tcp + 1 > data_end)
	    return XDP_DROP;
	eph = tcp->source;
	svc = tcp->dest;
	break;
    case IPPROTO_UDP:
	udp = (void *)(ip + 1);
	if (udp + 1 > data_end)
	    return XDP_DROP;
	eph = udp->source;
	svc = udp->dest;
	break;
    default:
	return XDP_DROP;
    }

    int overhead = 0;
    int mtu = MTU;

    switch (t.method) {
    case T_GRE:  overhead = sizeof(struct iphdr) + GRE_OVERHEAD; break;
    case T_FOU:  overhead = sizeof(struct iphdr) + FOU_OVERHEAD; break;
    case T_GUE:  overhead = sizeof(struct iphdr) + GUE_OVERHEAD; break;
    case T_IPIP: overhead = sizeof(struct iphdr);  break;
    case T_NONE: break;
    default: return XDP_DROP;
    }

    if ((data_end - (void *) ip) + overhead > mtu) {
	return XDP_DROP;
    }

    /*
    if ((data_end - (void *) ip) + overhead > mtu) {
	bpf_printk("IPv4 FRAG_NEEDED\n");
	__be32 internal = vlaninfo->source_ipv4;
	return send_frag_needed4(ctx, internal, mtu - overhead);
    }
    */

    // save l3/l4 parameters for checksum diffs
    struct l4 o = { .saddr = ip->saddr, .daddr = ip->daddr, .sport = eph, .dport = svc };    
    struct l4 n = o;
    struct iphdr old = *ip;
    
    // update l3 addresses
    n.saddr = ip->saddr = ext.addr4.addr;
    n.daddr = ip->daddr = vip.addr4.addr;

    // calculate new l3 checksum
    ip->check = ip4_csum_diff(ip, &old);

    // calculate new l4 checksum
    switch(proto) {
    case IPPROTO_TCP:
	tcp->check = l4_csum_diff(&n, &o, tcp->check);
	break;
    case IPPROTO_UDP:
	udp->check = l4_csum_diff(&n, &o, udp->check);
	break;
    }

    
    /**********************************************************************/

    int is_ipv6 = 0;
    int action = XDP_DROP;
    
    switch (t.method) {
    case T_NONE: action = send_l2(ctx, &t); break;
    case T_IPIP: action = send_ipip(ctx, &t, is_ipv6); break;
    case T_GRE:	 action = send_gre(ctx, &t, is_ipv6); break;
    case T_FOU:  action = send_fou(ctx, &t); break;
    case T_GUE:  action = send_gue(ctx, &t, is_ipv6); break;
    }

    if (action != XDP_TX || !t.vlanid) // verifier shenanigans if I check for !t.vlanid earlier!
	return XDP_DROP;

    // to match returning packet
    struct five_tuple rep = { .sport = svc, .dport = eph, .protocol = proto };
    rep.saddr = vip; // ???? upsets verifier if in declaration above
    rep.daddr = ext; // ???? upsets verifier if in declaration above
    
    struct addr_port_time map = { .port = eph, .time = bpf_ktime_get_ns() };
    map.nat = nat; // ??? upsets verifier if in declaration above
    map.src = src; // ??? upsets verifier if in declaration above    
    
    bpf_map_update_elem(&reply, &rep, &map, BPF_ANY);
    //return bpf_redirect_map(&redirect_map, t.vlanid, XDP_DROP);

    bpf_printk("REDIRECTING %d\n", t.vlanid);
    
    return is_ipv4_addr(t.daddr) ?
        bpf_redirect_map(&redirect_map, t.vlanid, XDP_DROP) :
        bpf_redirect_map(&redirect_map6, t.vlanid, XDP_DROP);
}

static __always_inline
int xdp_reply_v6(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    
    if (eth + 1 > data_end)
        return XDP_DROP;
    
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
       	return XDP_PASS;
    
    struct ip6_hdr *ip6 = (void *)(eth + 1);
    
    if (ip6 + 1 > data_end)
        return XDP_DROP;
    
    if ((ip6->ip6_ctlun.ip6_un2_vfc >> 4) != 6)
        return XDP_DROP;
    
    if(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6) {
        //return XDP_PASS;
	return XDP_DROP;
    }

    if (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim <= 1)
	return XDP_DROP;

    (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim)--;
        
    __u8 proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    addr_t saddr = { .addr6 = ip6->ip6_src };
    addr_t daddr = { .addr6 = ip6->ip6_dst };    
    
    struct five_tuple rep = { .protocol = proto };
    rep.saddr = saddr; // ??? upsets verifier if in declaration above
    rep.daddr = daddr; // ??? upsets verifier if in declaration above

    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
	
    switch(proto) {
    case IPPROTO_TCP:
	tcp = (void *) (ip6 + 1);
	if (tcp + 1 > data_end)
	    return XDP_DROP;
	rep.sport = tcp->source;
	rep.dport = tcp->dest;
	break;
    case IPPROTO_UDP:
	udp = (void *) (ip6 + 1);
	if (udp + 1 > data_end)
	    return XDP_DROP;
	rep.sport = udp->source;
	rep.dport = udp->dest;
	break;
    default:
	return XDP_DROP;
    }

    struct addr_port_time *match = bpf_map_lookup_elem(&reply, &rep);
    
    if (!match)
	return XDP_DROP;
    
    __u64 time = bpf_ktime_get_ns();

    if (time < match->time)
	return XDP_DROP;

    if ((time - match->time) > (5 * SECOND_NS))
	return XDP_DROP;

    struct l4v6 o = {.saddr = ip6->ip6_src, .daddr = ip6->ip6_dst, .sport = rep.sport, .dport = rep.dport };
    struct l4v6 n = o;
    
    n.saddr = ip6->ip6_src = match->nat.addr6; // reply comes from the NAT addr
    n.daddr = ip6->ip6_dst = match->src.addr6; // to the internal NETNS address
    
    switch(proto) {
    case IPPROTO_TCP:
	tcp->check = l4v6_csum_diff(&n, &o, tcp->check);
	break;
    case IPPROTO_UDP:
	udp->check = l4v6_csum_diff(&n, &o, udp->check);
	break;
    }
    
    return XDP_PASS;
}

static __always_inline
int xdp_reply_v4(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    
    if (eth + 1 > data_end)
        return XDP_DROP;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
	return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    
    if (ip + 1 > data_end)
	return XDP_DROP;
        
    if (ip->version != 4)
        return XDP_DROP;
    
    if (ip->ihl != 5)
        return XDP_DROP;
    
    if (ip->ttl <= 1)
        return XDP_DROP;
    
    ip_decrease_ttl(ip); // forwarding, so decrement TTL
    
    // ignore evil bit and DF, drop if more fragments flag set, or fragent offset is not 0
    if ((ip->frag_off & bpf_htons(0x3fff)) != 0)
        return XDP_DROP;
    
    __u8 proto = ip->protocol;
    addr_t saddr = { .addr4.addr = ip->saddr };
    addr_t daddr = { .addr4.addr = ip->daddr };    

    struct five_tuple rep = { .protocol = proto };
    rep.saddr = saddr; // ??? upsets verifier if in declaration above
    rep.daddr = daddr; // ??? upsets verifier if in declaration above
    
    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;    

    switch(proto) {
    case IPPROTO_TCP:
	tcp = (void *)(ip + 1);
	if (tcp + 1 > data_end)
	    return XDP_DROP;
	rep.sport = tcp->source;
	rep.dport = tcp->dest;
	break;
    case IPPROTO_UDP:
	udp = (void *)(ip + 1);
	if (udp + 1 > data_end)
	    return XDP_DROP;
	rep.sport = udp->source;
	rep.dport = udp->dest;
	break;
    default:
	return XDP_DROP;    
    }
    
    struct l4 o = { .saddr = ip->saddr, .daddr = ip->daddr };
    struct l4 n = o;
    struct iphdr old = *ip;
    
    struct addr_port_time *match = bpf_map_lookup_elem(&reply, &rep);
    
    if (!match)
	return XDP_DROP;
    
    __u64 time = bpf_ktime_get_ns();
    
    if (time < match->time)
	return XDP_DROP;
    
    if ((time - match->time) > (5 * SECOND_NS))
	return XDP_DROP;
    
    n.saddr = ip->saddr = match->nat.addr4.addr; // reply comes from the NAT addr
    n.daddr = ip->daddr = match->src.addr4.addr; // to the internal NETNS address

    //ip->check = ipv4_checksum_diff(~(ip->check), ip, &old);
    ip->check = ip4_csum_diff(ip, &old);
    
    switch(proto) {
    case IPPROTO_TCP:
	//tcp->check = l4_checksum_diff(~(tcp->check), &n, &o);
	tcp->check = l4_csum_diff(&n, &o, tcp->check);
	break;
    case IPPROTO_UDP:
	//udp->check = l4_checksum_diff(~(udp->check), &n, &o);
	udp->check = l4_csum_diff(&n, &o, udp->check);
	break;
    }
    
    return XDP_PASS;
}


SEC("xdp")
int xdp_fwd_func(struct xdp_md *ctx)
{
    __u64 start = bpf_ktime_get_ns();
    __u64 start_s = start / SECOND_NS;
    __u64 timeout = 60; // seconds

    struct settings *s = bpf_map_lookup_elem(&settings, &ZERO);
    if (!s)
	return XDP_PASS;

    if (s->ticker == 0) {
	s->ticker = start_s;
    } else if (s->ticker + timeout < start_s) {
	return XDP_PASS; // ticker hasn't been reset for 2mins - fail safe
    }

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    //int ingress    = ctx->ingress_ifindex;
    
    struct ethhdr *eth = data;
    
    if (eth + 1 > data_end)
        return XDP_DROP; // or drop?
    
    __u8 dot1q = 0;
    
    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
	dot1q = 1;
    }
    
    //fourtuple_t ft = {};
    fivetuple_t ft = {};    
    tunnel_t t = {};
    
    int action = xdp_fwd_func_(ctx, &ft, &t);
    
    struct vrpp vrpp = { .vaddr = ft.daddr, .raddr = t.daddr, .vport = ntohs(ft.dport), .protocol = ft.proto };
    struct counters *c = bpf_map_lookup_elem(&stats, &vrpp);

    if (c) {
	c->packets++;
	c->octets += data_end - data;
    }
    
    // handle stats here
    switch (action) {
    case XDP_PASS: return XDP_PASS;
    case XDP_DROP: return XDP_DROP;
    case XDP_TX:

	switch (s->multi) {
	case 0: // untagged bond - multi NIC, but only single VLAN in config
	    return XDP_TX; // possible efficiency, rather than XDP_REDIRECT to the bond device
	case 1: // single interface - TX either tagged or untagged
	    return XDP_TX;
	default:
	    if (dot1q) return XDP_TX; // muti-interface, if tagged packets then just TX to appropriate VLAN
	    return bpf_redirect_map(&redirect_map, t.vlanid, XDP_DROP); // otherwise redirect to interface
	}

	return XDP_DROP;
	
	//took = bpf_ktime_get_ns() - start;
	//int ack = dest.flags.ack ? 1 : 0;	
	//int syn = dest.flags.syn ? 1 : 0;	
	//bpf_printk("TOOK: %d\n", took);
	//bpf_printk("FT %d %d\n", bpf_ntohs(ft.sport), bpf_ntohs(ft.dport));
	//update(&ft, &t);
	return XDP_TX;
    case XDP_ABORTED: return XDP_ABORTED;
    case XDP_REDIRECT: return XDP_REDIRECT;
    }
    return XDP_PASS;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    return XDP_PASS;
}

SEC("xdp")
int xdp_vethb(struct xdp_md *ctx)
{
    __u64 start = bpf_ktime_get_ns();
    __u64 start_s = start / SECOND_NS;
    __u64 timeout = 60; // seconds

    struct settings *s = bpf_map_lookup_elem(&settings, &ZERO);
    if (!s)
	return XDP_PASS;

    if (s->ticker == 0) {
	s->ticker = start_s;
    } else if (s->ticker + timeout < start_s) {
	return XDP_PASS; // ticker hasn't been reset - fail safe
    }

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;

    bpf_printk("vethb got data\n");

    if (eth + 1 > data_end)
        return XDP_DROP;

    /*
    switch(eth->h_proto) {
    case bpf_htons(ETH_P_IP):
	return xdp_reply_v4(ctx);	
    case bpf_htons(ETH_P_IPV6):
	return xdp_reply_v6(ctx);
    }

    return XDP_PASS;
    */

    struct iphdr *ip = (void *)(eth + 1);
    struct ip6_hdr *ip6 = (void *)(eth + 1);
    
    switch(eth->h_proto) {
    case bpf_htons(ETH_P_IP):
	if (ip + 1 > data_end)
	    return XDP_DROP;
	
	switch(ip->protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	    reverse_ethhdr(eth);
	    bpf_printk("BOUNCE v4!!!!!!!!!!!\n");
	    return XDP_TX;
	}
	return XDP_PASS;
	
    case bpf_htons(ETH_P_IPV6):
	if (ip6 + 1 > data_end)
	    return XDP_DROP;
	
	switch(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	    reverse_ethhdr(eth);
	    bpf_printk("BOUNCE v6!!!!!!!!!!!\n");
	    return XDP_TX;
	}
	return XDP_PASS;
    }
    
    return XDP_PASS;
}

SEC("xdp")
int xdp_vetha(struct xdp_md *ctx)
{
    // TODO - have probes set from host side to NAT addresses via
    // veth, process on ns side and TX *back* to through veth, host
    // side veth then forwards out to the destination. Returning
    // traffic is forwarded from physical nic to the veth, mapped back
    // to NAT addresses and TX back to host. Obviates the need to exec
    // anything in the namespace!
    
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    
    if (eth + 1 > data_end)
	return XDP_DROP;

    /*
    switch(eth->h_proto) {
    case bpf_htons(ETH_P_IP):
	return xdp_request_v4(ctx);
    case bpf_htons(ETH_P_IPV6):
	return xdp_request_v6(ctx);
    }

    return XDP_PASS;
    */


    
    switch(eth->h_proto) {
	
    case bpf_htons(ETH_P_IP):
	if (XDP_PASS == xdp_reply_v4(ctx))
	    return XDP_PASS;
	return xdp_request_v4(ctx);
    case bpf_htons(ETH_P_IPV6):
	if (XDP_PASS == xdp_reply_v6(ctx))
            return XDP_PASS;
        return xdp_request_v6(ctx);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

#endif

/*
enum xdp_action {
        XDP_ABORTED = 0,
        XDP_DROP = 1,
        XDP_PASS = 2,
        XDP_TX = 3 ,
        XDP_REDIRECT = 4,
};

*/
