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

const __u8 F_CALCULATEX_CHECKSUM = 1;
const __u8 F_NOT_LOCAL = 0x80;

#include "imports.h"
#include "vlan.h"


#define VERSION 1
#define SECOND_NS 1000000000l

const __u32 ZERO = 0;
const __u16 MTU = 1500;
const __u64 TIMEOUT = 300; // seconds

//#define EXT_CORRUPT 252
//#define EXT_FRAG 253
//#define EXT_ICMP 254
//#define EXT_VETH 255


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

enum fwd_action {
    FWD_PASS = XDP_PASS,
    FWD_DROP = XDP_DROP,
    FWD_TX = XDP_TX,
    FWD_REDIRECT = XDP_REDIRECT,
    FWD_ABORTED = XDP_ABORTED,

    FWD_FAIL = 251,
    FWD_ICMP = 252,
    FWD_VETH = 253,
    FWD_FRAG = 254,
    FWD_CORRUPT = 255,
};

struct addr4 {
    __be32 pad1;
    __be32 pad2;
    __be32 pad3;
    __be32 addr;
};

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
struct tunnel {
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

typedef struct tunnel tunnel_t;

static __always_inline
int is_addr4(struct addr *a) {
    return (!(a->addr4.pad1) && !(a->addr4.pad2) && !(a->addr4.pad3)) ? 1 : 0;
}

#include "new.h"

struct five_tuple {
    addr_t saddr;
    addr_t daddr;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
};

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4096);
} redirect_map4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4096);
} redirect_map6 SEC(".maps");


#include "nat.h"


struct servicekey {
    addr_t addr;
    __be16 port;
    __u16 proto;
};

struct service {
    tunnel_t dest[256];
    __u8 hash[8192];
};
typedef struct service service_t;

struct flow {
    tunnel_t tunnel; // contains real IP of server, etc (64)
    __u64 time; // +8 = 72
    __u32 syn_seqn_reserved;
    __u8 finrst;
    __u8 era;
    __u8 pad;
    __u8 version; // +8 = 80
};
typedef struct flow flow_t;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_CPU_SUPPORT);
    __array(
            values,
            struct {
                __uint(type, BPF_MAP_TYPE_LRU_HASH);
		// strangely, some struct names don't work for all systems, but the following __u8 array workaround does:
                //__type(key, fourtuple_t);
		//__type(value, flow_t);
                __type(key, __u8[sizeof(fourtuple_t)]);
                __type(value, __u8[sizeof(flow_t)]);
                __uint(max_entries, FLOW_STATE_SIZE);
            });
} flows_tcp SEC(".maps");

// eventually, track flow for ~30s, reselect backend, and time flow
// out after ~120s - allows for breaking tie to a down server, whilst
// getting a rough idea about concurrent users
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, fourtuple_t);
    __type(value, flow_t);
    __uint(max_entries, FLOW_STATE_SIZE);
} flows_udp SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, fourtuple_t);
    __type(value, flow_t);
    __uint(max_entries, FLOW_STATE_SIZE);
} shared SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, __u8[sizeof(fourtuple_t) + sizeof(flow_t)]);
    __uint(max_entries, FLOW_QUEUE_SIZE);
} flow_queue SEC(".maps");

/**********************************************************************/

struct vrpp {
    addr_t vaddr; // virtual service IP
    addr_t raddr; // real server IP
    __be16 vport; // virtual service port
    __s16 protocol;
};
typedef struct vrpp vrpp_t;

struct counters {
    __u64 packets;
    __u64 octets;
    __u64 flows;
    __u64 errors;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, vrpp_t);
    __type(value, __s64);
    __uint(max_entries, 65536);
} vrpp_concurrent SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct vrpp);
    __type(value, struct counters);
    __uint(max_entries, 4095);
} stats SEC(".maps");



/**********************************************************************/

struct globals {
    __u64 corrupt; // malformed packet
    __u64 failed;  // modifying packet (adust head/tail) failed
    __u64 fragmented; // fragmented l4 packets - per service?
    __u64 icmp_echo_request;  // per vip?
    
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct globals);
    __uint(max_entries, 1);
} globals SEC(".maps");

struct settings {
    __u64 watchdog;
    __u64 packets;
    __u64 latency;
    __u32 veth;
    __u8 vetha[6];
    __u8 vethb[6];
    __u8 multi;
    __u8 era;
    __u8 active;
    __u8 pad[5]; // must be multiple of 8 bytes
};
typedef struct settings settings_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct settings);
    __uint(max_entries, 1);
} settings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, addr_t);
    __type(value, __u32); // value no longer used
    __uint(max_entries, 4096);
} vips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct servicekey);
    __type(value, service_t);
    __uint(max_entries, 4096);
} services SEC(".maps"); // rename to "services"?

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

/**********************************************************************/

/*

  assumes some method of screening out bogus SYN/ACK - anti DDoS box which sees both legs of the conversation

  
  if existing flow and SYN received:

  if flow older than 60s - drop old flow. Don't store SYN

  if live flow then store sequence number in flow but return NULL - new b/e lookup don't store SYN flows, so won't get overwritten

  when next packet comes in flow is found: compare seqn - if correct then delete flow, same backend will the chosen

  if incorrect then continue regular flow
  
 */

static __always_inline
flow_t *lookup_tcp_flow(void *flows, fourtuple_t *ft, __u8 syn)
{
    if (!flows)
	return NULL;

    if (syn) {
	bpf_map_delete_elem(flows, ft);
	return NULL;
    }
    
    flow_t *flow = bpf_map_lookup_elem(flows, ft);
    
    if (!flow)
	return NULL;

    __u64 time = bpf_ktime_get_ns();

    if (flow->time + (90 * SECOND_NS) < time)
    	return NULL;

    if (flow->time + (60 * SECOND_NS) > time)
	return flow;

    flow->time = time;

    struct flow_queue_entry {
	fourtuple_t ft;
	flow_t flow;
    } flow_queue_entry = { .ft = *ft, .flow = *flow };

    int r = bpf_map_push_elem(&flow_queue, &flow_queue_entry, 0);

    bpf_printk("FQE %d", r);
    
    return flow;
}

static __always_inline
flow_t *lookup_udp_flow(void *flows, fourtuple_t *ft)
{
    if (!flows)
	return NULL;
    
    flow_t *flow = bpf_map_lookup_elem(flows, ft);

    if (!flow)
	return NULL;

    __u64 time = bpf_ktime_get_ns();

    if (flow->time + (120 * SECOND_NS) < time)
    	return NULL;

    return flow;
}

static __always_inline
int store_flow(void *flows, fourtuple_t *ft, tunnel_t *t, __u8 era)
{
    if (!flows)
	return -1;

    __u64 time = bpf_ktime_get_ns();
    flow_t flow = { .tunnel = *t, .time = time, .era = era };
    bpf_map_update_elem(flows, ft, &flow, BPF_ANY);

    return 0;
}

void *array_of_maps(void *outer) {
    __u32 cpu_id = bpf_get_smp_processor_id();
    return bpf_map_lookup_elem(outer, &cpu_id);
}

struct metadata {
    __u32 octets;
    __u32 syn : 1;
    __u32 ack : 1;
    __u32 rst : 1;
    __u32 fin : 1;
};
typedef struct metadata metadata_t;

static __always_inline
void tcp_concurrent(vrpp_t vr, metadata_t *tcp, flow_t *flow, __u8 era)
{
    vr.protocol |= era%2 ? 0xff00 : 0x0000;
    __s64 *concurrent = bpf_map_lookup_elem(&vrpp_concurrent, &vr);

    // we don't get SYNs any more - they will delete a session instead
    if (tcp->syn == 1)
        flow->finrst = 0;
    
    if (flow->finrst == 0 && ((tcp->rst == 1) || (tcp->fin == 1))) {
        flow->finrst = 10;
    } else {
        if (flow->finrst > 0)
            (flow->finrst)--;
    }
    
    if (flow->era != era || tcp->syn == 1) {
        flow->era = era;

        switch(flow->finrst) {
        case 10:
            break;
        case 0:
            if (concurrent)
		(*concurrent)++;
            break;
        }
    } else {
        switch(flow->finrst) {
        case 10:
	    if (concurrent)
		(*concurrent)--;
            break;
        case 0:
            break;
        }
    }
}

static __always_inline
enum lookup_result lookup(fivetuple_t *ft, tunnel_t *t, metadata_t metadata, __u8 era)
{
    flow_t *flow = NULL;
    
    switch(ft->proto) {
    case IPPROTO_TCP:
	//if (metadata.syn)
	//    break;
	if ((flow = lookup_tcp_flow(array_of_maps(&flows_tcp), (fourtuple_t *) ft, metadata.syn))) {
	    vrpp_t vrpp = { .vaddr = ft->daddr, .raddr = flow->tunnel.daddr, .vport = bpf_ntohs(ft->dport), .protocol = ft->proto };
	    tcp_concurrent(vrpp, &metadata, flow, era);
	}
	break;

    case IPPROTO_UDP:
	flow = lookup_udp_flow(array_of_maps(&flows_tcp), (fourtuple_t *) ft);
	break;
    }

    
    if (flow) {
	flow->era = era;
	*t = flow->tunnel;
    } else {
	struct servicekey key = { .addr = ft->daddr, .port = bpf_ntohs(ft->dport), .proto = ft->proto };
	service_t *service = bpf_map_lookup_elem(&services, &key);
	
	if (!service)
	    return NOT_FOUND;
    
	__u8 sticky = service->dest[0].flags & F_STICKY;
	__u16 hash3 = l3_hash((fourtuple_t *) ft);
	__u16 hash4 = l4_hash((fourtuple_t *) ft);
	__u8 index = service->hash[(sticky ? hash3 : hash4) & 0x1fff]; // limit to 0-8191
	
	if (!index)
	    return NOT_FOUND;
	
	*t = service->dest[index];
	t->sport = t->sport ? t->sport : 0x8000 | (hash4 & 0x7fff);
    }

    __u32 vlanid = t->vlanid;
    
    if (!vlanid)
	return NOT_FOUND;
    
    struct vlaninfo *vlan = bpf_map_lookup_elem(&vlaninfo, &vlanid);

    if (!vlan)
	return NOT_FOUND;

    if (nulmac(t->h_dest))
	return NOT_FOUND;


    struct vrpp vrpp = { .vaddr = ft->daddr, .raddr = t->daddr, .vport = ntohs(ft->dport), .protocol = ft->proto };
    struct counters *counters = bpf_map_lookup_elem(&stats, &vrpp);

    if (!counters)
	return NOT_FOUND;

    counters->packets++;
    counters->octets += metadata.octets;

    // don't store a flow with a SYN - should stop SYN floods from wiping out the LRU hash
    if (!flow && !metadata.syn) {
	counters->flows++;
	switch(ft->proto) {
	case IPPROTO_TCP:
	    store_flow(array_of_maps(&flows_tcp), (fourtuple_t *) ft, t, era-1);
	    break;
	case IPPROTO_UDP:
	    store_flow(&flows_udp, (fourtuple_t *) ft, t, era-1);
	    break;
	}
    }
    
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
enum lookup_result lookup6(struct xdp_md *ctx, struct ip6_hdr *ip6, fivetuple_t *ft, tunnel_t *t, __u8 era)
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
	if (bpf_map_lookup_elem(&vips, &saddr))
	    return PROBE_REPLY; // source was a VIP - send to netns via veth interface	

	return NOT_A_VIP;
    }

    ft->saddr = saddr;
    ft->daddr = daddr;
    ft->proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

    if (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim <= 1)
	return NOT_FOUND; // FIXME - new enum

    (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim)--;
    
    metadata_t metadata = { .octets = data_end - (void *) ip6 };
    struct tcphdr *tcp = (void *) (ip6 + 1);
    struct udphdr *udp = (void *) (ip6 + 1);
    struct icmp6_hdr *icmp = (void *) (ip6 + 1);

    switch (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
    case IPPROTO_TCP:
	if (tcp + 1 > data_end)
	    return NOT_FOUND;
	ft->sport = tcp->source;
	ft->dport = tcp->dest;
	metadata.syn = tcp->syn;
	metadata.ack = tcp->ack;
	metadata.rst = tcp->rst;
	metadata.fin = tcp->fin;
	break;
	
    case IPPROTO_UDP:
	if (udp + 1 > data_end)
	    return NOT_FOUND;
	ft->sport = udp->source;
	ft->dport = udp->dest;
	break;
	
    case IPPROTO_ICMPV6:
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

    enum lookup_result r = lookup(ft, t, metadata, era);

    if (LAYER2_DSR == r && ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim > 1)
	ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = 1;

    return r;
}

static __always_inline
enum lookup_result lookup4(struct xdp_md *ctx, struct iphdr *ip, fivetuple_t *ft, tunnel_t *t, __u8 era)
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
	return PROBE_REPLY;
    }

    ft->saddr = saddr;
    ft->daddr = daddr;
    ft->proto = ip->protocol;
	
    /* We're going to forward the packet, so we should decrement the time to live */
    ip_decrease_ttl(ip);    

    metadata_t metadata = { .octets = data_end - (void *) ip };
    struct tcphdr *tcp = (void *) (ip + 1);
    struct udphdr *udp = (void *) (ip + 1);
    struct icmphdr *icmp = (void *) (ip + 1);
    
    switch (ip->protocol) {
    case IPPROTO_TCP:
	if (tcp + 1 > data_end)
	    return NOT_FOUND;
	ft->sport = tcp->source;
	ft->dport = tcp->dest;
	metadata.syn = tcp->syn;
	metadata.ack = tcp->ack;
	metadata.rst = tcp->rst;
	metadata.fin = tcp->fin;
	break;
	
    case IPPROTO_UDP:
	if (udp + 1 > data_end)
	    return NOT_FOUND;
	ft->sport = udp->source;
	ft->dport = udp->dest;
	break;
	
    case IPPROTO_ICMP:
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

    enum lookup_result r = lookup(ft, t, metadata, era);

    if (LAYER2_DSR == r && ip->ttl > 1)
	ip4_set_ttl(ip, 1);
    
    return r;
}

static __always_inline
enum fwd_action xdp_fwd(struct xdp_md *ctx, fivetuple_t *ft, tunnel_t *t, const settings_t *settings)
{
    int mtu = MTU;
    int overhead = 0;
    enum lookup_result result = NOT_A_VIP;
    int vip_is_ipv6 = 0;
	
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    
    if (eth + 1 > data_end)
        return FWD_CORRUPT;
    
    __be16 next_proto = eth->h_proto;
    void *next_header = eth + 1;
    
    struct vlan_hdr *vlan = NULL;
    
    if (next_proto == bpf_htons(ETH_P_8021Q)) {
	return FWD_PASS; // FIXME - not yet fully implmented
	vlan = next_header;
	
	if (vlan + 1 > data_end)
	    return FWD_CORRUPT;
	
	next_proto = vlan->h_vlan_encapsulated_proto;
	next_header = vlan + 1;
    }
    
    switch (next_proto) {
    case bpf_htons(ETH_P_IPV6):
	vip_is_ipv6 = 1;
	overhead = sizeof(struct ip6_hdr);
	result = lookup6(ctx, next_header, ft, t, settings->era);
	break;
    case bpf_htons(ETH_P_IP):
	vip_is_ipv6 = 0;
	overhead = sizeof(struct iphdr);
	result = lookup4(ctx, next_header, ft, t, settings->era);
	break;
    default:
	return FWD_PASS;
    }

    overhead = is_ipv4_addr(t->daddr) ? sizeof(struct iphdr) : sizeof(struct ip6_hdr);

    // no default here - handle all cases explicitly
    switch (result) {
    case NOT_A_VIP: return FWD_PASS;
    case NOT_FOUND: return FWD_DROP;
    case BOUNCE_ICMP: return FWD_ICMP;
    case PROBE_REPLY: return FWD_VETH;

    case LAYER3_GRE: overhead += GRE_OVERHEAD; break;
    case LAYER3_FOU: overhead += FOU_OVERHEAD; break;
    case LAYER3_GUE: overhead += GUE_OVERHEAD; break;
    case LAYER2_DSR: overhead = 0; break;
    case LAYER3_IPIP: break;
    }

    if (overhead && (data_end - next_header) + overhead > mtu) {
	if (vip_is_ipv6) {
	    bpf_printk("IPv6 FRAG_NEEDED - FIXME\n");
	    return icmp6_too_big(ctx, &(ft->daddr.addr6),  &(ft->saddr.addr6), mtu - overhead) < 0 ? FWD_FAIL : FWD_FRAG;
	} else {
	    bpf_printk("IPv4 FRAG_NEEDED - FIXME\n");
	    return frag_needed4(ctx, ft->saddr.addr4.addr, mtu) < 0 ? FWD_FAIL : FWD_FRAG;
	}
    }
    
    if (vlan) // update VLAN ID to that of the target if packet is tagged
	vlan->h_vlan_TCI = (vlan->h_vlan_TCI & bpf_htons(0xf000)) | (bpf_htons(t->vlanid) & bpf_htons(0x0fff));

    switch (result) {
    case LAYER3_IPIP: return send_ipip(ctx, t, vip_is_ipv6) < 0 ? FWD_FAIL : FWD_TX;
    case LAYER3_GRE:  return send_gre(ctx, t, vip_is_ipv6) < 0 ? FWD_FAIL : FWD_TX;
    case LAYER3_GUE:  return send_gue(ctx, t, vip_is_ipv6) < 0 ? FWD_FAIL : FWD_TX; // breaks 22.04
    case LAYER3_FOU:  return send_fou(ctx, t) < 0 ? FWD_FAIL : FWD_TX;
    case LAYER2_DSR:  return send_l2(ctx, t) < 0 ? FWD_FAIL : FWD_TX;
    default: break;
    }

    return FWD_DROP;
}





SEC("xdp")
int xdp_pass_func(struct xdp_md *ctx)
{
    return XDP_PASS;
}

SEC("xdp")
int xdp_vethb_func(struct xdp_md *ctx)
{
    __u64 start = bpf_ktime_get_ns();

    struct settings *s = bpf_map_lookup_elem(&settings, &ZERO);

    if (!s || !s->active)
	return XDP_PASS;

    // settings is a per-CPU map, so no concurrency issues
    if (s->watchdog == 0) {
	s->watchdog = start;
    } else if (s->watchdog + (TIMEOUT * SECOND_NS) < start) {
	return XDP_PASS;
    }

    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = (void *)(long)ctx->data;

    if (eth + 1 > data_end)
        return XDP_DROP;

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
	    return XDP_TX;
	}
	return XDP_PASS;
    }
    
    return XDP_PASS;
}

SEC("xdp")
int xdp_vetha_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = (void *)(long)ctx->data;
    
    if (eth + 1 > data_end)
	return XDP_DROP;

    switch(eth->h_proto) {
    case bpf_htons(ETH_P_IP):
	return XDP_PASS == xdp_reply_v4(ctx) ? XDP_PASS : xdp_request_v4(ctx);
    case bpf_htons(ETH_P_IPV6):
	return XDP_PASS == xdp_reply_v6(ctx) ? XDP_PASS : xdp_request_v6(ctx);
    }

    return XDP_PASS;
}


SEC("xdp")
int xdp_fwd_func(struct xdp_md *ctx)
{
    __u64 start = bpf_ktime_get_ns();

    struct settings *s = bpf_map_lookup_elem(&settings, &ZERO);
    
    if (!s || !s->active)
	return XDP_PASS;

    // settings is a per-CPU map, so no concurrency issues
    if (s->watchdog == 0) {
	s->watchdog = start;
    } else if (s->watchdog + (TIMEOUT * SECOND_NS) < start) {
	return XDP_PASS;
    }

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    //int ingress    = ctx->ingress_ifindex;
    
    struct ethhdr *eth = data;
    
    if (eth + 1 > data_end)
        return XDP_DROP;
    
    __u8 dot1q = 0;
    
    if (eth->h_proto == bpf_htons(ETH_P_8021Q))
	dot1q = 1;
    
    fivetuple_t ft = {};    
    tunnel_t t = {};
    
    // don't access packet pointers after here as it may have been adjusted by the forwarding functions
    enum fwd_action action = xdp_fwd(ctx, &ft, &t, s);
    // int action = xdp_fwd(ctx, &ft, &t, s);

    s->packets++;
    s->latency += (bpf_ktime_get_ns() - start);
    
    // handle stats here
    switch (action) {
    case FWD_PASS: return XDP_PASS;
    case FWD_DROP: return XDP_DROP;
    case FWD_TX:
		
	switch (s->multi) {
	case 0: // untagged bond - multi NIC, but only single VLAN in config
	    return XDP_TX;
	case 1: // single interface - TX either tagged or untagged
	    return XDP_TX;
	}

	// multi-interface, if tagged packets then just TX to appropriate VLAN (previously set)
	if (dot1q)
	    return XDP_TX; 
	
	// otherwise redirect to interface
	return is_ipv4_addr(t.daddr) ?
	    bpf_redirect_map(&redirect_map4, t.vlanid, XDP_DROP) :
	    bpf_redirect_map(&redirect_map6, t.vlanid, XDP_DROP);

    case FWD_ABORTED: return XDP_DROP;
    case FWD_REDIRECT: return XDP_REDIRECT;
    case FWD_FRAG: return XDP_TX; // packet is bounced back to source
    case FWD_ICMP: return XDP_TX; // packet is bounced back to source
    case FWD_FAIL: return XDP_DROP;	
    case FWD_VETH:
	if (!s->veth || nulmac(s->vetha) || nulmac(s->vethb))
	    return XDP_DROP;
	
        memcpy(eth->h_dest, s->vethb, 6);
        memcpy(eth->h_source, s->vetha, 6);
	
	if (dot1q && vlan_pop(ctx) < 0)
	    return XDP_DROP;

	return bpf_redirect(s->veth, 0);

    case FWD_CORRUPT: return XDP_DROP;
    }
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";

#endif
