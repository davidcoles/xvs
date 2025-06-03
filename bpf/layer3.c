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

#include "imports.h"
#include "vlan.h"


#define SECOND_NS 1000000000l

const __u32 ZERO = 0;
const __u16 MTU = 1500;
const __u64 TIMEOUT = 60; // seconds

enum fwd_action {
    FWD_OK = 0,
    FWD_TX,
    FWD_PROBE_REPLY,
    FWD_PASS,
    FWD_DROP,

    FWD_LAYER2_DSR,
    FWD_LAYER3_GRE,
    FWD_LAYER3_FOU,
    FWD_LAYER3_IPIP,
    FWD_LAYER3_GUE,
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

// proto is a __u32 here to align the struct to 4 bytes. if this is
// not done then inline initialisation will have some undefined bytes
// from the stack unless saddr and daddr are assigned separately,
// weirdly. as this is used as a key to map then lookups will fail
struct fivetuple {
    struct addr saddr;
    struct addr daddr;
    __be16 sport;
    __be16 dport;
    __u32 proto;
};
typedef struct fivetuple fivetuple_t;

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
    __u8 hints; // internal flags (ie.: not TunnelFlags)
    __u8 pad[7]; // round this up to 64 bytes - the size of a cache line
    __u32 _interface; // userspace use only!
};
typedef struct tunnel tunnel_t;

static __always_inline
int is_addr4(struct addr *a) {
    return (!(a->addr4.pad1) && !(a->addr4.pad2) && !(a->addr4.pad3)) ? 1 : 0;
}

#include "new.h"



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
    __u64 time; // 8 
    tunnel_t tunnel; // contains real IP of server, etc (+64 = 72)  
    __u32 syn_seqn_reserved; // FIXME - came to nothing so far
    __u8 finrst;
    __u8 era;
    __u8 pad;
    __u8 version; // +4 + 4 = 80
};
typedef struct flow flow_t;

/*
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
*/

struct flows {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, fourtuple_t);
    __type(value, flow_t);
    //__type(key, __u8[sizeof(fourtuple_t)]);
    //__type(value, __u8[sizeof(flow_t)]);
    __uint(max_entries, 1);
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_CPU_SUPPORT);
    __array(values, struct flows);
} flows_tcp SEC(".maps");

// UDP: eventually, track flow for ~30s, reselect backend, and time
// flow out after ~120s idle - allows for breaking tie to a down
// server, whilst getting a rough idea about concurrent users (array
// of maps?)
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

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, __u8[BUFFER]);
    __uint(max_entries, 1000);
} icmp_queue SEC(".maps");

/**********************************************************************/

struct vrpp {
    addr_t vaddr; // virtual service IP
    addr_t raddr; // real server IP
    __be16 vport; // virtual service port
    __s16 protocol;
};
typedef struct vrpp vrpp_t;

struct counter {
    __u64 packets;
    __u64 octets;
    __u64 flows;
    __u64 errors;

    __u64 syn;
    __u64 ack;
    __u64 fin;
    __u64 rst;

    __u64 tunnel_unsupported;
    __u64 too_big;
    __u64 adjust_failed;
    
};
typedef struct counter counter_t;

// if updating this, regenerate Go def with: perl -ne 'next if /^\s+$/; s/__u64//; s/;.*//; s/$/ uint64/; print' > /tmp/foo
struct metrics {
    __u64 malformed;
    __u64 not_ip;
    __u64 not_a_vip;
    __u64 probe_reply;
    
    // can be per vip
    __u64 l4_unsupported;
    __u64 icmp_unsupported;
    __u64 icmp_echo_request;
    __u64 fragmented;
    __u64 service_not_found;
    
    // can be per service (and by extension per vip) - forwarding state
    __u64 no_backend;
    __u64 too_big; // exceeds MTU for tunnel (separate ipv4 and ipv6 version?)
    __u64 expired; // TTL/hlim exceeded
    __u64 adjust_failed;
    __u64 tunnel_unsupported;

    // forwarded packets only?
    __u64 packets;
    __u64 octets;

    __u64 flows;
    __u64 errors;
    
    __u64 syn;
    __u64 ack;
    __u64 fin;
    __u64 rst;

    // can be per vip
    __u64 ip_options;
    __u64 tcp_header;
    __u64 udp_header;
    __u64 icmp_header;
    __u64 _current; // placeholder for concurrent connections count (used by userspace)
    __u64 _fwd_octets;  // can go - forwarded packets only in backeds
    __u64 icmp_too_big;     // IPv6
    __u64 icmp_frag_needed; // IPv4
    __u64 userspace;
};
typedef struct metrics global_t;
typedef struct metrics metrics_t;

struct metadata {
    metrics_t *global;
    metrics_t *vip;
    metrics_t *service;
    counter_t *backend;
    __u32 octets;
    __u16 mtu;
    __u8 syn:1;
    __u8 ack:1;
    __u8 rst:1;
    __u8 fin:1;
    __u8 urg:1;
    __u8 psh:1;
    __u8 new_flow:1;
    __u8 era;
};
typedef struct metadata metadata_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, vrpp_t);
    __type(value, __s64);
    __uint(max_entries, 65536);
} vrpp_concurrent SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct vrpp);
    __type(value, counter_t);
    __uint(max_entries, 4095);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, metrics_t);
    __uint(max_entries, 1);
} global_metrics SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, addr_t);
    __type(value, metrics_t);
    __uint(max_entries, 4096); 
} vip_metrics SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct servicekey);
    __type(value, metrics_t);
    __uint(max_entries, 4096);
} service_metrics SEC(".maps");



/**********************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u8[BUFFER]);
    __uint(max_entries, 1);
} buffers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct servicekey);
    __type(value, service_t);
    __uint(max_entries, 4096);
} services SEC(".maps");

// give these sensible names!
struct vlaninfo {
    addr_t ip4;
    addr_t ip6;
    //addr_t _gw6; // unused
    //__be32 _gw4; // unused
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


static __always_inline
flow_t *lookup_tcp_flow(void *flows, fourtuple_t *ft, __u8 syn)
{
    void *fqe = bpf_map_lookup_elem(&buffers, &ZERO);

    if (!fqe)
	return NULL;
    
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
    
    if (flow->time + (120 * SECOND_NS) < time)
    	return NULL;

    if (flow->time + (60 * SECOND_NS) > time)
    	return flow; // flow updated less then 1m ago - leave for now

    flow->time = time;
    flow->version = FLOW_VERSION;

    __builtin_memcpy(fqe, ft, sizeof(fourtuple_t));
    __builtin_memcpy(fqe + sizeof(fourtuple_t), flow, sizeof(flow_t));
    bpf_map_push_elem(&flow_queue, fqe, BPF_EXIST);

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

static __always_inline
flow_t *lookup_shared(void *flows, fourtuple_t *ft)
{
    if (!flows)
	return NULL;
    
    flow_t *flow = bpf_map_lookup_elem(&shared, ft);
    
    if (!flow)
	return NULL;

    
    __u64 time = bpf_ktime_get_ns();
    
    if (flow->time + (120 * SECOND_NS) < time)
	return NULL;
    
    flow->time = time;
    
    tunnel_t *t = &(flow->tunnel);
    
    __u32 vlanid = t->vlanid;

    if (!vlanid)
	return NULL;

    struct vlaninfo *vlan = bpf_map_lookup_elem(&vlaninfo, &vlanid);

    if (!vlan)
	return NULL;

    __u8 h_gw[6] = {};
    
    // some of the tunnel parameters will be node-local (source
    // IP/MAC, etc.) - update to this node's details
    if (is_ipv4_addr(t->daddr)) {
	t->saddr = vlan->ip4;              // set to this node's IP address on the vlan
	memcpy(t->h_source, vlan->hw4, 6); // set to this node's MAC address on thw vlan
	memcpy(h_gw, vlan->gh4, 6);        // copy this node's gateway MAC to temp addr
    } else {
	// same as above, but for IPv6 destinations ...
	t->saddr = vlan->ip6;
	memcpy(t->h_source, vlan->hw6, 6);
	memcpy(h_gw, vlan->gh6, 6);
    }

    // if the destination is not on a local VLAN then we need to send
    // the packet to the router using the h_gw address we set earlier
    //if ((t->method != T_NONE) && (t->flags & F_NOT_LOCAL)) {
    if ((t->method != T_NONE) && (t->hints & F_NOT_LOCAL)) {	
	memcpy(t->h_dest, h_gw, 6);
    }

    // write to the regular flow map
    bpf_map_update_elem(flows, ft, flow, BPF_ANY);

    return flow;
}

static __always_inline
void *array_of_maps(void *outer) {
    __u32 cpu_id = bpf_get_smp_processor_id();
    return bpf_map_lookup_elem(outer, &cpu_id);
}

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

#define FWD_ERROR1(F) ( metadata->global->F++, FWD_DROP )
#define FWD_ERROR2(F) ( metadata->global->F++, metadata->vip->F++, FWD_DROP )
#define FWD_ERROR3(F) ( metadata->global->F++, metadata->vip->F++, metadata->service->F++,FWD_DROP )
#define FWD_ERROR4(F) ( metadata->global->F++, metadata->vip->F++, metadata->service->F++, metadata->backend->F++, FWD_DROP )

static __always_inline
counter_t *is_backend_valid(fivetuple_t *ft, tunnel_t *t, metadata_t *metadata)
{
    struct vrpp vrpp = { .vaddr = ft->daddr, .raddr = t->daddr, .vport = ntohs(ft->dport), .protocol = ft->proto };
    counter_t *backend = NULL;
    
    if(!(backend = bpf_map_lookup_elem(&stats, &vrpp)))
	return NULL;

    __u32 vlanid = t->vlanid; // needs to be __u32 for bpf_map_lookup_elem()
    
    if (!vlanid || !bpf_map_lookup_elem(&vlaninfo, &vlanid) || nulmac(t->h_dest))
	return NULL;
    
    return backend;
}
    
static __always_inline
enum fwd_action lookup(fivetuple_t *ft, tunnel_t *t, metadata_t *metadata)
{
    flow_t *flow = NULL;
    
    switch(ft->proto) {
    case IPPROTO_TCP:
	if ((flow = lookup_tcp_flow(array_of_maps(&flows_tcp), (fourtuple_t *) ft, metadata->syn))) {
	    vrpp_t vrpp = { .vaddr = ft->daddr, .raddr = flow->tunnel.daddr, .vport = bpf_ntohs(ft->dport), .protocol = ft->proto };
	    tcp_concurrent(vrpp, metadata, flow, metadata->era);
	    break;
	}
	
	flow = lookup_shared(array_of_maps(&flows_tcp), (fourtuple_t *) ft);
	break;

    case IPPROTO_UDP:
	flow = lookup_udp_flow(array_of_maps(&flows_tcp), (fourtuple_t *) ft);
	break;
    }

    struct servicekey key = { .addr = ft->daddr, .port = bpf_ntohs(ft->dport), .proto = ft->proto };	

    if(!(metadata->service = bpf_map_lookup_elem(&service_metrics, &key)))
	return FWD_ERROR2(service_not_found);
    
    if (flow) {
	flow->era = metadata->era;
	*t = flow->tunnel;
    } else {
	service_t *service = bpf_map_lookup_elem(&services, &key);
	
	if (!service) {
	    metadata->service = NULL;
	    return FWD_ERROR2(service_not_found);
	}
    
	__u8 sticky = service->dest[0].flags & F_STICKY;
	__u16 hash3 = l3_hash((fourtuple_t *) ft);
	__u16 hash4 = l4_hash((fourtuple_t *) ft);
	__u8 index = service->hash[(sticky ? hash3 : hash4) & 0x1fff]; // limit to 0-8191
	
	if (!index)
	    return FWD_ERROR3(no_backend);
	
	*t = service->dest[index];
	t->sport = t->sport ? t->sport : 0x8000 | (hash4 & 0x7fff);
    }
    
    if (!(metadata->backend = is_backend_valid(ft, t, metadata)))
	return FWD_ERROR3(no_backend); // FIXME - new error type?
    
    // don't store a flow with a SYN - should stop SYN floods from
    // wiping out the LRU hash - we will store when the first ACK
    // comes through. Of course, an attacker could send a SYN and a
    // bogus ACK; but upstream stateful inspection DDoS could catch

    if (!flow && !metadata->syn && !metadata->rst && !metadata->fin) {
	metadata->new_flow = 1;
	switch(ft->proto) {
	case IPPROTO_TCP:
	    store_flow(array_of_maps(&flows_tcp), (fourtuple_t *) ft, t, metadata->era-1);
	    break;
	case IPPROTO_UDP:
	    store_flow(&flows_udp, (fourtuple_t *) ft, t, metadata->era-1);
	    break;
	}
    }
    
    switch ((enum tunnel_type) t->method) {
    case T_FOU:  return FWD_LAYER3_FOU;
    case T_GRE:  return FWD_LAYER3_GRE;
    case T_GUE:  return FWD_LAYER3_GUE;
    case T_IPIP: return FWD_LAYER3_IPIP;
    case T_NONE: return FWD_LAYER2_DSR;
    }

    FWD_ERROR4(tunnel_unsupported);
}

static __always_inline
enum fwd_action lookup6(struct xdp_md *ctx, struct ip6_hdr *ip6, fivetuple_t *ft, tunnel_t *t, metadata_t *metadata)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = (void *)(long)ctx->data;
    
    if (eth + 1 > data_end || ip6 + 1 > data_end || (ip6->ip6_ctlun.ip6_un2_vfc >> 4) != 6)
	return FWD_ERROR1(malformed);
    
    struct addr saddr = { .addr6 = ip6->ip6_src };
    struct addr daddr = { .addr6 = ip6->ip6_dst };

    ft->saddr = saddr;
    ft->daddr = daddr;
    ft->proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

    metadata->vip = bpf_map_lookup_elem(&vip_metrics, &daddr);
    
    if (!metadata->vip) {
    	if (bpf_map_lookup_elem(&vip_metrics, &saddr))
	    return FWD_PROBE_REPLY; // source was a VIP - send to netns via veth interface
	
	metadata->global->not_a_vip++;
	return FWD_PASS; // <- NOT AN ERROR
    }
    
    if (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim <= 1)
	return FWD_ERROR2(expired);

    (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim)--;
    
    struct tcphdr *tcp = (void *) (ip6 + 1);
    struct udphdr *udp = (void *) (ip6 + 1);
    struct icmp6_hdr *icmp = (void *) (ip6 + 1);

    switch (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
    case IPPROTO_TCP:
	if (tcp + 1 > data_end)
	    return FWD_ERROR2(tcp_header);
	ft->sport = tcp->source;
	ft->dport = tcp->dest;
	metadata->syn = tcp->syn;
	metadata->ack = tcp->ack;
	metadata->rst = tcp->rst;
	metadata->fin = tcp->fin;
	metadata->urg = tcp->urg;
	metadata->psh = tcp->psh;
	break;
	
    case IPPROTO_UDP:
	if (udp + 1 > data_end)
	    return FWD_ERROR2(udp_header);
	ft->sport = udp->source;
	ft->dport = udp->dest;
	break;
	
    case IPPROTO_ICMPV6:
        if (icmp + 1 > data_end)
	    return FWD_ERROR2(icmp_header);
	if (icmp->icmp6_type == ICMP6_ECHO_REQUEST && icmp->icmp6_code == 0) {
	    //bpf_printk("ICMPv6");
            ip6_reply(ip6, 64); // swap saddr/daddr, set TTL
	    struct icmp6_hdr old = *icmp;
            icmp->icmp6_type = ICMP6_ECHO_REPLY;
	    icmp->icmp6_cksum = icmp6_csum_diff(icmp, &old);
            reverse_ethhdr(eth);
	    metadata->vip->icmp_echo_request++;
	    metadata->global->icmp_echo_request++;
	    return FWD_TX; // <- NOT AN ERROR
	}
	if (icmp->icmp6_type == ICMP6_PACKET_TOO_BIG && icmp->icmp6_code == 0) {
	    //bpf_printk("ICMPv6 ICMP6_PACKET_TOO_BIG");
	    void *buffer = bpf_map_lookup_elem(&buffers, &ZERO);
	    
	    if (!buffer)
		return FWD_ERROR2(errors);
	    
	    if (icmp_dest_unreach_frag_needed6(ip6, icmp, data_end, buffer, BUFFER) < 0)
		return FWD_ERROR2(errors);
	    
	    // send packet to userspace to be forwarded to backend(s)
	    if (bpf_map_push_elem(&icmp_queue, buffer, BPF_EXIST) != 0)
		return FWD_ERROR2(userspace);
	}

	return FWD_ERROR2(icmp_echo_request);
	
    default:
	return FWD_ERROR2(l4_unsupported);
    }

    enum fwd_action r = lookup(ft, t, metadata);

    // FIXME - apply to all hosts on local VLANs?
    if (FWD_LAYER2_DSR == r && ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim > 1)
	ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = 1;

    return r;
}

static __always_inline
enum fwd_action lookup4(struct xdp_md *ctx, struct iphdr *ip, fivetuple_t *ft, tunnel_t *t, metadata_t *metadata)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = (void *)(long)ctx->data;
    
    if (eth + 1 > data_end || ip + 1 > data_end || ip->version != 4 || ip->ihl < 5 )
	return FWD_ERROR1(malformed);

    struct addr saddr = { .addr4.addr = ip->saddr };
    struct addr daddr = { .addr4.addr = ip->daddr };
    
    ft->saddr = saddr;
    ft->daddr = daddr;
    ft->proto = ip->protocol;

    metadata->vip = bpf_map_lookup_elem(&vip_metrics, &daddr);
    
    if (!metadata->vip) {
	if (bpf_map_lookup_elem(&vip_metrics, &saddr))
	    return FWD_PROBE_REPLY; // source was a VIP - send to netns via veth interface
	
	metadata->global->not_a_vip++;
	return FWD_PASS; // <- NOT AN ERROR
    }    

    if (ip->ihl != 5)
	return FWD_ERROR2(ip_options);

    // ignore evil bit and DF, drop if more fragments flag set, or fragent offset is not 0
    if ((ip->frag_off & bpf_htons(0x3fff)) != 0)
	return FWD_ERROR2(fragmented);	
    
    if (ip->ttl <= 1)
	return FWD_ERROR2(expired);
    	
    /* We're going to forward the packet, so we should decrement the time to live */
    ip_decrease_ttl(ip);    

    struct tcphdr *tcp = (void *) (ip + 1);
    struct udphdr *udp = (void *) (ip + 1);
    struct icmphdr *icmp = (void *) (ip + 1);
    
    switch (ip->protocol) {
    case IPPROTO_TCP:
	if (tcp + 1 > data_end)
	    return FWD_ERROR2(tcp_header);
	ft->sport = tcp->source;
	ft->dport = tcp->dest;
	metadata->syn = tcp->syn;
	metadata->ack = tcp->ack;
	metadata->rst = tcp->rst;
	metadata->fin = tcp->fin;
	metadata->urg = tcp->urg;
	metadata->psh = tcp->psh;
	break;
	
    case IPPROTO_UDP:
	if (udp + 1 > data_end)
	    return FWD_ERROR2(udp_header);
	ft->sport = udp->source;
	ft->dport = udp->dest;
	break;
	
    case IPPROTO_ICMP:
	if (icmp + 1 > data_end)
    	    return FWD_ERROR2(icmp_header);
	if (icmp->type == ICMP_ECHO && icmp->code == 0) {
	    //bpf_printk("ICMPv4");
	    ip4_reply(ip, 64); // swap saddr/daddr, set TTL
	    struct icmphdr old = *icmp;
	    icmp->type = ICMP_ECHOREPLY;
            icmp->checksum = icmp4_csum_diff(icmp, &old);
	    reverse_ethhdr(eth);
	    metadata->vip->icmp_echo_request++;
	    metadata->global->icmp_echo_request++;
	    return FWD_TX; // <- NOT AN ERROR
	}
	if (icmp->type == ICMP_DEST_UNREACH && icmp->code == ICMP_FRAG_NEEDED) {
	    //bpf_printk("ICMPv4 ICMP_FRAG_NEEDED");
	    void *buffer = bpf_map_lookup_elem(&buffers, &ZERO);
	    
	    if (!buffer)
		return FWD_ERROR2(errors);
	    
	    if (icmp_dest_unreach_frag_needed(ip, icmp, data_end, buffer, BUFFER) < 0)
		return FWD_ERROR2(errors);

	    // send packet to userspace to be forwarded to backend(s)
	    if (bpf_map_push_elem(&icmp_queue, buffer, BPF_EXIST) != 0)
		return FWD_ERROR2(userspace);
	}

	return FWD_ERROR2(icmp_unsupported);

    default:
	return FWD_ERROR2(l4_unsupported);
    }

    enum fwd_action r = lookup(ft, t, metadata);

    // FIXME - apply to all hosts on local VLANs?
    if (FWD_LAYER2_DSR == r && ip->ttl > 1)
	ip4_set_ttl(ip, 1);
    
    return r;
}

static __always_inline
int too_big(struct xdp_md *ctx, fivetuple_t *ft, int req_mtu, int vip_is_ipv6) {
    return vip_is_ipv6 ?
	icmp6_too_big(ctx, &(ft->daddr.addr6),  &(ft->saddr.addr6), req_mtu):
	frag_needed4(ctx, ft->saddr.addr4.addr, req_mtu); // FIXME - source addr
}

static __always_inline
enum fwd_action FWD(metadata_t *m, int r)
{
    if (r == 0)
	return FWD_OK;

    // can do more detailed error reporting here if r is set to something other than -1
    
    m->backend->adjust_failed++; // FIXME
    m->service->adjust_failed++;
    m->vip->adjust_failed++;
    m->global->adjust_failed++;
    return FWD_DROP;
}


static __always_inline
enum fwd_action xdp_fwd(struct xdp_md *ctx, struct ethhdr *eth, fivetuple_t *ft, tunnel_t *t, metadata_t *metadata)
{
    void *data_end = (void *)(long)ctx->data_end;
    __u8 ipv6 = 0, gue_protocol = 0; // plain fou by default
    enum fwd_action result = FWD_DROP;
    
    struct vlan_hdr *vlan = NULL;
    void *next_header = eth + 1;
    __be16 next_proto = eth->h_proto;
    if (next_proto == bpf_htons(ETH_P_8021Q)) {	
	if ((vlan = next_header) + 1 > data_end) {
	    metadata->global->malformed++;
	    return FWD_DROP;
	}
	next_proto = vlan->h_vlan_encapsulated_proto;
	next_header = vlan + 1;
    }

    metadata->octets = data_end - next_header;

    switch (next_proto) {
    case bpf_htons(ETH_P_IP):
	result = lookup4(ctx, next_header, ft, t, metadata);
	break;
    case bpf_htons(ETH_P_IPV6):
	result = lookup6(ctx, next_header, ft, t, metadata);
	ipv6 = 1;
	break;
    default:
	metadata->global->not_ip++;
	return FWD_PASS; // <- NOT AN ERROR
    }

    int overhead = is_ipv4_addr(t->daddr) ? sizeof(struct iphdr) : sizeof(struct ip6_hdr);
    
    switch (result) {
    case FWD_LAYER3_GRE: overhead += GRE_OVERHEAD; break;
    case FWD_LAYER3_FOU: overhead += FOU_OVERHEAD; break;
    case FWD_LAYER3_GUE: overhead += GUE_OVERHEAD; break;
    case FWD_LAYER2_DSR: overhead = 0; break; // no overheaded needed for l2
    case FWD_LAYER3_IPIP: break;
    default:
	return result;
    }

    if ((data_end - next_header) + overhead > metadata->mtu) {
	FWD_ERROR4(too_big); // FIXME FWD_ERROR4
	if (too_big(ctx, ft, metadata->mtu - overhead, ipv6) < 0)
	    return FWD_ERROR3(adjust_failed);
	return FWD_TX;
    }
    
    if (vlan) // update VLAN ID to that of the target if packet is tagged
    	vlan->h_vlan_TCI = (vlan->h_vlan_TCI & bpf_htons(0xf000)) | (bpf_htons(t->vlanid) & bpf_htons(0x0fff));

    switch ((int) result) { // cast to int to avoid having to deal with all cases
    case FWD_LAYER3_IPIP: return FWD(metadata, send_ipip(ctx, t, ipv6));
    case FWD_LAYER3_GRE:  return FWD(metadata, send_gre(ctx, t, ipv6));
    case FWD_LAYER2_DSR:  return FWD(metadata, send_l2(ctx, t));
    case FWD_LAYER3_GUE:  gue_protocol = ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP;    // fallthrough ...
    case FWD_LAYER3_FOU:  return FWD(metadata, send_gue(ctx, t, gue_protocol)); // default to plain FOU unless gue_protocol set above
    default: break;
    }

    return FWD_ERROR4(tunnel_unsupported);
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

    metadata_t metadata = { .era = s->era  };
    void *data_end = (void *)(long)ctx->data_end;
    //void *data     = (void *)(long)ctx->data;
    //int ingress    = ctx->ingress_ifindex;

    if (!(metadata.global = bpf_map_lookup_elem(&global_metrics, &ZERO)))
	return XDP_DROP;

    metadata.mtu = 1500;
    
    struct ethhdr *eth = (void *)(long)ctx->data;
    
    if (eth + 1 > data_end)
        return XDP_DROP;

    __u8 dot1q = 0;
    
    if (eth->h_proto == bpf_htons(ETH_P_8021Q))
	dot1q = 1;
    
    fivetuple_t ft = {};    
    tunnel_t t = {};

    // don't access packet pointers after here as it may have been adjusted by the forwarding functions
    enum fwd_action action = xdp_fwd(ctx, eth, &ft, &t, &metadata);

#define COUNTERS(c, m) \
    ((c)->syn += (m).syn, (c)->ack += (m).ack, (c)->fin += (m).fin, (c)->rst += (m).rst, \
     (c)->flows += (m).new_flow, (c)->packets++, (c)->octets += (m).octets)
    
    COUNTERS(metadata.global, metadata);
    
    if (metadata.vip)
	COUNTERS(metadata.vip, metadata);
    
    if (metadata.service)
    	COUNTERS(metadata.service, metadata);

    s->packets++;
    s->latency += (bpf_ktime_get_ns() - start);
    
    switch (action) {
    case FWD_TX:
	return XDP_TX;
	
    case FWD_DROP:
	return XDP_DROP;
	
    case FWD_PASS:
        return XDP_PASS;
	
    case FWD_OK:

	if (metadata.backend)
	    COUNTERS(metadata.backend, metadata);
	
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

    case FWD_PROBE_REPLY:
	if (!s->veth || nulmac(s->vetha) || nulmac(s->vethb))
	    return XDP_DROP;
	
        memcpy(eth->h_dest, s->vethb, 6);
        memcpy(eth->h_source, s->vetha, 6);
	
	if (dot1q && vlan_pop(ctx) < 0)
	    return XDP_DROP;

	return bpf_redirect(s->veth, 0);

	/**********************************************************************/

    case FWD_LAYER2_DSR: // should not be returned
    case FWD_LAYER3_GRE: // maybe a new error type
    case FWD_LAYER3_FOU: // for real foul-ups
    case FWD_LAYER3_IPIP:
    case FWD_LAYER3_GUE:
	return XDP_DROP;

    }
    
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";

#endif
