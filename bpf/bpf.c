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
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#include "vlan.h"
#include "helpers.h"
#include "imports.h"

#define VERSION 1
#define SECOND_NS 1000000000l

#define SHARE_FLOWS(f)    (((f)&F_NO_SHARE_FLOWS)?0:1)
#define TRACK_FLOWS(f)    (((f)&F_NO_TRACK_FLOWS)?0:1)
#define ESTIMATE_CONNS(f) (((f)&F_NO_ESTIMATE_CONNS)?0:1)
#define STORE_STATS(f)    (((f)&F_NO_STORE_STATS)?0:1)
#define TRACK_PREFIXES(f) (((f)&F_NO_PREFIXES)?0:1)
#define BLOCK_PREFIXES(f) (((f)&F_NO_PREFIXES)?0:1)


const __u32 ZERO = 0;
const __u32 VETH = VETH_ID;


struct setting {
    __u32 heartbeat;
    __u8 era;
    __u8 features;
    __u8 pad1;
    __u8 pad2;
};

// I presume that if this is only ever read then there is no advantage
// in making it percpu as no locks are needed anyway
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, struct setting);
    __uint(max_entries, 1);
} settings SEC(".maps");

struct global {
    __u64 rx_packets;
    __u64 rx_octets;
    __u64 perf_packets;
    __u64 perf_timens;
    __u64 perf_timer;
    __u64 settings_timer;
    __u64 new_flows;
    __u64 dropped;
    __u64 qfailed;
    __u64 blocked;
    __u64 toobig;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, struct global);
    __uint(max_entries, 1);
} globals SEC(".maps");

struct flow {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
} flow_unused; // we need to declare an instance so that the array of maps code works

struct state {
    __u32 time;
    __be32 rip;
    __u16 vid;
    __u8 mac[6];
    __u8 finrst;
    __u8 era;
    __u8 _pad;
    __u8 version;
} state_unused; // we need to declare an instance so that the array of maps code works (not necessary with workaround below)

//struct {
//    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
//    __type(key, struct flow);
//    __type(value, struct state);
//    __uint(max_entries, FLOW_STATE_SIZE);
//} flow_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_CPU_SUPPORT);
    __array(
	    values,
	    struct {
		__uint(type, BPF_MAP_TYPE_LRU_HASH);
		__type(key, struct flow);
		// strangely, this doesn't work for all systems, but the following __u8 array workaround does:
		//__type(value, struct state);
		__type(value, __u8[sizeof(struct state)]);
		__uint(max_entries, FLOW_STATE_SIZE);
	    });
} flow_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow);
    __type(value, struct state);
    __uint(max_entries, FLOW_STATE_SIZE);
} flow_share SEC(".maps");

struct flow_queue_entry {
    __u8 data[sizeof(struct flow) + sizeof(struct state)];
};

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, struct flow_queue_entry);
    __uint(max_entries, FLOW_QUEUE_SIZE);
} flow_queue SEC(".maps");

struct real {
    __be32 rip;
    __u16 vid;
    __u8 mac[6];
    __u8 flag[4];
    // flag entry in backend.real[0]
    // [0] - flags 0|0|0|0|0|0|0|sticky(l3hash)
    // [1] - if non-zeo then n/255 chance to send conn to ip/mac/vid in backend.real[0] (leastconns)
};

struct service {
    __be32 vip;
    __be16 port;
    __u8 protocol; // TCP=6 UDP=17
    __u8 pad;
};

struct backend {
    struct real real[256];
    __u8 hash[8192];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct service);
    __type(value, struct backend);
    __uint(max_entries, 4096);
} service_backend SEC(".maps");


struct vrpp {
    __be32 vip;
    __be32 rip;
    __be16 port;
    __u8 protocol;
    __u8 pad;
};

struct counter {
    __u64 packets;
    __u64 octets;
    __u64 flows;
    __u64 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct vrpp);
    __type(value, __s64);
    __uint(max_entries, 65536);
} vrpp_concurrent SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct vrpp);
    __type(value, struct counter);
    __uint(max_entries, 65536);
} vrpp_counter SEC(".maps");

struct redirect {
    __be32 addr;
    __u32 index; // info only, not used -  value is in redirect_map
    char dest[6];
    char source[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct redirect);
    __uint(max_entries, 4096);
} redirect_mac SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4096);
} redirect_map SEC(".maps");

struct nat {
    __be32 vip;
    __u16 vid;
    char mac[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32); // nat addr
    __type(value, struct nat);
    __uint(max_entries, 65536);
} nat_out SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat);
    __type(value, __be32); // nat addr
    __uint(max_entries, 65536);
} nat_in SEC(".maps");


struct prefixes {
    __u64 allowed;
    __u64 blocked;
};
    
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct prefixes);
    __uint(max_entries, 1048576); // counters for each /20 network (16 /20s per /16)
} prefix_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 16384);
} prefix_drop SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, __u8[SNOOP_BUFFER_SIZE]);
    __uint(max_entries, 1);
} snoop_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, __u8[SNOOP_BUFFER_SIZE]);
    __uint(max_entries, SNOOP_QUEUE_SIZE);
} snoop_queue SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, __u8[SNOOP_BUFFER_SIZE]);
    __uint(max_entries, ICMP_QUEUE_SIZE);
} icmp_queue SEC(".maps");

static __always_inline
void be_tcp_concurrent(struct iphdr *ip, struct tcphdr *tcp, struct state *state, __u8 era)
{
    if (!state)
	return;
    
    struct vrpp vr = { .vip = ip->daddr, .rip = state->rip, .port = tcp->dest, .protocol = IPPROTO_TCP, .pad = era%2 };
    __s64 *concurrent = NULL;

    if (tcp->syn == 1)
        state->finrst = 0;
    
    if (state->finrst == 0 && ((tcp->rst == 1) || (tcp->fin == 1))) {
        state->finrst = 10;
    } else {
        if (state->finrst > 0)
            (state->finrst)--;
    }
    
    if (state->era != era || tcp->syn == 1) {
        state->era = era;

        switch(state->finrst) {
        case 10:
            break;
        case 0:
            if((concurrent = bpf_map_lookup_elem(&vrpp_concurrent, &vr)))
		(*concurrent)++;
            break;
        }
    } else {
        switch(state->finrst) {
        case 10:
            if((concurrent = bpf_map_lookup_elem(&vrpp_concurrent, &vr)))
		(*concurrent)--;
            break;
        case 0:
            break;
        }
    }
}


static __always_inline
void store_tcp_flow(void *flow_state, struct iphdr *ip, struct l4ports l4, struct destination dest, struct global *global)
{
    if (!flow_state)
	return;
    
    char *m = dest.mac;
    __u64 time = bpf_ktime_get_ns() / SECOND_NS;
    struct flow flow = { .saddr = ip->saddr, .daddr = ip->daddr, .sport = l4.source, .dport = l4.dest };
    struct state state = { .rip = dest.rip, .vid = dest.vlanid, .time = time, .mac = { m[0], m[1], m[2], m[3], m[4], m[5] } };
    //bpf_map_update_elem(&flow_state, &flow, &state, BPF_ANY);
    bpf_map_update_elem(flow_state, &flow, &state, BPF_ANY);
    if (global)
	global->new_flows++;
}

static __always_inline
struct destination find_tcp_flow(void *flow_state, struct iphdr *ip, struct tcphdr *tcp, __u32 start_s, __u8 era, struct global *global, int share)
{
    struct destination d = { .vlanid = 0, .result = DEST_NOT_FOUND };

    if (!flow_state)
	return d;
    
    if (tcp->syn)
	return d;
	
    struct flow flow = { .saddr = ip->saddr, .daddr = ip->daddr, .sport = tcp->source, .dport = tcp->dest };
    //struct state *state = bpf_map_lookup_elem(&flow_state, &flow);
    struct state *state = bpf_map_lookup_elem(flow_state, &flow);

    if (state && (state->time + 120) > start_s) {
	
	d.result = DEST_FOUND;
	d.vlanid = state->vid;
	d.rip = state->rip;
	d.state = state;
	maccpy(d.mac, state->mac);

	// periodically update the stored time - and share the flow (if enabled)
	if((state->time + 60) < start_s) {
	    state->time = start_s + ((start_s + tcp->source) % 11);
	    state->version = VERSION;

	    if (share) {
		struct flow_queue_entry fqe = {};
		__builtin_memcpy((void *)&fqe, &flow, sizeof(struct flow));
		__builtin_memcpy((void *)&fqe + sizeof(struct flow), state, sizeof(struct state));
		if ((bpf_map_push_elem(&flow_queue, &fqe, 0) != 0) && global) {
		    global->qfailed++;
		}
	    }
	}

	return d;
    }

    if (share && (state = bpf_map_lookup_elem(&flow_share, &flow))) {
	
	if (state->version != VERSION)
	    return d;
	
	if (state->time == 0 || (state->time + 110) < start_s)
	    return d;

	// update time and era so that connections don't get double counted after takeover
	state->time = start_s;
	state->era = era;
	
	d.result = DEST_FOUND;
	d.vlanid = state->vid;
	d.rip = state->rip;
	d.state = state;
	maccpy(d.mac, state->mac);	

	struct l4ports l4 = { .source = tcp->source, .dest =  tcp->dest };
	store_tcp_flow(flow_state, ip, l4, d, NULL);
    }

    return d;
}

static __always_inline
int increment_backend_counter(struct iphdr *ip, __u16 port, __be32 rip, int octets, int new_flow)
{
    struct vrpp vrpp = { .vip = ip->daddr, .rip = rip, .port = port, .protocol = ip->protocol };
    struct counter *counter = bpf_map_lookup_elem(&vrpp_counter, &vrpp);
    if (counter) {
        counter->octets += octets;
	counter->packets++;
        if (new_flow)
	    counter->flows++;
	return 1;
    }
    return 0;
}

static __always_inline
int forward(struct ethhdr *eth, struct vlan_hdr *vlan, struct iphdr *ip, struct destination dest)
{
    if (ip->ttl <= 1)
	return XDP_DROP;
    
    ip_decrease_ttl(ip);
    
    maccpy(eth->h_source, eth->h_dest); // anticipating a XDP_TX
    maccpy(eth->h_dest, dest.mac);      // we will always be sending to dest mac
    
    if (vlan) {
	
	if (dest.vlanid == 0)
	    return XDP_DROP;
	
	vlan->h_vlan_TCI = (vlan->h_vlan_TCI & bpf_htons(0xf000)) | (bpf_htons(dest.vlanid) & bpf_htons(0x0fff));
	
	return XDP_TX;
    }

    if (dest.vlanid == 0) {
	return XDP_TX; // single NIC untagged mode
    }
        
    __u32 vid = dest.vlanid; // dest.vlanid is a __u16 - upgrade it to use as a map key
    struct redirect *r = bpf_map_lookup_elem(&redirect_mac, &vid);
    
    if (!r)
	return XDP_DROP;

    maccpy(eth->h_source, r->source); // send as the mac of the outgoing interface
    
    return bpf_redirect_map(&redirect_map, dest.vlanid, XDP_DROP);
}

// TODO - "leastconns"
static __always_inline
struct destination find_backend(struct iphdr *ip, struct l4ports l4)
{
    struct destination w = { .vlanid = 0, .result = DEST_NOT_FOUND };
    struct service s = { .vip = ip->daddr, .port = l4.dest, .protocol = ip->protocol };
    struct backend *b = bpf_map_lookup_elem(&service_backend, &s);

    if (!b)
	return w;
    
    w.result = DEST_NOT_AVAILABLE;
    
    __u8 flags = b->real[0].flag[0];
    
    if (flags & F_STICKY)
	l4.source = l4.dest = 0;

    __u16 hash = l4_hash(ip, l4);
    __u8 i = b->hash[l4_hash(ip, l4) >> 3];
    
    if (i == 0)
	return w;
    
    w.result = DEST_FOUND;
    
    struct real r = b->real[i];

    // "least-conns" mode - to enable, the IP and MAC stored in
    // real[0] must be valid and the lc-weight must be non-zero
    
    __u8 leastconns = b->real[0].flag[1];
    if(leastconns != 0 && ((__u8)((hash >> 8) ^ (hash & 0xff)) <= leastconns) &&
       b->real[0].rip != 0 && !nulmac(b->real[0].mac))
	r = b->real[0];
    
    w.new = 1;
    w.rip = r.rip;
    w.vlanid = r.vid;
    maccpy(w.mac, r.mac);
    
    return w;
}

static __always_inline int is_blocked(struct iphdr *ip) {
    __u32 saddr = bpf_ntohl(ip->saddr);

    if((saddr & 0xff000000) == 0x0a000000) return 0; // 10.0.0.0/8
    if((saddr & 0xfff00000) == 0xac100000) return 0; // 172.16.0.0/12
    if((saddr & 0xffff0000) == 0xc0800000) return 0; // 192.168.0.0/16
    if((saddr & 0xe0000000) == 0xe0000000) return 0; // 224.0.0.0/4

    __u32 s14 = saddr >> 18;
    __u64 *drop = bpf_map_lookup_elem(&prefix_drop, &s14);

    if (drop && *drop & pow64((saddr >> 12) & 0x3f)) // mask off lowest 6 bits and pass to pow64()
        return 1;

    return 0;
}

static __always_inline
int complete(struct global *global, __u64 start, int action)
{
    if (global) {
	global->perf_timens += (bpf_ktime_get_ns() - start);
	global->perf_packets++;
    }
    return action;
}


static __always_inline
void *is_ipv4(void *data, void *data_end)
{
    struct iphdr *iph = data;
    __u32 nh_off = sizeof(struct iphdr);

    if (data + nh_off > data_end)
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

// experimental ...
enum {
      E_OK = 0,
      E_TTL_EXCEEDED,
      E_INVALID_IP_PACKET,
      E_FRAGMENTED,
      E_BAD_PROTOCOL,
      E_ABORTED,
      E_QUEUE_FAILED,
};

static __always_inline
int icmp_dest_unreach_frag_needed(struct iphdr *ip, struct icmphdr *icmp, void *data_end, __u16 mock)
{
    // https://blog.cloudflare.com/path-mtu-discovery-in-practice/

    // find protocol + dest ip+port from the ICMP message
    // queue to userspace (this acts a rate-limiter for ICMP - size of queue & frequency of polling)
    // userspace sends to all backends for that service

    const __u16 TCP = 0;
    const __u16 UDP = 1;
    
    if (ip->ttl <= 1)
	return E_TTL_EXCEEDED;
    
    ip_decrease_ttl(ip);

    __be16 port = 0;
    __u16 protocol = TCP;
    
    if (mock != 0) {
	port = bpf_htons(mock);
    } else {
	// extract information about the flow to which this ICMP refers
	struct iphdr *inner_ip = ((void *) icmp) + sizeof(struct icmphdr);
	
	void *next_header;
	
	if (!(next_header = is_ipv4(inner_ip, data_end)))
	    return E_INVALID_IP_PACKET;
	
	if ((inner_ip->frag_off & bpf_htons(0x3fff)) != 0)
	    return E_FRAGMENTED;
	
	if (ip->daddr != inner_ip->saddr)
	    return E_INVALID_IP_PACKET;
	
	switch(inner_ip->protocol) {
	case IPPROTO_UDP:
	    protocol = UDP;
	    break;
	case IPPROTO_TCP:
	    protocol = TCP;
	    break;
	default:
	    return E_BAD_PROTOCOL;
	}
	
	if (next_header + sizeof(struct udphdr) > data_end)
	    return E_INVALID_IP_PACKET;
	
	// TCP and UDP headers the same for ports - which is all that we need
	struct udphdr *inner_udp = next_header;
	
	port = inner_udp->source; // this will. of course, be the SOURCE port of the inner ip/l4
    }
    
    // send [destip / destport / 0000|protocol|length ]+[original IP+ICMP packet]
    // 11 bits (2047 bytes > MTU of 1500) orig (IP) packet length
    // 1 bit  protocol 0 - TCP, 1 - UDP
    // 4 bits left - 16 reason codes? unlikely to need anything other than fragementation needed
    
    // 0 - ICMP_DEST_UNREACH / ICMP_FRAG_NEEDED
    __u16 reason = (0 << 12) | (protocol << 11); 
    __u8 *buffer = bpf_map_lookup_elem(&snoop_buffer, &ZERO);
    
    if (!buffer)
	return E_ABORTED;
    
    __u16 n = 0;
    for (n = 0; n < (SNOOP_BUFFER_SIZE-8); n++) { // 8 bytes of header
	if (((void *) ip) + n >= data_end)
	    break;
	((__u8 *) buffer)[8+n] = ((__u8 *) ip)[n]; // copy original IP packet to buffer
    }
    n &= 0x07ff; // mask to lowest 11 bit only (max value 2047)
    
    ((__be32 *) buffer)[0] = ip->daddr;             // bytes 0-3
    ((__u16 *)  buffer)[2] = port;                  // bytes 4&5
    ((__u16 *)  buffer)[3] = bpf_htons(reason | n); // bytes 6&7
	    
    // send packet to userspace to be forwarded to backend(s)
    if (bpf_map_push_elem(&icmp_queue, buffer, 0) != 0)
	return E_QUEUE_FAILED;
    
    return E_OK;
}



SEC("xdp")
int xdp_fwd_func(struct xdp_md *ctx)
{
    __u64 start = bpf_ktime_get_ns();
    __u64 start_s = start / SECOND_NS;
    
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    int octets = data_end - data;
    
    struct setting *setting = bpf_map_lookup_elem(&settings, &ZERO);
    struct global *global = bpf_map_lookup_elem(&globals, &ZERO);    

    if (!setting || !global)
	return XDP_PASS;

    if (global) {
	global->rx_packets++;
	global->rx_octets += octets;
    }

    __u8 flags = setting->features;
    
   // if 10s since last perf reset ...
    if ((global->perf_timer + 10) < start_s) {
        global->perf_timer = start_s;
        if(global->perf_packets > 1) {
            global->perf_timens = (global->perf_timens / global->perf_packets) * 100;
            global->perf_packets = 100;
        } else {
            global->perf_timens = 500;
            global->perf_packets = 100;
        }
    }

    // writing to the settings entry from userland will reset the heartbeat field to zero
    // if this does not happen for over 60s then we disable load balancer functionality
    // this should address the case in which the userland process dies without cleaning up
    if (setting->heartbeat == 0) {
        setting->heartbeat = start_s + 60;
    } else if(setting->heartbeat < start_s) {
        return XDP_PASS;
    }
    
    struct nat *outgoing = NULL;
    __be32 *incoming = NULL;

    __u32 *veth_if = bpf_map_lookup_elem(&redirect_map, &VETH);
    int is_veth = veth_if && *veth_if == ctx->ingress_ifindex;
    int is_nat  = veth_if && *veth_if != 0;
    
    
    struct ethhdr *eth = data;
    __u32 nh_off = sizeof(struct ethhdr);
    __be16 eth_proto;
    
    if (data + nh_off > data_end)
	return XDP_DROP;
    
    eth_proto = eth->h_proto;
    
    struct vlan_hdr *vlan = NULL;
    if (eth_proto == bpf_htons(ETH_P_8021Q)) {
        vlan = data + nh_off;
	
	nh_off += sizeof(struct vlan_hdr);
	
        if (data + nh_off > data_end)
            return XDP_DROP;
	
	eth_proto = vlan->h_vlan_encapsulated_proto;
    }

    /* We don't deal wih any traffic that is not IPv4 */
    if (eth_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = data + nh_off;
    
    nh_off += sizeof(struct iphdr);
    
    if (data + nh_off > data_end)
	return XDP_DROP;

    // if the TTL has expired then drop the packet
    if (ip->ttl == 0)
	return XDP_DROP;
    
    // we don't support IP options
    if (ip->ihl != 5)
	return XDP_DROP;

    // ignore evil bit and DF, drop if more fragments flag set, or fragent offset is not 0
    if ((ip->frag_off & bpf_htons(0x3fff)) != 0)
        return XDP_DROP;

    if (is_veth) {
	// we're the outoing side of the veth pair - only NAT addresses accepted
	if ((outgoing = bpf_map_lookup_elem(&nat_out, &(ip->daddr))))
	    goto do_nat;
	
	return XDP_DROP;
    } else if (is_nat) {
	// we're an external interface - if source ip is vip and real mac then do NAT
	// look up ctx->ingress_ifindex to find vid - or if tagged use the tag
	struct nat in = { .vip = ip->saddr, .vid = 0 };
	maccpy(in.mac, eth->h_source);
	
	if ((incoming = bpf_map_lookup_elem(&nat_in, &in)))
	    goto do_nat;
    }

    struct prefixes *prefix = NULL;

    if (TRACK_PREFIXES(flags)) {
	__u32 slash20 = bpf_ntohl(ip->saddr) >> 12; // obtain /20
	prefix = bpf_map_lookup_elem(&prefix_counters, &slash20);
    }
    
    if (BLOCK_PREFIXES(flags) && is_blocked(ip)) {
	if (prefix) prefix->blocked++;
	if (global) global->blocked++;
	return complete(global, start, XDP_DROP);
    }	

    //complete(global, start, 0); global = NULL; // measure time to this point
    
    if (prefix) prefix->allowed++;	
    
    // look for traffic to VIP - balance

    struct tcphdr *tcp = NULL;
    struct tcphdr *udp = NULL;
    struct icmphdr *icmp = NULL;

    struct destination dest = { .result = DEST_NOT_FOUND };
    struct l4ports l4;

    __u32 cpu_id = bpf_get_smp_processor_id();
    void *flow_state = NULL;

    // look up the flow_state hash that we should use for this cpu core from the flow_states array_of_maps (if tracking enabled)
    if (TRACK_FLOWS(flags))
	flow_state = bpf_map_lookup_elem(&flow_states, &cpu_id);
    
    switch (ip->protocol) {
	
    case IPPROTO_TCP:	
	tcp = data + nh_off;
	
        nh_off += sizeof(struct tcphdr);
	
        if (data + nh_off > data_end)
	    return XDP_DROP;
	
	l4.source = tcp->source;
	l4.dest = tcp->dest;

	//if (TRACK_FLOWS(flags))
	dest = find_tcp_flow(flow_state, ip, tcp, start_s, setting->era, global, SHARE_FLOWS(flags));

	if (dest.result == DEST_FOUND) {
	    if(ESTIMATE_CONNS(flags))
		be_tcp_concurrent(ip, tcp, dest.state, setting->era);
	} else {
	    dest = find_backend(ip, l4);
	    
	    switch(dest.result) {
	    case DEST_NOT_FOUND:
		return XDP_PASS; // check if vip exists and drop?
	    case DEST_NOT_AVAILABLE:
		return complete(global, start, XDP_DROP);
	    case DEST_FOUND:
		//if (TRACK_FLOWS(flags))
		store_tcp_flow(flow_state, ip, l4, dest, global);
		break;
	    default:
		return complete(global, start, XDP_DROP);
	    }
	}

	if(STORE_STATS(flags)) {
	    // if the backend counter does not exist then this destination is no longer valid
	    if (!increment_backend_counter(ip, l4.dest, dest.rip, octets, dest.new))
		return complete(global, start, XDP_DROP);
	}
	
	return complete(global, start, forward(eth, vlan, ip, dest));
	
    case IPPROTO_UDP:
	udp = data + nh_off;
	
        nh_off += sizeof(struct udphdr);
	
        if (data + nh_off > data_end)
	    return XDP_DROP;

	l4.source = udp->source;
	l4.dest = udp->dest;
	dest = find_backend(ip, l4);
	
	switch(dest.result) {
	case DEST_NOT_FOUND:
            return XDP_PASS; // check if vip exists and drop?
	case DEST_NOT_AVAILABLE:
	    return XDP_DROP;
	case DEST_FOUND:
	    break;
	default:
	    return XDP_DROP;
	}

	if(STORE_STATS(flags))
	    increment_backend_counter(ip, l4.dest, dest.rip, octets, 0);
	
	return forward(eth, vlan, ip, dest);

    case IPPROTO_ICMP:
	icmp = data + nh_off;
	
	nh_off += sizeof(struct icmphdr);
	
	if (data + nh_off > data_end)
	    return XDP_DROP;
	
	// respond to pings to configured VIPs
	struct vrpp vr = { .vip = ip->daddr };
	struct counter *c = bpf_map_lookup_elem(&vrpp_counter, &vr);
	
	if (!c)
	    break;

	// An ICMP message generated by an intermediate router will
	// not be delivered to the same core via RSS (or even load
	// balancer when ECMP is in use) so we not be able to locate
	// the correct (per-CPU) flow information. To ensure that the
	// message goes to the right backend we pass it up to
	// userspace where it is forwarded to every backend for that
	// service; it will be ignored by all but the intended
	// server (all balancers should see the same set of backends):

	if (icmp->type == ICMP_DEST_UNREACH && icmp->code == ICMP_FRAG_NEEDED) {
	    // TODO: check return code if we want more detailed stats
	    icmp_dest_unreach_frag_needed(ip, icmp, data_end, 0);
	    if (global)
		global->toobig++;
	    return XDP_DROP;
	}
	
	if (icmp->type != ICMP_ECHO || icmp->code != 0)
	    return XDP_DROP;

	// temporary mock for testing - pretend to be dest_unreach/frag_needed for port 80
	//icmp_dest_unreach_frag_needed(ip, icmp, data_end, 80);
	//return XDP_DROP;

	__u16 old_csum = icmp->checksum;
	icmp->checksum = 0;	
	struct icmphdr old = *icmp;
	
	icmp->type = ICMP_ECHOREPLY;
	icmp->checksum = icmp_checksum_diff(~old_csum, icmp, &old);

	ip_reply(ip); // reset TTL and swap source and destination

	char mac[6];
	maccpy(mac, eth->h_dest);
	maccpy(eth->h_dest, eth->h_source);
	maccpy(eth->h_source, mac);

	return XDP_TX;
    }

    return XDP_PASS;
    
    __u32 vid = ZERO;
    __be32 src, dst;
 do_nat:
    
    if (ip->ttl == 1)
	return XDP_DROP;

    if (is_veth) {
	if (!outgoing)
	    return XDP_DROP;
	vid = outgoing->vid;
    } else {
	if (!incoming)
	    return XDP_DROP;
	vid = VETH;
    }
    
    struct redirect *r;
    if (!(r = bpf_map_lookup_elem(&redirect_mac, &vid)))
	return XDP_DROP;
    
    if (is_veth) {
	maccpy(eth->h_dest, outgoing->mac);
	maccpy(eth->h_source, r->source);
	src = r->addr; // send from phys ip + mac to vip/real's mac
	dst = outgoing->vip;
    } else {
	maccpy(eth->h_dest, r->dest);
	maccpy(eth->h_source, r->source);
	src = *incoming;
	dst = r->addr; // send to netns ip + mac, from vip/veth's mac
    }
    
    if (nulmac(eth->h_source) || nulmac(eth->h_dest) || !src || !dst)
	return XDP_DROP;
    
    if (nat_ok(ip, data_end, src, dst)) {
	int action = bpf_redirect_map(&redirect_map, vid, XDP_DROP);
	
	// pop VLAN header if received on a tagged interface
	if (vlan && vlan_tag_pop(ctx, eth) < 0)
	    return XDP_DROP;
	
	return action;
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
