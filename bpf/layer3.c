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

https://www.etb-tech.com/netronome-agilio-cx-40gb-qsfp-dual-port-low-profile-network-card-pcbd0097-005-nic00476.html

https://datatracker.ietf.org/doc/html/draft-herbert-gue-01

bpf_printk: cat /sys/kernel/debug/tracing/trace_pipe

# remember to set up IPv6 and VIPs
ip a add 192.168.101.201 dev lo
ip -6 a add fd6e:eec8:76ac:ac1d:200::1 dev lo

* check VIP against know list
* lookup flow in state table first
* if not there then try shared flow table
* if not found then lookup backend server/tunnel info
* modify packet
* if required then store new/updated flow record in state table
* push to userland queue if necessary
* update stats
* TX/redirect_map packet as indicated in dest record

# TODO
* IPv6 ICMP - frag needed
* ICMP replies
* flow table
* healthchecks

**********************************************************************

# can use same port for IP and IPV6 in GOU as there is a protocol field

# IPv4 in GUE4
modprobe fou
modprobe ipip
ip fou add port 9999 gue
ip link set dev tunl0 up
sysctl -w net.ipv4.conf.tunl0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0

# IPv6 in GUE4
modprobe fou
modprobe sit
ip l set dev sit0 up
ip fou add port 9999 gue

**********************************************************************

# IPv4 in FOU4
modprobe fou
modprobe ipip
ip fou add port 9999 ipproto 4
ip link set dev tunl0 up
sysctl -w net.ipv4.conf.tunl0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0

# IPv6 in FOU4
modprobe fou
modprobe sit
ip l set dev sit0 up
ip fou add port 6666 ipproto 41

# IPv6 in FOU6
modprobe fou
modprobe fou6 # creates ip6tnl0
ip -6 fou add port 6666 ipproto 41
ip l set dev ip6tnl0 up
# DOES NOT WORK ATM - I thought this was working previously

# IPv4 in FOU6 - couldn't get to work

**********************************************************************

# IPIP
modprobe ipip
ip l set dev tunl0 up
tcpdump tunl0
sysctl -w net.ipv4.conf.tunl0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0

# 6in4
modprobe sit
ip l set dev sit0 up

# 6in6
modprobe ip6_tunnel
ip -6 tunnel change ip6tnl0 mode ip6ip6
ip l set dev ip6tnl0 up

# 4in6 
modprobe ip6_tunnel
ip -6 tunnel change ip6tnl0 mode ip4ip6
ip l set dev ip6tnl0 up
sysctl -w net.ipv4.conf.ip6tnl0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0

**********************************************************************

# 4in4 and 6in4 4 GRE
modprobe ip_gre
ip l set dev gre0 up
sysctl -w net.ipv4.conf.gre0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0

# 6in6 and 4in6 GRE
modprobe ip6_gre
ip l set dev ip6gre0 up
sysctl -w net.ipv4.conf.ip6gre0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0

**********************************************************************

ip link add name geneve0 type geneve id VNI remote REMOTE_IPv4_ADDR

ip link add name geneve0 type geneve id 666 remote 0.0.0.0
ip l set dev geneve0 up
sysctl -w net.ipv4.conf.geneve0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0

For a basic FOU4 backend:

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

#include <netinet/ip6.h>

#define IS_DF(f) (((f) & bpf_htons(0x02<<13)) ? 1 : 0)
#define memcpy(d, s, n) __builtin_memcpy((d), (s), (n))
//#define memcmp(d, s, n) __builtin_memcmp((d), (s), (n))
//#define memcmp(d, s, n) (1)

const __u8 F_CALCULATE_CHECKSUM = 1;

#include "vlan.h"


#define VERSION 1
#define SECOND_NS 1000000000l


const __u32 NETNS = 4095;

const __u32 ZERO = 0;
const __u16 MTU = 1500;

const __u8 F_STICKY = 0x01;

const __u8 F_LAYER2_DSR    = 0;
const __u8 F_LAYER3_FOU    = 1;
const __u8 F_LAYER3_GRE    = 2;
const __u8 F_LAYER3_GUE    = 3;
const __u8 F_LAYER3_IPIP   = 4;

// https://developers.redhat.com/blog/2019/05/17/an-introduction-to-linux-virtual-interfaces-tunnels

enum lookup_result {
		    NOT_FOUND = 0,
		    NOT_A_VIP,
		    PROBE_REPLY,
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

struct addr6 {
    __u8 addr[16];
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

struct tunnel {
    addr_t saddr;
    addr_t daddr;
    __be16 sport;
    __be16 dport;
    __u16 nochecksum : 1;
    __u16 type : 3;

    __u8 hwaddr[6];
    __u16 vlanid;
};
typedef struct tunnel tunnel_t;

#include "new.h"


struct info {
    __u16 sticky : 1;
    __u16 syn : 1;
    __u16 ack : 1;
    __u16 fin : 1;
    __u16 rst : 1;

};
typedef struct info info_t;


struct servicekey {
    struct addr addr;
    __be16 port;
    __u16 proto;
};


typedef __u8 mac[6];

struct destinations {
    __u8 hash[8192];
    __u8 flag[256];    // flag[0] - global flags for service; sticky, leastconns
    __u16 dport[256];  // port[0] - high byte leastconns score, low byte destination index to use
    struct addr daddr[256];
    struct addr saddr; // source address to use with tunnels
    struct addr saddr6; // source address to use with tunnels    
    __u8 router[6];    // router MAC address to send encapsulated packets to
    __u16 vlanid;      // VLAN ID on which encapsulated packets should be received/sent
    //struct addr icmp; // optional address to send ICMP UNREACH/FRAG from?
    // maybe seperate vlan/mac records if IPv6 is to support L2
    mac hwaddr[256];
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
    __be32 vaddr; // virtual service IP
    __be32 raddr; // real server IP
    __be16 vport; // virtual service port
    __be16 protocol;
};

struct counters {
    __u64 packets;
    __u64 octets;
    __u64 flows;
    __u64 errors;

    __be16 dport; // to terminate
    __be16 type;  // old mappings
    __be16 pad1;  // pad to 8-bytes alignment
    __be16 pad2;  // pad to 8-bytes alignment
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct vrpp);
    __type(value, struct counters);
    __uint(max_entries, 4096);
} stats SEC(".maps");


/**********************************************************************/

struct vlaninfo {
    __u32 source_ipv4;
    struct addr source_ipv6;
    __u32 ifindex;
    __u8 hwaddr[6]; // interface's MAC
    __u8 router[6]; // router's MAC (peer's address in case of veth)
};

struct nat_info {
    __u16 vlanid;
    __u8 hwaddr[6]; // L2 MAC address of backend
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32); // "VLAN" ID
    __type(value, struct vlaninfo);
    __uint(max_entries, 4096);
} vlan_info SEC(".maps");


//struct three_tuple {
//    struct addr addr;
//    __u16 port;
//    __u16 protocol;
//};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, addr_t); // nat
    __type(value, addr_t[2]); // vip/rip
    __uint(max_entries, 4096);
} nat_to_vip_rip SEC(".maps");
    
struct vip_info {
    addr_t ext_ip_;
    __u16 vlanid;
    __u8 h_dest_[6];   // router MAC - unused
    __u8 h_source_[6]; // external interface AMC - unused
    __u8 pad[2];
};

struct five_tuple {
    addr_t saddr;
    addr_t daddr;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
};

struct addr_port_time {
    __u64 time;
    addr_t addr;
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fourtuple);
    __type(value, struct flow);
    __uint(max_entries, 100);
} flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8[16]);
    //    __type(value, __u32);
    __type(value, struct vip_info);
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

/**********************************************************************/

static __always_inline
int is_addr4(struct addr *a) {
    return (!(a->addr4.pad1) && !(a->addr4.pad2) && !(a->addr4.pad3)) ? 1 : 0;
}

static __always_inline
int send_l2(struct xdp_md *ctx, tunnel_t *t)
{
    return redirect_eth(ctx, t->hwaddr) < 0 ? XDP_ABORTED : XDP_TX;
}

static __always_inline
int send_fou(struct xdp_md *ctx, tunnel_t *t)
{
    if (is_addr4(&(t->daddr)))
	return push_fou4(ctx, t->hwaddr, t) < 0 ? XDP_ABORTED : XDP_TX;
    
    return push_fou6(ctx, t->hwaddr, t) < 0 ? XDP_ABORTED : XDP_TX;    
}

static __always_inline
int send_gue(struct xdp_md *ctx, tunnel_t *t, __u8 protocol)
{
    if (is_addr4(&(t->daddr)))
	return push_gue4(ctx, t->hwaddr, t, protocol) < 0 ? XDP_ABORTED : XDP_TX;
    
    return push_gue6(ctx, t->hwaddr, t, protocol) < 0 ? XDP_ABORTED : XDP_TX;
}

static __always_inline
int send_in4(struct xdp_md *ctx, tunnel_t *t, int is_ipv6)
{

    if (is_addr4(&(t->daddr))) {
	
	if (is_ipv6)
	    return push_6in4(ctx, t->hwaddr, t) < 0 ? XDP_ABORTED : XDP_TX;
	
	return push_ipip(ctx, t->hwaddr, t) < 0 ? XDP_ABORTED : XDP_TX;
    }

    if (is_ipv6)
	return push_6in6(ctx, t->hwaddr, t) < 0 ? XDP_ABORTED : XDP_TX;
	
    return push_4in6(ctx, t->hwaddr, t) < 0 ? XDP_ABORTED : XDP_TX;
}


static __always_inline
int send_gre(struct xdp_md *ctx, tunnel_t *t, __u16 protocol)
{
    if (is_addr4(&(t->daddr)))
	return push_gre4(ctx, t->hwaddr, t, protocol) < 0 ? XDP_ABORTED : XDP_TX;
    
    return push_gre6(ctx, t->hwaddr, t, protocol) < 0 ? XDP_ABORTED : XDP_TX;
}

//static __always_inline
int send_frag_needed4(struct xdp_md *ctx, __be32 saddr, __u16 mtu)
{
    // should probably rate limit sending frag_needed - calculating checksum is slow
    // could have a token queue refilled from userspace every second?
    return (frag_needed4(ctx, saddr, mtu, NULL) < 0) ? XDP_ABORTED : XDP_TX;    
}

//static __always_inline
__u16 l3_hash(fourtuple_t *ft)
{
    return sdbm((unsigned char *) ft, sizeof(addr_t) * 2);
}

//static __always_inline
__u16 l4_hash(fourtuple_t *ft)
{
    return sdbm((unsigned char *) ft, sizeof(fourtuple_t));
}

static __always_inline
int is_ipv4_addr(struct addr a) {
    return (!a.addr4.pad1 && !a.addr4.pad2 && !a.addr4.pad3) ? 1 : 0;
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
enum lookup_result lookup(fourtuple_t *ft, __u8 protocol, tunnel_t *t)
{
    struct servicekey key = { .addr = ft->daddr, .port = bpf_ntohs(ft->dport), .proto = protocol };
    struct destinations *service = bpf_map_lookup_elem(&destinations, &key);

    if (IPPROTO_TCP == protocol) {
	// lookup in flow table
    }

    
    if (!service)
	return NOT_FOUND;
    
    __u8 sticky = service->flag[0] & F_STICKY;
    __u16 hash3 = l3_hash(ft);
    __u16 hash4 = l4_hash(ft);
    __u8 index = service->hash[(sticky ? hash3 : hash4) & 0x1fff]; // limit to 0-8191

    if (!index)
	return NOT_FOUND;


    t->daddr = service->daddr[index];     // backend's address
    t->saddr = is_ipv4_addr(t->daddr) ? service->saddr : service->saddr6;
    t->sport = 0x8000 | (hash4 & 0x7fff); // source port for L3 tunnel (eg. FOU)
    t->dport = service->dport[index];     // destination port for L3 tunnel (eg. FOU)
    //t->nochecksum = 1;

    memcpy(t->hwaddr, service->router, 6); // router MAC for L3 tunnel - may be better in vips
    t->vlanid = service->vlanid;           // VLAN ID that L3 services should use - maybe vips?
    
    __u8 type = service->flag[index] & 0xf; // bottom 4 bit only from userspace

    
    // store flow? - maybe better to mark as new flow and allow a later stage to do this

    // for layer 2 the destination hwaddr is that of the backend, not a router
    if (F_LAYER2_DSR == type)	
	memcpy(t->hwaddr, service->hwaddr[index], 6);
    
    if (nulmac(t->hwaddr))
	return NOT_FOUND;
    
    switch (type) {
    case F_LAYER3_FOU:  return LAYER3_FOU;
    case F_LAYER3_GRE:  return LAYER3_GRE;
    case F_LAYER3_IPIP: return LAYER3_IPIP;
    case F_LAYER3_GUE:  return LAYER3_GUE;
    case F_LAYER2_DSR:  return LAYER2_DSR;
    }
    
   return NOT_FOUND;
}

//static __always_inline
enum lookup_result lookup6(struct xdp_md *ctx, struct ip6_hdr *ip6, fourtuple_t *ft, tunnel_t *t)
{
    void *data_end = (void *)(long)ctx->data_end;

    if (ip6 + 1 > data_end)
        return NOT_FOUND;

    if ((ip6->ip6_ctlun.ip6_un2_vfc >> 4) != 6)
        return NOT_FOUND;

    struct addr saddr = { .addr6 = ip6->ip6_src };
    struct addr daddr = { .addr6 = ip6->ip6_dst };

    ft->saddr = saddr;
    ft->daddr = daddr;
    
    if (!bpf_map_lookup_elem(&vips, &daddr))
        return NOT_A_VIP;
    
    if(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6) {
        //bpf_printk("IPv6 ICMP!\n");
        return NOT_A_VIP;
    }

    if(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP)
        return NOT_FOUND;

    struct tcphdr *tcp = (void *) (ip6 + 1);

    if (tcp + 1 > data_end)
        return NOT_FOUND;

    ft->sport = tcp->source;
    ft->dport = tcp->dest;
    
    //int x = bpf_ntohs(tcp->dest);
    //bpf_printk("IPv6 TCP %d\n", x);

    if (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim <= 1)
	return NOT_FOUND; // FIXME - new enum

    (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim)--;
    
    return lookup(ft, ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt, t);
}

//static __always_inline
enum lookup_result lookup4(struct xdp_md *ctx, struct iphdr *ip, fourtuple_t *ft, tunnel_t *t)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;

    if (eth + 1 > data_end)
        return NOT_FOUND;

    if (ip + 1 > data_end)
	return NOT_FOUND;
    
    struct addr saddr = { .addr4.addr = ip->saddr };
    struct addr daddr = { .addr4.addr = ip->daddr };

    if (bpf_map_lookup_elem(&vips, &saddr)) {
	// source was a VIP
	
	struct vlaninfo *vlaninfo = bpf_map_lookup_elem(&vlan_info, &NETNS);
	
	if (!vlaninfo)
	    return NOT_FOUND;

	// set correct MAC address for veth pair
	memcpy(eth->h_dest, vlaninfo->hwaddr, 6);
	memcpy(eth->h_source, vlaninfo->router, 6);	    
	return PROBE_REPLY;
    }
    
    ft->saddr = saddr;
    ft->daddr = daddr;
    
    if (!bpf_map_lookup_elem(&vips, &daddr))
    	return NOT_A_VIP;

    if (ip->version != 4)
	return NOT_FOUND;
    
    if (ip->ihl != 5)
        return NOT_FOUND;

    if (ip->ttl <= 1)
	return NOT_FOUND; // FIXME - new enum
    
    // ignore evil bit and DF, drop if more fragments flag set, or fragent offset is not 0
    if ((ip->frag_off & bpf_htons(0x3fff)) != 0)
        return NOT_FOUND; // FIXME - new enum;
    
    if (ip->protocol != IPPROTO_TCP)
	return NOT_FOUND;
    
    struct tcphdr *tcp = (void *)(ip + 1);

    if (tcp + 1 > data_end)
      return NOT_FOUND;
    
    ft->sport = tcp->source;
    ft->dport = tcp->dest;
    
    /* We're going to forward the packet, so we should decrement the time to live */
    ip_decrease_ttl(ip);    

    return lookup(ft, ip->protocol, t);
}

static __always_inline
int check_ingress_interface(__u32 ingress, struct vlan_hdr *vlan, __u32 expected) {

    if (vlan) {
	__u16 vlanid = bpf_ntohs(vlan->h_vlan_TCI) & 0x0fff;
	if (vlanid != expected)
	    return -1;
    } else {
	__u32 *interface = bpf_map_lookup_elem(&redirect_map, &expected);   
	if (!interface || !(*interface) || (*interface != ingress))
	    return -1;
    }

    return 0;
}



//SEC("XDP")
static __always_inline
int xdp_fwd_func_(struct xdp_md *ctx, struct fourtuple *ft, tunnel_t *t)    
{

    int mtu = MTU;
    int overhead = 0;
    enum lookup_result result = NOT_A_VIP;
    int is_ipv6 = 0;

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
    
    if (next_proto == ETH_P_8021Q) {
	return XDP_PASS; // not yet fully implmented
	vlan = next_header;
	
	if (vlan + 1 > data_end)
	    return XDP_PASS;
	
	next_proto = vlan->h_vlan_encapsulated_proto;
	next_header = vlan + 1;
    }

    switch (next_proto) {
    case bpf_htons(ETH_P_IPV6):
	is_ipv6 = 1;
	overhead = sizeof(struct ip6_hdr);
	result = lookup6(ctx, next_header, ft, t);
	break;
    case bpf_htons(ETH_P_IP):
	is_ipv6 = 0;
	overhead = sizeof(struct iphdr);
	result = lookup4(ctx, next_header, ft, t);
	break;
    default:
	return XDP_PASS;
    }

	    overhead = is_ipv4_addr(t->daddr) ? sizeof(struct iphdr) : sizeof(struct ip6_hdr);    

    // no default here - handle all cases explicitly
    switch (result) {
    case LAYER2_DSR: return send_l2(ctx, t);
    case LAYER3_GRE: overhead += GRE_OVERHEAD; break;
    case LAYER3_FOU: overhead += FOU_OVERHEAD; break;
    case LAYER3_GUE: overhead += GUE_OVERHEAD; break;
    case LAYER3_IPIP: break;
    case NOT_A_VIP: return XDP_PASS;
    case NOT_FOUND: return XDP_DROP;
    case PROBE_REPLY: return bpf_redirect_map(&redirect_map, NETNS, XDP_DROP);
    }

    // Layer 3 service packets should only ever be received on the same interface/VLAN as they will be sent
    // FIXME: need to make provision for untagged bond interfaces - list of acceptable interfaces?
    // Also check if packet is too large to encapsulate
    switch (result) {
    case LAYER3_GRE: // fallthough
    case LAYER3_FOU: // fallthough
    case LAYER3_GUE: // fallthough
    case LAYER3_IPIP:
	if (check_ingress_interface(ctx->ingress_ifindex, vlan, t->vlanid) < 0)
            return XDP_DROP;
	
	if ((data_end - next_header) + overhead > mtu) {
	    if (is_ipv6) {
		bpf_printk("IPv6 FRAG_NEEDED - FIXME\n");
	    } else {
		bpf_printk("IPv4 FRAG_NEEDED\n");
		//return send_frag_needed4(ctx, dest->saddr.addr4.addr, mtu - overhead);
		return send_frag_needed4(ctx, ft->saddr.addr4.addr, mtu - overhead);		
	    }
	}
	
	break;

    default:
	break;
    }
    
    switch (result) {
    case LAYER3_FOU:    return send_fou(ctx, t);
    case LAYER3_IPIP:   return send_in4(ctx, t, is_ipv6);
    case LAYER3_GRE:    return send_gre(ctx, t, is_ipv6 ? ETH_P_IPV6 : ETH_P_IP);
    case LAYER3_GUE:    return send_gue(ctx, t, is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP);
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




SEC("xdp")
int xdp_fwd_func(struct xdp_md *ctx)
{
    //__u64 start = bpf_ktime_get_ns();
    //__u32 took = 0;
     
    fourtuple_t ft = {};
    tunnel_t t = {};
    
    int action = xdp_fwd_func_(ctx, &ft, &t);

    // handle stats here
    switch (action) {
    case XDP_PASS: return XDP_PASS;
    case XDP_DROP: return XDP_DROP;
    case XDP_TX:
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
    
    return XDP_DROP;
}


SEC("xdp")
int xdp_request(struct xdp_md *ctx)
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
	return XDP_PASS;

    addr_t nat = { .addr4.addr = ip->daddr};
    addr_t *vip_rip = bpf_map_lookup_elem(&nat_to_vip_rip, &nat);

    if (!vip_rip)
    	return XDP_PASS;

    addr_t vip = vip_rip[0];
    addr_t rip = vip_rip[1];
    
    struct vip_info *vip_info = bpf_map_lookup_elem(&vips, &vip);
    
    if (!vip_info)
	return XDP_DROP;
    
    __u32 vlanid = vip_info->vlanid;
    
    struct vlaninfo *vlaninfo = bpf_map_lookup_elem(&vlan_info, &vlanid);

    if (!vlaninfo)
	return XDP_DROP;
    
    if (!vlaninfo->ifindex) // FIXME - in case of single nic/no vlan setup?
	return XDP_DROP;
    
    if (ip->version != 4)
	return XDP_DROP;
    
    if (ip->ihl != 5)
        return XDP_DROP;
    
    if (ip->ttl <= 1)
	return XDP_DROP;

    // ignore evil bit and DF, drop if more fragments flag set, or fragent offset is not 0
    if ((ip->frag_off & bpf_htons(0x3fff)) != 0)
        return XDP_DROP; // FIXME - new enum;
    
    if (ip->protocol != IPPROTO_TCP)
	return XDP_DROP;
    
    struct tcphdr *tcp = (void *)(ip + 1);
    
    if (tcp + 1 > data_end)
      return XDP_DROP;

    __be16 eph = tcp->source;
    __be16 svc = tcp->dest;
    addr_t ext = { .addr4.addr = vlaninfo->source_ipv4 };
    
    tunnel_t t = {
		  .saddr = ext,
		  .daddr = rip,
		  .sport = 0x6666,
		  .dport = 9999,
		  .nochecksum = 1,
		  .type = F_LAYER3_GUE,
		  .vlanid = vip_info->vlanid,
    };
    
    memcpy(t.hwaddr, vlaninfo->router, 6);
    
    /**********************************************************************/
    // SAVE CHECKSUM INFO
    /**********************************************************************/
    struct l4 o = {.saddr = ip->saddr, .daddr = ip->daddr, .sport = tcp->source, .dport = tcp->dest };
    __u16 old_csum = ip->check;
    struct iphdr old = *ip;
    old.check = 0;
    /**********************************************************************/

    ip->saddr = ext.addr4.addr;
    ip->daddr = vip.addr4.addr;

    __u16 tmp = htons(eph);
    tcp->source = tmp;

    /**********************************************************************/
    // CHECKSUM DIFFS FROM OLD
    /**********************************************************************/
    ip->check = 0;
    ip->check = ipv4_checksum_diff(~old_csum, ip, &old);
    //struct l4 n = {.saddr = ip->saddr, .daddr = ip->daddr};
    struct l4 n = {.saddr = ip->saddr, .daddr = ip->daddr, .sport = tcp->source, .dport = tcp->dest };    
    tcp->check = l4_checksum_diff(~(tcp->check), &n, &o);
    /**********************************************************************/

    // TODO - handle all options
    if(push_gue4(ctx, vlaninfo->router, &t, IPPROTO_IPIP) < 0)
	return XDP_DROP;

    /**********************************************************************/
    data_end = (void *)(long)ctx->data_end;
    data     = (void *)(long)ctx->data;

    eth = data;

    if (eth + 1 > data_end)
        return XDP_PASS;
    
    memcpy(eth->h_dest, vlaninfo->router, 6);   // router/dest addr
    memcpy(eth->h_source, vlaninfo->hwaddr, 6); // our hw addr
    /**********************************************************************/
    

    // to match returning packet
    struct five_tuple rep = {
                             .sport = svc,
                             .dport = tmp, // might be modified
                             .protocol = IPPROTO_TCP,
    };
    rep.saddr = vip; // ????
    rep.daddr = ext; // ????
    
    struct addr_port_time map = {
                            .port = eph,
			    .time = bpf_ktime_get_ns(),
    };
    map.addr = nat; // ???
    
    bpf_map_update_elem(&reply, &rep, &map, BPF_ANY);
    
    return bpf_redirect(vlaninfo->ifindex, 0);
}

SEC("xdp")
int xdp_reply(struct xdp_md *ctx)
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

    // ignore evil bit and DF, drop if more fragments flag set, or fragent offset is not 0
    if ((ip->frag_off & bpf_htons(0x3fff)) != 0)
        return XDP_DROP;
    
    if (ip->protocol != IPPROTO_TCP)
        return XDP_DROP;
    
    struct tcphdr *tcp = (void *)(ip + 1);
    
    if (tcp + 1 > data_end)
	return XDP_DROP;    


    /**********************************************************************/
    // SAVE CHECKSUM INFO
    /**********************************************************************/
    struct l4 o = {.saddr = ip->saddr, .daddr = ip->daddr};
    __u16 old_csum = ip->check;
    struct iphdr old = *ip;
    old.check = 0;
    /**********************************************************************/
    
    addr_t saddr = { .addr4.addr = ip->saddr };
    addr_t daddr = { .addr4.addr = ip->daddr };    
    
    struct five_tuple rep = {
                             .protocol = IPPROTO_TCP,
                             .sport = tcp->source,
                             .dport = tcp->dest,
    };
    
    rep.saddr = saddr;
    rep.daddr = daddr;
    
    struct addr_port_time *match = bpf_map_lookup_elem(&reply, &rep);
    
    if (!match)
	return XDP_DROP;

    __u64 time = bpf_ktime_get_ns();

    if (time < match->time)
	return XDP_DROP;

    if ((time - match->time) > (5 * SECOND_NS))
	return XDP_DROP;

    struct vlaninfo *vlaninfo = bpf_map_lookup_elem(&vlan_info, &NETNS);
    
    if (!vlaninfo)
	return XDP_DROP;    

    ip->saddr = match->addr.addr4.addr;
    ip->daddr = vlaninfo->source_ipv4;
    tcp->dest = match->port;

    /**********************************************************************/
    // CHECKSUM DIFFS FROM OLD
    /**********************************************************************/
    ip->check = 0;
    ip->check = ipv4_checksum_diff(~old_csum, ip, &old);
    struct l4 n = {.saddr = ip->saddr, .daddr = ip->daddr};
    tcp->check = l4_checksum_diff(~(tcp->check), &n, &o);
    /**********************************************************************/

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

#endif
