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

const __u32 ZERO = 0;
const __u16 MTU = 1500;

const __u8 F_STICKY = 0x01;

const __u8 F_LAYER2_DSR  = 0;
const __u8 F_LAYER3_FOU  = 1;
const __u8 F_LAYER3_GRE  = 2;
const __u8 F_LAYER3_GUE  = 3;
const __u8 F_LAYER3_IPIP = 4;

enum lookup_result {
		    NOT_FOUND = 0,
		    NOT_A_VIP,
		    LAYER2_DSR,
		    LAYER3_GRE,
		    LAYER3_FOU,
		    LAYER3_IPIP,
		    LAYER3_GUE,
};

/*
const int BUFFLEN = 4096;
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, __u8[4096]);    
    __uint(max_entries, 1);
} buffers SEC(".maps");
*/


/*
struct info {
    __be32 vip;
    __be32 saddr;
    char h_dest[6];
    char pad[2];
};
*/

struct myflags {
    __u16 new : 1;
    __u16 tcp : 1; 
    __u16 syn : 1;
    __u16 ack : 1;     
    __u16 fin : 1;
    __u16 rst : 1;
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
	__u8 ptr[16];
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
};
typedef struct tunnel tunnel_t;

struct servicekey {
    struct addr addr;
    __be16 port;
    __u16 proto;
};

struct destination {
    struct addr daddr;
    struct addr saddr;
    __u16 sport; // FOU / GUE
    __u16 dport; // FOU / GUE
    __u8 hwaddr[6]; // MAC of router for L3 or backend for L2
    __u16 vlanid;
    tunnel_t tunnel;
};

#include "new.h"


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
    tunnel_t tunnel;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fourtuple);
    __type(value, struct flow);
    __uint(max_entries, 100);
} flows SEC(".maps");


    
/**********************************************************************/
/*
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, struct info);
    __uint(max_entries, 1);
} infos SEC(".maps");
*/


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8[16]);
    __type(value, __u32);
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

#define FLAGS F_CALCULATE_CHECKSUM
#define xFLAGS 0

static __always_inline
int is_addr4(struct addr *a) {
    return (!a->addr4.pad1 && !a->addr4.pad2 && !a->addr4.pad3) ? 1 : 0;
}

static __always_inline
int send_l2(struct xdp_md *ctx, struct destination *dest)
{
    return redirect_eth(ctx, dest->hwaddr) < 0 ? XDP_ABORTED : XDP_TX;
}

static __always_inline
int send_fou(struct xdp_md *ctx, struct destination *dest, tunnel_t *t)
{
    if (is_addr4(&(t->daddr)))
	return push_fou4(ctx, dest->hwaddr, t) < 0 ? XDP_ABORTED : XDP_TX;
    
    return push_fou6(ctx, dest->hwaddr, t) < 0 ? XDP_ABORTED : XDP_TX;    
}

static __always_inline
int send_gue(struct xdp_md *ctx, struct destination *dest, tunnel_t *t, __u8 protocol)
{
    if (is_addr4(&(t->daddr)))
	return push_gue4(ctx, dest->hwaddr, t, protocol) < 0 ? XDP_ABORTED : XDP_TX;
    
    return push_gue6(ctx, dest->hwaddr, t, protocol) < 0 ? XDP_ABORTED : XDP_TX;
}

static __always_inline
int send_in4(struct xdp_md *ctx, struct destination *dest, tunnel_t *t, int is_ipv6)
{

    if (is_addr4(&(t->daddr))) {
	
	if (is_ipv6)
	    return push_6in4(ctx, dest->hwaddr, t) < 0 ? XDP_ABORTED : XDP_TX;
	
	return push_ipip(ctx, dest->hwaddr, t) < 0 ? XDP_ABORTED : XDP_TX;
    }

    if (is_ipv6)
	return push_6in6(ctx, dest->hwaddr, t) < 0 ? XDP_ABORTED : XDP_TX;
	
    return push_4in6(ctx, dest->hwaddr, t) < 0 ? XDP_ABORTED : XDP_TX;
}


static __always_inline
int send_gre(struct xdp_md *ctx, struct destination *dest, tunnel_t *t, __u16 protocol)
{
    if (is_addr4(&(t->daddr)))
	return push_gre4(ctx, dest->hwaddr, t, protocol) < 0 ? XDP_ABORTED : XDP_TX;
    
    return push_gre6(ctx, dest->hwaddr, t, protocol) < 0 ? XDP_ABORTED : XDP_TX;
    
    return XDP_ABORTED;
}

//static __always_inline
int send_frag_needed4(struct xdp_md *ctx, __be32 saddr, __u16 mtu)
{
    /*
    __u8 *buffer = NULL;
    if (!(buffer = bpf_map_lookup_elem(&buffers, &ZERO)))
	return XDP_ABORTED;
     
    return (frag_needed(ctx, saddr, mtu, buffer) < 0) ? XDP_ABORTED : XDP_TX;
    */

    
    // should probably rate limit sending frag_needed - calculating checksum is slow
    // could have a token queue refilled from userspace every second?
    return (frag_needed4(ctx, saddr, mtu, NULL) < 0) ? XDP_ABORTED : XDP_TX;    
}

/*
static __always_inline
__u16 l4_hash(struct addr *saddr, struct addr *daddr, void *l4)
{
    // UDP, TCP and SCTP all have src and dst port in 1st 32 bits, so use shortest type (UDP)
    struct udphdr *udp = (struct udphdr *) l4;
    struct {
	struct addr src;
	struct addr dst;
	__be16 sport;
	__be16 dport;
    } h = { .src = *saddr, .dst = *daddr};
    if (udp) {
	h.sport = udp->source;
	h.dport = udp->dest;
    }
    return sdbm((unsigned char *) &h, sizeof(h));
}
*/
//static __always_inline
__u16 l4_hash_(fourtuple_t *ft, int sticky)
{
    // UDP, TCP and SCTP all have src and dst port in 1st 32 bits, so use shortest type (UDP)
    if (sticky)
	return sdbm((unsigned char *) ft, sizeof(addr_t) * 2);
	
    return sdbm((unsigned char *) ft, sizeof(fourtuple_t));
}

static __always_inline
int is_ipv4_addr(struct addr a) {
    return (!a.addr4.pad1 && !a.addr4.pad2 && !a.addr4.pad3) ? 1 : 0;
}

static __always_inline
int lookupy(fourtuple_t *ft, __u8 protocol)
{
    struct flow *flow = bpf_map_lookup_elem(&flows, ft);

    if (!flow)
	return -1;
    
    return 0;
}

static __always_inline
enum lookup_result lookupx(fourtuple_t *ft, __u8 protocol, struct destination *d, tunnel_t *t) // flags arg?    
{
    struct servicekey key = { .addr = ft->daddr, .port = bpf_ntohs(ft->dport), .proto = protocol };
    struct destinations *service = bpf_map_lookup_elem(&destinations, &key);

    if (!service)
	return NOT_FOUND;
    
    __u8 sticky = service->flag[0] & F_STICKY;
    __u16 hash3 = l4_hash_(ft, 1);
    __u16 hash4 = l4_hash_(ft, 0);
    __u8 index = service->hash[(sticky ? hash3 : hash4) & 0x1fff]; // limit to 0-8191

    if (!index)
	return NOT_FOUND;

    d->daddr = service->daddr[index];      // backend's address, inc. MAC and VLAN for L2
    d->dport = service->dport[index];      // destination port for L3 tunnel (eg. FOU)
    d->sport = 0x8000 | (hash4 & 0x7fff);  // source port for L3 tunnel (eg. FOU)
    memcpy(d->hwaddr, service->router, 6); // router MAC for L3 tunnel - may be better in vips    
    d->vlanid = service->vlanid;           // VLAN ID that L3 services should use - may be better in vips

    d->saddr = is_ipv4_addr(d->daddr) ? service->saddr : service->saddr6;

    t->saddr = d->saddr;
    t->daddr = d->daddr;
    t->sport = d->sport;
    t->dport = d->dport;
    t->nochecksum = 1;
    
    __u8 type = service->flag[index] & 0xf; // bottom 4 bit only from userspace

    
    // store flow? - maybe better to mark as new flow and allow a later stage to do this

    // for layer 2 the destination hwaddr is that of the backend, not a router
    //if (F_LAYER2_DSR == flag)
    if (F_LAYER2_DSR == type)	
	memcpy(d->hwaddr, service->hwaddr[index], 6);
    
    if (nulmac(d->hwaddr))
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
enum lookup_result lookup6(struct xdp_md *ctx, struct ip6_hdr *ip6, struct destination *dest, fourtuple_t *ft, tunnel_t *t)
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
    
    //return lookup(&saddr, &daddr, tcp, ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt, dest, t);
    return lookupx(ft, ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt, dest, t);
}

//static __always_inline
enum lookup_result lookup4(struct xdp_md *ctx, struct iphdr *ip, struct destination *dest, fourtuple_t *ft, tunnel_t *t)
{
    void *data_end = (void *)(long)ctx->data_end;
    
    if (ip + 1 > data_end)
	return NOT_FOUND;
    
    struct addr saddr = { .addr4.addr = ip->saddr };
    struct addr daddr = { .addr4.addr = ip->daddr };

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
    
    //return lookup(&saddr, &daddr, tcp, ip->protocol, dest, t);
    return lookupx(ft, ip->protocol, dest, t);
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
int xdp_fwd_func_(struct xdp_md *ctx, struct destination *dest, struct fourtuple *ft, tunnel_t *t)    
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
	result = lookup6(ctx, next_header, dest, ft, t);
	overhead = sizeof(struct ip6_hdr);
	break;
    case bpf_htons(ETH_P_IP):
	result = lookup4(ctx, next_header, dest, ft, t);
	overhead = sizeof(struct iphdr);	
	break;
    default:
	return XDP_PASS;
    }

    overhead = is_ipv4_addr(dest->daddr) ? sizeof(struct iphdr) : sizeof(struct ip6_hdr);

    // no default here - handle all cases explicitly
    switch (result) {
    case LAYER2_DSR: return send_l2(ctx, dest);
    case LAYER3_GRE: overhead += GRE_OVERHEAD; break;
    case LAYER3_FOU: overhead += FOU_OVERHEAD; break;
    case LAYER3_GUE: overhead += GUE_OVERHEAD; break;
    case LAYER3_IPIP: break;
    case NOT_A_VIP: return XDP_PASS;
    case NOT_FOUND: return XDP_DROP;
    }

    // Layer 3 service packets should only ever be received on the same interface/VLAN as they will be sent
    // FIXME: need to make provision for untagged bond interfaces - list of acceptable interfaces?
    // Also check if packet is too large to encapsulate
    switch (result) {
    case LAYER3_GRE: // fallthough
    case LAYER3_FOU: // fallthough
    case LAYER3_GUE: // fallthough
    case LAYER3_IPIP:
	if (check_ingress_interface(ctx->ingress_ifindex, vlan, dest->vlanid) < 0)
            return XDP_DROP;
	
	if ((data_end - next_header) + overhead > mtu) {
	    if (is_ipv6) {
		bpf_printk("IPv6 FRAG_NEEDED - FIXME\n");
	    } else {
		bpf_printk("IPv4 FRAG_NEEDED\n");
		return send_frag_needed4(ctx, dest->saddr.addr4.addr, mtu - overhead);
	    }
	}
	
	break;

    default:
	break;
    }
    
    switch (result) {
    case LAYER3_FOU:  return send_fou(ctx, dest, t);
    case LAYER3_IPIP: return send_in4(ctx, dest, t, is_ipv6);
    case LAYER3_GRE:  return send_gre(ctx, dest, t, is_ipv6 ? ETH_P_IPV6 : ETH_P_IP);
    case LAYER3_GUE:  return send_gue(ctx, dest, t, is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP);
    default:
	break;
    }
    return XDP_DROP; 
}

static __always_inline
void update(fourtuple_t *key, tunnel_t *t)
{
    //struct fourtuple key = { .sport = sport, .dport = dport };
    struct flow val = { .tunnel = *t };
    
    if (bpf_map_update_elem(&flows, key, &val, BPF_ANY)) {
	bpf_printk("ERR\n");
    } else {
	bpf_printk("OK\n");
    }
}




SEC("xdp")
int xdp_fwd_func(struct xdp_md *ctx)
{
    __u64 start = bpf_ktime_get_ns();
     __u32 took = 0;
     
    struct destination dest = {};
    fourtuple_t ft = {};
    tunnel_t t = {};
    
    int action = xdp_fwd_func_(ctx, &dest, &ft, &t);

    //if (dest.flags.syn)	update(dest.sport, dest.dport);
    //update(dest.client, dest.vip, dest.sport, dest.dport);    
    
    // handle stats here
    switch (action) {
    case XDP_PASS: return XDP_PASS;
    case XDP_DROP: return XDP_DROP;
    case XDP_TX:
	took = bpf_ktime_get_ns() - start;
	//int ack = dest.flags.ack ? 1 : 0;	
	//int syn = dest.flags.syn ? 1 : 0;	
	bpf_printk("TOOK: %d\n", took);
	bpf_printk("FT %d %d\n", bpf_ntohs(ft.sport), bpf_ntohs(ft.dport));
	update(&ft, &t);
	return XDP_TX;
    case XDP_ABORTED: return XDP_ABORTED;
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
