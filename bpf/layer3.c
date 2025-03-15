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

ip a add 192.168.101.201 dev lo
ip -6 a add fd6e:eec8:76ac:ac1d:200::1 dev lo


ip a add fd6e:eec8:76ac:ac1d:100::2/64 dev ens160


modprobe ipip
modprobe fou

ip6_gre
gre

modprobe ip6_gre:
ip6tnl0
ip6gre0

ip l set dev ip6gre0 up:
ip a add 192.168.101.201 dev ip6gre0 # WORKS
ip -6 a add fd6e:eec8:76ac:ac1d:200::1 dev ip6gre0 # WORKS

# ip l add gre0 type gre
RTNETLINK answers: File exists (odd - gre0 then exists)

# ip l set dev gre0 up
6in4 gre then works
# ip a add 192.168.101.201 dev gre0
4in4 gre then works



**********************************************************************

# IPv4 in FOU4
modprobe fou
modprobe ipip
ip fou add port 9999 ipproto 4
ip link set dev tunl0 up
sysctl -w net.ipv4.conf.tunl0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0
ip a add 192.168.101.201/32 dev lo

# IPv6 in FOU4
modprobe fou
ip a add fd6e:eec8:76ac:ac1d:100::2/64 dev ens160 # need an IPv6 address to reply from
modprobe sit
ip l set dev sit0 up
ip fou add port 6666 ipproto 41
ip -6 a add fd6e:eec8:76ac:ac1d:200::1/128 dev lo

# IPv6 in FOU6
ip -6 a add fd6e:eec8:76ac:ac1d:100::2/64 dev ens160 # need an IPv6 address to reply from
ip -6 a add fd6e:eec8:76ac:ac1d:200::1/128 dev lo
modprobe fou
modprobe fou6 # creates ip6tnl0
ip -6 fou add port 6666 ipproto 41
ip l set dev ip6tnl0 up
# DOES NOT WORK ATM - I thought this was working previously

# IPv4 in FOU6 - couldn't get to work

**********************************************************************

# IPIP
ip a add 192.168.101.201 dev lo
modprobe ipip
ip l set dev tunl0 up
tcpdump tunl0
sysctl -w net.ipv4.conf.tunl0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0

# 6in4
ip -6 a add fd6e:eec8:76ac:ac1d:100::2/64 dev ens160 # need an IPv6 address to reply from
ip -6 a add fd6e:eec8:76ac:ac1d:200::1/128 dev lo
modprobe sit
ip l set dev sit0 up

# 6in6
ip -6 a add fd6e:eec8:76ac:ac1d:100::2/64 dev ens160 # need an IPv6 address to reply from
ip -6 a add fd6e:eec8:76ac:ac1d:200::1/128 dev lo
modprobe ip6_tunnel
ip l set dev ip6tnl0 up

# 4in6 
ip a add 192.168.101.201 dev lo
ip -6 a add fd6e:eec8:76ac:ac1d:100::2/64 dev ens160 # need an IPv6 address to reply from
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


ip l set dev tunl0 up
ip l set dev ip6tnl0 up


ip a add 192.168.101.201 dev tunl0


ip l set dev gre0 up
ip a add 192.168.101.1 dev gre0

ip l add gre6 type ip6gre
ip a add 192.168.101.201 dev ip6gre0

/etc/networkd-dispatcher/routable.d/50-ifup-hooks:
#!/bin/sh
ip fou add port 9999 ipproto 4
ip link set dev tunl0 up
sysctl -w net.ipv4.conf.tunl0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0

/etc/modules:
fou
ipip


ip -6 tunnel change ip6tnl0 mode ipip6

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
#define memcpy(d, s, n) __builtin_memcpy((d), (s), (n));

#define VERSION 1
#define SECOND_NS 1000000000l

const __u32 ZERO = 0;
const __u16 MTU = 1500;

const __u8 F_STICKY = 0x01;

const __u8 F_LAYER2_DSR  = 0x00;
const __u8 F_LAYER3_FOU = 0x01;
const __u8 F_LAYER3_GRE = 0x02;
const __u8 F_LAYER3_IPIP = 0x03;

enum lookup_result {
		    NOT_FOUND = 0,
		    LAYER2_DSR,
		    LAYER3_GRE,
		    LAYER3_FOU,  // FOU + IP-in-IP and 6in4
		    LAYER3_IPIP, // IP-in-IP and 6in4
};

const int BUFFLEN = 4096;
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, __u8[4096]);    
    __uint(max_entries, 1);
} buffers SEC(".maps");



// https://stackoverflow.com/questions/30858973/udp-checksum-calculation-for-ipv6-packet
#define HDRTESTL 36
#define UDPTESTLXX 52
#define UDPTESTL 12
#define ALLTESTL HDRTESTL+ALLTESTL

__u8 HDRTEST[HDRTESTL] = {
		    0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAB, 0xCD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Source IP
		    0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x60, // Dest   IP
		    0x00, 0x11, // Protocol (UDP)
		    0x00, 0x0C,  // Proto Len: (UDP Header + Body)
		    };

//			  0x60, 0x00, 0x00, 0x00, 0x00, 0x34, 0x11, 0x01, 0x21, 0x00, 0x00, 0x00,
//			  0x00, 0x00, 0x00, 0x01, 0xAB, 0xCD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
//			  0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//			  0x00, 0x00, 0x01, 0x60,
__u8 UDPTEST[UDPTESTL] = {
			  0x26, 0x92,
			  0x26, 0x92,
			  0x00, 0x0C,
			  // 0x7E, 0xD5,
			  0x00, 0x00,
			  0x12, 0x34,
			  0x56, 0x78,
};

__u8 ALLTEST[HDRTESTL+UDPTESTL] = {
				   0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAB, 0xCD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Source IP
				   0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x60, // Dest   IP
				   0x00, 0x11, // Protocol (UDP)
				   0x00, 0x0C,  // Proto Len: (UDP Header + Body)
				   0x26, 0x92,
                          0x26, 0x92,
                          0x00, 0x0C,
                          // 0x7E, 0xD5,
                          0x00, 0x00,
                          0x12, 0x34,
                          0x56, 0x78,
};

#include "vlan.h"
#include "new.h"



struct info {
    __be32 vip;
    __be32 saddr;
    char h_dest[6];
    char pad[2];
};

struct addr4 {
    __u8 pad[12];
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

struct servicekey {
    struct addr addr;    
    __be16 port;
    __u16 proto;
};

struct destination {
    struct addr daddr;
    struct addr saddr;
    __u16 sport; // FOU
    __u16 dport; // FOU
    __u8 h_dest[6]; // router MAC
    __u16 vlanid;
};

struct destinations {
    __u8 hash[8192];
    __u8 flag[256];    // flag[0] - global flags for service; sticky, leastconns
    __u16 dport[256];  // port[0] - high byte leastconns score, low byte destination index to use
    struct addr daddr[256];
    struct addr saddr; // source address to use with tunnels
    struct addr saddr6; // source address to use with tunnels    
    __u8 h_dest[6];    // router MAC address to send encapsulated packets to
    __u16 vlanid;      // VLAN ID on which encapsulated packets should be received/sent
    //struct addr icmp; // optional address to send ICMP UNREACH/FRAG from?
    // maybe seperate vlan/mac records if IPv6 is to support L2
};

/**********************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, struct info);
    __uint(max_entries, 1);
} infos SEC(".maps");

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

static __always_inline
int send_fou4(struct xdp_md *ctx, struct destination *dest)
{
    //return fou4_push(ctx, dest->h_dest, dest->saddr.addr4.addr, dest->daddr.addr4.addr, dest->sport, dest->dport) < 0 ?
    // 	XDP_ABORTED : XDP_TX;
    return push_fou4(ctx, dest->h_dest, dest->saddr.addr4.addr, dest->daddr.addr4.addr, dest->sport, dest->dport) < 0 ?
    XDP_ABORTED : XDP_TX;
}

static __always_inline
int send_fou6(struct xdp_md *ctx, struct destination *dest)
{
    bpf_printk("send_fou6\n");
    return fou6_push(ctx, dest->h_dest, dest->saddr.addr6, dest->daddr.addr6, dest->sport, dest->dport) < 0 ?
    XDP_ABORTED : XDP_TX;
    //return push_fou6(ctx, dest->h_dest, dest->saddr.addr6, dest->daddr.addr6, dest->sport, dest->dport) < 0 ?
    //	XDP_ABORTED : XDP_TX;
}

static __always_inline
int send_6in6(struct xdp_md *ctx, struct destination *dest)
{
    return push_6in6(ctx, dest->h_dest, dest->saddr.addr6, dest->daddr.addr6) < 0 ?	
	XDP_ABORTED : XDP_TX;
}

int send_ip4in6(struct xdp_md *ctx, struct destination *dest)
{
    bpf_printk("send_ip4ip6\n");
    return push_4in6(ctx, dest->h_dest, dest->saddr.addr6, dest->daddr.addr6) < 0 ?
	XDP_ABORTED : XDP_TX;
}

static __always_inline
int send_6in4(struct xdp_md *ctx, struct destination *dest)
{
    return push_6in4(ctx, dest->h_dest, dest->saddr.addr4.addr, dest->daddr.addr4.addr) < 0 ?	
	XDP_ABORTED : XDP_TX;
}

static __always_inline
int send_ipip(struct xdp_md *ctx, struct destination *dest)
{
    return ipip_push(ctx, dest->h_dest, dest->saddr.addr4.addr, dest->daddr.addr4.addr) < 0 ?	
	XDP_ABORTED : XDP_TX;
}


static __always_inline
int send_gre4(struct xdp_md *ctx, struct destination *dest)
{
    return push_gre4(ctx, dest->h_dest, dest->saddr.addr4.addr, dest->daddr.addr4.addr, ETH_P_IP) < 0 ?
	XDP_ABORTED : XDP_TX;
}

static __always_inline
int send_gre_6in4(struct xdp_md *ctx, struct destination *dest)
{
    return push_gre4(ctx, dest->h_dest, dest->saddr.addr4.addr, dest->daddr.addr4.addr, ETH_P_IPV6) < 0 ?
	XDP_ABORTED : XDP_TX;
}

static __always_inline
int send_gre_6in6(struct xdp_md *ctx, struct destination *dest)
{
    return push_gre6(ctx, dest->h_dest, dest->saddr.addr6, dest->daddr.addr6, ETH_P_IPV6) < 0 ?
	XDP_ABORTED : XDP_TX;
}

static __always_inline
int send_gre_4in6(struct xdp_md *ctx, struct destination *dest)
{
    return push_gre6(ctx, dest->h_dest, dest->saddr.addr6, dest->daddr.addr6, ETH_P_IP) < 0 ?
	XDP_ABORTED : XDP_TX;
}


static __always_inline
int send_frag_needed(struct xdp_md *ctx, __be32 saddr, __u16 mtu)
{
    bpf_printk("FRAG_NEEDED\n");

    __u8 *buffer = NULL;
    if (!(buffer = bpf_map_lookup_elem(&buffers, &ZERO)))
	return XDP_ABORTED;
     
    return (frag_needed(ctx, saddr, mtu, buffer) < 0) ? XDP_ABORTED : XDP_TX;
}

static __always_inline
__u16 l4_hash(struct addr saddr, struct addr daddr, void *l4)
{
    // UDP, TCP and SCTP all have src and dst port in 1st 32 bits, so use shortest type (UDP)
    struct udphdr *udp = (struct udphdr *) l4;
    struct {
	struct addr src;
	struct addr dst;
	__be16 sport;
	__be16 dport;
    } h = { .src = saddr, .dst = daddr};
    if (udp) {
	h.sport = udp->source;
	h.dport = udp->dest;
    }
    return sdbm((unsigned char *)&h, sizeof(h));
}

static __always_inline
int is_ipv4_addr(struct addr addr) {
    char *p = addr.addr4.pad;

    if (!p[0] && !p[1] && !p[2] && !p[3] &&
	!p[4] && !p[5] && !p[6] && !p[7] &&
	!p[8] && !p[9] && !p[10] && !p[11])
	return 1;
    
    return 0;
}


static __always_inline
enum lookup_result lookup(struct addr saddr, struct addr daddr, void *l4, __u8 protocol, struct destination *r) // flags arg?    
{
    // lookup flow in state map?
    
    __be16 sport = 0;
    __be16 dport = 0;    
    
    if (l4) {
	struct udphdr *udp = l4;
	sport = udp->source;
	dport = udp->dest;	
	
    } 

    //int x = sport;
    //int y = dport;
    //bpf_printk("PORTS %d %d\n", x, y);
    
    struct servicekey key = { .addr = daddr, .port = bpf_ntohs(dport), .proto = protocol };
    struct destinations *service = bpf_map_lookup_elem(&destinations, &key);

    if (!service)
	return NOT_FOUND;

    //bpf_printk("FOUND\n");
    
    __u8 sticky = service->flag[0] & F_STICKY;
    __u16 hash3 = l4_hash(saddr, daddr, NULL);
    __u16 hash4 = l4_hash(saddr, daddr, l4);
    __u8 index = service->hash[(sticky ? hash3 : hash4) & 0x1fff]; // limit to 0-8191

    if (!index)
	return NOT_FOUND;
    
    r->daddr = service->daddr[index];      // backend's address, inc. MAC and VLAN for L2
    r->dport = service->dport[index];      // destination port for L3 tunnel (eg. FOU)
    r->sport = 0x8000 | (hash4 & 0x7fff);  // source port for L3 tunnel (eg. FOU)
    memcpy(r->h_dest, service->h_dest, 6); // router MAC for L3 tunnel - may be better in vips
    r->vlanid = service->vlanid;           // VLAN ID that L3 services should use - may bebetter in vips

    r->saddr = is_ipv4_addr(r->daddr) ? service->saddr : service->saddr6;
    
    __u8 flag = service->flag[index];

    // store flow?
    
    switch (flag) {
    case F_LAYER2_DSR:  return LAYER2_DSR;
    case F_LAYER3_FOU:  return LAYER3_FOU;
    case F_LAYER3_GRE:  return LAYER3_GRE;
    case F_LAYER3_IPIP: return LAYER3_IPIP;	
    }
    
   return NOT_FOUND;
}

static __always_inline
enum lookup_result lookup4(struct iphdr *ip, void *l4, struct destination *r)
{
    struct addr saddr = { .addr4.addr = ip->saddr };
    struct addr daddr = { .addr4.addr = ip->daddr };
    return lookup(saddr, daddr, l4, ip->protocol, r);
}

static __always_inline
enum lookup_result lookup6(struct ip6_hdr *ip6, void *l4, struct destination *r) 
{
    struct addr saddr = { .addr6 = ip6->ip6_src };
    struct addr daddr = { .addr6 = ip6->ip6_dst };
    return lookup(saddr, daddr, l4, ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt, r);
}


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



static __always_inline
int xdp_fwd_func6(struct xdp_md *ctx, struct ethhdr *eth, struct vlan_hdr *vlan, struct ip6_hdr *ip6)
{
    void *data_end = (void *)(long)ctx->data_end;

    if (ip6 + 1 > data_end)
	return XDP_PASS;
    
    if ((ip6->ip6_ctlun.ip6_un2_vfc >> 4) != 6)
	return XDP_PASS;

    if(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6) {
	bpf_printk("IPv6 ICMP!\n");
	return XDP_PASS;
    }
    
    if(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP)
	return XDP_PASS;

    struct tcphdr *tcp = (void *) (ip6 + 1);

    if (tcp + 1 > data_end)
        return XDP_PASS;

    int x = bpf_ntohs(tcp->dest);
    
    bpf_printk("IPv6 TCP %d\n", x);

    struct destination dest = {};

    enum lookup_result result = lookup6(ip6, tcp, &dest);

    if (!is_ipv4_addr(dest.daddr)) {
	switch (result) {
	case LAYER3_FOU:  return send_fou6(ctx, &dest); // IPv6 in FOU in IPv6 - can't see how to decap this
	case LAYER3_IPIP: return send_6in6(ctx, &dest); // IPv6 in IPv6 - works
	case LAYER3_GRE:  return send_gre_6in6(ctx, &dest);
	default: break;
	}
	bpf_printk("IPv6 destinations not supported yet");
	return XDP_ABORTED;
    }
    
    switch (result) {
    case LAYER3_FOU:  return send_fou4(ctx, &dest); // IPv6 in FOU in IPv4 - works
    case LAYER3_IPIP: return send_6in4(ctx, &dest); // IPv6 in IPv4 - works
    case LAYER3_GRE:  return send_gre_6in4(ctx, &dest);

    case LAYER2_DSR:
    case NOT_FOUND:
	break;
    }

    return XDP_DROP;
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

    if (next_proto == bpf_htons(ETH_P_IPV6)) {
	return xdp_fwd_func6(ctx, eth, vlan, next_header);
    }
    
    if (next_proto != bpf_htons(ETH_P_IP))
	return XDP_PASS;
    
    struct iphdr *ip = next_header;

    if (ip + 1 > data_end)
	return XDP_PASS;

    struct addr daddr = { .addr4.addr = ip->daddr };
    
    if (!bpf_map_lookup_elem(&vips, &daddr))
    	return XDP_PASS;

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
    
    struct destination dest = {};

    /* We're going to forward the packet, so we should decrement the time to live */
    ip_decrease_ttl(ip);    


    // 0x1CB4C
    __u32 size = HDRTESTL>>1;//+UDPTESTL;
    //__u32 size = UDPTESTL>>1;//+UDPTESTL;
    //__u32 size = (HDRTESTL+UDPTESTL)>>1;
    //__u32 csum = bpf_csum_diff((__be32 *) HDRTEST, 0, (__be32 *) HDRTEST, size, 0);
    //csum = csum_fold_helper(csum);
    //bpf_printk("csum %x\n", csum);
    __u32 csum = 0;
    __u16 *hdr = (void *) HDRTEST;
    for (int n = 0; n < size; n++) {
	csum += bpf_ntohs(hdr[n]);
    }
    bpf_printk("csum %x %d\n", csum, size);
    
    size = UDPTESTL>>1;
    csum = 0;
    hdr = (void *) UDPTEST;
    for (int n = 0; n < size; n++) {
	csum += bpf_ntohs(hdr[n]);
    }
    bpf_printk("csum %x %d\n", csum, size);


    size = (HDRTESTL+UDPTESTL)>>1;
    csum = 0;
    hdr = (void *) ALLTEST;
    for (int n = 0; n < size; n++) {
	csum += bpf_ntohs(hdr[n]);
    }
    csum = csum_fold_helper(csum);
    bpf_printk("csum %x %d\n", csum, size);

    size = (HDRTESTL+UDPTESTL);
    csum = bpf_csum_diff((__be32 *) ALLTEST, 0, (__be32 *) ALLTEST, size, 0);
    csum = csum_fold_helper(csum);
    bpf_printk("csum! %x\n", htons(csum));

    
    int mtu = MTU;

    enum lookup_result result = lookup4(ip, tcp, &dest);

    // Layer 3 service packets should only ever be received on the same interface/VLAN as they will be sent
    // FIXME: need to make provision for untagged bond interfaces - list of acceptable interfaces?
    switch (result) {
    case LAYER3_GRE:
    case LAYER3_FOU:
    case LAYER3_IPIP:
	if (check_ingress_interface(ctx->ingress_ifindex, vlan, dest.vlanid) < 0)
            return XDP_DROP;
	break;
	
    case LAYER2_DSR:
    case NOT_FOUND:
	return XDP_DROP;
    }

    if (!is_ipv4_addr(dest.daddr)) {
	switch(result) {
	case LAYER3_IPIP: return send_ip4in6(ctx, &dest);
	case LAYER3_GRE:  return send_gre_4in6(ctx, &dest);
	default:
	    break;
	}
        bpf_printk("IPv6 destinations not supported yet\n");
    	return XDP_ABORTED;
    }
    
    switch (result) {
    case LAYER3_FOU:	
	/* Will the packet and FOU headers exceed the MTU? Send ICMP ICMP_UNREACH/FRAG_NEEDED */
	if ((data_end - ((void *) ip)) + FOU4_OVERHEAD > mtu)
	    return send_frag_needed(ctx, dest.saddr.addr4.addr, mtu - FOU4_OVERHEAD);

	return send_fou4(ctx, &dest);

    case LAYER3_IPIP:
	/* Will the packet and extra IP header exceed the MTU? Send ICMP ICMP_UNREACH/FRAG_NEEDED */
	if ((data_end - ((void *) ip)) + IPIP_OVERHEAD > mtu)
	    return send_frag_needed(ctx, dest.saddr.addr4.addr, mtu - IPIP_OVERHEAD);
	
	return send_ipip(ctx, &dest);

    case LAYER3_GRE:
	if ((data_end - ((void *) ip)) + GRE4_OVERHEAD > mtu)
            return send_frag_needed(ctx, dest.saddr.addr4.addr, mtu - GRE4_OVERHEAD);
	 
	return send_gre4(ctx, &dest);
	
	
    case LAYER2_DSR:  /* not implemented yet */
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
