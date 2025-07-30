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

package xvs

import (
	"fmt"
	"net/netip"
	"unsafe"
)

type uP = unsafe.Pointer

type addr16 [16]byte
type addr4 [4]byte
type mac [6]byte

func as16(a netip.Addr) (r addr16) {
	if a.Is6() {
		return a.As16()
	}

	if a.Is4() {
		ip := a.As4()
		copy(r[12:], ip[:])
	}

	return
}

func (m mac) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

func (m mac) rfc7042() string {
	return fmt.Sprintf("%02x-%02x-%02x-%02x-%02x-%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

func (a addr16) String() string {
	var is6 bool = false
	for n := 0; n < 12; n++ {
		if a[n] != 0 {
			is6 = true
		}
	}

	if is6 {
		return netip.AddrFrom16(a).String()
	}

	var a4 [4]byte

	copy(a4[:], a[12:])

	return netip.AddrFrom4(a4).String()
}

type bpf_vrpp struct {
	vaddr    addr16 // virtual service IP
	raddr    addr16 // real server IP
	vport    uint16 // virtual service port
	protocol uint16
}

type bpf_counter struct {
	packets            uint64
	octets             uint64
	flows              uint64
	errors             uint64
	syn                uint64
	ack                uint64
	fin                uint64
	rst                uint64
	tunnel_unsupported uint64
	too_big            uint64
	adjust_failed      uint64
	current            uint64
}

func (c *bpf_counter) add(x bpf_counter) {
	c.packets += x.packets
	c.octets += x.octets
	c.flows += x.flows
	c.errors += x.errors

	c.syn += x.syn
	c.ack += x.ack
	c.fin += x.fin
	c.rst += x.rst
}

func (c bpf_counter) stats() (s Stats) {
	s.Connections = c.flows
	s.IncomingPackets = c.packets
	s.IncomingBytes = c.octets
	return
}

func (c bpf_counter) metrics() map[string]uint64 {
	m := make(map[string]uint64, 10)
	m["packets"] = c.packets
	m["octets"] = c.octets
	m["flows"] = c.flows
	m["errors"] = c.errors
	m["syn"] = c.syn
	m["ack"] = c.ack
	m["fin"] = c.fin
	m["rst"] = c.rst
	m["tunnel_unsupported"] = c.tunnel_unsupported
	m["too_big"] = c.too_big
	m["adjust_failed"] = c.adjust_failed
	m["current"] = c.current
	return m
}

type bpf_settings struct {
	watchdog uint64 // periodically reset to 0
	packets  uint64
	latency  uint64
	multi    uint8
	era      uint8
	active   uint8
	pad      [5]uint8
}

type bpf_tunnel struct {
	daddr      addr16
	saddr      addr16
	dport      uint16
	sport      uint16
	vlanid     uint16
	method     uint8
	flags      uint8
	h_dest     mac
	h_source   mac
	hints      uint8
	pad        [7]byte // pad to 64 bytes
	_interface uint32  // userspace only
}

func (t bpf_tunnel) String() string {
	return fmt.Sprintf("[%d:%d:%d %s->%s %s->%s]", t.method, t.vlanid, t._interface, t.h_source, t.h_dest, t.saddr, t.daddr)
}

func (t *bpf_tunnel) remote() bool {
	return t.hints&notLocal != 0
}

func (t *bpf_tunnel) local() bool {
	return t.hints&notLocal == 0
}

func (t *bpf_tunnel) slog() (l []any) {
	l = []any{
		"vlan.id", t.vlanid,
		"interface.id", t._interface,
		"destination.ip", t.daddr.String(),
		"destination.mac", t.h_dest.rfc7042(),
		"source.ip", t.saddr.String(),
		"source.mac", t.h_source.rfc7042(),
	}

	if TunnelType(t.method) != NONE {
		l = append(l, "tunnel.type", TunnelType(t.method).string())

		switch TunnelType(t.method) {
		case IPIP:
		case GRE:
		default:
			if t.dport != 0 {
				l = append(l, "tunnel.port", t.dport)
			}
		}
	}

	return
}

type bpf_vlaninfo struct {
	ip4 addr16
	ip6 addr16
	hw4 mac
	hw6 mac
	gw4 mac
	gw6 mac
}

type bpf_service struct {
	dest [256]bpf_tunnel
	hash [8192]uint8
}

type bpf_servicekey struct {
	addr  addr16
	port  uint16
	proto uint16
}

type bpf_vip_rip struct {
	tunnel bpf_tunnel
	vip    addr16
	ext    addr16
}

// this struct neds to have the same number of entries as bpf_global
type bpf_global_ struct {
	counters [32]uint64
}

func (g *bpf_global_) add(c bpf_global_) {
	for i, n := range c.counters {
		g.counters[i] += n
	}
}

func (f bpf_global) stats() (s Stats) {
	s.Connections = f.flows
	s.IncomingPackets = f.packets
	s.IncomingBytes = f.octets
	return
}

type bpf_global struct {
	current                uint64
	err_malformed          uint64
	err_tot_len            uint64
	err_l4_unsupported     uint64
	err_icmp_unsupported   uint64
	err_fragmented         uint64
	err_service_not_found  uint64
	err_no_backend         uint64
	err_backend_invalid    uint64
	err_no_tunnel_port     uint64
	err_expired            uint64
	err_adjust_failed      uint64
	err_tunnel_unsupported uint64
	err_tcp_header         uint64
	err_udp_header         uint64
	err_icmp_header        uint64
	err_internal           uint64
	err_cve_2025_37799     uint64
	not_ip                 uint64
	not_a_vip              uint64
	probe_reply            uint64
	userspace              uint64
	icmp_echo_request      uint64
	too_big                uint64
	packets                uint64
	octets                 uint64
	flows                  uint64
	errors                 uint64
	syn                    uint64
	ack                    uint64
	fin                    uint64
	rst                    uint64
}

func (f bpf_global) metrics() map[string]uint64 {
	// cat /tmp/foo | grep -v '//' | awk '{print "m[\"" $1 "\"] = f." $1}'
	m := make(map[string]uint64, 30)

	m["current"] = f.current
	m["err_malformed"] = f.err_malformed
	m["err_tot_len"] = f.err_tot_len
	m["err_l4_unsupported"] = f.err_l4_unsupported
	m["err_icmp_unsupported"] = f.err_icmp_unsupported
	m["err_fragmented"] = f.err_fragmented
	m["err_service_not_found"] = f.err_service_not_found
	m["err_no_backend"] = f.err_no_backend
	m["err_backend_invalid"] = f.err_backend_invalid
	m["err_no_tunnel_port"] = f.err_no_tunnel_port
	m["err_expired"] = f.err_expired
	m["err_adjust_failed"] = f.err_adjust_failed
	m["err_tunnel_unsupported"] = f.err_tunnel_unsupported
	m["err_tcp_header"] = f.err_tcp_header
	m["err_udp_header"] = f.err_udp_header
	m["err_icmp_header"] = f.err_icmp_header
	m["err_internal"] = f.err_internal
	m["err_cve_2025_37799"] = f.err_cve_2025_37799
	m["not_ip"] = f.not_ip
	m["not_a_vip"] = f.not_a_vip
	m["probe_reply"] = f.probe_reply
	m["userspace"] = f.userspace
	m["icmp_echo_request"] = f.icmp_echo_request
	m["too_big"] = f.too_big
	m["packets"] = f.packets
	m["octets"] = f.octets
	m["flows"] = f.flows
	m["errors"] = f.errors
	m["syn"] = f.syn
	m["ack"] = f.ack
	m["fin"] = f.fin
	m["rst"] = f.rst

	return m
}
