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

//func as4(a netip.Addr) (r addr4) {
//	if a.Is4() {
//		return a.As4()
//	}
//
//	return
//}

func (m mac) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
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

func from16(a [16]byte) netip.Addr {
	var is6 bool = false
	for n := 0; n < 12; n++ {
		if a[n] != 0 {
			is6 = true
		}
	}

	if is6 {
		return netip.AddrFrom16(a)
	}

	var a4 [4]byte

	copy(a4[:], a[12:])

	return netip.AddrFrom4(a4)
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
	_current           uint64
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
	s.Packets = c.packets
	s.Octets = c.octets
	s.Flows = c.flows
	s.Errors = c.errors
	s.Current = c._current

	//s.SYN = c.syn
	//s.ACK = c.ack
	//s.FIN = c.fin
	//s.RST = c.rst
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
	m["current"] = c._current
	return m
}

type bpf_settings struct {
	watchdog uint64 // periodically reset to 0
	packets  uint64
	latency  uint64
	veth     uint32
	vetha    mac
	vethb    mac
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

type bpf_vlaninfo struct {
	ip4 addr16
	ip6 addr16
	hw4 mac
	hw6 mac
	gh4 mac
	gh6 mac
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

type bpf_global_ struct {
	counters [31]uint64
}

func (g *bpf_global_) add(c bpf_global_) {
	for i, n := range c.counters {
		g.counters[i] += n
	}
}

type bpf_global struct {
	malformed          uint64
	not_ip             uint64
	not_a_vip          uint64
	probe_reply        uint64
	l4_unsupported     uint64
	icmp_unsupported   uint64
	icmp_echo_request  uint64
	fragmented         uint64
	service_not_found  uint64
	no_backend         uint64
	too_big            uint64
	expired            uint64
	adjust_failed      uint64
	tunnel_unsupported uint64
	packets            uint64
	octets             uint64
	flows              uint64
	errors             uint64
	syn                uint64
	ack                uint64
	fin                uint64
	rst                uint64
	ip_options         uint64
	tcp_header         uint64
	udp_header         uint64
	icmp_header        uint64
	_current           uint64
	fwd_octets         uint64
	icmp_too_big       uint64
	icmp_frag_needed   uint64
	userspace          uint64
}

func (p bpf_global) String() string {
	return fmt.Sprintf("malformed:%d not_ip:%d not_a_vip:%d too_big:%d packets:%d flows:%d syn:%d ack:%d",
		p.malformed, p.not_ip, p.not_a_vip, p.too_big, p.packets, p.flows, p.syn, p.ack)
}

func (f bpf_global) stats() (s Stats) {
	s.Packets = f.packets
	s.Octets = f.octets
	s.Flows = f.flows
	s.Current = f._current
	s.Errors = f.errors
	return
}

func (f bpf_global) metrics() map[string]uint64 {
	// cat /tmp/foo | grep -v '//' | awk '{print "m.[\"" $1 "\"] = f." $1}'
	m := make(map[string]uint64, 30)

	m["malformed"] = f.malformed
	m["not_ip"] = f.not_ip
	m["not_a_vip"] = f.not_a_vip
	m["probe_reply"] = f.probe_reply
	m["l4_unsupported"] = f.l4_unsupported
	m["icmp_unsupported"] = f.icmp_unsupported
	m["icmp_echo_request"] = f.icmp_echo_request
	m["fragmented"] = f.fragmented
	m["service_not_found"] = f.service_not_found
	m["no_backend"] = f.no_backend
	m["too_big"] = f.too_big
	m["expired"] = f.expired
	m["adjust_failed"] = f.adjust_failed
	m["tunnel_unsupported"] = f.tunnel_unsupported
	m["packets"] = f.packets
	m["octets"] = f.octets
	m["flows"] = f.flows
	m["errors"] = f.errors
	m["syn"] = f.syn
	m["ack"] = f.ack
	m["fin"] = f.fin
	m["rst"] = f.rst
	m["ip_options"] = f.ip_options
	m["tcp_header"] = f.tcp_header
	m["udp_header"] = f.udp_header
	m["icmp_header"] = f.icmp_header
	m["current"] = f._current
	//m["fwd_octets"] = f.fwd_octets
	m["icmp_too_big"] = f.icmp_too_big
	m["icmp_frag_needed"] = f.icmp_frag_needed
	m["userspace"] = f.userspace

	return m
}
