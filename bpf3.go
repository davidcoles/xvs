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

import "unsafe"
import "fmt"

func init() {
	if (unsafe.Sizeof(bpf_global_{}) != unsafe.Sizeof(bpf_global{})) {
		panic("Inconsistent bpf_global definition")
	}
}

type uP = unsafe.Pointer

type bpf_vrpp struct {
	vaddr    addr16 // virtual service IP
	raddr    addr16 // real server IP
	vport    uint16 // virtual service port
	protocol uint16
}

type bpf_counter struct {
	packets uint64
	octets  uint64
	flows   uint64
	errors  uint64
	syn     uint64
	ack     uint64
	fin     uint64
	rst     uint64
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

func (c bpf_counter) stats(sessions uint64) (s Stats) {
	s.Packets = c.packets
	s.Octets = c.octets
	s.Flows = c.flows
	s.Errors = c.errors
	s.Current = sessions

	s.SYN = c.syn
	s.ACK = c.ack
	s.FIN = c.fin
	s.RST = c.rst
	return
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
	daddr    addr16
	saddr    addr16
	dport    uint16
	sport    uint16
	vlanid   uint16
	method   TunnelType // uint8
	flags    uint8
	h_dest   mac
	h_source mac
	pad      [12]byte // pad to 64 bytes
}

type bpf_vlaninfo struct {
	ip4 addr16
	ip6 addr16
	gw6 addr16
	gw4 addr4
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
	counters [30]uint64
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
	fwd_packets        uint64
	fwd_octets         uint64
	icmp_too_big       uint64
	icmp_frag_needed   uint64
}

func (p bpf_global) String() string {
	return fmt.Sprintf("malformed:%d not_ip:%d not_a_vip:%d too_big:%d packets:%d flows:%d syn:%d ack:%d",
		p.malformed, p.not_ip, p.not_a_vip, p.too_big, p.packets, p.flows, p.syn, p.ack)
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
	m["fwd_packets"] = f.fwd_packets
	m["fwd_octets"] = f.fwd_octets
	m["icmp_too_big"] = f.icmp_too_big
	m["icmp_frag_needed"] = f.icmp_frag_needed

	trim0(m)
	return m
}

func trim0(m map[string]uint64) {
	for k, v := range m {
		if v == 0 {
			delete(m, k)
		}
	}
}
