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

func (c bpf_counter) stats(sessions uint64) (s Stats3) {
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
