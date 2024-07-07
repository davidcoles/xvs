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
	"sort"
	"time"

	"github.com/davidcoles/xvs/bpf"
	"github.com/davidcoles/xvs/maglev"
	"github.com/davidcoles/xvs/xdp"
)

const (
	TCP Protocol = 0x06
	UDP Protocol = 0x11
)

type MAC = mac

type be_state struct {
	sticky      bool
	fallback    bool
	leastconns  ip4
	weight      uint8
	bpf_backend bpf_backend
	bpf_reals   map[ip4]bpf_real
}

type key struct {
	addr netip.Addr
	port uint16
	prot uint8
}

type Protocol = uint8

type Service struct {
	Address  netip.Addr // The Virtual IP address of the service
	Port     uint16     // Layer 4 port number
	Protocol Protocol   // IP protocol number; TCP (6), and UDP (17) are current supported
	Sticky   bool       // Only use source and destination IP addresses when determining backend
}

//type service = _Service

type service struct {
	Address  netip.Addr // The Virtual IP address of the service
	Port     uint16     // Layer 4 port number
	Protocol Protocol   // IP protocol number; TCP (6), and UDP (17) are current supported
	Sticky   bool       // Only use source and destination IP addresses when determining backend

	backend map[ip4]*Destination
	state   *be_state
}

func (s *Service) service() *service {
	var r service

	r.Address = s.Address
	r.Port = s.Port
	r.Protocol = s.Protocol
	r.Sticky = s.Sticky

	r.backend = map[ip4]*Destination{}
	r.state = nil
	return &r
}

func (s *service) extend(c *Client) (se ServiceExtended) {
	var r Service
	r.Address = s.Address
	r.Port = s.Port
	r.Protocol = s.Protocol
	r.Sticky = s.Sticky
	se.Service = r

	for _, d := range s.destinations(c) {
		se.Stats.add(d.Stats)
	}

	return
}

type ServiceExtended struct {
	Service Service
	Stats   Stats
}

func (s *service) update(u Service) (changed bool) {
	if s.Sticky != u.Sticky {
		s.Sticky = u.Sticky
		changed = true
	}
	return
}

func (s *service) remove(c *Client, more bool) (del []ip4) {

	if s.Address.Is4() {

		for ip, d := range s.backend {
			s.delDestination(d, c)
			del = append(del, ip)
		}

		sb := bpf_service{vip: s.Address.As4(), port: htons(s.Port), protocol: uint8(s.Protocol)}
		c.service_backend().DeleteElem(uP(&sb))
		if !more {
			c.vrpp_counter().DeleteElem(uP(&bpf_vrpp{vip: s.Address.As4()}))
		}
	}

	return
}

func (s *service) removeDestination(c *Client, d Destination) error {

	if !s.Address.Is4() {
		return fmt.Errorf("Not IPv4")
	}

	addr := d.Address.As4()

	b, ok := s.backend[addr]

	if !ok {
		return fmt.Errorf("Destination does not exist")
	}

	s.delDestination(b, c) // remove counters from kernel

	delete(s.backend, addr) // remove dest from desrvice

	s.sync(c, c.hwaddr, c.tags) // rebuild forwarding table

	return nil
}

func (s *Service) key() key {
	return key{addr: s.Address, port: s.Port, prot: uint8(s.Protocol)}
}

func (s *service) concurrent(c *Client) {

	if s.Address.Is4() {
		vip := s.Address.As4()
		for rip, b := range s.backend {
			b.current = c.read_and_clear_concurrent(vip, rip, s.Port, uint8(s.Protocol))
		}
	}

}

func (s *service) set(c *Client, svc Service, dst []Destination) (add []ip4, del []ip4) {

	if !s.Address.Is4() {
		return
	}

	s.update(svc)

	vip := s.Address.As4()

	c.update_vrpp_counter(&bpf_vrpp{vip: vip}, &bpf_counter{}, xdp.BPF_NOEXIST)

	new := map[ip4]*Destination{}

	for _, x := range dst {
		d := x // we will take a pointer, so don't use the loop var!

		if !d.Address.Is4() {
			continue
		}

		rip := ip4(d.Address.As4())

		new[rip] = &d

		if o, ok := s.backend[rip]; !ok {
			add = append(add, rip)
			s.addDestination(c, &d)
		} else {
			d.current = o.current // preserve counter
		}
	}

	for rip, d := range s.backend {
		if _, ok := new[rip]; !ok {
			del = append(del, rip)
			s.delDestination(d, c)
		}
	}

	s.backend = new

	return
}

func (s *service) destination(c *Client, d *Destination) (de DestinationExtended) {
	de.Destination = *d
	de.Stats = s.stats(c, d)
	return
}

func (s *service) destinations(c *Client) map[ip4]DestinationExtended {
	destinations := map[ip4]DestinationExtended{}

	if s.Address.Is4() {
		for rip, d := range s.backend {
			destinations[rip] = s.destination(c, d)
		}
	}

	return destinations
}

func (s *service) sync(c *Client, arp map[ip4]mac, tag map[netip.Addr]int16) {

	port := s.Port
	protocol := uint8(s.Protocol)

	if !s.Address.Is4() {
		return
	}

	var nilip ip4
	var nilmac mac

	vip := ip4(s.Address.As4())
	bpf_reals := map[ip4]bpf_real{}

	//fmt.Println("SYNC", vip, port, protocol)

	//var lc ip4

	for ip, real := range s.backend {
		mac := arp[ip]
		vid := tag[netip.AddrFrom4(ip)]

		//fmt.Println("    ", b4s(ip), b6s(mac), vid, real.Weight)

		if ip != nilip && mac != nilmac && real.Weight > 0 && vid >= 0 && vid < 4095 {
			bpf_reals[ip] = bpf_real{rip: ip, mac: mac, vid: uint16(vid)}
			//lc = ip
		} else {
			//fmt.Println("UNAVAILABLE", ip, mac, real.Weight, vid)
		}
	}

	key := &bpf_service{vip: vip, port: htons(port), protocol: protocol}
	val := &be_state{fallback: false, sticky: s.Sticky, bpf_reals: bpf_reals}

	now := time.Now()

	if val.update_backend(s.state) {
		c.update_service_backend(key, &(val.bpf_backend), xdp.BPF_ANY)
		if c.Debug != nil {
			backends := make([]byte, len(val.bpf_backend.hash))
			copy(backends[:], val.bpf_backend.hash[:])
			c.Debug.Backend(netip.AddrFrom4(vip), port, protocol, backends[:], time.Now().Sub(now))
		}
		s.state = val
	}
}

func (s *service) tuples() (ret [][2]b4) {
	if s.Address.Is4() {
		for rip, _ := range s.backend {
			ret = append(ret, [2]b4{s.Address.As4(), rip})
		}
	}
	return
}

func (s *service) stats(cl *Client, d *Destination) (stats Stats) {
	if !s.Address.Is4() || !d.Address.Is4() {
		return
	}

	vip := s.Address.As4()
	rip := d.Address.As4()
	v := bpf_vrpp{vip: vip, rip: rip, port: htons(s.Port), protocol: uint8(s.Protocol)}
	c := bpf_counter{}
	cl.lookup_vrpp_counter(&v, &c)
	stats.Packets = c.packets
	stats.Octets = c.octets
	stats.Flows = c.flows
	stats.Current = d.current

	return
}

func (s *service) addDestination(c *Client, d *Destination) {
	if !s.Address.Is4() || !d.Address.Is4() {
		return
	}

	vip := s.Address.As4()
	rip := d.Address.As4()

	v0 := bpf_vrpp{vip: vip, rip: rip, port: htons(s.Port), protocol: uint8(s.Protocol), pad: 0}
	v1 := bpf_vrpp{vip: vip, rip: rip, port: htons(s.Port), protocol: uint8(s.Protocol), pad: 1}
	c.update_vrpp_counter(&v0, &bpf_counter{}, xdp.BPF_NOEXIST)
	c.update_vrpp_concurrent(&v0, nil, xdp.BPF_NOEXIST)
	c.update_vrpp_concurrent(&v1, nil, xdp.BPF_NOEXIST)

}

func (s *service) delDestination(d *Destination, c *Client) {
	if !s.Address.Is4() || !d.Address.Is4() {
		return
	}

	vip := s.Address.As4()
	rip := d.Address.As4()
	v0 := bpf_vrpp{vip: vip, rip: rip, port: htons(s.Port), protocol: uint8(s.Protocol), pad: 0}
	v1 := bpf_vrpp{vip: vip, rip: rip, port: htons(s.Port), protocol: uint8(s.Protocol), pad: 1}
	c.vrpp_counter().DeleteElem(uP(&v0))
	c.vrpp_concurrent().DeleteElem(uP(&v0))
	c.vrpp_concurrent().DeleteElem(uP(&v1))
}

/**********************************************************************/

type Destination struct {
	Address netip.Addr // Destination server IP address
	Weight  uint8      // Not fully implemented; 0 - don't use the destination, non-zero enables the destination
	current uint64
}

type DestinationExtended struct {
	Destination Destination
	MAC         MAC
	Stats       Stats
}

func (curr *be_state) update_backend(prev *be_state) bool {

	if !curr.diff(prev) {
		return false
	}

	var flag [4]byte

	if curr.sticky {
		flag[0] |= bpf.F_STICKY
	}

	mapper := map[[4]byte]uint8{}

	var list []ip4

	for ip, _ := range curr.bpf_reals {
		list = append(list, ip)
	}

	sort.SliceStable(list, func(i, j int) bool {
		return nltoh(list[i]) < nltoh(list[j])
	})

	var real [256]bpf_real

	for i, ip := range list {
		if i < 255 {
			idx := uint8(i) + 1
			mapper[ip] = idx
			real[idx] = curr.bpf_reals[ip]
		} else {
			fmt.Println("more than 255 hosts", ip, i)
		}
	}

	curr.bpf_backend.real = real
	curr.bpf_backend.hash, _ = maglev8192(mapper)

	var rip ip4
	var mac mac
	var vid uint16
	var nul ip4

	if curr.leastconns != nul {
		if n, ok := mapper[curr.leastconns]; ok {
			flag[1] = curr.weight
			rip = real[n].rip
			mac = real[n].mac
			vid = real[n].vid
		}
	}

	curr.bpf_backend.real[0] = bpf_real{rip: rip, mac: mac, vid: vid, flag: flag}

	return true
}

func (curr *be_state) diff(prev *be_state) bool {

	bpf_reals_differ := func(a, b map[ip4]bpf_real) bool {
		if len(a) != len(b) {
			return true
		}

		// presuming that the two maps are are equivalent, if both
		// maps have same number of entries, then all keys that exist
		// in a must also be in b - so check that the values match

		for k, v := range a {
			if x, ok := b[k]; !ok || x != v {
				return true
			}
		}

		return false
	}

	if prev == nil {
		return true
	}

	if curr.sticky != prev.sticky ||
		curr.fallback != prev.fallback ||
		curr.leastconns != prev.leastconns ||
		curr.weight != prev.weight {
		return true
	}

	if bpf_reals_differ(curr.bpf_reals, prev.bpf_reals) {
		return true
	}

	return false
}

func maglev8192(m map[[4]byte]uint8) (r [8192]uint8, b bool) {

	if len(m) < 1 {
		return r, false
	}

	a := make([]ip4, len(m))

	n := 0
	for k, _ := range m {
		a[n] = k
		n++
	}

	sort.SliceStable(a, func(i, j int) bool {
		return nltoh(a[i]) < nltoh(a[j])
	})

	h := make([][]byte, len(a))

	for k, v := range a {
		b := make([]byte, 4)
		copy(b[:], v[:])
		h[k] = b
	}

	t := maglev.Maglev8192(h)

	for k, v := range t {
		ip := a[v]
		x, ok := m[ip]
		if !ok {
			return r, false
		}
		r[k] = x
	}

	return r, true
}
