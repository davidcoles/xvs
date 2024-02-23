/*
 * VC5 load balancer. Copyright (C) 2021-present David Coles
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
	"time"

	"github.com/davidcoles/xvs/xdp"
)

const (
	TCP Protocol = 0x06
	UDP Protocol = 0x11
)

type Protocol = uint8

type Service struct {
	Address  netip.Addr
	Port     uint16
	Protocol Protocol

	Sticky bool

	backend map[ip4]*Destination
	state   *be_state
}

type ServiceExtended struct {
	Service Service
	Stats   Stats
}

func (s *Service) update(u Service) (changed bool) {
	if s.Sticky != u.Sticky {
		s.Sticky = u.Sticky
		changed = true
	}
	return
}

func (s *Service) remove(maps *Maps, more bool) (del []ip4) {

	if s.Address.Is4() {

		for ip, d := range s.backend {
			s.delDestination(d, maps)
			del = append(del, ip)
		}

		sb := bpf_service{vip: s.Address.As4(), port: htons(s.Port), protocol: uint8(s.Protocol)}
		xdp.BpfMapDeleteElem(maps.service_backend(), uP(&sb))

		if !more {
			xdp.BpfMapDeleteElem(maps.vrpp_counter(), uP(&bpf_vrpp{vip: s.Address.As4()}))
		}
	}

	return
}

func (s *Service) dup() Service {
	var r Service
	r = *s
	r.backend = map[ip4]*Destination{}
	r.state = nil
	return r
}

func (s *Service) dupp() *Service {
	dup := s.dup()
	return &dup
}

func (s *Service) key() (key, error) {
	return key{addr: s.Address, port: s.Port, prot: uint8(s.Protocol)}, nil
}

func (s *Service) concurrent(m *Maps) {
	if s.Address.Is4() {
		vip := s.Address.As4()
		for rip, b := range s.backend {
			b.current = m.read_and_clear_concurrent(vip, rip, s.Port, uint8(s.Protocol))
		}
	}
}

func (s *Service) set(maps *Maps, svc Service, dst []Destination) (add []ip4, del []ip4) {

	if !s.Address.Is4() {
		return
	}

	s.update(svc)

	vip := s.Address.As4()

	maps.update_vrpp_counter(&bpf_vrpp{vip: vip}, &bpf_counter{}, xdp.BPF_NOEXIST)

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
			s.addDestination(&d, maps)
		} else {
			d.current = o.current // preserve counter
		}
	}

	for rip, d := range s.backend {
		if _, ok := new[rip]; !ok {
			del = append(del, rip)
			s.delDestination(d, maps)
		}
	}

	s.backend = new

	return
}

func (s *Service) extend(maps *Maps) (se ServiceExtended) {
	se.Service = s.dup()

	for _, d := range s.destinations(maps) {
		se.Stats.add(d.Stats)
	}

	return
}

func (s *Service) destination(d *Destination, m *Maps) (de DestinationExtended) {
	de.Destination = *d
	de.Stats = s.stats(d, m)
	return
}

func (s *Service) destinations(maps *Maps) map[ip4]DestinationExtended {
	destinations := map[ip4]DestinationExtended{}

	if s.Address.Is4() {
		for rip, d := range s.backend {
			destinations[rip] = s.destination(d, maps)
		}
	}

	return destinations
}

func (s *Service) sync(arp map[ip4]MAC, tag map[netip.Addr]uint16, maps *Maps) {

	port := s.Port
	protocol := uint8(s.Protocol)

	if s.Address.Is4() {

		vip := ip4(s.Address.As4())
		bpf_reals := map[ip4]bpf_real{}

		for ip, real := range s.backend {
			mac := arp[ip]
			vid := tag[netip.AddrFrom4(ip)]
			if !ip.IsNil() && !mac.IsNil() && real.Weight > 0 && vid < 4095 {
				bpf_reals[ip] = bpf_real{rip: ip, mac: mac, vid: htons(vid)}
			} else {
				//fmt.Println("UNAVAILABLE", ip, mac, real.Weight, vid)
			}
		}

		key := &bpf_service{vip: vip, port: htons(port), protocol: protocol}
		val := &be_state{fallback: false, sticky: s.Sticky, bpf_reals: bpf_reals}

		now := time.Now()

		if val.update_backend(s.state) {
			maps.update_service_backend(key, &(val.bpf_backend), xdp.BPF_ANY)
			log := kv{"vip": vip, "port": port, "protocol": protocol, "backends": fmt.Sprint(val.bpf_backend.hash[:32]),
				"duration_ms": int64(time.Now().Sub(now) / time.Millisecond)}
			maps.log().INFO("forward", log)

			s.state = val
		}
	}
}

func (s *Service) tuples() (ret [][2]b4) {
	if s.Address.Is4() {
		for rip, _ := range s.backend {
			ret = append(ret, [2]b4{s.Address.As4(), rip})
		}
	}
	return
}

func (s *Service) stats(d *Destination, m *Maps) (stats Stats) {
	if !s.Address.Is4() || !d.Address.Is4() {
		return
	}
	vip := s.Address.As4()
	rip := d.Address.As4()
	v := bpf_vrpp{vip: vip, rip: rip, port: htons(s.Port), protocol: uint8(s.Protocol)}
	c := bpf_counter{}
	m.lookup_vrpp_counter(&v, &c)
	stats.Packets = c.packets
	stats.Octets = c.octets
	stats.Flows = c.flows
	stats.Current = d.current
	return
}

func (s *Service) addDestination(d *Destination, m *Maps) {
	if !s.Address.Is4() || !d.Address.Is4() {
		return
	}
	vip := s.Address.As4()
	rip := d.Address.As4()
	v0 := bpf_vrpp{vip: vip, rip: rip, port: htons(s.Port), protocol: uint8(s.Protocol), pad: 0}
	v1 := bpf_vrpp{vip: vip, rip: rip, port: htons(s.Port), protocol: uint8(s.Protocol), pad: 1}
	m.update_vrpp_counter(&v0, &bpf_counter{}, xdp.BPF_NOEXIST)
	m.update_vrpp_concurrent(&v0, nil, xdp.BPF_NOEXIST)
	m.update_vrpp_concurrent(&v1, nil, xdp.BPF_NOEXIST)
}

func (s *Service) delDestination(d *Destination, m *Maps) {
	if !s.Address.Is4() || !d.Address.Is4() {
		return
	}
	vip := s.Address.As4()
	rip := d.Address.As4()
	v0 := bpf_vrpp{vip: vip, rip: rip, port: htons(s.Port), protocol: uint8(s.Protocol), pad: 0}
	v1 := bpf_vrpp{vip: vip, rip: rip, port: htons(s.Port), protocol: uint8(s.Protocol), pad: 1}
	xdp.BpfMapDeleteElem(m.vrpp_counter(), uP(&v0))
	xdp.BpfMapDeleteElem(m.vrpp_concurrent(), uP(&v0))
	xdp.BpfMapDeleteElem(m.vrpp_concurrent(), uP(&v1))
}

/**********************************************************************/

type Destination struct {
	Address netip.Addr
	Weight  uint8
	current uint64
}

type DestinationExtended struct {
	Destination Destination
	MAC         MAC
	Stats       Stats
}
