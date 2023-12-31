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
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/davidcoles/xvs/xdp"
)

const (
	TCP protocol = 0x06
	UDP protocol = 0x11
)

type Protocol uint8
type protocol = Protocol

type Service struct {
	Address  netip.Addr
	Port     uint16
	Protocol protocol

	Sticky bool

	backend map[IP4]*Destination
	state   *be_state
}

type ServiceExtended struct {
	Service Service
	Stats   Stats
}

func (s *Service) update(u Service) {
	s.Sticky = u.Sticky
}

func (m *Maps) removeDestination(svc key, rip IP4) {

	if svc.addr.Is4() {
		vr := bpf_vrpp{vip: svc.addr.As4(), rip: rip, port: htons(svc.port), protocol: svc.prot}
		xdp.BpfMapDeleteElem(m.vrpp_counter(), uP(&vr))
		xdp.BpfMapDeleteElem(m.vrpp_concurrent(), uP(&vr))
		vr.pad = 1
		xdp.BpfMapDeleteElem(m.vrpp_concurrent(), uP(&vr))
	}
}

func (m *Maps) removeDestination_(vip, rip IP4, port uint16, prot uint8) {

	vr := bpf_vrpp{vip: vip, rip: rip, port: htons(port), protocol: prot}
	xdp.BpfMapDeleteElem(m.vrpp_counter(), uP(&vr))
	xdp.BpfMapDeleteElem(m.vrpp_concurrent(), uP(&vr))
	vr.pad = 1
	xdp.BpfMapDeleteElem(m.vrpp_concurrent(), uP(&vr))
}

func (s *Service) remove(maps *Maps) {

	if s.Address.Is4() {

		for ip, _ := range s.backend {
			maps.removeDestination_(s.Address.As4(), ip, s.Port, uint8(s.Protocol))
		}

		sb := bpf_service{vip: s.Address.As4(), port: htons(s.Port), protocol: uint8(s.Protocol)}
		xdp.BpfMapDeleteElem(maps.service_backend(), uP(&sb))
		// TODO //xdp.BpfMapDeleteElem(c.maps.vrpp_counter(), uP(&bpf_vrpp{vip: s.Address.As4()}))
	}
}

func (s *Service) dup() Service {
	var r Service
	r = *s
	r.backend = map[IP4]*Destination{}
	r.state = nil
	return r
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

func (s *Service) sync(arp map[IP4]MAC, tag map[netip.Addr]uint16, maps *Maps) {

	port := s.Port
	protocol := uint8(s.Protocol)

	if s.Address.Is4() {

		vip := s.Address.As4()
		bpf_reals := map[IP4]bpf_real{}

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

		//if update_backend(val, s.state) {
		if val.update_backend(s.state) {
			maps.update_service_backend(key, &(val.bpf_backend), xdp.BPF_ANY)
			fmt.Println("FWD:", vip, port, protocol, val.bpf_backend.hash[:32], time.Now().Sub(now))
			s.state = val
		}
	}
}

/**********************************************************************/

type Destination struct {
	Address netip.Addr
	Weight  uint8
	current uint64
}

func (d *Destination) rip() (IP4, error) {
	if !d.Address.Is4() {
		return IP4{}, errors.New("Not IPv4")
	}

	return d.Address.As4(), nil
}

func (d *Destination) extend(ip IP4) DestinationExtended {
	var de DestinationExtended
	de.Destination.Address = netip.AddrFrom4(ip)
	de.Destination.Weight = d.Weight
	return de
}

type DestinationExtended struct {
	Destination Destination
	MAC         MAC
	Stats       Stats
}
