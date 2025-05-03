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
	"log"
	"net/netip"
	"sort"
	"time"

	// "github.com/davidcoles/xvs/bpf"
	"github.com/davidcoles/xvs/maglev"
	"github.com/davidcoles/xvs/xdp"
)

func (d *Destination3) is4() bool {
	return d.Address.Is4()
}

func (d *Destination3) as16() (r addr16) {
	if d.is4() {
		ip := d.Address.As4()
		copy(r[12:], ip[:])
	} else {
		r = d.Address.As16()
	}
	return
}

func (d Destination3) check() error {

	if !d.Address.IsValid() || d.Address.IsUnspecified() || d.Address.IsMulticast() || d.Address.IsLoopback() {
		return fmt.Errorf("Bad destination address: %s", d.Address)
	}

	return nil
}

type real struct {
	weight   uint8
	destinfo bpf_destinfo
	netinfo  ninfo // only used for debug purposes atm
}

type service3 struct {
	dests   map[netip.Addr]Destination3
	service Service3
	layer3  *layer3
	sess    map[netip.Addr]uint64
}

func (s *service3) set(service Service3, more bool, ds ...Destination3) error {

	m := make(map[netip.Addr]Destination3, len(ds))

	for _, d := range ds {
		if _, exists := s.dests[d.Address]; !exists {
			if err := d.check(); err != nil {
				return err
			}

			log.Println("ADDING", d)
			s.layer3.natmap.add(s.service.Address, d.Address)
		}

		m[d.Address] = d
	}

	for d, _ := range s.dests {
		if _, exists := m[d]; !exists {
			s.layer3.removeCounters(s.vrpp(d)) // d was deleted
		}
	}

	for _, d := range m {
		s.layer3.natmap.add(s.service.Address, d.Address)
	}

	s.service = service
	s.dests = m
	s.layer3.natmap.index()

	if !more {
		s.layer3.clean()
	}
	s.recalc()

	return nil
}

func (s *service3) createDestination(d Destination3) error {

	if _, exists := s.dests[d.Address]; exists {
		return fmt.Errorf("Destination exists")
	}

	if err := d.check(); err != nil {
		return err
	}

	s.layer3.natmap.add(s.service.Address, d.Address)
	s.layer3.natmap.index()
	s.dests[d.Address] = d
	s.recalc()
	return nil
}

func (l *layer3) createService(s Service3, ds ...Destination3) error {

	if !s.Address.IsValid() || s.Address.IsUnspecified() || s.Address.IsMulticast() || s.Address.IsLoopback() {
		return fmt.Errorf("Bad IP address")
	}

	if s.Port == 0 {
		return fmt.Errorf("Reserved port")
	}

	if s.Protocol != TCP && s.Protocol != UDP {
		return fmt.Errorf("Unsupported protocol")
	}

	service := &service3{dests: map[netip.Addr]Destination3{}, service: s, layer3: l}

	err := service.set(s, true, ds...)

	if err != nil {
		return err
	}

	l.services[s.key()] = service

	l.clean()

	return nil
}

func (s *service3) extend() Service3Extended {
	var c bpf_counters3
	for d, _ := range s.dests {
		c.add(s.layer3.counters(s.vrpp(d)))
	}
	return Service3Extended{Service: s.service, Stats: c.stats()}
}

func (s *service3) update(service Service3) error {
	s.service = service
	s.recalc()
	return nil
}

func (s *service3) key() bpf_servicekey {
	return bpf_servicekey{addr: as16(s.service.Address), port: s.service.Port, proto: uint16(s.service.Protocol)}
}

func (s *service3) remove() error {
	key := s.key()

	for d, _ := range s.dests {
		s.layer3.removeCounters(s.vrpp(d))
	}

	s.layer3.destinations.DeleteElem(uP(&key))
	delete(s.layer3.services, s.service.key())
	s.layer3.clean()
	return nil
}

func (s *service3) removeDestination(d Destination3) error {
	if _, exists := s.dests[d.Address]; !exists {
		return fmt.Errorf("Destination does not exist")
	}

	s.layer3.removeCounters(s.vrpp(d.Address))

	delete(s.dests, d.Address)
	s.recalc()
	s.layer3.clean()
	return nil
}

func (s *service3) updateDestination(d Destination3) error {

	if _, exists := s.dests[d.Address]; !exists {
		return fmt.Errorf("Destination does not exist")
	}

	s.dests[d.Address] = d

	s.recalc()

	return nil
}

func (s *service3) destinations() (r []Destination3Extended, e error) {
	for a, d := range s.dests {
		stats := s.layer3.counters(s.vrpp(a)).stats()
		stats.Current = s.sess[a]
		r = append(r, Destination3Extended{Destination: d, Stats: stats})
	}
	return
}

func (s *service3) sessions() {
	svc := s.service
	sess := make(map[netip.Addr]uint64, len(s.dests))
	for d, _ := range s.dests {
		vrpp := bpf_vrpp3{vaddr: as16(svc.Address), raddr: as16(d), vport: svc.Port, protocol: uint16(svc.Protocol)}
		sess[d] = s.layer3.read_and_clear(vrpp)
	}
	s.sess = sess
}

func (s *service3) a16() addr16   { return as16(s.service.Address) }
func (s *service3) port() uint16  { return s.service.Port }
func (s *service3) proto() uint16 { return uint16(s.service.Protocol) }
func (s *service3) vrpp(d netip.Addr) bpf_vrpp3 {
	return bpf_vrpp3{vaddr: s.a16(), raddr: as16(d), vport: s.port(), protocol: s.proto()}
}

func (s *service3) recalc() {

	reals := make(map[netip.Addr]real, len(s.dests))

	for k, d := range s.dests {
		di, ni := s.layer3.destinfo(d)
		reals[k] = real{destinfo: di, netinfo: ni, weight: d.Weight}
	}

	s.forwarding(reals)
	s.nat(reals)

	v16 := as16(s.service.Address)
	s.layer3.vips.UpdateElem(uP(&v16), uP(&ZERO), xdp.BPF_ANY) // value is not used
}

func (s *service3) nat(reals map[netip.Addr]real) {
	vip := s.service.Address

	for k, v := range reals {
		nat := s.layer3.nat(s.service.Address, k)
		n16 := as16(nat)
		ext := s.layer3.netinfo.ext(v.destinfo.vlanid, s.service.Address.Is6())

		vip_rip := bpf_vip_rip{destinfo: v.destinfo, vip: as16(vip), ext: as16(ext)}
		s.layer3.nat_to_vip_rip.UpdateElem(uP(&n16), uP(&vip_rip), xdp.BPF_ANY)

		fmt.Println("NAT", s.service.Address, k, nat, v.netinfo, ext, vip)
	}
}

func (s *service3) forwarding(reals map[netip.Addr]real) {

	addrs := make([]netip.Addr, 0, len(reals))

	for k, v := range reals {
		if v.weight != 0 && v.destinfo.vlanid != 0 {
			addrs = append(addrs, k)
		}
		s.layer3.createCounters(s.vrpp(k))
	}

	var val bpf_destinations
	val.destinfo[0] = bpf_destinfo{flags: uint8(s.service.Flags)}

	var dur time.Duration

	if len(addrs) > 0 {
		// we need the list to be sorted for maglev to be stable
		sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })

		dests := make([]bpf_destinfo, len(addrs))
		nodes := make([][]byte, len(addrs))

		for i, a := range addrs {
			dests[i] = reals[a].destinfo
			nodes[i] = []byte(a.String())
		}

		for i, v := range dests {
			val.destinfo[i+1] = v
		}

		now := time.Now()
		for i, v := range maglev.Maglev8192(nodes) {
			val.hash[i] = uint8(v + 1)
		}
		dur = time.Now().Sub(now)
	}

	fmt.Println("MAG", val.hash[0:32], dur)

	key := s.key()
	s.layer3.destinations.UpdateElem(uP(&key), uP(&val), xdp.BPF_ANY)
}
