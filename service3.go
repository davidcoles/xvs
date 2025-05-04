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

	"github.com/davidcoles/xvs/maglev"
	"github.com/davidcoles/xvs/xdp"
)

type dest struct {
	weight   uint8
	destinfo bpf_destinfo
	netinfo  ninfo // only used for debug purposes atm
}

type service3 struct {
	dests    map[netip.Addr]Destination3
	service  Service3
	layer3   *layer3
	sessions map[netip.Addr]uint64
}

func (s *service3) debug(info ...any) {
	//fmt.Println(info...)
}

func (s *service3) set(service Service3, ds ...Destination3) (del bool, err error) {

	m := make(map[netip.Addr]Destination3, len(ds))

	for _, d := range ds {
		m[d.Address] = d
		if err = d.check(); err != nil {
			return
		}
	}

	for d, _ := range m {
		if _, exists := s.dests[d]; !exists {
			s.debug("ADDING", d)
			s.layer3.createCounters(s.vrpp(d))
			s.layer3.natmap.add(s.service.Address, d)
		}
	}

	for d, _ := range s.dests {
		if _, exists := m[d]; !exists {
			del = true
			s.layer3.removeCounters(s.vrpp(d)) // d was deleted
		}
	}

	for _, d := range m {
		s.layer3.natmap.add(s.service.Address, d.Address)
	}

	s.service = service
	s.dests = m
	s.layer3.natmap.index()
	s.recalc()

	return
}

func (s *service3) createDestination(d Destination3) error {

	if _, exists := s.dests[d.Address]; exists {
		return fmt.Errorf("Destination exists")
	}

	if err := d.check(); err != nil {
		return err
	}

	s.layer3.createCounters(s.vrpp(d.Address))
	s.layer3.natmap.add(s.service.Address, d.Address)
	s.layer3.natmap.index()
	s.dests[d.Address] = d
	s.recalc()
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

	_, err := service.set(s, ds...)

	if err != nil {
		return err
	}

	l.services[s.key()] = service

	return nil
}

func (s *service3) extend() Service3Extended {
	var c bpf_counters3
	var t uint64
	for d, _ := range s.dests {
		c.add(s.layer3.counters(s.vrpp(d)))
		t += s.sessions[d]
	}
	return Service3Extended{Service: s.service, Stats: c.stats(t)}
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

	s.layer3.maps.services.DeleteElem(uP(&key))
	delete(s.layer3.services, s.service.key())
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

func (s *service3) stats(d netip.Addr) Stats3 {
	return s.layer3.counters(s.vrpp(d)).stats(s.sessions[d])
}

func (s *service3) destinations() (r []Destination3Extended, e error) {
	for a, d := range s.dests {
		r = append(r, Destination3Extended{Destination: d, Stats: s.stats(a)})
	}
	return
}

func (s *service3) readSessions() {
	sessions := make(map[netip.Addr]uint64, len(s.dests))
	for d, _ := range s.dests {
		sessions[d] = s.layer3.readAndClearSession(s.vrpp(d))
	}
	s.sessions = sessions
}

func (s *service3) a16() addr16   { return as16(s.service.Address) }
func (s *service3) port() uint16  { return s.service.Port }
func (s *service3) proto() uint16 { return uint16(s.service.Protocol) }
func (s *service3) vrpp(d netip.Addr) bpf_vrpp3 {
	return bpf_vrpp3{vaddr: s.a16(), raddr: as16(d), vport: s.port(), protocol: s.proto()}
}

func (s *service3) recalc() {

	reals := make(map[netip.Addr]dest, len(s.dests))

	for k, d := range s.dests {
		di, ni := s.layer3.destinfo(d)
		reals[k] = dest{destinfo: di, netinfo: ni, weight: d.Weight}
		s.debug("FWD", ni, di.flags)
	}

	s.forwarding(reals)
	s.nat(reals)

	v16 := as16(s.service.Address)
	s.layer3.maps.vips.UpdateElem(uP(&v16), uP(&ZERO), xdp.BPF_ANY) // value is not used
}

func (s *service3) nat(reals map[netip.Addr]dest) {
	vip := s.service.Address

	for k, v := range reals {
		nat := s.layer3.nat(s.service.Address, k)
		n16 := as16(nat)
		ext := s.layer3.netinfo.ext(v.destinfo.vlanid, s.service.Address.Is6())

		vip_rip := bpf_vip_rip{destinfo: v.destinfo, vip: as16(vip), ext: as16(ext)}
		s.layer3.maps.nat_to_vip_rip.UpdateElem(uP(&n16), uP(&vip_rip), xdp.BPF_ANY)

		s.debug("NAT", s.service.Address, k, nat, v.netinfo, ext, vip)
	}
}

func (s *service3) forwarding(reals map[netip.Addr]dest) {

	addrs := make([]netip.Addr, 0, len(reals))

	for k, v := range reals {
		if v.weight != 0 && v.destinfo.vlanid != 0 {
			addrs = append(addrs, k)
		}
		//s.layer3.createCounters(s.vrpp(k))
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

	s.debug("MAG", s.service, val.hash[0:32], dur)

	key := s.key()
	s.layer3.maps.services.UpdateElem(uP(&key), uP(&val), xdp.BPF_ANY)
}
