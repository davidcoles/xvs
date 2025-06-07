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
)

type dest struct {
	disable bool
	tunnel  bpf_tunnel
}

type service struct {
	service  Service
	dests    map[netip.Addr]Destination
	mac      map[netip.Addr]mac
	sessions map[netip.Addr]uint64
}

func (s *service) current() (r uint64) {
	for d, _ := range s.dests {
		r += s.sessions[d]
	}
	return
}

func (s *service) concurrent() (c uint64) {
	for d, _ := range s.dests {
		c += s.sessions[d]
	}
	return
}

func (s *Service) key() threetuple {
	return threetuple{address: s.Address, port: s.Port, protocol: s.Protocol}
}

func (s *service) set(service Service, ds ...Destination) (err error, add []netip.Addr, del []netip.Addr) {

	destinations := make(map[netip.Addr]Destination, len(ds))

	for _, d := range ds {
		destinations[d.Address] = d
		if err = d.check(); err != nil {
			return
		}
	}

	for d, _ := range destinations {
		if _, exists := s.dests[d]; !exists {
			add = append(add, d)
		}
	}

	for d, _ := range s.dests {
		if _, exists := destinations[d]; !exists {
			del = append(del, d)
		}
	}

	s.service = service
	s.dests = destinations

	return
}

func (s *service) createDestination(d Destination) error {

	if _, exists := s.dests[d.Address]; exists {
		return fmt.Errorf("Destination exists")
	}

	if err := d.check(); err != nil {
		return err
	}

	s.dests[d.Address] = d

	return nil
}

func (s *service) removeDestination(d Destination) error {

	if _, exists := s.dests[d.Address]; !exists {
		return fmt.Errorf("Destination does not exist")
	}

	delete(s.dests, d.Address)

	return nil
}

func (s *service) update(service Service) error {
	s.service = service
	return nil
}

func (s *service) key() bpf_servicekey {
	return bpf_servicekey{addr: as16(s.service.Address), port: s.service.Port, proto: uint16(s.service.Protocol)}
}

func (s *service) updateDestination(d Destination) error {

	if _, exists := s.dests[d.Address]; !exists {
		return fmt.Errorf("Destination does not exist")
	}

	s.dests[d.Address] = d

	return nil
}

func (s *service) readSessions(m maps, era bool) {
	sessions := make(map[netip.Addr]uint64, len(s.dests))
	for d, _ := range s.dests {
		sessions[d] = m.readAndClearSession(s.vrpp(d), era)
	}
	s.sessions = sessions
}

func (s *service) vrpp(d netip.Addr) bpf_vrpp {
	return bpf_vrpp{vaddr: as16(s.service.Address), raddr: as16(d), vport: s.service.Port, protocol: uint16(s.service.Protocol)}
}

func (s *service) vrpps() map[netip.Addr]bpf_vrpp {
	r := make(map[netip.Addr]bpf_vrpp, len(s.dests))
	for a, _ := range s.dests {
		r[a] = s.vrpp(a)
	}
	return r
}

func (s *service) local() (r []netip.Addr) {
	for a, _ := range s.mac {
		r = append(r, a)
	}

	return
}

func (s *service) recalc(debug func(...any), netinfo *netinfo, nat func(netip.Addr, netip.Addr) netip.Addr) (bpf_service, map[addr16]bpf_vip_rip) {

	reals := make(map[netip.Addr]dest, len(s.dests))
	tunn := make(map[netip.Addr]bpf_tunnel, len(s.dests))
	macs := make(map[netip.Addr]mac, len(s.dests))

	for k, d := range s.dests {
		t := netinfo.find(k).bpf_tunnel(d.TunnelType, d.TunnelFlags, d.TunnelPort)

		d.Disable = false

		reals[k] = dest{tunnel: t, disable: d.Disable}

		if !d.Disable && t.vlanid != 0 {
			tunn[k] = t
		}

		if t.local() {
			macs[k] = t.h_dest
		}

		debug("FWD", d, t)
	}

	s.mac = macs

	return s.forwarding(debug, reals), s.nat(debug, netinfo, nat, reals)
}

func (s *service) nat(debug func(...any), netinfo *netinfo, natfn func(netip.Addr, netip.Addr) netip.Addr, reals map[netip.Addr]dest) map[addr16]bpf_vip_rip {
	vip := s.service.Address
	ret := map[addr16]bpf_vip_rip{}

	for k, v := range reals {
		tun := v.tunnel
		nat := natfn(vip, k)
		ext := netinfo.ext(tun.vlanid, vip.Is6())

		if !nat.IsValid() || !ext.IsValid() {
			tun.vlanid = 0 // request will be dropped
		}

		debug(fmt.Sprintf("NAT %s->%s => %s %s %s->%s", vip, k, nat, tun, ext, vip))

		ret[as16(nat)] = bpf_vip_rip{tunnel: tun, vip: as16(vip), ext: as16(ext)}
	}

	return ret
}

func (s *service) forwarding(debug func(...any), reals map[netip.Addr]dest) (fwd bpf_service) {
	//func (s *service) forwarding(debug func(...any), reals map[netip.Addr]bpf_tunnel) (fwd bpf_service) {

	addrs := make([]netip.Addr, 0, len(reals))

	for k, v := range reals {
		if v.tunnel.vlanid != 0 {
			addrs = append(addrs, k)
		}
	}

	fwd.dest[0].flags = uint8(s.service.Flags)

	var duration time.Duration

	if len(addrs) > 0 {
		// we need the list to be sorted for maglev to be stable
		sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })

		dests := make([]bpf_tunnel, len(addrs))
		nodes := make([][]byte, len(addrs))

		for i, a := range addrs {
			dests[i] = reals[a].tunnel
			nodes[i] = []byte(a.String())
			//nodes[i] = []byte(reals[a].daddr.String())
		}

		for i, v := range dests {
			fwd.dest[i+1] = v
		}

		now := time.Now()
		for i, v := range maglev.Maglev8192(nodes) {
			fwd.hash[i] = uint8(v + 1)
		}
		duration = time.Now().Sub(now)
	}

	debug("MAG", s.service, fwd.hash[0:32], duration)

	return
}

func (s *service) rips() (r []netip.Addr) {
	for rip, _ := range s.dests {
		r = append(r, rip)
	}
	return
}

func (s *service) destinations(m maps) (r []DestinationExtended) {
	for a, d := range s.dests {
		c := m.counters(s.vrpp(a), s.sessions[a])
		r = append(r, DestinationExtended{Destination: d, MAC: s.mac[a], Stats: c.stats(), Metrics: c.metrics()})
	}
	return
}
