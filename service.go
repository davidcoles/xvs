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
	//"github.com/davidcoles/xvs/xdp"
)

type dest struct {
	disable bool
	tunnel  bpf_tunnel
}

type service struct {
	dests    map[netip.Addr]Destination
	mac      map[netip.Addr]mac
	service  Service
	layer3   *layer3
	tunnel   map[netip.Addr]bpf_tunnel
	sessions map[netip.Addr]uint64
}

func (s *service) debug(info ...any) {
	//fmt.Println(info...)
}

func (s *Service) key() threetuple {
	return threetuple{address: s.Address, port: s.Port, protocol: s.Protocol}
}

func (s *service) set(service Service, ds ...Destination) (deleted bool, err error) {

	destinations := make(map[netip.Addr]Destination, len(ds))

	for _, d := range ds {
		destinations[d.Address] = d
		if err = d.check(); err != nil {
			return
		}
	}

	for d, _ := range destinations {
		if _, exists := s.dests[d]; !exists {
			s.debug("ADDING", d)
			s.layer3.ping(d)
			s.layer3.maps.createCounters(s.vrpp(d))
			s.layer3.natmap.add(s.service.Address, d)
		}
	}

	for d, _ := range s.dests {
		if _, exists := destinations[d]; !exists {
			s.layer3.maps.removeCounters(s.vrpp(d)) // d was deleted
			deleted = true
		}
	}

	s.service = service
	s.dests = destinations
	s.layer3.natmap.index()
	s.recalc()

	return // do NOT run a clean here, let caller do it - service may not yet be in the client's service map
}

func (s *service) createDestination(d Destination) error {

	if _, exists := s.dests[d.Address]; exists {
		return fmt.Errorf("Destination exists")
	}

	if err := d.check(); err != nil {
		return err
	}

	s.layer3.ping(d.Address)
	s.layer3.maps.createCounters(s.vrpp(d.Address))
	s.layer3.natmap.add(s.service.Address, d.Address)
	s.layer3.natmap.index()
	s.dests[d.Address] = d
	s.recalc()
	return nil
}

func (s *service) removeDestination(d Destination) error {

	if _, exists := s.dests[d.Address]; !exists {
		return fmt.Errorf("Destination does not exist")
	}

	s.layer3.maps.removeCounters(s.vrpp(d.Address))

	delete(s.dests, d.Address)
	s.recalc()
	s.layer3.clean()
	return nil
}

func (l *layer3) createService(s Service, ds ...Destination) error {

	if !s.Address.IsValid() || s.Address.IsUnspecified() || s.Address.IsMulticast() || s.Address.IsLoopback() {
		return fmt.Errorf("Bad IP address")
	}

	if s.Port == 0 {
		return fmt.Errorf("Reserved port")
	}

	if s.Protocol != TCP && s.Protocol != UDP {
		return fmt.Errorf("Unsupported protocol")
	}

	service := &service{dests: map[netip.Addr]Destination{}, service: s, layer3: l}

	_, err := service.set(s, ds...)

	if err != nil {
		return err
	}

	l.services[s.key()] = service

	return nil
}

func (s *service) current() (r uint64) {
	for d, _ := range s.dests {
		r += s.sessions[d]
	}
	return
}

func (s *service) extend() ServiceExtended {
	var c bpf_counter
	var t uint64
	for d, _ := range s.dests {
		c.add(s.layer3.maps.counters(s.vrpp(d)))
		t += s.sessions[d]
	}
	metrics := s.layer3.maps.serviceMetrics(s.key()).metrics()
	return ServiceExtended{Service: s.service, Stats: c.stats(t), Metrics: metrics}
}

func (s *service) update(service Service) error {
	s.service = service
	s.recalc()
	return nil
}

func (s *service) key() bpf_servicekey {
	return bpf_servicekey{addr: as16(s.service.Address), port: s.service.Port, proto: uint16(s.service.Protocol)}
}

func (s *service) remove() error {
	for d, _ := range s.dests {
		s.layer3.maps.removeCounters(s.vrpp(d))
	}

	s.layer3.maps.removeService(s.key())
	delete(s.layer3.services, s.service.key())
	s.layer3.clean()
	return nil
}

func (s *service) updateDestination(d Destination) error {

	if _, exists := s.dests[d.Address]; !exists {
		return fmt.Errorf("Destination does not exist")
	}

	s.dests[d.Address] = d

	s.recalc()

	return nil
}

func (s *service) stats(d netip.Addr) Stats {
	return s.layer3.maps.counters(s.vrpp(d)).stats(s.sessions[d])
}

func (s *service) destinations() (r []DestinationExtended, e error) {
	for a, d := range s.dests {
		m := s.layer3.maps.counters(s.vrpp(a)).metrics()
		mac := s.mac[a]
		r = append(r, DestinationExtended{Destination: d, Stats: s.stats(a), Metrics: m, MAC: mac})
	}
	return
}

func (s *service) readSessions() {
	sessions := make(map[netip.Addr]uint64, len(s.dests))
	for d, _ := range s.dests {
		sessions[d] = s.layer3.maps.readAndClearSession(s.vrpp(d), s.layer3.era())
	}
	s.sessions = sessions
}

func (s *service) a16() addr16   { return as16(s.service.Address) }
func (s *service) port() uint16  { return s.service.Port }
func (s *service) proto() uint16 { return uint16(s.service.Protocol) }
func (s *service) vrpp(d netip.Addr) bpf_vrpp {
	return bpf_vrpp{vaddr: s.a16(), raddr: as16(d), vport: s.port(), protocol: s.proto()}
}

func (s *service) local() (r []netip.Addr) {
	for a, _ := range s.mac {
		r = append(r, a)
	}

	return
}

func (s *service) recalc() {

	reals := make(map[netip.Addr]dest, len(s.dests))
	macs := make(map[netip.Addr]mac, len(s.dests))

	for k, d := range s.dests {
		t := s.layer3.find(d).bpf_tunnel(d.TunnelType, d.TunnelFlags, d.TunnelPort)

		reals[k] = dest{tunnel: t, disable: d.Disable}

		if !t.remote() {
			macs[k] = t.h_dest
		}

		s.debug("FWD", d, t)
	}

	s.mac = macs

	key := s.key()
	fwd := s.forwarding(reals)

	//s.layer3.maps.services.UpdateElem(uP(&key), uP(&fwd), xdp.BPF_ANY)
	s.layer3.maps.setService(key, fwd)

	s.nat(reals)

	//v16 := as16(s.service.Address)
	//all := make([]bpf_global, xdp.BpfNumPossibleCpus()+1)
	//s.layer3.maps.vip_metrics.UpdateElem(uP(&v16), uP(&all[0]), xdp.BPF_NOEXIST)
	//s.layer3.maps.service_metrics.UpdateElem(uP(&key), uP(&all[0]), xdp.BPF_NOEXIST)
}

func (s *service) nat(reals map[netip.Addr]dest) {
	vip := s.service.Address

	for k, v := range reals {
		tun := v.tunnel
		nat := s.layer3.nat(vip, k)
		ext := s.layer3.ext(tun.vlanid, vip.Is6())

		if !nat.IsValid() || !ext.IsValid() {
			tun.vlanid = 0 // request will be dropped
		}

		//key := as16(nat)
		//vip_rip := bpf_vip_rip{tunnel: tun, vip: as16(vip), ext: as16(ext)}
		//s.layer3.maps.nat_to_vip_rip.UpdateElem(uP(&key), uP(&vip_rip), xdp.BPF_ANY) // FIXME
		s.layer3.maps.nat(as16(nat), bpf_vip_rip{tunnel: tun, vip: as16(vip), ext: as16(ext)})

		s.debug(fmt.Sprintf("NAT %s->%s => %s %s %s->%s", vip, k, nat, tun, ext, vip))
	}
}

func (s *service) forwarding(reals map[netip.Addr]dest) (fwd bpf_service) {

	addrs := make([]netip.Addr, 0, len(reals))

	for k, v := range reals {
		if !v.disable && v.tunnel.vlanid != 0 {
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

	s.debug("MAG", s.service, fwd.hash[0:32], duration)

	return
}

func (s *service) repeat(packet []byte, send func([]byte)) {

	vip := s.service.Address

	for rip, _ := range s.dests {

		nat := s.layer3.NAT(vip, rip)

		if !nat.IsValid() {
			continue
		}

		if nat.Is4() {
			as4 := nat.As4()
			copy(packet[16:], as4[:]) // offset 16 is the destination address in IPv4
		} else if nat.Is6() {
			as16 := nat.As16()
			copy(packet[24:], as16[:]) // offset 24 is the destination address in IPv6
		} else {
			continue
		}

		send(packet)
	}
}
