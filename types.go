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
	"net"
	"net/netip"
	"sort"
	"sync"
	"unsafe"
)

type IP4 [4]byte
type MAC [6]byte

func (i IP4) String() string { return fmt.Sprintf("%d.%d.%d.%d", i[0], i[1], i[2], i[3]) }
func (i *IP4) IsNil() bool   { return i[0] == 0 && i[1] == 0 && i[2] == 0 && i[3] == 0 }

func (m MAC) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

func (m *MAC) string() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

func (m *MAC) MarshalText() ([]byte, error) {
	return []byte(m.string()), nil
}

func (m *MAC) IsNil() bool {
	return m[0] == 0 && m[1] == 0 && m[2] == 0 && m[3] == 0 && m[4] == 0 && m[5] == 0
}

type uP = unsafe.Pointer

func nltoh(n [4]byte) uint32 {
	return uint32(n[0])<<24 | uint32(n[1])<<16 | uint32(n[2])<<8 | uint32(n[0])
}

var mutex sync.Mutex

const (
	TCP protocol = 0x06
	UDP protocol = 0x11
)

type Protocol uint8
type protocol = Protocol

type svc struct {
	IP       IP4
	Port     uint16
	Protocol protocol
}

type nat_map map[[2]IP4]uint16

func (n *nat_map) set(tuples map[[2]IP4]bool) {
	mutex.Lock()
	defer mutex.Unlock()

	nm := natmap(tuples, *n)

	*n = nm
}

func (n *nat_map) get() map[[2]IP4]uint16 {
	mutex.Lock()
	defer mutex.Unlock()

	r := map[[2]IP4]uint16{}

	for k, v := range *n {
		r[k] = v
	}

	return r
}

func (n *nat_map) rip() (r []IP4) {
	mutex.Lock()
	defer mutex.Unlock()

	m := map[IP4]bool{}

	for k, _ := range *n {
		m[k[1]] = true
	}

	for k, _ := range m {
		r = append(r, k)
	}

	return r
}

func (n *nat_map) ent(vip, rip IP4) uint16 {
	mutex.Lock()
	defer mutex.Unlock()

	x := (map[[2]IP4]uint16)(*n)

	i, _ := x[[2]IP4{vip, rip}]

	return i
}

type tag_map map[IP4]uint16

func (t tag_map) set(ip IP4, id uint16) {
	mutex.Lock()
	defer mutex.Unlock()
	x := (map[IP4]uint16)(t)
	x[ip] = id
}

func (n *tag_map) get() map[IP4]uint16 {
	mutex.Lock()
	defer mutex.Unlock()

	r := map[IP4]uint16{}

	for k, v := range *n {
		r[k] = v
	}

	return r
}

func (t tag_map) ent(ip IP4) (uint16, bool) {
	mutex.Lock()
	defer mutex.Unlock()

	x := (map[IP4]uint16)(t)

	r, ok := x[ip]

	return r, ok
}

type vc struct {
	vid uint16
	net net.IPNet
}

func (c *Client) targets() (r []IP4) {

	t := map[IP4]bool{}

	nm := c.nat_map.get()

	for k, _ := range nm {
		rip := k[1]
		t[rip] = true
	}

	for k, _ := range t {
		r = append(r, k)
	}

	return
}

type Service struct {
	Address  netip.Addr
	Port     uint16
	Protocol protocol

	Sticky bool
	//Scheduler uint8
	//Leastconns       bool
	//LeastconnsIP     IP4
	//LeastconnsWeight uint8

	backend map[IP4]*Destination
	state   *be_state
}

func (s *Service) Service(x svc) Service {
	var r Service
	r = *s
	r.backend = map[IP4]*Destination{}
	r.state = nil
	return r
}

type ServiceExtended struct {
	Service Service
	Stats   Stats
}

func (s *Service) update(u Service) {
	//s.Scheduler = u.Scheduler
	s.Sticky = u.Sticky
	//s.Leastconns = u.Leastconns
	//s.LeastconnsIP = u.LeastconnsIP
	//s.LeastconnsWeight = u.LeastconnsWeight
}

func (s *Service) svc() (svc, error) {
	if !s.Address.Is4() {
		return svc{}, errors.New("Not IPv4")
	}
	ip := s.Address.As4()
	return svc{IP: ip, Port: s.Port, Protocol: s.Protocol}, nil
}

type Destination struct {
	Address netip.Addr
	Weight  uint8
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

type Info struct {
	Packets   uint64
	Octets    uint64
	Flows     uint64
	Latency   uint64
	Dropped   uint64
	Blocked   uint64
	NotQueued uint64
}

type Stats struct {
	Packets uint64
	Octets  uint64
	Flows   uint64
}

func (s Stats) String() string { return fmt.Sprintf("p:%d o:%d f:%d", s.Packets, s.Octets, s.Flows) }

type DestinationExtended struct {
	Destination Destination
	MAC         MAC
	Stats       Stats
}

func natmap(tuples map[[2]IP4]bool, previous map[[2]IP4]uint16) (mapping map[[2]IP4]uint16) {

	mapping = map[[2]IP4]uint16{}
	inverse := map[uint16][2]IP4{}

	for k, v := range previous {
		if _, ok := tuples[k]; ok {
			if _, exists := inverse[v]; !exists {
				inverse[v] = k
				mapping[k] = v
			}
		}
	}

	var n uint16
	for k, _ := range tuples {
		if _, ok := mapping[k]; ok {
			continue
		}

	find:
		n++
		if n > 65000 {
			return
		}

		if _, ok := inverse[n]; ok {
			goto find
		}

		mapping[k] = n
	}

	return
}

func (c *Client) vlanIDs() []vc {
	var vlans []vc

	for k, v := range c.vlans {
		vlans = append(vlans, vc{k, v})
	}
	sort.SliceStable(vlans, func(i, j int) bool {
		return vlans[i].vid < vlans[j].vid
	})

	return vlans
}

func (c *Client) tag(ips []IP4) map[IP4]uint16 {
	vlans := c.vlanIDs()
	r := map[IP4]uint16{}

outer:
	for _, i := range ips {
		ip := net.IP(i[:])
		for _, v := range vlans {
			if v.net.Contains(ip) {
				r[i] = v.vid
				continue outer
			}
		}
	}

	return r
}

func (c *Client) tag1(i IP4) uint16 {
	vlans := c.vlanIDs()

	ip := net.IP(i[:])
	for _, v := range vlans {
		if v.net.Contains(ip) {
			return v.vid
		}
	}

	return 0
}
