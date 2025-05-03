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
)

type TunnelType uint8
type TunnelFlags uint8
type Flags uint8

const (
	Sticky Flags = 0x01
)

type Client3 interface {
	Info() (Info, error)

	Config() (Config, error)
	SetConfig(Config) error

	Services() ([]Service3Extended, error)
	Service(Service3) (Service3Extended, error)
	CreateService(Service3) error
	UpdateService(Service3) error
	RemoveService(Service3) error

	Destinations(Service3) ([]Destination3Extended, error)
	CreateDestination(Service3, Destination3) error
	UpdateDestination(Service3, Destination3) error
	RemoveDestination(Service3, Destination3) error

	SetService(Service3, ...Destination3) error
	NAT(netip.Addr, netip.Addr) netip.Addr
}

func (s *Service3) key() threetuple {
	return threetuple{address: s.Address, port: s.Port, protocol: s.Protocol}
}

type Service3 struct {
	Address  netip.Addr
	Port     uint16
	Protocol Protocol
	Flags    Flags
}

type Stats3 struct {
	Packets uint64
	Octets  uint64
	Flows   uint64
	Current uint64
	Errors  uint64
}

type Service3Extended struct {
	Service Service3
	Stats   Stats3
}

type Destination3 struct {
	Address     netip.Addr
	TunnelType  TunnelType
	TunnelPort  uint16
	TunnelFlags TunnelFlags
	Weight      uint8
}

type Destination3Extended struct {
	Destination Destination3
	Stats       Stats3
}

type Config struct {
	VLAN4 map[uint16]netip.Prefix
	VLAN6 map[uint16]netip.Prefix
}

func New(interfaces ...string) (Client3, error) {
	return newClient(interfaces...)
}

func (l *layer3) Info() (Info, error) {
	for t, service3 := range l.services {
		for _, d := range service3.dests {
			vip := t.address
			rip := d.Address
			nat := l.netns.addr(l.natmap.get(vip, rip), vip.Is6())
			fmt.Println(vip, t.port, t.protocol, rip, nat, nat.IsValid())
		}
	}

	return Info{}, nil
}

func (l *layer3) Config() (Config, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	return l.config, nil
}

func (l *layer3) SetConfig(c Config) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.config = c

	l.reconfig()

	return nil
}

func (l *layer3) Services() (r []Service3Extended, e error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	for _, v := range l.services {
		r = append(r, Service3Extended{Service: v.service})
	}

	return
}

func (l *layer3) Service(s Service3) (r Service3Extended, e error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return r, fmt.Errorf("Service does not exist")
	}

	return service.extend(), nil
}

func (l *layer3) CreateService(s Service3) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if _, exists := l.services[s.key()]; exists {
		return fmt.Errorf("Service exists")
	}

	return l.createService(s)
}

func (l *layer3) UpdateService(s Service3) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	return service.update(s)
}

func (l *layer3) RemoveService(s Service3) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	return service.remove()
}

func (l *layer3) Destinations(s Service3) (r []Destination3Extended, e error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return nil, fmt.Errorf("Service does not exist")
	}

	return service.destinations()
}

func (l *layer3) CreateDestination(s Service3, d Destination3) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	return service.createDestination(d)
}

func (l *layer3) UpdateDestination(s Service3, d Destination3) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	return service.updateDestination(d)
}

func (l *layer3) RemoveDestination(s Service3, d Destination3) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	return service.removeDestination(d)
}

func (l *layer3) SetService(s Service3, ds ...Destination3) (err error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return l.createService(s, ds...)
	}

	return service.set(s, false, ds...)
}

func (l *layer3) NAT(vip netip.Addr, rip netip.Addr) netip.Addr {
	return l.nat(vip, rip)
}

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
