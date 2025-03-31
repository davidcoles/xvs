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
type Flags uint8

const (
	Sticky Flags = 0x01
)

type Client3 interface {
	Info() (Info, error)
	Clean()

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

type Service3Extended struct {
	Service Service3
}

type Destination3Extended struct {
	Destination Destination3
}

type Config struct {
	Router [6]byte
}

func New(interfaces ...string) (Client3, error) {
	return Layer3(interfaces[0], mac{})
}

func (l *layer3) Info() (Info, error) {
	for t, service3 := range l.services {
		for _, d := range service3.dests {
			vip := t.address
			rip := d.Address
			nat := l.ns.addr(l.natmap.get(vip, rip), vip.Is6())
			fmt.Println(vip, t.port, t.protocol, rip, nat, nat.IsValid())
		}
	}
	return Info{}, nil
}

func (l *layer3) Clean() {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.deletion()
}

func (l *layer3) Config() (Config, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	return Config{}, nil
}

func (l *layer3) SetConfig(c Config) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.h_dest = c.Router
	l.config()
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

func (l *layer3) Service(s Service3) (Service3Extended, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return Service3Extended{}, fmt.Errorf("Service does not exist")
	}

	return Service3Extended{Service: service.service}, nil
}

func (l *layer3) CreateService(s Service3) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if _, exists := l.services[s.key()]; exists {
		return fmt.Errorf("Service exists")
	}

	service := &service3{
		dests:   map[netip.Addr]Destination3{},
		service: s,
	}

	l.services[s.key()] = service

	service.recalc(l)

	return nil
}

func (l *layer3) UpdateService(s Service3) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	service.service = s

	service.recalc(l)

	return nil
}

func (l *layer3) RemoveService(s Service3) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	service.delete(l)

	return nil
}

func (l *layer3) Destinations(s Service3) (r []Destination3Extended, e error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return nil, fmt.Errorf("Service does not exist")
	}

	for _, v := range service.dests {
		r = append(r, Destination3Extended{Destination: v})
	}

	return
}

func (l *layer3) CreateDestination(s Service3, d Destination3) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	if _, exists := service.dests[d.Address]; exists {
		return fmt.Errorf("Destination exists")
	}

	service.dests[d.Address] = d

	l.natmap.add(s.Address, d.Address)
	l.natmap.index()

	// TODO - add stats map eniires

	service.recalc(l)

	return nil
}

func (l *layer3) UpdateDestination(s Service3, d Destination3) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	if _, exists := service.dests[d.Address]; !exists {
		return fmt.Errorf("Destination does not exist")
	}

	service.dests[d.Address] = d

	service.recalc(l)

	return nil
}

func (l *layer3) RemoveDestination(s Service3, d Destination3) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	if _, exists := service.dests[d.Address]; !exists {
		return fmt.Errorf("Destination does not exist")
	}

	return service.deldest(l, d)
}
