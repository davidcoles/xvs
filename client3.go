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

	//Config() (Config, error)
	SetConfig(Config) error

	CreateService(Service3) error
	UpdateService(Service3) error
	RemoveService(Service3) error

	CreateDestination(Service3, Destination3) error
	UpdateDestination(Service3, Destination3) error
	RemoveDestination(Service3, Destination3) error
}

type Service3 struct {
	Address  netip.Addr
	Port     uint16
	Protocol Protocol
	Flags    Flags
}

type Config struct {
	Router [6]byte
}

func New(interfaces ...string) (Client3, error) {
	return Layer3(interfaces[0], mac{})
}

func (l *layer3) SetConfig(c Config) error {
	l.h_dest = c.Router
	l.config()
	return nil
}

func (l *layer3) CreateService(s Service3) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	tt := threetuple{address: s.Address, port: s.Port, protocol: s.Protocol}

	if _, exists := l.services[tt]; exists {
		return fmt.Errorf("Service exists")
	}

	service := &l3service{
		dests:   map[netip.Addr]L3Destination{},
		service: s,
	}

	l.services[tt] = service

	service.recalc(l)

	return nil
}

func (l *layer3) UpdateService(s Service3) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	tt := threetuple{address: s.Address, port: s.Port, protocol: s.Protocol}

	service, exists := l.services[tt]

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

	t := threetuple{address: s.Address, port: s.Port, protocol: s.Protocol}

	_, exists := l.services[t]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	delete(l.services, t)

	// remove service entry
	key := bpf_servicekey{
		addr:  as16(t.address),
		port:  t.port,
		proto: uint16(t.protocol),
	}
	l.destinations.DeleteElem(uP(&key))

	// clean up - TODO
	// remove all stats map entries - TODO

	return nil
}

func (l *layer3) CreateDestination(s Service3, d Destination3) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	tt := threetuple{address: s.Address, port: s.Port, protocol: s.Protocol}

	service, exists := l.services[tt]

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

	t := threetuple{address: s.Address, port: s.Port, protocol: s.Protocol}

	service, exists := l.services[t]

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

	t := threetuple{address: s.Address, port: s.Port, protocol: s.Protocol}

	service, exists := l.services[t]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	if _, exists := service.dests[d.Address]; !exists {
		return fmt.Errorf("Destination does not exist")
	}

	delete(service.dests, d.Address)

	// check if there are more vip/rip on a different port clean natmap

	service.recalc(l)

	return nil
}

func (l *layer3) Clean() {

	vips := map[netip.Addr]bool{}
	nmap := map[[2]netip.Addr]bool{}
	nats := map[netip.Addr]bool{}

	for k, v := range l.services {
		vips[k.address] = true
		for r, _ := range v.dests {
			nmap[[2]netip.Addr{k.address, r}] = true
		}
	}

	// update natmap
	l.natmap.clean(nmap)

	clean_map(l.vips, vips)
	clean_map(l.vips, vips)

	for k, v := range l.natmap.all() {
		nat := l.ns.addr(v, k[0].Is6()) // k[0] is the vip
		nats[nat] = true
	}

	clean_map(l.nat_to_vip_rip, nats)
	clean_map(l.nat_to_vip_rip, nats)

}
