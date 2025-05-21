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
	//"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

type TunnelType uint8
type TunnelFlags uint8
type Flags uint8

const (
	Sticky Flags = 0x01
)

const (
	TunnelEncapNoChecksums TunnelFlags = 0x01 // FIXME - add check?
)

type Options struct {
	Native bool
	BPF    []byte
	Flows  uint32
	VLANs4 map[uint16]netip.Prefix
	VLANs6 map[uint16]netip.Prefix
	//Bonded    bool
	KillSwitch bool
}

type Client interface {
	Info() (Info, error)

	Config() (Config, error)
	SetConfig(Config) error

	Services() ([]ServiceExtended, error)
	Service(Service) (ServiceExtended, error)
	CreateService(Service) error
	UpdateService(Service) error
	RemoveService(Service) error

	Destinations(Service) ([]DestinationExtended, error)
	CreateDestination(Service, Destination) error
	UpdateDestination(Service, Destination) error
	RemoveDestination(Service, Destination) error

	SetService(Service, ...Destination) error
	NAT(netip.Addr, netip.Addr) netip.Addr
	Addresses() (netip.Addr, netip.Addr) // temporary?

	ReadFlow() []byte
	WriteFlow([]byte)
}

func (l *layer3) Addresses() (netip.Addr, netip.Addr) {
	return l.netns.address4(), l.netns.address6()
}

func (s *Service) key() threetuple {
	return threetuple{address: s.Address, port: s.Port, protocol: s.Protocol}
}

type Service struct {
	Address  netip.Addr
	Port     uint16
	Protocol Protocol
	Flags    Flags
}

type Stats struct {
	Packets uint64
	Octets  uint64
	Flows   uint64
	Current uint64
	Errors  uint64

	SYN uint64
	ACK uint64
	FIN uint64
	RST uint64
}

type ServiceExtended struct {
	Service Service
	Stats   Stats
}

type Destination struct {
	Address     netip.Addr
	TunnelType  TunnelType
	TunnelPort  uint16
	TunnelFlags TunnelFlags
	Weight      uint8
}

type DestinationExtended struct {
	Destination Destination
	Stats       Stats
	MAC         MAC
}

type Config struct {
	VLANs4 map[uint16]netip.Prefix
	VLANs6 map[uint16]netip.Prefix
}

func (c *Config) copy() (r Config) {
	r.VLANs4 = make(map[uint16]netip.Prefix, len(c.VLANs4))
	r.VLANs6 = make(map[uint16]netip.Prefix, len(c.VLANs6))
	for k, v := range c.VLANs4 {
		if v.Addr().Is4() {
			r.VLANs4[k] = v
		}
	}
	for k, v := range c.VLANs6 {
		if v.Addr().Is6() {
			r.VLANs6[k] = v
		}
	}
	return
}

func New(interfaces ...string) (Client, error) {
	return newClient(interfaces...)
}

func NewWithOptions(options Options, interfaces ...string) (Client, error) {
	return newClientWithOptions(options, interfaces...)
}

func (l *layer3) Info() (Info, error) {
	for t, s := range l.services {
		for _, d := range s.dests {
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

func (l *layer3) Services() (r []ServiceExtended, e error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	for _, v := range l.services {
		r = append(r, ServiceExtended{Service: v.service})
	}

	return
}

func (l *layer3) Service(s Service) (r ServiceExtended, e error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return r, fmt.Errorf("Service does not exist")
	}

	return service.extend(), nil
}

func (l *layer3) CreateService(s Service) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if _, exists := l.services[s.key()]; exists {
		return fmt.Errorf("Service exists")
	}

	return l.createService(s)
}

func (l *layer3) UpdateService(s Service) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	return service.update(s)
}

func (l *layer3) RemoveService(s Service) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	return service.remove()
}

func (l *layer3) Destinations(s Service) (r []DestinationExtended, e error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return nil, fmt.Errorf("Service does not exist")
	}

	return service.destinations()
}

func (l *layer3) CreateDestination(s Service, d Destination) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	return service.createDestination(d)
}

func (l *layer3) UpdateDestination(s Service, d Destination) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	return service.updateDestination(d)
}

func (l *layer3) RemoveDestination(s Service, d Destination) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	return service.removeDestination(d)
}

func (l *layer3) SetService(s Service, ds ...Destination) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return l.createService(s, ds...)
	}

	del, err := service.set(s, ds...)

	if del {
		l.clean()
	}

	return err
}

func (l *layer3) NAT(vip netip.Addr, rip netip.Addr) netip.Addr {
	return l.nat(vip, rip)
}

func (d *Destination) is4() bool {
	return d.Address.Is4()
}

func (d *Destination) as16() (r addr16) {
	if d.is4() {
		ip := d.Address.As4()
		copy(r[12:], ip[:])
	} else {
		r = d.Address.As16()
	}
	return
}

func (d Destination) check() error {

	if !d.Address.IsValid() || d.Address.IsUnspecified() || d.Address.IsMulticast() || d.Address.IsLoopback() {
		return fmt.Errorf("Bad destination address: %s", d.Address)
	}

	return nil
}

func (l *layer3) ReadFlow() []byte {
	var entry [ft_size + flow_size]byte

try:
	if l.maps.flow_queue.LookupAndDeleteElem(nil, uP(&entry)) != 0 {
		return nil
	}

	kern := ktime()
	when := *((*uint64)(uP(&entry[ft_size])))

	if when < kern {
		// expected
		if when+uint64(2*time.Second) < kern {
			print("-")
			goto try
		}
	} else {
		if kern+uint64(2*time.Second) < when {
			print("+")
			goto try
		}
	}

	return entry[:]
}

func (l *layer3) WriteFlow(f []byte) {

	if len(f) != int(ft_size+flow_size) {
		return
	}

	key := uP(&f[0])
	val := uP(&f[ft_size])
	time := (*uint64)(val)
	*time = ktime() // set first 8 bytes of state to the local kernel time
	fmt.Println(l.maps.shared.UpdateElem(key, val, xdpBPF_ANY))
}
