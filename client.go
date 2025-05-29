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
	"time"
)

type Protocol uint8
type TunnelType uint8
type TunnelFlags uint8
type Flags uint8

const (
	TCP Protocol = 0x06
	UDP Protocol = 0x11
)

type Options struct {
	Native bool
	BPF    []byte
	Flows  uint32
	VLANs4 map[uint16]netip.Prefix
	VLANs6 map[uint16]netip.Prefix
	//Bonded    bool
	UntaggedBond bool
}

func (o *Options) config() *Config {
	return &Config{VLANs4: o.VLANs4, VLANs6: o.VLANs6}
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

	ReadFlow() []byte
	WriteFlow([]byte)

	VirtualMetrics(netip.Addr) map[string]uint64
}

func (l *layer3) VirtualMetrics(a netip.Addr) map[string]uint64 {
	return l.maps.virtualMetrics(as16(a)).metrics() // lock not required
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
	Flows   uint64 // rename? "Connections" (total connections, a counter, like Packets and Octets, more in tune with ipvs)
	Current uint64 // rename? or move to DestinationExtended - ActiveConnections, like ipvs
	Errors  uint64 // maybe remove?
}

type ServiceExtended struct {
	Service Service
	Stats   Stats
	Metrics map[string]uint64
}

type Destination struct {
	Address     netip.Addr
	TunnelType  TunnelType
	TunnelPort  uint16
	TunnelFlags TunnelFlags
	Disable     bool
}

type DestinationExtended struct {
	Destination Destination
	Stats       Stats
	Metrics     map[string]uint64
	MAC         [6]byte
}

type Config struct {
	VLANs4 map[uint16]netip.Prefix
	VLANs6 map[uint16]netip.Prefix
	Routes map[netip.Prefix]uint16
}

func (c *Config) copy() (r Config, e error) {
	r = *c
	r.VLANs4 = make(map[uint16]netip.Prefix, len(c.VLANs4))
	r.VLANs6 = make(map[uint16]netip.Prefix, len(c.VLANs6))
	r.Routes = make(map[netip.Prefix]uint16, len(c.Routes))

	for k, v := range c.Routes {
		r.Routes[k] = v
	}

	for k, v := range c.VLANs4 {
		if k == 0 || k > 4094 {
			return r, fmt.Errorf("%d is not a valid VLAN ID", k)
		}
		if !v.Addr().Is4() {
			return r, fmt.Errorf("Non-IPv4 prefix in VLANs4: %s", v)
		}
		r.VLANs4[k] = v
	}

	for k, v := range c.VLANs6 {
		if k == 0 || k > 4094 {
			return r, fmt.Errorf("%d is not a valid VLAN ID", k)
		}
		if !v.Addr().Is6() {
			return r, fmt.Errorf("Non-IPv6 prefix in VLANs6: %s", v)
		}
		r.VLANs6[k] = v
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
	l.mutex.Lock()
	defer l.mutex.Unlock()

	g := l.maps.globals()
	latency := l.latency
	if latency == 0 {
		latency = 1000 // 0 would clearly be nonsense (happens at statup), so set to something realistic
	}

	return Info{
		Stats: Stats{
			Packets: g.packets,
			Octets:  g.octets,
			Flows:   g.flows,
			Current: l.current(),
		},
		Latency: latency,
		Metrics: l.maps.globals().metrics(),
		IPv4:    l.ns.address4(),
		IPv6:    l.ns.address6(),
	}, nil
}

type Info struct {
	Stats   Stats
	Latency uint64
	Metrics map[string]uint64
	IPv4    netip.Addr
	IPv6    netip.Addr
}

func (l *layer3) Config() (Config, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	return l.config, nil
}

func (l *layer3) SetConfig(c Config) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	config, err := c.copy()

	if err != nil {
		return err
	}

	l.config = config

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

// Creates a service if it does not exist, and populate the list of
// destinations. Any extant destinations which are not specified are
// removed.
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

// Given the virtual IP address of a service and the address of a real
// server this will return the NAT address that can be used to query
// the VIP address on the backend.
func (l *layer3) NAT(vip netip.Addr, rip netip.Addr) netip.Addr {
	return l.nat(vip, rip)
}

// Returns the IPv4 and IPv6 address of the veth interface - if a
// socket needs to be explicitly bound to to query the NAT addresses
// of backend servers then these can be used.
//func (l *layer3) Addresses() (ipv4 netip.Addr, ipv6 netip.Addr) {
//	return l.netns.address4(), l.netns.address6()
//}

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

// Retrieves an opaque flow record from a ueue written to by the
// kernel. If no flow records are available then a zero length slice
// is returned. This can be used to share flow state with peers, with
// the flow record stored using the WriteFlow() function. Stale
// records are skipped.
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

// Stores a flow retrieved with ReadFlow()
func (l *layer3) WriteFlow(f []byte) {

	if len(f) != int(ft_size+flow_size) || f[len(f)-1] != flow_version {
		return
	}

	key := uP(&f[0])
	val := uP(&f[ft_size])
	time := (*uint64)(val)
	*time = ktime() // set first 8 bytes of state to the local kernel time
	fmt.Println(l.maps.shared.UpdateElem(key, val, bpf_any))
}
