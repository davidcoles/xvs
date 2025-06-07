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
	Bond   bool
	BPF    []byte
	Flows  uint32
	VLANs4 map[uint16]netip.Prefix
	VLANs6 map[uint16]netip.Prefix
	Test   bool
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
	SetService(Service, ...Destination) error

	Destinations(Service) ([]DestinationExtended, error)
	CreateDestination(Service, Destination) error
	UpdateDestination(Service, Destination) error
	RemoveDestination(Service, Destination) error

	VIP(netip.Addr) VIP
	VIPs() []VIP

	// NAT returns an address which can be used to query a specific
	// VIP on a backend server, this can be used to implement health
	// checks
	NAT(vip, rip netip.Addr) (nat netip.Addr)

	// ReadFlow retrieves an opaque flow record from a queue written to by the
	// kernel. If no flow records are available then a zero length
	// slice is returned. This can be used to share flow state with
	// peers, storing the flow with the WriteFlow() function. Stale
	// records are skipped.
	ReadFlow() []byte
	WriteFlow([]byte)
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

type VIP struct {
	Address netip.Addr
	Metrics map[string]uint64
}

type Config struct {
	VLANs4 map[uint16]netip.Prefix
	VLANs6 map[uint16]netip.Prefix
	Routes map[netip.Prefix]uint16
}

func (s *Service) vrpp(d netip.Addr) bpf_vrpp {
	return bpf_vrpp{vaddr: as16(s.Address), raddr: as16(d), vport: s.Port, protocol: uint16(s.Protocol)}
}

func (s *Service) check() error {

	if !s.Address.IsValid() || s.Address.IsUnspecified() || s.Address.IsMulticast() || s.Address.IsLoopback() {
		return fmt.Errorf("Bad IP address")
	}

	if s.Port == 0 {
		return fmt.Errorf("Reserved port")
	}

	if s.Protocol != TCP && s.Protocol != UDP {
		return fmt.Errorf("Unsupported protocol")
	}

	return nil
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

func (d Destination) check() error {

	if !d.Address.IsValid() || d.Address.IsUnspecified() || d.Address.IsMulticast() || d.Address.IsLoopback() {
		return fmt.Errorf("Bad destination address: %s", d.Address)
	}

	return nil
}
