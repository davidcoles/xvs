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
	"log/slog"
	"net/netip"
)

type Protocol uint8
type TunnelType uint8
type tunnelFlags uint8
type flags uint8

const (
	TCP Protocol = 0x06
	UDP Protocol = 0x11
)

type Config struct {
	IPv4VLANs map[uint16]netip.Prefix
	IPv6VLANs map[uint16]netip.Prefix
	Routes    map[netip.Prefix]uint16
}

type Options struct {
	DriverMode         bool                    // Use XDP_FLAGS_DRV_MODE flag when attaching interface
	Bonding            bool                    // Explicitly declare interfaces to be aggregated
	BPFProgram         []byte                  // Override the embedded BPF program with this object code
	FlowsPerCPU        uint32                  // Override default size of flow tracking tables
	InterfaceInitDelay uint8                   // Pause (seconds) between each link attach/detach; to prevent bonds flapping
	IPv4VLANs          map[uint16]netip.Prefix // VLAN ID/IPv4 Prefix mapping
	IPv6VLANs          map[uint16]netip.Prefix // VLAN ID/IPv6 Prefix mapping
	Routes             map[netip.Prefix]uint16 // Override route selection for layer 3 backends; prefix-to-VLAN ID map
	Logger             *slog.Logger
}

func (o *Options) config() *Config {
	return &Config{IPv4VLANs: o.IPv4VLANs, IPv6VLANs: o.IPv6VLANs, Routes: o.Routes}
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

	// SetService combines the functionality of CreateService,
	// UpdateService, CreateDestination, UpdateDestination and
	// RemoveDestination. If the service does not exist it will be
	// created with the given parameters and destinations, or updated
	// to match them if extant.
	SetService(Service, ...Destination) error

	VIPs() ([]VIP, error)
	VIP(netip.Addr) (VIP, error)

	// NAT returns an address which can be used to query a specific
	// virtual IP on a backend ("real") server, this can be used to
	// implement health checks which accurately reflect the ability of
	// the backend to serve traffic for a particular VIP.
	NAT(vip, rip netip.Addr) (nat netip.Addr)

	// ReadFlow retrieves an opaque flow record from a queue written
	// to by the kernel. If no flow records are available then a zero
	// length slice is returned. This can be used to share flow state
	// with peers, storing the flow with the WriteFlow()
	// function. Stale records in the queue (older than a few seconds)
	// are skipped.
	ReadFlow() []byte
	WriteFlow([]byte)
}

type Service struct {
	Address  netip.Addr
	Port     uint16
	Protocol Protocol
	Sticky   bool
	//Flags    Flags
}

type Stats struct {
	Connections     uint64
	IncomingPackets uint64
	IncomingBytes   uint64

	/*
		Packets uint64
		Octets  uint64
		Flows   uint64
		Current uint64
		Errors  uint64
	*/
}

type ServiceExtended struct {
	Service Service
	Stats   Stats
	Metrics map[string]uint64
}

type Destination struct {
	Address               netip.Addr
	TunnelType            TunnelType
	TunnelPort            uint16
	TunnelEncapNoChecksum bool
	Disable               bool
}

func (d *Destination) tunnelFlags() (f tunnelFlags) {
	if d.TunnelEncapNoChecksum {
		f |= tunnelEncapNoChecksums
	}
	return
}

type DestinationExtended struct {
	Destination       Destination
	ActiveConnections uint32
	Stats             Stats
	Metrics           map[string]uint64
	MAC               [6]byte
}

type VIP struct {
	Address netip.Addr
	Stats   Stats
	Metrics map[string]uint64
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
	r.IPv4VLANs = make(map[uint16]netip.Prefix, len(c.IPv4VLANs))
	r.IPv6VLANs = make(map[uint16]netip.Prefix, len(c.IPv6VLANs))
	r.Routes = make(map[netip.Prefix]uint16, len(c.Routes))

	for k, v := range c.Routes {
		r.Routes[k] = v
	}

	for k, v := range c.IPv4VLANs {
		if k == 0 || k > 4094 {
			return r, fmt.Errorf("%d is not a valid VLAN ID", k)
		}
		if !v.Addr().Is4() {
			return r, fmt.Errorf("Non-IPv4 prefix in VLANs4: %s", v)
		}
		r.IPv4VLANs[k] = v
	}

	for k, v := range c.IPv6VLANs {
		if k == 0 || k > 4094 {
			return r, fmt.Errorf("%d is not a valid VLAN ID", k)
		}
		if !v.Addr().Is6() {
			return r, fmt.Errorf("Non-IPv6 prefix in VLANs6: %s", v)
		}
		r.IPv6VLANs[k] = v
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
