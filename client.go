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
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/davidcoles/xvs/xdp"
)

type threetuple struct {
	address  netip.Addr
	port     uint16
	protocol Protocol
}

type client struct {
	config   Config
	mutex    sync.Mutex
	services map[threetuple]*service
	settings bpf_settings
	natmap   natmap
	netinfo  netinfo
	netns    netns
	icmp     icmp
	maps     maps
	latency  uint64
	test     bool
	logger   *slog.Logger
}

func (c *client) current() (r uint64) {
	for _, s := range c.services {
		r += s.current()
	}
	return
}

func newClient(interfaces ...string) (*client, error) {
	return newClientWithOptions(Options{}, interfaces...)
}

func newClientWithOptions(options Options, interfaces ...string) (_ *client, err error) {

	c := &client{services: map[threetuple]*service{}, natmap: natmap{}, logger: options.Logger}

	var nics []uint32

	for _, ifname := range interfaces {
		if iface, err := net.InterfaceByName(ifname); err != nil {
			return nil, err
		} else {
			nics = append(nics, uint32(iface.Index))
		}
	}

	if c.config, err = options.config().copy(); err != nil {
		return nil, err
	}

	if err = c.maps.init(options.BPFProgram); err != nil {
		return nil, err
	}

	if err = c.netns.init(c.maps.xdp); err != nil {
		return nil, err
	}

	//c.settings = bpf_settings{veth: c.netns.nic(), vetha: c.netns.src(), vethb: c.netns.dst(), active: 1}
	c.settings = bpf_settings{active: 1}

	if options.Bonding {
		c.settings.multi = 0 // if untagged packet recieved then TX it rather than redirect
	} else {
		c.settings.multi = uint8(len(interfaces))
	}

	if err = c.icmp.start(); err != nil {
		return nil, err
	}

	for _, nic := range nics {
		c.maps.xdp.LinkDetach(nic)
		if options.InterfaceInitDelay > 0 {
			time.Sleep(time.Duration(options.InterfaceInitDelay) * time.Second)
		}
	}

	if err = c.maps.tailCall("xdp_reply_v4", 0); err != nil {
		return nil, err
	}

	if err = c.maps.tailCall("xdp_reply_v6", 1); err != nil {
		return nil, err
	}

	if err = c.maps.initialiseFlows(options.FlowsPerCPU); err != nil {
		return nil, err
	}

	for _, nic := range nics {
		if err = c.maps.xdp.LoadBpfSection("xdp_forward_func", options.DriverMode, nic); err != nil {
			return nil, err
		}
		if options.InterfaceInitDelay > 0 {
			time.Sleep(time.Duration(options.InterfaceInitDelay) * time.Second)
		}
	}

	c.configure()
	c.maps.updateSettings(c.settings)
	go c.background()

	return c, nil
}

func (c *client) background() error {
	reconfig := time.NewTicker(time.Minute)
	sessions := time.NewTicker(time.Second * 30)
	icmp := time.NewTicker(time.Millisecond * 100)
	ping := time.NewTicker(time.Second * 15)
	init := time.NewTimer(time.Second * 20)

	defer func() {
		reconfig.Stop()
		sessions.Stop()
		icmp.Stop()
		ping.Stop()
	}()

	var latencies []uint64
	hosts := make(map[netip.Addr]bool, 65536)

	for {
		select {
		case <-ping.C:
			clear(hosts)
			c.mutex.Lock()
			for _, s := range c.services {
				for _, d := range s.local() {
					hosts[d] = true
				}
			}
			for _, r := range c.netinfo.routers() {
				hosts[r] = true
			}
			c.mutex.Unlock()
			for ip, _ := range hosts {
				c.icmp.ping(ip)
			}

		case <-sessions.C:

			latencies = append(latencies, c.maps.readLatency())

			for len(latencies) > 5 {
				latencies = latencies[1:]
			}

			if len(latencies) > 0 {
				var total uint64
				for _, l := range latencies {
					total += l
				}
				c.latency = total / uint64(len(latencies))
			}

			c.mutex.Lock()
			c.settings.era++
			c.maps.updateSettings(c.settings) // reset the watchdog
			for _, s := range c.services {
				s.readSessions(c.maps, c.settings.era%2 > 0)
			}
			c.mutex.Unlock()

		case <-reconfig.C:
			// re-scan network interfaces and match to VLANs
			// recalc all services as parameters may have changed
			c.mutex.Lock()
			c.configure()
			c.mutex.Unlock()

		case <-init.C:
			// as above, but early to catch responses of first set of pings - FIXME: kludge
			// (native mode is sluggish to start - this speeds it up a bit)
			c.mutex.Lock()
			c.configure()
			c.mutex.Unlock()

		case <-icmp.C:
			c.mutex.Lock()
			c.icmpQueue()
			c.mutex.Unlock()
		}
	}
}

func (c *client) icmpQueue() {

	const IPv4 = 0
	const IPv6 = 1

	for n := 0; n < 100; n++ {
		var buff [buffer_length]byte
		if c.maps.icmp_queue.LookupAndDeleteElem(nil, uP(&buff[0])) != 0 {
			return
		}

		// 16 bits of metadata (inc packet length)
		// 16 bits of port (host byte order)
		// ip source address (4 or 16 bytes)
		// original packet

		// metadata:
		// 11 bits (2047 bytes > MTU of 1500) original ip packet length
		// 1 bit address family; 0 - IPv4, 1 - IPv6
		// 1 bit protocol; 0 - TCP, 1 - UDP
		// 3 bits reason codes
		//   000 - fragmentation needed

		meta := *(*uint16)(uP(&buff[0]))
		port := *(*uint16)(uP(&buff[2]))

		length := meta >> 5
		family := meta >> 4 & 0x01
		proto4 := meta >> 3 & 0x01
		//reason := meta & 0x07

		protocol := TCP

		if proto4 != 0 {
			protocol = UDP
		}

		if length > 2000 {
			continue // unfeasibly large packet - avoid overstepping array bounds
		}

		var addr netip.Addr
		var packet []byte
		if family == IPv4 {
			var four [4]byte
			copy(four[:], buff[4:])
			addr = netip.AddrFrom4(four)
			packet = buff[4+4 : 4+4+length] // 4 metadata header, plus 4 bytes source address
		} else {
			var sixteen [16]byte
			copy(sixteen[:], buff[4:])
			addr = netip.AddrFrom16(sixteen)
			packet = buff[4+16 : 4+16+length] // 4 metadata header, plus 16 bytes source address
		}

		skey := threetuple{address: addr, port: port, protocol: protocol}
		s, ok := c.services[skey]

		if !ok {
			continue
		}

		for _, rip := range s.rips() {
			nat := c.NAT(addr, rip)

			if !nat.IsValid() {
				continue
			}

			if nat.Is4() {
				if family != IPv4 {
					continue // shouldn't happen, but handle gracefully
				}
				as4 := nat.As4()
				copy(packet[16:], as4[:]) // offset 16 is the destination address in IPv4
			} else if nat.Is6() {
				if family != IPv6 {
					continue // shouldn't happen, but handle gracefully
				}
				as16 := nat.As16()
				copy(packet[24:], as16[:]) // offset 24 is the destination address in IPv6
			} else {
				continue // *REALLY* shouldn't happen, but handle gracefully
			}

			raw := make([]byte, 14+len(packet)) // prepend packet with ethernet header
			iface := c.netns.i2.idx
			h_dest := c.netns.i3.mac
			h_source := c.netns.i2.mac

			copy(raw[0:], h_dest[:])
			copy(raw[6:], h_source[:])

			if family == IPv4 {
				raw[12] = 0x08
				raw[13] = 0x00
			} else {
				raw[12] = 0x86
				raw[13] = 0xdd
			}

			copy(raw[14:], packet[:])

			c.maps.xdp.SendRawPacket(int(iface), raw) // FIXME - log failed sends
		}
	}
}

func (c *client) configure() {

	c.netinfo.config(c.config.IPv4VLANs, c.config.IPv6VLANs, c.config.Routes)

	for i := uint32(1); i < 4095; i++ {
		vi, v4, v6 := c.netinfo.vlaninfo(uint16(i))
		c.maps.redirect_map4.UpdateElem(uP(&i), uP(&v4), xdp.BPF_ANY)
		c.maps.redirect_map6.UpdateElem(uP(&i), uP(&v6), xdp.BPF_ANY)
		c.maps.vlaninfo.UpdateElem(uP(&i), uP(&vi), xdp.BPF_ANY)
	}

	for _, s := range c.services {
		c.syncService(s, false, false)
	}
}

func (c *client) clean() {
	mark := time.Now()
	serv := map[bpf_servicekey]bool{}
	vips := map[netip.Addr]bool{}
	nats := map[netip.Addr]bool{}
	nmap := map[[2]netip.Addr]bool{}
	vrpp := map[bpf_vrpp]bool{}

	for k, service := range c.services {
		serv[service.key()] = true
		vips[k.address] = true
		for a, v := range service.vrpps() {
			nmap[[2]netip.Addr{k.address, a}] = true
			vrpp[v] = true
			v.protocol |= 0xff00
			vrpp[v] = true
		}
	}

	c.natmap.clean(nmap)

	for k, v := range c.natmap.all() {
		nat := c.netns.nat(v, k[0].Is6()) // k[0] is the vip
		nats[nat] = true
	}

	c.maps.clean(serv, vips, vrpp, nats, c.test)

	if c.logger != nil {
		c.logger.Info("Clean-up took", "duration", time.Now().Sub(mark))
	}
}

func (c *client) Info() (Info, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	metrics := c.maps.globals(c.current())
	latency := c.latency
	if latency == 0 {
		latency = 1000 // 0 would clearly be nonsense (but happens at statup), so set to something realistic
	}

	return Info{
		Stats:   metrics.stats(),
		Metrics: metrics.metrics(),
		Latency: latency,
		IPv4:    c.netns.ipv4(),
		IPv6:    c.netns.ipv6(),
	}, nil
}

type Info struct {
	Stats   Stats
	Latency uint64
	Metrics map[string]uint64
	IPv4    netip.Addr
	IPv6    netip.Addr
}

func (c *client) Config() (Config, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.config.copy()
}

func (c *client) SetConfig(x Config) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	config, err := x.copy()

	if err != nil {
		return err
	}

	c.config = config

	c.configure()

	return nil
}

func (c *client) serviceExtended(s *service) ServiceExtended {
	metrics := c.maps.serviceMetrics(s.key(), s.current())
	return ServiceExtended{Service: s.service, Stats: metrics.stats(), Metrics: metrics.metrics()}
}

func (c *client) Service(s Service) (r ServiceExtended, e error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	service, exists := c.services[s.key()]

	if !exists {
		return r, fmt.Errorf("Service does not exist")
	}

	return c.serviceExtended(service), nil
}

func (c *client) Services() (r []ServiceExtended, e error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, s := range c.services {
		r = append(r, c.serviceExtended(s))
	}

	return
}

func (c *client) createService(s Service, ds ...Destination) error {

	if err := s.check(); err != nil {
		return err
	}

	service := &service{dests: map[netip.Addr]Destination{}, service: s}

	add, _, err := service.set(s, ds...)

	if err != nil {
		return err
	}

	for _, d := range add {
		c.icmp.ping(d)
		c.maps.createCounters(s.vrpp(d))
		c.natmap.add(s.Address, d)
	}

	c.services[s.key()] = service

	return c.syncService(service, len(add) != 0, false)
}

func (c *client) syncService(s *service, index, clean bool) error {

	if index {
		c.natmap.index()
	}

	natfn := func(v, r netip.Addr) netip.Addr {
		return c.netns.nat(c.natmap.get(v, r), v.Is6())
	}

	fwd, nat := s.recalc(c.logger, &(c.netinfo), natfn)

	c.maps.setService(s.key(), fwd)

	for addr, vip_rip := range nat {
		c.maps.nat(addr, vip_rip)
	}

	if clean {
		c.clean()
	}

	return nil
}

func (c *client) CreateService(s Service) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, exists := c.services[s.key()]; exists {
		return fmt.Errorf("Service exists")
	}

	return c.createService(s)
}

func (c *client) UpdateService(s Service) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	service, exists := c.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	if err := service.update(s); err != nil {
		return err
	}

	return c.syncService(service, false, false)
}

func (c *client) RemoveService(s Service) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	service, exists := c.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	delete(c.services, s.key())

	c.maps.removeService(service.key())

	for _, d := range service.rips() {
		c.maps.removeCounters(service.vrpp(d))
	}

	c.clean()
	return nil
}

func (c *client) Destinations(s Service) (r []DestinationExtended, e error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	service, exists := c.services[s.key()]

	if !exists {
		return nil, fmt.Errorf("Service does not exist")
	}

	return service.destinations(c.maps), nil
}

func (c *client) CreateDestination(s Service, d Destination) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	service, exists := c.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	err := service.createDestination(d)

	if err != nil {
		return err
	}

	c.icmp.ping(d.Address)
	c.maps.createCounters(s.vrpp(d.Address))
	c.natmap.add(s.Address, d.Address)

	return c.syncService(service, true, false)
}

func (c *client) UpdateDestination(s Service, d Destination) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	service, exists := c.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	if err := service.updateDestination(d); err != nil {
		return err
	}

	return c.syncService(service, false, false)
}

func (c *client) RemoveDestination(s Service, d Destination) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	service, exists := c.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	if err := service.removeDestination(d); err != nil {
		return err
	}

	c.maps.removeCounters(s.vrpp(d.Address))

	return c.syncService(service, false, true)
}

// Creates a service if it does not exist, and populate the list of
// destinations. Any extant destinations which are not specified are
// removed.
func (c *client) SetService(s Service, ds ...Destination) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	service, exists := c.services[s.key()]

	if !exists {
		return c.createService(s, ds...)
	}

	add, del, err := service.set(s, ds...)

	if err != nil {
		return err
	}

	for _, d := range del {
		c.maps.removeCounters(s.vrpp(d))
	}

	for _, d := range add {
		c.icmp.ping(d)
		c.maps.createCounters(service.vrpp(d))
		c.natmap.add(s.Address, d)
	}

	return c.syncService(service, len(add) != 0, len(del) != 0)
}

// Given the virtual IP address of a service and the address of a real
// server this will return the NAT address that can be used to query
// the VIP address on the backend.
func (c *client) NAT(vip netip.Addr, rip netip.Addr) netip.Addr {
	return c.netns.nat(c.natmap.get(vip, rip), vip.Is6())
}

func (c *client) ReadFlow() []byte {
	var entry [ft_size + flow_size]byte

try:
	if c.maps.flow_queue.LookupAndDeleteElem(nil, uP(&entry)) != 0 {
		return nil
	}

	kern := ktime() // no nanosecond component currently
	when := *((*uint64)(uP(&entry[ft_size])))

	if when < kern {
		// expected
		if when+uint64(2*time.Second) < kern {
			goto try
		}
	} else {
		if kern+uint64(2*time.Second) < when {
			goto try
		}
	}

	return entry[:]
}

// Stores a flow retrieved with ReadFlow()
func (c *client) WriteFlow(f []byte) {
	c.maps.writeFlow(f)
}

func (c *client) vip(a netip.Addr) VIP {
	var t uint64
	for k, s := range c.services {
		if k.address == a {
			t += s.current()
		}
	}
	metrics := c.maps.virtualMetrics(as16(a), t)
	return VIP{Address: a, Stats: metrics.stats(), Metrics: metrics.metrics()}
}

func (c *client) VIP(a netip.Addr) (VIP, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.vip(a), nil
}

func (c *client) VIPs() (r []VIP, e error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	vips := map[netip.Addr]bool{}

	for _, s := range c.services {
		vips[s.service.Address] = true
	}

	for v, _ := range vips {
		r = append(r, c.vip(v))
	}

	return
}
