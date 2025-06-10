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
	"log"
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

func (t threetuple) bpf() bpf_servicekey {
	return bpf_servicekey{addr: as16(t.address), port: t.port, proto: uint16(t.protocol)}
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
}

func (c *client) ping(ip netip.Addr)                { c.icmp.ping(ip) }
func (c *client) nat(v, r netip.Addr) netip.Addr    { return c.netns.nat(c.natmap.get(v, r), v.Is6()) }
func (c *client) ext(id uint16, v6 bool) netip.Addr { return c.netinfo.ext(id, v6) }
func (c *client) era() bool                         { return c.settings.era%2 > 0 }
func (c *client) find(d Destination) backend        { return c.netinfo.find(d.Address) }

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

	c := &client{services: map[threetuple]*service{}, natmap: natmap{}, test: options.Test}

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

	if err = c.maps.init(options.BPF); err != nil {
		return nil, err
	}

	if err = c.netns.init(c.maps.xdp); err != nil {
		return nil, err
	}

	c.settings = bpf_settings{veth: c.netns.nic(), vetha: c.netns.src(), vethb: c.netns.dst(), active: 1}

	if options.Bond {
		c.settings.multi = 0 // if untagged packet recieved then TX it rather than redirect
	} else {
		c.settings.multi = uint8(len(interfaces))
	}

	if err = c.icmp.start(); err != nil {
		return nil, err
	}

	for _, nic := range nics {
		c.maps.xdp.LinkDetach(nic)
	}

	if err = c.maps.initialiseFlows(options.Flows); err != nil {
		return nil, err
	}

	for _, nic := range nics {
		if err = c.maps.xdp.LoadBpfSection("xdp_forward_func", options.Native, nic); err != nil {
			return nil, err
		}
	}

	c.configure()
	c.maps.updateSettings(c.settings)
	go c.background()

	return c, nil
}

func (c *client) background() error {
	reconfig := time.NewTicker(time.Minute)
	sessions := time.NewTicker(time.Second * 5)
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
				//fmt.Println("PING", ip)
				c.ping(ip)
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
				s.readSessions(c.maps, c.era())
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
			//nat := s.client.NAT(addr, rip)
			nat := c.NAT(addr, rip)

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

			c.maps.xdp.SendRawPacket(int(c.settings.veth), c.settings.vethb, c.settings.vetha, packet)
		}
	}
}

func (c *client) configure() {

	c.netinfo.config(c.config.VLANs4, c.config.VLANs6, c.config.Routes)

	for i := uint32(1); i < 4095; i++ {
		vi, v4, v6 := c.netinfo.vlaninfo(uint16(i))
		c.maps.redirect_map4.UpdateElem(uP(&i), uP(&v4), xdp.BPF_ANY)
		c.maps.redirect_map6.UpdateElem(uP(&i), uP(&v6), xdp.BPF_ANY)
		c.maps.vlaninfo.UpdateElem(uP(&i), uP(&vi), xdp.BPF_ANY)
	}

	for _, s := range c.services {
		c.calcService(s)
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

		fmt.Println("CLEAN", k, *service)
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

	c.debug("Clean-up took", time.Now().Sub(mark))
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

	svc := &service{dests: map[netip.Addr]Destination{}, service: s}

	err, add, _ := svc.set(s, ds...)

	if err != nil {
		return err
	}

	for _, d := range add {
		c.ping(d)
		c.maps.createCounters(s.vrpp(d))
		c.natmap.add(s.Address, d)
	}

	if len(add) != 0 {
		c.natmap.index()
	}

	c.services[s.key()] = svc

	c.calcService(svc)

	return nil
}

func (c *client) debug(info ...any) {
	if c.test {
		log.Println(info...)
	}
}

func (c *client) calcService(s *service) {

	debug := func(info ...any) {
		c.debug(info...)
	}

	natfn := func(v, r netip.Addr) netip.Addr {
		return c.netns.nat(c.natmap.get(v, r), v.Is6())
	}

	fwd, nat := s.recalc(debug, &(c.netinfo), natfn)

	c.maps.setService(s.key(), fwd)

	for addr, vip_rip := range nat {
		c.maps.nat(addr, vip_rip)
	}
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

	c.calcService(service)

	return nil
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
	fmt.Println("REMOVED", service.key())
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

	c.ping(d.Address)
	c.maps.createCounters(service.vrpp(d.Address))
	c.natmap.add(service.service.Address, d.Address)
	c.natmap.index()

	c.calcService(service)

	return nil
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

	c.calcService(service)

	return nil
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

	//service.recalc()
	c.calcService(service)
	c.clean()

	return nil
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

	err, add, del := service.set(s, ds...)

	if err != nil {
		return err
	}

	for _, d := range add {
		c.ping(d)
		c.maps.createCounters(service.vrpp(d))
		c.natmap.add(service.service.Address, d)
	}

	if len(add) != 0 {
		c.natmap.index()
	}

	for _, d := range del {
		c.maps.removeCounters(s.vrpp(d))
	}

	if len(del) != 0 {
		c.clean()
	}

	//service.recalc()
	c.calcService(service)

	return nil
}

// Given the virtual IP address of a service and the address of a real
// server this will return the NAT address that can be used to query
// the VIP address on the backend.
func (c *client) NAT(vip netip.Addr, rip netip.Addr) netip.Addr {
	return c.nat(vip, rip)
}

func (c *client) ReadFlow() []byte {
	var entry [ft_size + flow_size]byte

try:
	if c.maps.flow_queue.LookupAndDeleteElem(nil, uP(&entry)) != 0 {
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
	return VIP{Address: a, Metrics: c.maps.virtualMetrics(as16(a), t).metrics()}
}

func (c *client) VIP(a netip.Addr) VIP {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.vip(a)
}

func (c *client) VIPs() (r []VIP) {
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
