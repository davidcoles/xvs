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
}

func (l *client) ping(ip netip.Addr)                { l.icmp.ping(ip) }
func (l *client) nat(v, r netip.Addr) netip.Addr    { return l.netns.nat(l.natmap.get(v, r), v.Is6()) }
func (l *client) ext(id uint16, v6 bool) netip.Addr { return l.netinfo.ext(id, v6) }
func (l *client) era() bool                         { return l.settings.era%2 > 0 }
func (l *client) find(d Destination) backend        { return l.netinfo.find(d.Address) }

func (l *client) current() (r uint64) {
	for _, s := range l.services {
		r += s.current()
	}
	return
}

func newClient(interfaces ...string) (*client, error) {
	return newClientWithOptions(Options{}, interfaces...)
}

func newClientWithOptions(options Options, interfaces ...string) (_ *client, err error) {

	c := &client{services: map[threetuple]*service{}, natmap: natmap{}}

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

	if err = c.netns.init(c.maps.xdp, "xdp_vetha_func", "xdp_vethb_func"); err != nil {
		return nil, err
	}

	c.settings = bpf_settings{veth: c.netns.veth(), vetha: c.netns.vetha(), vethb: c.netns.vethb(), active: 1}

	if options.Bond {
		c.settings.multi = 0 // if untagged packet recieved then TX it rather redirect
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
		if err = c.maps.xdp.LoadBpfSection("xdp_fwd_func", options.Native, nic); err != nil {
			return nil, err
		}
	}

	c.configure()
	c.maps.updateSettings(c.settings)
	go c.background()

	return c, nil
}

func (l *client) background() error {
	reconfig := time.NewTicker(time.Minute)
	sessions := time.NewTicker(time.Second * 5)
	icmp := time.NewTicker(time.Millisecond * 100)
	ping := time.NewTicker(time.Minute)

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
			l.mutex.Lock()
			for _, s := range l.services {
				for _, d := range s.local() {
					hosts[d] = true
				}
			}
			for _, r := range l.netinfo.routers() {
				hosts[r] = true
			}
			l.mutex.Unlock()

			for ip, _ := range hosts {
				//fmt.Println("PING", ip)
				l.ping(ip)
			}

		case <-sessions.C:

			latencies = append(latencies, l.maps.readLatency())

			for len(latencies) > 5 {
				latencies = latencies[1:]
			}

			if len(latencies) > 0 {
				var total uint64
				for _, l := range latencies {
					total += l
				}
				l.latency = total / uint64(len(latencies))
			}

			l.mutex.Lock()
			l.settings.era++
			l.maps.updateSettings(l.settings) // reset the watchdog
			for _, s := range l.services {
				s.readSessions()
			}
			l.mutex.Unlock()

		case <-reconfig.C:
			// re-scan network interfaces and match to VLANs
			// recalc all services as parameters may have changed
			l.mutex.Lock()
			l.configure()
			l.mutex.Unlock()

		case <-icmp.C:
			l.mutex.Lock()
			l.icmpQueue()
			l.mutex.Unlock()
		}
	}
}

func (l *client) icmpQueue() {

	const IPv4 = 0
	const IPv6 = 1

	for n := 0; n < 100; n++ {
		var buff [buffer_length]byte
		if l.maps.icmp_queue.LookupAndDeleteElem(nil, uP(&buff[0])) != 0 {
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
		reason := meta & 0x07

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
		if s, ok := l.services[skey]; ok {
			s.repeat(packet, uint8(reason), func(p []byte) {
				l.maps.xdp.SendRawPacket(int(l.settings.veth), l.settings.vethb, l.settings.vetha, p)
			})
		}
	}
}

func (l *client) configure() {

	l.netinfo.config(l.config.VLANs4, l.config.VLANs6, l.config.Routes)

	for i := uint32(1); i < 4095; i++ {
		vi, v4, v6 := l.netinfo.vlaninfo(uint16(i))
		l.maps.redirect_map4.UpdateElem(uP(&i), uP(&v4), xdp.BPF_ANY)
		l.maps.redirect_map6.UpdateElem(uP(&i), uP(&v6), xdp.BPF_ANY)
		l.maps.vlaninfo.UpdateElem(uP(&i), uP(&vi), xdp.BPF_ANY)
	}

	for _, s := range l.services {
		s.recalc()
	}
}

func (l *client) clean() {
	mark := time.Now()
	vips := map[netip.Addr]bool{}
	nats := map[netip.Addr]bool{}
	nmap := map[[2]netip.Addr]bool{}
	vrpp := map[bpf_vrpp]bool{}

	for k, v := range l.services {
		vips[k.address] = true
		for r, _ := range v.dests {
			nmap[[2]netip.Addr{k.address, r}] = true
			vv := v.vrpp(r)
			vrpp[vv] = true
			vv.protocol |= 0xff00
			vrpp[vv] = true
		}
	}

	l.natmap.clean(nmap)

	for k, v := range l.natmap.all() {
		nat := l.netns.nat(v, k[0].Is6()) // k[0] is the vip
		nats[nat] = true
	}

	l.maps.clean(vips, vrpp, nats)

	log.Println("Clean-up took", time.Now().Sub(mark))
}

func (l *client) Info() (Info, error) {
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
		IPv4:    l.netns.ipv4(),
		IPv6:    l.netns.ipv6(),
	}, nil
}

type Info struct {
	Stats   Stats
	Latency uint64
	Metrics map[string]uint64
	IPv4    netip.Addr
	IPv6    netip.Addr
}

func (l *client) Config() (Config, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	return l.config, nil
}

func (l *client) SetConfig(c Config) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	config, err := c.copy()

	if err != nil {
		return err
	}

	l.config = config

	l.configure()

	return nil
}

func (l *client) Services() (r []ServiceExtended, e error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	for _, v := range l.services {
		r = append(r, ServiceExtended{Service: v.service})
	}

	return
}

func (l *client) Service(s Service) (r ServiceExtended, e error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return r, fmt.Errorf("Service does not exist")
	}

	return service.extend(), nil
}

func (l *client) CreateService(s Service) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if _, exists := l.services[s.key()]; exists {
		return fmt.Errorf("Service exists")
	}

	return l.createService(s)
}

func (l *client) UpdateService(s Service) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	return service.update(s)
}

func (l *client) RemoveService(s Service) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	return service.remove()
}

func (l *client) Destinations(s Service) (r []DestinationExtended, e error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return nil, fmt.Errorf("Service does not exist")
	}

	return service.destinations()
}

func (l *client) CreateDestination(s Service, d Destination) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	return service.createDestination(d)
}

func (l *client) UpdateDestination(s Service, d Destination) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	service, exists := l.services[s.key()]

	if !exists {
		return fmt.Errorf("Service does not exist")
	}

	return service.updateDestination(d)
}

func (l *client) RemoveDestination(s Service, d Destination) error {
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
func (l *client) SetService(s Service, ds ...Destination) error {
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
func (l *client) NAT(vip netip.Addr, rip netip.Addr) netip.Addr {
	return l.nat(vip, rip)
}

// Retrieves an opaque flow record from a ueue written to by the
// kernel. If no flow records are available then a zero length slice
// is returned. This can be used to share flow state with peers, with
// the flow record stored using the WriteFlow() function. Stale
// records are skipped.
func (l *client) ReadFlow() []byte {
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
func (l *client) WriteFlow(f []byte) {
	l.maps.writeFlow(f)
}

func (c *client) VIP(a netip.Addr) VIP {
	return VIP{Address: a, Metrics: c.maps.virtualMetrics(as16(a)).metrics()} // lock not required
}

func (c *client) VIPs() (r []VIP) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	vips := map[netip.Addr]bool{}

	for _, s := range c.services {
		vips[s.service.Address] = true
	}

	for v, _ := range vips {
		r = append(r, VIP{Address: v, Metrics: c.maps.virtualMetrics(as16(v)).metrics()})
	}

	return
}
