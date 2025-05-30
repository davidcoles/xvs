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

type layer3 struct {
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

func (l *layer3) ping(ip netip.Addr)                { l.icmp.ping(ip) }
func (l *layer3) nat(v, r netip.Addr) netip.Addr    { return l.netns.nat(l.natmap.get(v, r), v.Is6()) }
func (l *layer3) ext(id uint16, v6 bool) netip.Addr { return l.netinfo.ext(id, v6) }
func (l *layer3) era() bool                         { return l.settings.era%2 > 0 }

func (l *layer3) tunnel(d Destination) bpf_tunnel {
	return l.netinfo.find(d.Address).bpf_tunnel(d.TunnelType, d.TunnelFlags, d.TunnelPort)
}

func (l *layer3) current() (r uint64) {
	for _, s := range l.services {
		r += s.current()
	}
	return
}

func newClient(interfaces ...string) (*layer3, error) {
	return newClientWithOptions(Options{}, interfaces...)
}

func newClientWithOptions(options Options, interfaces ...string) (_ *layer3, err error) {

	l3 := &layer3{services: map[threetuple]*service{}, natmap: natmap{}}

	if l3.config, err = options.config().copy(); err != nil {
		return nil, err
	}

	if err = l3.maps.init(options.BPF); err != nil {
		return nil, err
	}

	if err = l3.netns.init(l3.maps.xdp, "xdp_vetha_func", "xdp_vethb_func"); err != nil {
		return nil, err
	}

	l3.settings = bpf_settings{veth: l3.netns.veth(), vetha: l3.netns.vetha(), vethb: l3.netns.vethb(), active: 1}

	if options.Bond {
		l3.settings.multi = 0 // if untagged packet recieved then TX it rather redirect
	} else {
		l3.settings.multi = uint8(len(interfaces))
	}

	if err = l3.icmp.start(); err != nil {
		return nil, err
	}

	if err = l3.maps.initialiseFlows(options.Flows); err != nil {
		return nil, err
	}

	var nics []uint32

	for _, ifname := range interfaces {
		if iface, err := net.InterfaceByName(ifname); err != nil {
			return nil, err
		} else {
			nics = append(nics, uint32(iface.Index))
		}
	}

	for _, nic := range nics {
		l3.maps.xdp.LinkDetach(nic)
		if err = l3.maps.xdp.LoadBpfSection("xdp_fwd_func", options.Native, nic); err != nil {
			return nil, err
		}
	}

	l3.reconfig()
	l3.maps.updateSettings(l3.settings)
	go l3.background()

	return l3, nil
}

func (l *layer3) background() error {
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
			l.reconfig()
			l.mutex.Unlock()

		case <-icmp.C:
			l.mutex.Lock()
			l.icmpQueue()
			l.mutex.Unlock()
		}
	}
}

func (l *layer3) icmpQueue() {

	const IPv4 = 0
	const IPv6 = 1

	for n := 0; n < 100; n++ {
		var buff [2048]byte
		if l.maps.icmp_queue.LookupAndDeleteElem(nil, uP(&buff[0])) != 0 {
			return
		}

		// 16 bits of metadata (inc packet length)
		// 16 bits of port (host byte order)
		// ip source address (4 or 16 bytes)
		// original packet

		// metadata:
		// 11 bits (2047 bytes > MTU of 1500) orig (IP) packet length
		// 1 bit source; 0 - IPv4, 1 - IPv6
		// 1 bit protocol; 0 - TCP, 1 - UDP
		// 3 bits reason codes
		//   000 - fragmentation needed

		meta := *(*uint16)(uP(&buff[0]))
		port := *(*uint16)(uP(&buff[2]))

		length := meta >> 5
		family := meta >> 4 & 0x01
		//proto4 := meta >> 3 & 0x01
		//reason := meta & 0x07

		var addr netip.Addr
		var packet []byte
		if family == IPv4 {
			var four [4]byte
			copy(four[:], buff[4:])
			addr = netip.AddrFrom4(four)
			packet = buff[4+4 : 4+4+length]
		} else {
			var sixteen [16]byte
			copy(sixteen[:], buff[4:])
			addr = netip.AddrFrom16(sixteen)
			packet = buff[4+16 : 4+16+length]
		}

		//fmt.Println(length, family, proto4, reason, addr, port)

		skey := threetuple{address: addr, port: port, protocol: TCP}
		if s, ok := l.services[skey]; ok {
			s.repeat(packet, func(p []byte) { l.raw(p) })
		}
	}
}

func (l *layer3) raw(packet []byte) {
	l.maps.xdp.SendRawPacket(int(l.settings.veth), l.settings.vethb, l.settings.vetha, packet)
}

func (l *layer3) vlans(vlan4, vlan6 map[uint16]netip.Prefix, route map[netip.Prefix]uint16) {

	l.netinfo.config(vlan4, vlan6, route)

	for i := uint32(1); i < 4095; i++ {
		vi, v4, v6 := l.netinfo.vlaninfo(uint16(i))
		l.maps.redirect_map4.UpdateElem(uP(&i), uP(&v4), xdp.BPF_ANY)
		l.maps.redirect_map6.UpdateElem(uP(&i), uP(&v6), xdp.BPF_ANY)
		l.maps.vlaninfo.UpdateElem(uP(&i), uP(&vi), xdp.BPF_ANY)
	}
}

func (l *layer3) reconfig() {

	l.vlans(l.config.VLANs4, l.config.VLANs6, l.config.Routes)

	for _, s := range l.services {
		s.recalc()
	}
}

func (l *layer3) clean() {

	clean_map := func(m xdp.Map, a map[netip.Addr]bool) {
		b := map[addr16]bool{}

		for k, _ := range a {
			b[as16(k)] = true
		}

		var key, next, nul addr16
		for r := 0; r == 0; key = next {
			r = m.GetNextKey(uP(&key), uP(&next))
			if _, exists := b[key]; !exists && key != nul {
				m.DeleteElem(uP(&key))
			}
		}
	}

	// TODO - reveal any clean-up bugs
	clean_map2 := func(m xdp.Map, a map[bpf_vrpp]bool) {
		var key, next, nul bpf_vrpp
		for r := 0; r == 0; key = next {
			r = m.GetNextKey(uP(&key), uP(&next))
			if _, exists := a[key]; !exists && key != nul {
				m.DeleteElem(uP(&key))
				log.Fatal("clean_map2", key)
			}
		}
	}

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

	clean_map(l.maps.vip_metrics, vips)
	clean_map(l.maps.nat_to_vip_rip, nats)
	clean_map2(l.maps.stats, vrpp)
	clean_map2(l.maps.sessions, vrpp)

	log.Println("Clean-up took", time.Now().Sub(mark))
}
