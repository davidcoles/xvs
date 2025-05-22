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
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"github.com/davidcoles/xvs/bpf"
	"github.com/davidcoles/xvs/xdp"
)

const xdpBPF_ANY = xdp.BPF_ANY

func ktime() uint64 { return xdp.KtimeGet() * uint64(time.Second) }

//go:embed bpf/layer3.o.gz
var layer3_gz []byte

// startup options:
// bpf file
// max flows
// native
// interfaces
// vlans
// routing

func layer3_o() ([]byte, error) {
	z, err := gzip.NewReader(bytes.NewReader(layer3_gz))
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(z)
}

const (
	NONE TunnelType = bpf.T_NONE
	IPIP TunnelType = bpf.T_IPIP
	GRE  TunnelType = bpf.T_GRE
	FOU  TunnelType = bpf.T_FOU
	GUE  TunnelType = bpf.T_GUE
)

const F_NOT_LOCAL = 0x80

type addr16 [16]byte
type addr4 [4]byte

type threetuple struct {
	address  netip.Addr
	port     uint16
	protocol uint8
}

func as16(a netip.Addr) (r addr16) {
	if a.Is6() {
		return a.As16()
	}

	if a.Is4() {
		ip := a.As4()
		copy(r[12:], ip[:])
	}

	return
}

func as4(a netip.Addr) (r addr4) {
	if a.Is4() {
		return a.As4()
	}

	return
}

type layer3 struct {
	config   Config
	mutex    sync.Mutex
	services map[threetuple]*service3
	settings bpf_settings
	natmap   natmap6
	netinfo  *netinfo
	netns    *newns
	maps     maps

	killswitch bool
}

type maps struct {
	xdp            *xdp.XDP
	nat_to_vip_rip xdp.Map
	redirect_map4  xdp.Map
	redirect_map6  xdp.Map
	flow_queue     xdp.Map
	icmp_queue     xdp.Map
	services       xdp.Map
	vlaninfo       xdp.Map
	settings       xdp.Map
	sessions       xdp.Map
	globals        xdp.Map
	shared         xdp.Map
	stats          xdp.Map
	vips           xdp.Map
}

func (l *layer3) nat(v, r netip.Addr) netip.Addr { return l.netns.addr(l.natmap.get(v, r), v.Is6()) }
func (l *layer3) era() bool                      { return l.settings.era%2 > 0 }

func (l *layer3) counters(vrpp bpf_vrpp) (c bpf_counter) {
	all := make([]bpf_counter, xdp.BpfNumPossibleCpus())

	l.maps.stats.LookupElem(uP(&vrpp), uP(&(all[0])))

	for _, v := range all {
		c.add(v)
	}

	return c
}

func (l *layer3) globals() (c bpf_global) {
	var ZERO uint32 = 0
	all := make([]bpf_global_, xdp.BpfNumPossibleCpus()+1)

	l.maps.globals.LookupElem(uP(&ZERO), uP(&(all[0])))

	var b bpf_global_

	for _, v := range all {
		b.add(v)
	}

	c = *((*bpf_global)(uP(&b)))

	return c
}

func (l *layer3) vipsc() (c []bpf_global) {
	var key, next, nul addr16
	for r := 0; r == 0; key = next {
		r = l.maps.vips.GetNextKey(uP(&key), uP(&next))
		if key != nul {
			c = append(c, l.vipsc2(key))
		}
	}

	return
}

func (l *layer3) vipsc2(a16 addr16) (c bpf_global) {
	all := make([]bpf_global_, xdp.BpfNumPossibleCpus()+1)

	l.maps.vips.LookupElem(uP(&a16), uP(&(all[0])))

	var b bpf_global_

	for _, v := range all {
		b.add(v)
	}

	c = *((*bpf_global)(uP(&b)))

	return
}

func (l *layer3) createCounters(vrpp bpf_vrpp) {
	counters := make([]bpf_counter, xdp.BpfNumPossibleCpus())
	l.maps.stats.UpdateElem(uP(&vrpp), uP(&counters[0]), xdp.BPF_NOEXIST)

	sessions := make([]int64, xdp.BpfNumPossibleCpus())
	//fmt.Println("ADD", vrpp)
	l.maps.sessions.UpdateElem(uP(&vrpp), uP(&sessions[0]), xdp.BPF_NOEXIST)
	vrpp.protocol |= 0xff00
	//fmt.Println("ADD", vrpp)
	l.maps.sessions.UpdateElem(uP(&vrpp), uP(&sessions[0]), xdp.BPF_NOEXIST)
}

func (l *layer3) removeCounters(vrpp bpf_vrpp) {
	l.maps.stats.DeleteElem(uP(&vrpp))
	//fmt.Println("DEL", vrpp)
	l.maps.sessions.DeleteElem(uP(&vrpp))
	vrpp.protocol |= 0xff00
	//fmt.Println("DEL", vrpp)
	l.maps.sessions.DeleteElem(uP(&vrpp))
}

func (l *layer3) readAndClearSession(vrpp bpf_vrpp) (total uint64) {
	all := make([]int64, xdp.BpfNumPossibleCpus())

	if !l.era() {
		vrpp.protocol |= 0xff00
	}

	l.maps.sessions.LookupElem(uP(&vrpp), uP(&all[0]))

	for i, v := range all {
		if v > 0 {
			total += uint64(v)
		}
		all[i] = 0
	}

	l.maps.sessions.UpdateElem(uP(&vrpp), uP(&all[0]), xdp.BPF_EXIST)

	return
}

// empty vlanid in tunnel/ni indicates error
func (l *layer3) tunnel(d Destination) (bpf_tunnel, ninfo) {
	ni, err := l.netinfo.info(d.Address)

	if err != nil || ni.vlanid == 0 {
		//log.Fatal("FWD ERROR", err)
		return bpf_tunnel{}, ninfo{}
	}

	if d.TunnelType == NONE && ni.l3 {
		log.Fatal("LOOP ERROR", ni)
		return bpf_tunnel{}, ninfo{}
	}

	flags := uint8(d.TunnelFlags & 0x7f)

	if ni.l3 {
		flags |= F_NOT_LOCAL
	}

	return bpf_tunnel{
		daddr:    as16(ni.daddr),
		saddr:    as16(ni.saddr),
		dport:    d.TunnelPort,
		sport:    0,
		vlanid:   ni.vlanid,
		method:   d.TunnelType,
		flags:    flags,
		h_dest:   ni.h_dest,
		h_source: ni.h_source,
	}, ni
}

func (l *layer3) updateSettings() {
	var ZERO uint32 = 0

	all := make([]bpf_settings, xdp.BpfNumPossibleCpus())
	for i, _ := range all {
		all[i] = l.settings
	}

	l.maps.settings.UpdateElem(uP(&ZERO), uP(&all[0]), xdp.BPF_ANY)
}

func (l *layer3) readSettings() uint64 {
	var ZERO uint32 = 0
	var packets uint64
	var latency uint64

	all := make([]bpf_settings, xdp.BpfNumPossibleCpus())
	l.maps.settings.LookupElem(uP(&ZERO), uP(&all[0]))

	for _, s := range all {
		packets += s.packets
		latency += s.latency
	}

	if packets > 0 {
		return latency / packets
	}

	return 0
}

func newClient(interfaces ...string) (*layer3, error) {
	return newClientWithOptions(Options{}, interfaces...)
}

func newClientWithOptions(options Options, interfaces ...string) (_ *layer3, err error) {

	if len(options.BPF) == 0 {

		options.BPF, err = layer3_o()

		if err != nil {
			return nil, err
		}
	}

	x, err := xdp.LoadBpfFile(options.BPF)

	if err != nil {
		return nil, err
	}

	var m maps

	err = m.init(x)

	if err != nil {
		return nil, err
	}

	ns, err := nat3(x, "xdp_vetha_func", "xdp_vethb_func") // checks

	if err != nil {
		return nil, err
	}

	multi := uint8(len(interfaces))

	var untagged_bond bool

	if untagged_bond && multi == 1 {
		multi = 0
	}

	settings := bpf_settings{
		veth:   uint32(ns.a.idx),
		vetha:  ns.a.mac,
		vethb:  ns.b.mac,
		multi:  multi,
		active: 1,
	}

	config := &Config{VLANs4: options.VLANs4, VLANs6: options.VLANs6}

	l3 := &layer3{
		config:     config.copy(),
		services:   map[threetuple]*service3{},
		settings:   settings,
		natmap:     natmap6{},
		netinfo:    &netinfo{},
		netns:      ns,
		maps:       m,
		killswitch: options.KillSwitch,
	}

	err = l3.initialiseFlows(x, options.Flows)

	if err != nil {
		return nil, err
	}

	l3.updateSettings()
	l3.reconfig()

	var nics []uint32

	for _, ifname := range interfaces {

		iface, err := net.InterfaceByName(ifname)

		if err != nil {
			return nil, err
		}

		nic := uint32(iface.Index)

		if err != nil {
			return nil, err
		}

		x.LinkDetach(nic)

		nics = append(nics, nic)
	}

	for _, nic := range nics {
		if err = x.LoadBpfSection("xdp_fwd_func", options.Native, nic); err != nil {
			return nil, err
		}
	}

	go l3.background()

	return l3, nil
}

const ft_size uint32 = 36
const flow_size uint32 = 80

func (l *layer3) initialiseFlows(x *xdp.XDP, max uint32) error {

	flows_tcp, err := x.FindMap("flows_tcp", 4, 4)

	if err != nil {
		return err
	}

	if max == 0 {
		// default max entries to be the same as the shared map
		max_entries := l.maps.shared.MaxEntries()

		if max_entries < 1 {
			return fmt.Errorf("Error looking up size of the flow state map")
		}

		max = uint32(max_entries)
	}

	max_cpu := flows_tcp.MaxEntries()

	if max_cpu < 1 {
		return fmt.Errorf("Error looking up size of the CPU flow state map")
	}

	num_cpu := xdp.BpfNumPossibleCpus()

	if num_cpu > max_cpu {
		return fmt.Errorf("Number of CPUs is greater than the number compiled in to the ELF object")
	}

	for cpu := 0; cpu < num_cpu; cpu++ {
		name := fmt.Sprintf("flows_tcp_inner_%d", cpu)
		if r := flows_tcp.CreateLruHash(uint32(cpu), name, ft_size, flow_size, max); r != 0 {
			return fmt.Errorf("Unable to create flow state map for CPU %d: %d", cpu, r)
		}
	}

	return nil
}

func (l *layer3) background() error {
	reconfig := time.NewTicker(time.Minute)
	sessions := time.NewTicker(time.Second * 5)
	icmp := time.NewTicker(time.Millisecond * 100) // 10Hz

	defer reconfig.Stop()
	defer sessions.Stop()

	for {
		select {
		case <-sessions.C:
			l.mutex.Lock()

			//fmt.Println("LATENCY", l.readSettings())

			l.settings.era++
			if !l.killswitch {
				l.updateSettings() // reset the watchdog, but not if the killswitch is set
			}
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

func (l *layer3) icmpQueue() {

	const IPv4 = 0
	const IPv6 = 1

	for n := 0; n < 100; n++ {
		var buff [2048]byte
		if l.maps.icmp_queue.LookupAndDeleteElem(nil, uP(&buff[0])) != 0 {
			return
		}

		meta := *(*uint16)(uP(&buff[0]))
		port := *(*uint16)(uP(&buff[2]))

		length := meta >> 5
		family := meta >> 4 & 0x01
		proto4 := meta >> 3 & 0x01
		reason := meta & 0x07

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

		fmt.Println(length, family, proto4, reason, addr, port)

		skey := threetuple{address: addr, port: port, protocol: TCP}
		//send := func(packet []byte) {
		//	//fmt.Println(int(l.settings.veth), l.settings.vethb, l.settings.vetha, packet)
		//	l.maps.xdp.SendRawPacket(int(l.settings.veth), l.settings.vethb, l.settings.vetha, packet)
		//}

		if s, ok := l.services[skey]; ok {
			//s.repeat(packet, send)
			s.repeat(packet, func(p []byte) { l.raw(p) })
		}
	}
}

func (l *layer3) raw(packet []byte) {
	l.maps.xdp.SendRawPacket(int(l.settings.veth), l.settings.vethb, l.settings.vetha, packet)
}

// func (l *layer3) vlansx(vlans map[uint16][2]netip.Prefix) error {
func (l *layer3) vlans(vlan4, vlan6 map[uint16]netip.Prefix) error {

	for _, v := range vlan4 {
		if !v.Addr().Is4() {
			return fmt.Errorf("IPv4 VLAN entry is not a v4 prefix: %s", v.String())
		}
	}

	for _, v := range vlan6 {
		if !v.Addr().Is6() {
			return fmt.Errorf("IPv6 VLAN entry is not a v6 prefix: %s", v.String())
		}
	}

	route := map[netip.Prefix]uint16{}

	err := l.netinfo.config(vlan4, vlan6, route)

	if err != nil {
		return err
	}

	for i := uint32(1); i < 4095; i++ {
		vi, v4, v6 := l.netinfo.vlaninfo(i)
		l.maps.redirect_map4.UpdateElem(uP(&i), uP(&v4), xdp.BPF_ANY)
		l.maps.redirect_map6.UpdateElem(uP(&i), uP(&v6), xdp.BPF_ANY)
		l.maps.vlaninfo.UpdateElem(uP(&i), uP(&vi), xdp.BPF_ANY)
	}

	return nil
}

func (l *layer3) reconfig() {

	l.vlans(l.config.VLANs4, l.config.VLANs6)

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

	now := time.Now()

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

	// update natmap
	l.natmap.clean(nmap)

	for k, v := range l.natmap.all() {
		nat := l.netns.addr(v, k[0].Is6()) // k[0] is the vip
		nats[nat] = true
	}

	clean_map(l.maps.vips, vips)
	clean_map(l.maps.nat_to_vip_rip, nats)
	clean_map2(l.maps.stats, vrpp)
	clean_map2(l.maps.sessions, vrpp)

	log.Println("Clean-up took", time.Now().Sub(now))
}

func (m *maps) init(x *xdp.XDP) (err error) {

	m.xdp = x

	m.redirect_map4, err = x.FindMap("redirect_map4", 4, 4)

	if err != nil {
		return err
	}

	m.redirect_map6, err = x.FindMap("redirect_map6", 4, 4)

	if err != nil {
		return err
	}

	m.services, err = x.FindMap("services", int(unsafe.Sizeof(bpf_servicekey{})), int(unsafe.Sizeof(bpf_service{})))

	if err != nil {
		return err
	}

	m.nat_to_vip_rip, err = x.FindMap("nat_to_vip_rip", 16, int(unsafe.Sizeof(bpf_vip_rip{})))

	if err != nil {
		return err
	}

	m.vlaninfo, err = x.FindMap("vlaninfo", 4, int(unsafe.Sizeof(bpf_vlaninfo{})))

	if err != nil {
		return err
	}

	m.settings, err = x.FindMap("settings", 4, int(unsafe.Sizeof(bpf_settings{})))

	if err != nil {
		return err
	}

	m.stats, err = x.FindMap("stats", int(unsafe.Sizeof(bpf_vrpp{})), int(unsafe.Sizeof(bpf_counter{})))

	if err != nil {
		return err
	}

	m.sessions, err = x.FindMap("vrpp_concurrent", int(unsafe.Sizeof(bpf_vrpp{})), 8)

	if err != nil {
		return err
	}

	m.flow_queue, err = x.FindMap("flow_queue", 0, int(ft_size+flow_size))

	if err != nil {
		return err
	}

	m.icmp_queue, err = x.FindMap("icmp_queue", 0, int(2048))

	if err != nil {
		return err
	}

	m.shared, err = x.FindMap("shared", int(ft_size), int(flow_size))

	if err != nil {
		return err
	}

	m.globals, err = x.FindMap("globals", 4, int(unsafe.Sizeof(bpf_global{})))

	if err != nil {
		return err
	}

	//m.vips, err = x.FindMap("vips", 16, 4)
	m.vips, err = x.FindMap("vips", 16, int(unsafe.Sizeof(bpf_global{})))

	if err != nil {
		return err
	}

	return nil
}
