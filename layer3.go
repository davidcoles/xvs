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
	"runtime"
	"sort"
	"sync"
	"time"
	"unsafe"

	"github.com/davidcoles/xvs/bpf"
	"github.com/davidcoles/xvs/maglev"
	"github.com/davidcoles/xvs/xdp"
)

// TODO:
// ingress interface/vlan -> interface IPs, for correct ICMP "too big" responses?
// process intermediate system ICMP too big messages and pass to backends
// health probe ICMP?
// stats
// latency
// handle udp/icmp
// Ping tracking in NAT
// TOO BIG notifications to NAT source in NAT
// flow tables

//go:embed bpf/layer3.o.gz
var layer3_gz []byte

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

var ZERO uint32 = 0

const F_NOT_LOCAL = 0x80

type bpf_vrpp2 struct {
	vaddr    addr16 // virtual service IP
	raddr    addr16 // real server IP
	vport    uint16 // virtual service port
	protocol uint16
}

type bpf_counters2 struct {
	packets uint64
	octets  uint64
	flows   uint64
	errors  uint64
}

func (c *bpf_counters2) add(x bpf_counters2) {
	c.packets += x.packets
	c.octets += x.octets
	c.flows += x.flows
	c.errors += x.errors
}

func (c bpf_counters2) stats() (s Stats3) {
	s.Packets = c.packets
	s.Octets = c.octets
	s.Flows = c.flows
	s.Errors = c.errors
	return
}

type bpf_settings struct {
	ticker uint64 // periodically reset
	vetha  mac
	vethb  mac
	multi  uint8
	era    uint8
	pad    [2]uint8
}

type bpf_destinfo struct {
	daddr    addr16
	saddr    addr16
	dport    uint16
	sport    uint16
	vlanid   uint16
	method   TunnelType // uint8
	flags    uint8
	h_dest   mac
	h_source mac
	pad      [12]byte // pad to 64 bytes
}

type bpf_vlaninfo struct {
	ip4 addr4
	gw4 addr4
	ip6 addr16
	gw6 addr16
	hw4 mac
	hw6 mac
	gh4 mac
	gh6 mac
}

type bpf_destinations struct {
	destinfo [256]bpf_destinfo
	hash     [8192]uint8
}

type bpf_servicekey struct {
	addr  addr16
	port  uint16
	proto uint16
}

type bpf_netns struct {
	i uint32
	a [6]byte
	b [6]byte
}

type bpf_vip_rip struct {
	destinfo bpf_destinfo
	vip      addr16
	ext      addr16
}

type addr16 [16]byte
type addr4 [4]byte

type threetuple struct {
	address  netip.Addr
	port     uint16
	protocol uint8
}

type service3 struct {
	dests   map[netip.Addr]Destination3
	service Service3
	layer3  *layer3
	sess    map[netip.Addr]uint64
}

type layer3 struct {
	config   Config
	services map[threetuple]*service3
	mutex    sync.Mutex
	natmap   natmap6
	netinfo  *netinfo
	netns    *newns
	setting  bpf_settings

	nat_to_vip_rip xdp.Map
	redirect_map4  xdp.Map
	redirect_map6  xdp.Map
	destinations   xdp.Map
	vlaninfo       xdp.Map
	settings       xdp.Map
	sessions       xdp.Map
	stats          xdp.Map
	vips           xdp.Map
}

func (d *Destination3) is4() bool {
	return d.Address.Is4()
}

func (d *Destination3) as16() (r addr16) {
	if d.is4() {
		ip := d.Address.As4()
		copy(r[12:], ip[:])
	} else {
		r = d.Address.As16()
	}
	return
}

type neighbor struct {
	dev string
	mac mac
}

func (s *service3) set(service Service3, more bool, ds ...Destination3) error {

	m := make(map[netip.Addr]Destination3, len(ds))

	for _, d := range ds {
		if _, exists := s.dests[d.Address]; !exists {
			if err := d.check(); err != nil {
				return err
			}

			log.Println("ADDING", d)
			s.layer3.natmap.add(s.service.Address, d.Address)
		}

		m[d.Address] = d
	}

	for d, _ := range s.dests {
		if _, exists := m[d]; !exists {
			//s.layer3.removeSessions(s.service, d) // d was deleted
			s.layer3.removeSessions(s.vrpp(d)) // d was deleted
		}
	}

	for _, d := range m {
		s.layer3.natmap.add(s.service.Address, d.Address)
	}

	s.service = service
	s.dests = m
	s.layer3.natmap.index()

	if !more {
		s.layer3.clean()
	}
	s.recalc()

	return nil
}

func (d Destination3) check() error {

	if !d.Address.IsValid() || d.Address.IsUnspecified() || d.Address.IsMulticast() || d.Address.IsLoopback() {
		return fmt.Errorf("Bad destination address: %s", d.Address)
	}

	return nil
}

func (s *service3) createDestination(d Destination3) error {

	if _, exists := s.dests[d.Address]; exists {
		return fmt.Errorf("Destination exists")
	}

	if err := d.check(); err != nil {
		return err
	}

	s.layer3.natmap.add(s.service.Address, d.Address)
	s.layer3.natmap.index()
	s.dests[d.Address] = d
	s.recalc()
	return nil
}

func (l *layer3) createService(s Service3, ds ...Destination3) error {

	if !s.Address.IsValid() || s.Address.IsUnspecified() || s.Address.IsMulticast() || s.Address.IsLoopback() {
		return fmt.Errorf("Bad IP address")
	}

	if s.Port == 0 {
		return fmt.Errorf("Reserved port")
	}

	if s.Protocol != TCP && s.Protocol != UDP {
		return fmt.Errorf("Unsupported protocol")
	}

	service := &service3{dests: map[netip.Addr]Destination3{}, service: s, layer3: l}

	err := service.set(s, true, ds...)

	if err != nil {
		return err
	}

	l.services[s.key()] = service

	l.clean()

	return nil
}

func (l *layer3) getStats(vrpp bpf_vrpp2) (c bpf_counters2) {

	all := make([]bpf_counters2, xdp.BpfNumPossibleCpus())

	l.stats.LookupElem(uP(&vrpp), uP(&(all[0])))

	for _, v := range all {
		c.add(v)
	}

	return c
}

func (s *service3) extend() Service3Extended {
	var c bpf_counters2
	for d, _ := range s.dests {
		//c.add(s.layer3.getStats(s.service.Address, d, s.service.Port, uint16(s.service.Protocol)))
		c.add(s.layer3.getStats(s.vrpp(d)))
	}
	return Service3Extended{Service: s.service, Stats: c.stats()}
}

func (s *service3) update(service Service3) error {
	s.service = service
	s.recalc()
	return nil
}

func (s *service3) key() bpf_servicekey {
	return bpf_servicekey{addr: as16(s.service.Address), port: s.service.Port, proto: uint16(s.service.Protocol)}
}

func (s *service3) remove() error {
	key := s.key()

	for d, _ := range s.dests {
		//s.layer3.removeSessions(s.service, d)
		s.layer3.removeSessions(s.vrpp(d))
	}

	s.layer3.destinations.DeleteElem(uP(&key))
	delete(s.layer3.services, s.service.key())
	s.layer3.clean()
	return nil
}

func (s *service3) removeDestination(d Destination3) error {
	if _, exists := s.dests[d.Address]; !exists {
		return fmt.Errorf("Destination does not exist")
	}

	//s.layer3.removeSessions(s.service, d.Address)
	s.layer3.removeSessions(s.vrpp(d.Address))

	delete(s.dests, d.Address)
	s.recalc()
	s.layer3.clean()
	return nil
}

func (s *service3) updateDestination(d Destination3) error {

	if _, exists := s.dests[d.Address]; !exists {
		return fmt.Errorf("Destination does not exist")
	}

	s.dests[d.Address] = d

	s.recalc()

	return nil
}

func (s *service3) destinations() (r []Destination3Extended, e error) {
	for a, d := range s.dests {
		stats := s.layer3.getStats(s.vrpp(a)).stats()
		stats.Current = s.sess[a]
		r = append(r, Destination3Extended{Destination: d, Stats: stats})
	}
	return
}

func (l *layer3) nat(v, r netip.Addr) netip.Addr {
	return l.netns.addr(l.natmap.get(v, r), v.Is6())
}

type real struct {
	weight   uint8
	destinfo bpf_destinfo
	netinfo  ninfo // only used for debug purposes atm
}

func (l *layer3) createSessions(vrpp bpf_vrpp2) {
	vrpp.protocol &= 0xff

	counters := make([]bpf_counters2, xdp.BpfNumPossibleCpus())
	l.stats.UpdateElem(uP(&vrpp), uP(&counters[0]), xdp.BPF_NOEXIST)

	sessions := make([]int64, xdp.BpfNumPossibleCpus())
	log.Println("createSessions", vrpp)
	l.sessions.UpdateElem(uP(&vrpp), uP(&sessions[0]), xdp.BPF_NOEXIST)
	vrpp.protocol |= 0xff00
	l.sessions.UpdateElem(uP(&vrpp), uP(&sessions[0]), xdp.BPF_NOEXIST)
}

func (l *layer3) removeSessions(vrpp bpf_vrpp2) {
	vrpp.protocol &= 0xff
	l.stats.DeleteElem(uP(&vrpp))
	l.sessions.DeleteElem(uP(&vrpp))
	vrpp.protocol |= 0xff00
	l.sessions.DeleteElem(uP(&vrpp))
}

func (l *layer3) read_and_clear(vrpp bpf_vrpp2) (total uint64) {
	all := make([]int64, xdp.BpfNumPossibleCpus())

	vrpp.protocol &= 0xff

	if !(l.setting.era%2 > 0) {
		vrpp.protocol |= 0xff00
	}

	l.sessions.LookupElem(uP(&vrpp), uP(&all[0]))

	for i, v := range all {
		if v > 0 {
			total += uint64(v)
		}
		all[i] = 0
	}

	l.sessions.UpdateElem(uP(&vrpp), uP(&all[0]), xdp.BPF_EXIST)

	return
}

func (s *service3) sessions() {
	svc := s.service
	sess := make(map[netip.Addr]uint64, len(s.dests))
	for d, _ := range s.dests {
		vrpp := bpf_vrpp2{vaddr: as16(svc.Address), raddr: as16(d), vport: svc.Port, protocol: uint16(svc.Protocol)}
		sess[d] = s.layer3.read_and_clear(vrpp)
	}
	s.sess = sess
}

func (s *service3) a16() addr16   { return as16(s.service.Address) }
func (s *service3) port() uint16  { return s.service.Port }
func (s *service3) proto() uint16 { return uint16(s.service.Protocol) }
func (s *service3) vrpp(d netip.Addr) bpf_vrpp2 {
	return bpf_vrpp2{vaddr: s.a16(), raddr: as16(d), vport: s.port(), protocol: s.proto()}
}

func (s *service3) recalc() {

	reals := make(map[netip.Addr]real, len(s.dests))

	for k, d := range s.dests {
		di, ni := destinfo(s.layer3, d)
		reals[k] = real{destinfo: di, netinfo: ni, weight: d.Weight}
	}

	s.forwarding(reals)
	s.nat(reals)

	v16 := as16(s.service.Address)
	s.layer3.vips.UpdateElem(uP(&v16), uP(&ZERO), xdp.BPF_ANY) // value is not used
}

func (s *service3) nat(reals map[netip.Addr]real) {
	vip := s.service.Address

	for k, v := range reals {
		nat := s.layer3.nat(s.service.Address, k)
		n16 := as16(nat)
		ext := s.layer3.netinfo.ext(v.destinfo.vlanid, s.service.Address.Is6())

		vip_rip := bpf_vip_rip{destinfo: v.destinfo, vip: as16(vip), ext: as16(ext)}
		s.layer3.nat_to_vip_rip.UpdateElem(uP(&n16), uP(&vip_rip), xdp.BPF_ANY)

		fmt.Println("NAT", s.service.Address, k, nat, v.netinfo, ext, vip)
	}
}

func (s *service3) forwarding(reals map[netip.Addr]real) {

	addrs := make([]netip.Addr, 0, len(reals))

	for k, v := range reals {
		if v.weight != 0 && v.destinfo.vlanid != 0 {
			addrs = append(addrs, k)
		}
		s.layer3.createSessions(s.vrpp(k))
	}

	var val bpf_destinations
	val.destinfo[0] = bpf_destinfo{flags: uint8(s.service.Flags)}

	var dur time.Duration

	if len(addrs) > 0 {
		// we need the list to be sorted for maglev to be stable
		sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })

		dests := make([]bpf_destinfo, len(addrs))
		nodes := make([][]byte, len(addrs))

		for i, a := range addrs {
			dests[i] = reals[a].destinfo
			nodes[i] = []byte(a.String())
		}

		for i, v := range dests {
			val.destinfo[i+1] = v
		}

		now := time.Now()
		for i, v := range maglev.Maglev8192(nodes) {
			val.hash[i] = uint8(v + 1)
		}
		dur = time.Now().Sub(now)
	}

	fmt.Println("MAG", val.hash[0:32], dur)

	key := s.key()
	s.layer3.destinations.UpdateElem(uP(&key), uP(&val), xdp.BPF_ANY)
}

// empty vlanid in di/ni indicates error
func destinfo(l *layer3, d Destination3) (bpf_destinfo, ninfo) {
	ni, err := l.netinfo.info(d.Address)

	if err != nil || ni.vlanid == 0 {
		log.Fatal("FWD ERROR", err)
		return bpf_destinfo{}, ninfo{}
	}

	if d.TunnelType == NONE && ni.l3 {
		log.Fatal("LOOP ERROR", ni)
		return bpf_destinfo{}, ninfo{}
	}

	flags := uint8(d.TunnelFlags & 0x7f)

	if ni.l3 {
		flags |= F_NOT_LOCAL
		log.Println("NOT_LOCAL", d.Address)
	}

	fmt.Println("FWD", ni)

	return bpf_destinfo{
		daddr:    as16(ni.daddr),
		saddr:    as16(ni.saddr),
		dport:    d.TunnelPort,
		sport:    0,
		vlanid:   ni.vlanid,
		method:   d.TunnelType,
		flags:    flags, // TODO
		h_dest:   ni.h_dest,
		h_source: ni.h_source,
	}, ni
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

func newClient(interfaces ...string) (*layer3, error) {

	ni := &netinfo{}

	var native bool

	bpf_file, err := layer3_o()

	if err != nil {
		return nil, err
	}

	x, err := xdp.LoadBpfFile(bpf_file)

	if err != nil {
		return nil, err
	}

	redirect_map4, err := x.FindMap("redirect_map4", 4, 4)

	if err != nil {
		return nil, err
	}

	redirect_map6, err := x.FindMap("redirect_map6", 4, 4)

	if err != nil {
		return nil, err
	}

	vips, err := x.FindMap("vips", 16, 4)

	if err != nil {
		return nil, err
	}

	destinations, err := x.FindMap("destinations", int(unsafe.Sizeof(bpf_servicekey{})), int(unsafe.Sizeof(bpf_destinations{})))

	if err != nil {
		return nil, err
	}

	nat_to_vip_rip, err := x.FindMap("nat_to_vip_rip", 16, int(unsafe.Sizeof(bpf_vip_rip{})))

	if err != nil {
		return nil, err
	}

	vlaninfo, err := x.FindMap("vlaninfo", 4, int(unsafe.Sizeof(bpf_vlaninfo{})))

	if err != nil {
		return nil, err
	}

	settings, err := x.FindMap("settings", 4, int(unsafe.Sizeof(bpf_settings{})))

	if err != nil {
		return nil, err
	}

	stats, err := x.FindMap("stats", int(unsafe.Sizeof(bpf_vrpp2{})), int(unsafe.Sizeof(bpf_counters2{})))

	if err != nil {
		return nil, err
	}

	sessions, err := x.FindMap("vrpp_concurrent", int(unsafe.Sizeof(bpf_vrpp2{})), 8)

	if err != nil {
		return nil, err
	}

	netns, err := x.FindMap("netns", 4, int(unsafe.Sizeof(bpf_netns{})))

	if err != nil {
		return nil, err
	}

	ns, err := nat3(x, "xdp_vetha", "xdp_vethb") // checks

	if err != nil {
		return nil, err
	}

	multi := uint8(len(interfaces))

	var untagged_bond bool

	if untagged_bond && multi == 1 {
		multi = 0
	}

	setting := bpf_settings{
		vetha: ns.a.mac,
		vethb: ns.b.mac,
		multi: multi,
	}

	//settings.UpdateElem(uP(&ZERO), uP(&setting), xdp.BPF_ANY)

	updateSettings(settings, setting)

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
		if err = x.LoadBpfSection("xdp_fwd_func", native, nic); err != nil {
			return nil, err
		}
	}

	fmt.Println("VETH", ns.a.mac.String(), ns.b.mac.String())

	netns.UpdateElem(uP(&ZERO), uP(&(bpf_netns{i: uint32(ns.a.idx), a: ns.a.mac, b: ns.b.mac})), xdp.BPF_ANY)

	fmt.Println("NumCPU", runtime.NumCPU())

	/**********************************************************************/
	//var flow_size uint32 = 8
	var flow_size uint32 = 72
	var ft_size uint32 = 36

	flows_tcp, err := x.FindMap("flows_tcp", 4, 4)

	if err != nil {
		return nil, err
	}

	reference, err := x.FindMap("reference", 4, int(flow_size))

	if err != nil {
		return nil, err
	}

	// flow_share map has the same size as the inner map, so use this as a reference
	max_entries := reference.MaxEntries()

	if max_entries < 0 {
		return nil, fmt.Errorf("Error looking up size of the flow state map")
	}

	//if c.MaxFlows > 0 {
	//	max_entries = int(c.MaxFlows)
	//	}

	//max_entries := 1000
	max_cpu := flows_tcp.MaxEntries()

	if max_cpu < 0 {
		return nil, fmt.Errorf("Error looking up size of the CPU flow state map")
	}

	num_cpu := uint32(runtime.NumCPU())

	if num_cpu > uint32(max_cpu) {
		return nil, fmt.Errorf("Number of CPUs is greater than the number compiled in to the ELF object")
	}

	for cpu := uint32(0); cpu < num_cpu; cpu++ {
		name := fmt.Sprintf("flows_tcp_inner_%d", cpu)
		if r := flows_tcp.CreateLruHash(cpu, name, ft_size, flow_size, uint32(max_entries)); r != 0 {
			return nil, fmt.Errorf("Unable to create flow state map for CPU %d: %d", cpu, r)
		}
	}
	/**********************************************************************/

	l3 := &layer3{
		config:   Config{},
		services: map[threetuple]*service3{},
		netns:    ns,
		natmap:   natmap6{},
		netinfo:  ni,
		setting:  setting,

		nat_to_vip_rip: nat_to_vip_rip,
		redirect_map4:  redirect_map4,
		redirect_map6:  redirect_map6,
		destinations:   destinations,
		vlaninfo:       vlaninfo,
		settings:       settings,
		sessions:       sessions,
		stats:          stats,
		vips:           vips,
	}

	go l3.background()

	return l3, nil
}

func (l *layer3) background() error {
	ticker := time.NewTicker(time.Minute)
	session := time.NewTicker(time.Second * 5)

	defer ticker.Stop()
	defer session.Stop()

	for {
		select {
		case <-session.C:
			l.setting.era++

			l.mutex.Lock()
			updateSettings(l.settings, l.setting)
			for _, s := range l.services {
				s.sessions()
			}
			l.mutex.Unlock()

		case <-ticker.C:
			// re-scan network interfaces and match to VLANs
			// recalc all services as parameters may have changed
			l.mutex.Lock()
			l.reconfig()
			l.mutex.Unlock()
		}
	}
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
		f := l.netinfo.l2info4[uint16(i)]
		if f.ifindex == 0 {
			f = l.netinfo.l2info6[uint16(i)]
		}
		nic := f.ifindex
		if nic != 0 {
			fmt.Println(">>>>>>", f)
		}
		l.redirect_map4.UpdateElem(uP(&i), uP(&nic), xdp.BPF_ANY)

		f4 := l.netinfo.l2info4[uint16(i)]
		f6 := l.netinfo.l2info6[uint16(i)]

		g4 := l.netinfo.l3info4[uint16(i)]
		g6 := l.netinfo.l3info6[uint16(i)]

		vi := bpf_vlaninfo{
			ip4: as4(f4.ip),
			gw4: as4(g4.ip),
			ip6: as16(f6.ip),
			gw6: as16(g6.ip),
			hw4: f4.hw,
			hw6: f6.hw,
			gh4: g4.hw,
			gh6: g6.hw,
		}

		if nic != 0 {
			fmt.Println("<<<<<<", vi)
		}

		nic = f6.ifindex
		l.redirect_map6.UpdateElem(uP(&i), uP(&nic), xdp.BPF_ANY)

		l.vlaninfo.UpdateElem(uP(&i), uP(&vi), xdp.BPF_ANY)
	}

	return nil
}

func (l *layer3) reconfig() {

	l.vlans(l.config.VLAN4, l.config.VLAN6)

	for _, s := range l.services {
		s.recalc()
	}
}

func clean_map(m xdp.Map, a map[netip.Addr]bool) {

	b := map[addr16]bool{}

	for k, _ := range a {
		b[as16(k)] = true
	}

	var key, next addr16

	for r := 0; r == 0; key = next {
		r = m.GetNextKey(uP(&key), uP(&next))
		if _, exists := b[key]; !exists {
			m.DeleteElem(uP(&key))
		}
	}
}

func (l *layer3) clean() {
	now := time.Now()

	vips := map[netip.Addr]bool{}
	nats := map[netip.Addr]bool{}
	nmap := map[[2]netip.Addr]bool{}

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
		nat := l.netns.addr(v, k[0].Is6()) // k[0] is the vip
		nats[nat] = true
	}

	clean_map(l.nat_to_vip_rip, nats)
	clean_map(l.nat_to_vip_rip, nats)

	log.Println("Clean-up took", time.Now().Sub(now))
}

func updateSettings(settings xdp.Map, setting bpf_settings) {

	all := make([]bpf_settings, xdp.BpfNumPossibleCpus())
	for i, _ := range all {
		all[i] = setting
	}

	settings.UpdateElem(uP(&ZERO), uP(&all[0]), xdp.BPF_ANY)
}
