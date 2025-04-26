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

var VETH32 uint32 = 4095
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
}

type layer3 struct {
	services map[threetuple]*service3
	mutex    sync.Mutex
	natmap   natmap6
	netinfo  *netinfo
	netns    *newns

	nat_to_vip_rip xdp.Map
	redirect_map   xdp.Map
	redirect_map6  xdp.Map
	destinations   xdp.Map
	vlaninfo       xdp.Map
	settings       xdp.Map
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

func (s *service3) set(service Service3, ds ...Destination3) error {

	m := make(map[netip.Addr]Destination3, len(ds))

	for _, d := range ds {
		if _, exists := s.dests[d.Address]; !exists {
			if err := d.check(); err != nil {
				return err
			}
			s.layer3.natmap.add(s.service.Address, d.Address)
		}

		m[d.Address] = d
	}

	s.service = service
	s.dests = m
	s.layer3.natmap.index()
	s.layer3.clean()
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

	err := service.set(s, ds...)

	if err != nil {
		return err
	}

	l.services[s.key()] = service

	return nil
}

func (l *layer3) getStats(s, d netip.Addr, port, protocol uint16) (c bpf_counters2) {

	vrpp := bpf_vrpp2{vaddr: as16(s), raddr: as16(d), vport: port, protocol: protocol}
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
		c.add(s.layer3.getStats(s.service.Address, d, s.service.Port, uint16(s.service.Protocol)))
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

func (s *service3) delete() error {
	key := s.key()
	s.layer3.destinations.DeleteElem(uP(&key))
	delete(s.layer3.services, s.service.key())
	s.layer3.clean()
	return nil
}

func (s *service3) removeDestination(d Destination3) error {
	if _, exists := s.dests[d.Address]; !exists {
		return fmt.Errorf("Destination does not exist")
	}

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
	for _, d := range s.dests {

		stats := s.layer3.getStats(s.service.Address, d.Address, s.service.Port, uint16(s.service.Protocol)).stats()

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

func (s *service3) recalc() {

	reals := make(map[netip.Addr]real, len(s.dests))

	for k, d := range s.dests {
		di, ni := destinfo(s.layer3, d)
		reals[k] = real{destinfo: di, netinfo: ni, weight: d.Weight}

		svc := s.service
		vrpp := bpf_vrpp2{vaddr: as16(svc.Address), raddr: as16(d.Address), vport: svc.Port, protocol: uint16(svc.Protocol)}
		counters := make([]bpf_counters2, xdp.BpfNumPossibleCpus())
		s.layer3.stats.UpdateElem(uP(&vrpp), uP(&counters[0]), xdp.BPF_NOEXIST)
	}

	s.forwarding(reals)

	vip := as16(s.service.Address)

	for k, v := range reals {
		nat := as16(s.layer3.nat(s.service.Address, k))
		ext := as16(s.layer3.netinfo.ext(v.destinfo.vlanid, s.service.Address.Is6()))

		vip_rip := bpf_vip_rip{destinfo: v.destinfo, vip: vip, ext: ext}
		s.layer3.nat_to_vip_rip.UpdateElem(uP(&nat), uP(&vip_rip), xdp.BPF_ANY)

		fmt.Println("NAT", v.netinfo, ext, vip)
	}

	s.layer3.vips.UpdateElem(uP(&vip), uP(&ZERO), xdp.BPF_ANY) // value is not used
}

func (s *service3) forwarding(reals map[netip.Addr]real) {

	addrs := make([]netip.Addr, 0, len(reals))

	// filter out unusable destinations
	for k, v := range reals {
		if v.weight != 0 && v.destinfo.vlanid != 0 {
			addrs = append(addrs, k)
		}
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

	redirect_map, err := x.FindMap("redirect_map", 4, 4)

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

	netns, err := x.FindMap("netns", 4, int(unsafe.Sizeof(bpf_netns{})))

	if err != nil {
		return nil, err
	}

	ns, err := nat3(x, "xdp_request", "xdp_reply") // checks

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

	settings.UpdateElem(uP(&ZERO), uP(&setting), xdp.BPF_ANY)

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

	// can replace this with a vlaninfo entry at 0
	netns.UpdateElem(uP(&ZERO), uP(&(bpf_netns{a: ns.a.mac, b: ns.b.mac})), xdp.BPF_ANY)

	var ns_nic uint32 = uint32(ns.a.idx)
	redirect_map.UpdateElem(uP(&VETH32), uP(&ns_nic), xdp.BPF_ANY)
	redirect_map6.UpdateElem(uP(&VETH32), uP(&ns_nic), xdp.BPF_ANY)

	redirect_map.UpdateElem(uP(&ZERO), uP(&ns_nic), xdp.BPF_ANY)
	redirect_map6.UpdateElem(uP(&ZERO), uP(&ns_nic), xdp.BPF_ANY)

	return &layer3{
		services: map[threetuple]*service3{},
		netns:    ns,
		natmap:   natmap6{},
		netinfo:  ni,

		nat_to_vip_rip: nat_to_vip_rip,
		redirect_map:   redirect_map,
		redirect_map6:  redirect_map6,
		destinations:   destinations,
		vlaninfo:       vlaninfo,
		settings:       settings,
		stats:          stats,
		vips:           vips,
	}, nil
}

//func (l *layer3) vlansx(vlans map[uint16][2]netip.Prefix) error {
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
		l.redirect_map.UpdateElem(uP(&i), uP(&nic), xdp.BPF_ANY)

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

func (l *layer3) config() {
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
