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

// TODO:
// ingress interface/vlan -> interface IPs, for correct ICMP "too big" responses
// process intermediate system ICMP too big messages and pass to backends
// health probe ICMP?
// stats
// latency
// handle udp/icmp

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
	s.service = service

	m := map[netip.Addr]Destination3{}

	for _, d := range ds {
		m[d.Address] = d
		s.layer3.natmap.add(s.service.Address, d.Address)
	}

	s.dests = m
	s.layer3.natmap.index()
	s.layer3.clean()

	s.recalc()
	return nil
}

func (s *service3) set_old(service Service3, ds ...Destination3) error {
	s.service = service

	m := map[netip.Addr]Destination3{}

	for _, d := range ds {
		m[d.Address] = d
		s.layer3.natmap.add(s.service.Address, d.Address)
		s.layer3.natmap.index()
	}

	s.dests = m
	s.recalc()
	s.layer3.clean()
	return nil
}

func (l *layer3) createService(s Service3, ds ...Destination3) *service3 {

	service := &service3{
		dests:   map[netip.Addr]Destination3{},
		service: s,
		layer3:  l,
	}

	service.set(s, ds...)

	l.services[s.key()] = service

	return service
}

func (s *service3) extend() Service3Extended {
	return Service3Extended{Service: s.service}
}

func (s *service3) update(service Service3) error {
	s.service = service
	s.recalc()
	return nil
}

func (s *service3) key() (k bpf_servicekey) {
	k.addr = as16(s.service.Address)
	k.port = s.service.Port
	k.proto = uint16(s.service.Protocol)
	return
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

func (s *service3) createDestination(d Destination3) error {

	if _, exists := s.dests[d.Address]; exists {
		return fmt.Errorf("Destination exists")
	}

	s.dests[d.Address] = d

	s.layer3.natmap.add(s.service.Address, d.Address)
	s.layer3.natmap.index()

	// TODO - add stats map eniires

	s.recalc()

	return nil
}

func (s *service3) destinations() (r []Destination3Extended, e error) {
	for _, v := range s.dests {
		r = append(r, Destination3Extended{Destination: v})
	}
	return
}

func (l *layer3) nat(v, r netip.Addr) netip.Addr {
	return l.netns.addr(l.natmap.get(v, r), v.Is6())
}

func (s *service3) recalc() {

	l := s.layer3

	var dests []Destination3
	for _, v := range s.dests {
		dests = append(dests, v)
	}

	var val bpf_destinations
	for i, d := range dests {
		ni, err := l.netinfo.info(d.Address)

		if err != nil {
			log.Fatal("FWD", err)
		}

		const NOT_LOCAL = 0x80

		flags := uint8(d.TunnelFlags & 0x7f)

		if ni.l3 {
			flags |= NOT_LOCAL
			log.Println("NOT_LOCAL", d.Address)
		}

		i2 := bpf_destinfo{
			vlanid: ni.vlanid,
			//h_source: ni.h_source,
			//saddr:    as16(ni.saddr),
			h_dest: ni.h_dest,
			daddr:  as16(ni.daddr),
			dport:  d.TunnelPort,
			sport:  0,
			method: d.TunnelType,
			flags:  flags, // TODO
		}

		val.destinfo[i+1] = i2

		fmt.Println("FWD", ni)

		if d.TunnelType == NONE && ni.l3 {
			log.Fatal("LOOP", ni)
		}
	}

	if len(dests) > 0 {
		for i, _ := range val.hash {
			val.hash[i] = byte((i % len(dests)) + 1)
		}
	}

	val.destinfo[0] = bpf_destinfo{flags: uint8(s.service.Flags)}

	vip := as16(s.service.Address)

	key := s.key()

	l.destinations.UpdateElem(uP(&key), uP(&val), xdp.BPF_ANY)

	/**********************************************************************/

	//l.vips.UpdateElem(uP(&vip), uP(&VLANID), xdp.BPF_ANY)
	l.vips.UpdateElem(uP(&vip), uP(&ZERO), xdp.BPF_ANY) // value is not used

	for _, d := range dests {

		ni, err := l.netinfo.info(d.Address)

		if err != nil {
			log.Fatal("NAT", err, ni)
		}

		nat := as16(l.nat(s.service.Address, d.Address))
		ext := as16(l.netinfo.ext(ni.vlanid, s.service.Address.Is6()))

		if d.TunnelType == NONE && ni.l3 {
			log.Fatal("LOOP", ni)
		}

		vip_rip := bpf_vip_rip{
			destinfo: bpf_destinfo{
				daddr:    as16(ni.daddr),
				saddr:    as16(ni.saddr),
				dport:    d.TunnelPort,
				sport:    0,
				vlanid:   ni.vlanid,
				method:   d.TunnelType,
				flags:    0,
				h_dest:   ni.h_dest,
				h_source: ni.h_source,
			},
			vip: vip,
			ext: ext,
		}

		fmt.Println("NAT", ni, ext, vip)

		l.nat_to_vip_rip.UpdateElem(uP(&nat), uP(&vip_rip), xdp.BPF_ANY)
	}
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

	netns.UpdateElem(uP(&ZERO), uP(&(bpf_netns{a: ns.a.mac, b: ns.b.mac})), xdp.BPF_ANY)

	var ns_nic uint32 = uint32(ns.a.idx)
	redirect_map.UpdateElem(uP(&VETH32), uP(&ns_nic), xdp.BPF_ANY)
	redirect_map6.UpdateElem(uP(&VETH32), uP(&ns_nic), xdp.BPF_ANY)

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
		vips:           vips,
	}, nil
}

func (l *layer3) vlans(vlans map[uint16][2]netip.Prefix) error {

	route := map[netip.Prefix]uint16{}

	err := l.netinfo.config(vlans, route)

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
