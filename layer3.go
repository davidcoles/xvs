package xvs

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"sync"
	"time"
	"unsafe"

	"github.com/davidcoles/xvs/bpf"
	"github.com/davidcoles/xvs/xdp"
)

//go:embed bpf/layer3.o.gz
var layer3_gz []byte
var layer3_o []byte

func init() {
	if z, err := gzip.NewReader(bytes.NewReader(layer3_gz)); err == nil {
		layer3_o, _ = ioutil.ReadAll(z)
	}
}

const LAYER2 TunnelType = bpf.T_LAYER2
const FOU TunnelType = bpf.T_FOU
const GRE TunnelType = bpf.T_GRE
const GUE TunnelType = bpf.T_GUE
const IPIP TunnelType = bpf.T_IPIP

const F_STICKY uint8 = bpf.F_STICKY

var VLANID uint32 = 100
var VETH32 uint32 = 4095

type bpf_destinfo struct {
	daddr    addr6
	saddr    addr6
	dport    uint16
	sport    uint16
	vlanid   uint16
	method   TunnelType // uint8
	flags    uint8
	h_dest   mac
	h_source mac
	pad      [12]byte // pad to 64 bytes
}

type bpf_destinations struct {
	destinfo [256]bpf_destinfo
	hash     [8192]uint8
}

type bpf_servicekey struct {
	addr  addr6
	port  uint16
	proto uint16
}

type bpf_vlaninfo struct {
	source_ipv4 [4]byte
	source_ipv6 [16]byte
	ifindex     uint32
	hwaddr      [6]byte
	router      [6]byte
}

type bpf_vip_rip struct {
	destinfo bpf_destinfo
	vip      [16]byte
	ext      [16]byte
}

type addr4 = [4]byte
type addr6 = [16]byte

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
	vlanid         uint16
	h_dest         mac
	h_source       mac
	destinations   xdp.Map
	nat_to_vip_rip xdp.Map
	vips           xdp.Map
	vlan_info      xdp.Map
	redirect_map   xdp.Map
	saddr4         [4]byte
	saddr6         [16]byte
	ns             *newns
	natmap         natmap6
	mutex          sync.Mutex
	netinfo        *netinfo

	nic uint32

	services map[threetuple]*service3
}

func (d *Destination3) is4() bool {
	return d.Address.Is4()
}

func (d *Destination3) as16() (r addr6) {
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

func hw6() map[netip.Addr]neighbor {

	hw6 := map[netip.Addr]neighbor{}

	cmd := exec.Command("/bin/sh", "-c", "ip -6 neighbor show")
	_, _ = cmd.StdinPipe()
	//stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()

	re := regexp.MustCompile(`^(\S+)\s+dev\s+(\S+)\s+lladdr\s+(\S+)\s+(\S+)$`)

	if err := cmd.Start(); err != nil {
		return nil
	}

	defer stdout.Close()

	s := bufio.NewScanner(stdout)

	for s.Scan() {
		line := s.Text()

		m := re.FindStringSubmatch(line)

		if len(m) != 5 {
			continue
		}

		addr, err := netip.ParseAddr(m[1])

		if err != nil {
			continue
		}

		dev := m[2]

		hw, err := net.ParseMAC(m[3])

		if err != nil || len(hw) != 6 {
			continue
		}

		var mac mac

		copy(mac[:], hw[:])

		hw6[addr] = neighbor{dev: dev, mac: mac}
	}

	return hw6
}

func (s *service3) set(service Service3, ds ...Destination3) error {
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
	return l.ns.addr(l.natmap.get(v, r), v.Is6())
}

func (s *service3) recalc() {

	l := s.layer3

	var dests []Destination3
	for _, v := range s.dests {
		dests = append(dests, v)
	}

	tuple := threetuple{address: s.service.Address, port: s.service.Port, protocol: s.service.Protocol}

	var val bpf_destinations

	for i, d := range dests {
		ni, err := l.netinfo.info(d.Address)

		if err != nil {
			log.Fatal("FWD", err)
		}

		i2 := bpf_destinfo{
			daddr:    as16(ni.daddr),
			saddr:    as16(ni.saddr),
			vlanid:   ni.vlanid,
			h_dest:   ni.h_dest,
			h_source: ni.h_source,
			dport:    d.TunnelPort,
			sport:    0,
			method:   d.TunnelType,
			flags:    0, // TODO
		}

		val.destinfo[i+1] = i2

		fmt.Println("FWD", ni)

		if d.TunnelType == LAYER2 && ni.l3 {
			log.Fatal("LOOP", ni)
		}
	}

	if len(dests) > 0 {
		for i, _ := range val.hash {
			val.hash[i] = byte((i % len(dests)) + 1)
		}
	}

	v := tuple.address
	vip := as16(v)

	key := s.key()

	l.destinations.UpdateElem(uP(&key), uP(&val), xdp.BPF_ANY)

	/**********************************************************************/

	l.vips.UpdateElem(uP(&vip), uP(&VLANID), xdp.BPF_ANY)

	for _, d := range dests {

		ni, err := l.netinfo.info(d.Address)

		if err != nil {
			log.Fatal("NAT", err, ni)
		}

		//index := l.natmap.get(v, d.Address)
		//var nat [16]byte
		//if v.Is4() {
		//	nat = l.ns.nat4(index)
		//} else {
		//	nat = l.ns.nat6(index)
		//}

		nat := as16(l.nat(v, d.Address))

		ext := as16(l.netinfo.ext(ni.vlanid, v.Is6()))

		if d.TunnelType == LAYER2 && ni.l3 {
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

func as16(a netip.Addr) (r [16]byte) {
	if a.Is6() {
		return a.As16()
	}

	ip := a.As4()
	copy(r[12:], ip[:])
	return
}

func _as16(a netip.Addr) (r [16]byte) {
	if a.Is6() {
		return a.As16()
	}

	ip := a.As4()
	copy(r[12:], ip[:])
	return
}

func newClient(ifname string, h_dest [6]byte) (*layer3, error) {

	iface, err := net.InterfaceByName(ifname)

	if err != nil {
		return nil, err
	}

	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("Nope")
	}

	nic := uint32(iface.Index)

	var prefix4 netip.Prefix
	var prefix6 netip.Prefix

	addrs, _ := iface.Addrs()
	for _, a := range addrs {
		prefix := netip.MustParsePrefix(a.String())
		addr := prefix.Addr()

		if !addr.IsGlobalUnicast() {
			continue
		}

		if addr.Is4() {
			prefix4 = prefix
		} else {
			prefix6 = prefix
		}
	}

	fmt.Println(prefix4, prefix6)

	//vlan4 := map[uint16]netip.Prefix{uint16(VLANID): prefix4}
	//vlan6 := map[uint16]netip.Prefix{uint16(VLANID): prefix6}
	//vlan4 = map[uint16]netip.Prefix{uint16(VLANID): netip.MustParsePrefix("10.73.35.254/24")}

	vlan4 := map[uint16]netip.Prefix{}
	vlan6 := map[uint16]netip.Prefix{}
	vlan4 = map[uint16]netip.Prefix{}

	ni := &netinfo{}
	ni.config(vlan4, vlan6, nil)

	saddr4 := prefix4.Addr().As4()
	saddr6 := prefix6.Addr().As16()

	var h_source mac
	copy(h_source[:], iface.HardwareAddr[:])

	fmt.Println("MAC", h_source.String())

	var native bool

	x, err := xdp.LoadBpfFile(layer3_o)

	if err != nil {
		return nil, err
	}

	x.LinkDetach(nic)

	if err != nil {
		return nil, err
	}

	redirect_map, err := x.FindMap("redirect_map", 4, 4)

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

	vlan_info, err := x.FindMap("vlan_info", 4, int(unsafe.Sizeof(bpf_vlaninfo{})))

	if err != nil {
		return nil, err
	}

	ns, err := nat3(x, "xdp_request", "xdp_reply") // checks

	if err != nil {
		return nil, err
	}

	if err = x.LoadBpfSection("xdp_fwd_func", native, nic); err != nil {
		return nil, err
	}

	vlaninfo := bpf_vlaninfo{
		source_ipv4: saddr4,
		source_ipv6: saddr6,
		ifindex:     nic,
		hwaddr:      h_source,
		router:      h_dest,
	}

	fmt.Println("VLAN", vlaninfo.source_ipv4, vlaninfo.source_ipv6)

	vlan_info.UpdateElem(uP(&VLANID), uP(&vlaninfo), xdp.BPF_ANY)

	internal := bpf_vlaninfo{
		source_ipv4: ns.ipv4(),
		source_ipv6: ns.ipv6(),
		ifindex:     uint32(ns.a.idx),
		hwaddr:      ns.b.mac,
		router:      ns.a.mac,
	}

	fmt.Println("VETH", internal.source_ipv4, internal.source_ipv6)

	vlan_info.UpdateElem(uP(&VETH32), uP(&internal), xdp.BPF_ANY)

	/**********************************************************************/

	redirect_map.UpdateElem(uP(&VLANID), uP(&nic), xdp.BPF_ANY)

	var ns_nic uint32 = uint32(ns.a.idx)

	redirect_map.UpdateElem(uP(&VETH32), uP(&ns_nic), xdp.BPF_ANY)

	return &layer3{
		vlanid:   uint16(VLANID),
		h_dest:   h_dest,
		h_source: h_source,
		saddr4:   saddr4,
		saddr6:   saddr6,
		services: map[threetuple]*service3{},

		destinations:   destinations,
		vips:           vips,
		nat_to_vip_rip: nat_to_vip_rip,
		vlan_info:      vlan_info,
		redirect_map:   redirect_map,
		nic:            nic,
		ns:             ns,
		natmap:         natmap6{},
		netinfo:        ni,
	}, nil
}

func (l *layer3) foo(vlan4, vlan6 map[uint16]netip.Prefix) {

	route := map[netip.Prefix]uint16{}

	fmt.Println("FOO", vlan4, vlan6)

	l.netinfo.config(vlan4, vlan6, route)

	for i := uint32(1); i < 4095; i++ {
		f := l.netinfo.l2info4[uint16(i)]
		nic := f.ifindex
		l.redirect_map.UpdateElem(uP(&i), uP(&nic), xdp.BPF_ANY)
	}

	return
}

func (l *layer3) config() {
	vlaninfo := bpf_vlaninfo{
		source_ipv4: l.saddr4,
		source_ipv6: l.saddr6,
		ifindex:     l.nic,
		hwaddr:      l.h_source,
		router:      l.h_dest,
	}

	l.vlan_info.UpdateElem(uP(&VLANID), uP(&vlaninfo), xdp.BPF_ANY)

	for _, s := range l.services {
		s.recalc()
	}
}

func clean_map(m xdp.Map, a map[netip.Addr]bool) {

	b := map[[16]byte]bool{}

	for k, _ := range a {
		b[as16(k)] = true
	}

	var key, next [16]byte

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
		nat := l.ns.addr(v, k[0].Is6()) // k[0] is the vip
		nats[nat] = true
	}

	clean_map(l.nat_to_vip_rip, nats)
	clean_map(l.nat_to_vip_rip, nats)

	log.Println("Clean-up took", time.Now().Sub(now))
}
