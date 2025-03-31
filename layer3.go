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
	vip    [16]byte
	rip    [16]byte
	port   uint16
	method TunnelType // uint8
	flags  uint8
	hwaddr [6]byte
	vlanid uint16
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
	saddr4         [4]byte
	saddr6         [16]byte
	ns             *newns
	natmap         natmap6
	mutex          sync.Mutex

	nic uint32

	services map[threetuple]*service3
}

type Destination3 struct {
	Address    netip.Addr
	TunnelType TunnelType
	TunnelPort uint16
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

func (s *service3) delete(l *layer3) {
	// remove service entry
	key := bpf_servicekey{
		addr:  as16(s.service.Address),
		port:  s.service.Port,
		proto: uint16(s.service.Protocol),
	}

	l.destinations.DeleteElem(uP(&key))

	delete(l.services, s.service.key())

	l.deletion()
}

func (s *service3) deldest(l *layer3, d Destination3) error {
	delete(s.dests, d.Address)
	s.recalc(l)
	l.deletion()
	return nil
}

func (s *service3) recalc(l *layer3) {

	hwaddr, _ := arp()
	hwaddr6 := hw6()

	var dests []Destination3
	for _, v := range s.dests {
		dests = append(dests, v)
	}

	tuple := threetuple{address: s.service.Address, port: s.service.Port, protocol: s.service.Protocol}

	var val bpf_destinations

	for i, d := range dests {

		var backend mac
		var saddr addr6
		as16 := d.as16()

		if d.is4() {
			var ip [4]byte
			copy(ip[:], as16[12:])
			copy(saddr[12:], l.saddr4[:])
			backend = hwaddr[ip]
		} else {
			saddr = l.saddr6
			if hw, ok := hwaddr6[d.Address]; ok {
				backend = hw.mac
			}
		}

		var h_dest mac
		h_source := l.h_source

		if d.TunnelType == LAYER2 {
			h_dest = backend
		} else {
			h_dest = l.h_dest
		}

		var info bpf_destinfo
		info.daddr = as16
		info.saddr = saddr
		info.dport = d.TunnelPort
		info.sport = 0
		info.method = d.TunnelType
		info.flags = 0 // TODO
		info.vlanid = l.vlanid
		info.h_dest = h_dest
		info.h_source = h_source
		val.destinfo[i+1] = info
	}

	if len(dests) > 0 {
		for i, _ := range val.hash {
			val.hash[i] = byte((i % len(dests)) + 1)
		}
	}

	v := tuple.address
	vip := as16(v)

	key := bpf_servicekey{
		addr:  vip,
		port:  tuple.port,
		proto: uint16(tuple.protocol),
	}

	l.destinations.UpdateElem(uP(&key), uP(&val), xdp.BPF_ANY)

	/**********************************************************************/

	l.vips.UpdateElem(uP(&vip), uP(&VLANID), xdp.BPF_ANY)

	for _, d := range dests {
		r := d.Address
		rip := as16(r)

		index := l.natmap.get(v, r)

		var mac, nul mac
		var nat [16]byte

		if v.Is4() {
			nat = l.ns.nat4(index)
		} else {
			nat = l.ns.nat6(index)
		}

		// get mac address of backend if local
		if r.Is4() {
			mac = hwaddr[r.As4()]
		} else {
			mac = hwaddr6[r].mac
		}

		// use the router as the next hop if not found locally and not a layer 2 service (otherwise we get a loop)
		// TODO - compare RIP to local VLAN prefixes
		if mac == nul && d.TunnelType != LAYER2 {
			mac = l.h_dest
		}

		vip_rip := bpf_vip_rip{
			vip:    vip,
			rip:    rip,
			port:   d.TunnelPort,
			method: d.TunnelType,
			hwaddr: mac,
			vlanid: uint16(VLANID),
		}

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

func Layer3(ifname string, h_dest [6]byte) (*layer3, error) {

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

		nic:    nic,
		ns:     ns,
		natmap: natmap6{},
	}, nil
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
	//l.recalc2()
	//l.recalc3()
	for _, s := range l.services {
		s.recalc(l)
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

func (l *layer3) deletion() {
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
