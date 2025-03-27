package xvs

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io/ioutil"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"unsafe"

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

const LAYER2 uint8 = 0
const FOU uint8 = 1
const GRE uint8 = 2
const GUE uint8 = 3
const IPIP uint8 = 4

const F_STICKY uint8 = 0x01

type bpf_info struct {
	vip    [4]byte
	saddr  [4]byte
	h_dest [6]byte
	pad    [2]byte
}

type bpf_vip_info struct {
	ext_ip   [16]byte
	vlanid   uint16
	h_dest   [6]byte
	h_source [6]byte
	pad      [2]byte
}

type bpf_dest4 struct {
	vid  uint16
	mac  [6]byte
	pad  [4]byte
	addr [4]byte
}

type bpf_dest [16]byte

type bpf_destinfo struct {
	daddr    addr6
	saddr    addr6
	dport    uint16
	sport    uint16
	vlanid   uint16
	method   uint8
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
	method uint8
	flags  uint8
	hwaddr [6]byte
	vlanid uint16
}

type addr4 = [4]byte
type addr6 = [16]byte

type a16 = [16]byte

type dinfo struct {
	dest  a16
	flags uint8
	index uint16
	tport uint16
	mac   [6]byte
}

type threetuple struct {
	address  netip.Addr
	port     uint16
	protocol uint8
}

type l3service struct {
	dests map[netip.Addr]L3Destination
}

type layer3 struct {
	vlanid         uint16
	h_dest         mac
	h_source       mac
	viprip         map[[2]a16]dinfo
	destinations   xdp.Map
	nat_to_vip_rip xdp.Map
	vips           xdp.Map
	saddr4         [4]byte
	saddr6         [16]byte

	services map[threetuple]*l3service
}

type L3Destination struct {
	Address    netip.Addr
	TunnelType uint8
	TunnelPort uint16
}

func (d *L3Destination) is4() bool {
	return d.Address.Is4()
}
func (d *L3Destination) as16() (r a16) {
	if d.is4() {
		ip := d.Address.As4()
		copy(r[12:], ip[:])
	} else {
		r = d.Address.As16()
	}
	return
}

func (l *layer3) SetDestination(v netip.Addr, port uint16, l3d L3Destination) {

	tuple := threetuple{address: v, port: port, protocol: TCP}

	service := l.services[tuple]

	if service == nil {
		service = &l3service{dests: map[netip.Addr]L3Destination{}}
		l.services[tuple] = service
	}

	service.dests[l3d.Address] = l3d

	var vip, rip [16]byte
	r := l3d.Address

	if len(l.viprip) < 1 {
		l.viprip = map[[2]a16]dinfo{}
	}

	if v.Is4() {
		as4 := v.As4()
		copy(vip[12:], as4[:])
	} else {
		vip = v.As16()
	}

	hwaddr, _ := arp()
	hwaddr6 := hw6()

	var mac [6]byte

	if r.Is4() {
		as4 := r.As4()
		copy(rip[12:], as4[:])
		mac = hwaddr[as4]
	} else {
		rip = r.As16()

		if hw, ok := hwaddr6[r]; ok {
			mac = hw.mac
		}
	}

	vr := [2]a16{vip, rip}

	flags := l3d.TunnelType & 0x7

	l.viprip[vr] = dinfo{flags: flags, tport: l3d.TunnelPort, mac: mac}

	l.recalc2()
	l.recalc()
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

func (l *layer3) recalc2() {

	hwaddr, _ := arp()
	hwaddr6 := hw6()

	for tuple, l3service := range l.services {
		var dests []L3Destination
		for _, v := range l3service.dests {
			dests = append(dests, v)
		}

		var val bpf_destinations

		for i, d := range dests {

			var backend mac
			as16 := d.as16()
			//saddr := l.saddr6
			var saddr addr6

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

			if d.TunnelPort == uint16(LAYER2) {
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

		for i, _ := range val.hash {
			val.hash[i] = byte((i % len(dests)) + 1)
		}

		var vip a16

		if tuple.address.Is4() {
			ip := tuple.address.As4()
			copy(vip[12:], ip[:])
		} else {
			vip = tuple.address.As16()
		}

		key := bpf_servicekey{
			addr:  vip,
			port:  tuple.port,
			proto: uint16(tuple.protocol),
		}

		l.destinations.UpdateElem(uP(&key), uP(&val), xdp.BPF_ANY)

	}
}

func (l *layer3) recalc() {
	var index uint16
	var vlanid uint32 = 100 // key to a bpf map - needs to be uint32

	for vr, d := range l.viprip {
		index++
		d.index = index
		l.viprip[vr] = d
	}

	vips := map[a16][]dinfo{}
	for vr, d := range l.viprip {
		v := vr[0]
		r := vr[1]
		d.dest = r
		vips[v] = append(vips[v], d)

	}

	for vip, dests := range vips {

		vip_info := bpf_vip_info{
			vlanid:   uint16(vlanid),
			h_dest:   l.h_dest,
			h_source: [6]byte{0x00, 0x0c, 0x29, 0xeb, 0xf0, 0xd2},
		}

		l.vips.UpdateElem(uP(&vip), uP(&vip_info), xdp.BPF_ANY)

		for _, d := range dests {

			mac := l.h_dest // default to router - potential loop?

			if d.flags&0x07 == LAYER2 {
				mac = d.mac
			}

			// TODO - check if dst is on local interface

			nat := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 255, 0, byte(d.index)}

			var is6 bool

			for i := 0; i < 12; i++ {
				if vip[i] != 0 {
					is6 = true
				}
			}

			rip := d.dest

			if is6 {
				nat = [16]byte{0xfe, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(d.index)}
				nat[0] = 0xfe
				nat[1] = 0xfe
			}

			vip_rip := bpf_vip_rip{
				vip:    vip,
				rip:    rip,
				port:   d.tport,
				method: d.flags,
				hwaddr: mac,
				vlanid: uint16(vlanid),
			}

			l.nat_to_vip_rip.UpdateElem(uP(&nat), uP(&vip_rip), xdp.BPF_ANY)
		}
	}
}

//func Layer3(ifname string, h_dest [6]byte, saddr4 addr4, saddr6 addr6) (*layer3, error) {
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

	//return nil, nil
	saddr4 := prefix4.Addr().As4()
	saddr6 := prefix6.Addr().As16()

	var h_source [6]byte
	copy(h_source[:], iface.HardwareAddr[:])

	var vlanid uint32 = 100

	var native bool

	x, err := xdp.LoadBpfFile(layer3_o)

	if err != nil {
		return nil, err
	}

	x.LinkDetach(uint32(nic))

	if err != nil {
		return nil, err
	}

	redirect_map, err := x.FindMap("redirect_map", 4, 4)

	if err != nil {
		return nil, err
	}

	vips, err := x.FindMap("vips", 16, int(unsafe.Sizeof(bpf_vip_info{})))

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

	ns.test()

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

	fmt.Println(vlaninfo, vlan_info)

	vlan_info.UpdateElem(uP(&vlanid), uP(&vlaninfo), xdp.BPF_ANY)

	internal := bpf_vlaninfo{
		source_ipv4: ns.addr(),
		source_ipv6: ns.ipv6(),
		ifindex:     uint32(ns.a.idx),
		hwaddr:      ns.b.mac,
		router:      ns.a.mac,
	}

	var ftanf = uint32(4095)
	vlan_info.UpdateElem(uP(&ftanf), uP(&internal), xdp.BPF_ANY)

	/**********************************************************************/

	redirect_map.UpdateElem(uP(&vlanid), uP(&nic), xdp.BPF_ANY)

	var ns_nic uint32 = uint32(ns.a.idx)

	redirect_map.UpdateElem(uP(&ftanf), uP(&ns_nic), xdp.BPF_ANY)

	return &layer3{
		vlanid:         uint16(vlanid),
		h_dest:         h_dest,
		h_source:       h_source,
		destinations:   destinations,
		vips:           vips,
		saddr4:         saddr4,
		saddr6:         saddr6,
		nat_to_vip_rip: nat_to_vip_rip,
		services:       map[threetuple]*l3service{},
	}, nil
}
