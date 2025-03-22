package xvs

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io/ioutil"
	"net/netip"
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

const F_LAYER2_DSR uint8 = 0
const F_LAYER3_FOU4 uint8 = 1  // IPv4 host with FOU tunnel
const F_LAYER3_GRE uint8 = 2   // IPv6 host with FOU tunnel
const F_LAYER3_GUE uint8 = 3   // IPv4 host with IP-in-IP tunnel
const F_LAYER3_IPIP4 uint8 = 4 // IPv4 host with IP-in-IP tunnel

const FOU uint8 = F_LAYER3_FOU4
const GRE uint8 = F_LAYER3_GRE
const GUE uint8 = F_LAYER3_GUE
const IPIP uint8 = F_LAYER3_IPIP4
const LAYER2 uint8 = F_LAYER2_DSR

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

type bpf_destinations struct {
	hash   [8192]uint8
	flag   [256]uint8
	sport  [256]uint16
	daddr  [256]bpf_dest
	saddr  bpf_dest
	saddr6 addr6
	h_dest [6]byte
	vlanid uint16
	hwaddr [256]mac
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
}

type addr4 = [4]byte
type addr6 = [16]byte

type a16 = [16]byte

type dinfo struct {
	dest  a16
	flags uint8
	index uint16
	tport uint16
}

type layer3 struct {
	viprip         map[[2]a16]dinfo
	destinations   xdp.Map
	nat_to_vip_rip xdp.Map
	vips           xdp.Map
	saddr4         [4]byte
	saddr6         [16]byte
}

func (l *layer3) SetDestination(v, r netip.Addr, method uint8, h_dest [6]byte) {
	var vip, rip [16]byte

	if len(l.viprip) < 1 {
		l.viprip = map[[2]a16]dinfo{}
	}

	if v.Is4() {
		as4 := v.As4()
		copy(vip[12:], as4[:])
	} else {
		vip = v.As16()
	}

	if r.Is4() {
		as4 := r.As4()
		copy(rip[12:], as4[:])
	} else {
		rip = v.As16()
	}

	vr := [2]a16{vip, rip}

	flags := method & 0x7

	l.viprip[vr] = dinfo{flags: flags}

	l.recalc(h_dest)
}

func (l *layer3) recalc(h_dest [6]byte) {
	var index uint16
	var vlanid uint32 = 100

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

	hwaddr, _ := arp()

	for vip, dests := range vips {

		vip_info := bpf_vip_info{
			vlanid:   uint16(vlanid),
			h_dest:   h_dest,
			h_source: [6]byte{0x00, 0x0c, 0x29, 0xeb, 0xf0, 0xd2},
		}

		fmt.Println(vip_info)

		l.vips.UpdateElem(uP(&vip), uP(&vip_info), xdp.BPF_ANY)

		/**********************************************************************/

		var val bpf_destinations

		//if sticky {
		//	val.flag[0] |= F_STICKY
		//}

		copy(val.saddr[12:], l.saddr4[:])
		val.saddr6 = l.saddr6
		val.h_dest = h_dest
		val.vlanid = uint16(vlanid)

		isIPv4 := func(ip [16]byte) bool {
			for i := 0; i < 12; i++ {
				if ip[i] != 0 {
					return false
				}
			}
			return true
		}

		for i, d := range dests {

			val.flag[i+1] = d.flags
			val.sport[i+1] = d.tport
			val.daddr[i+1] = d.dest

			if isIPv4(d.dest) {
				var ip [4]byte
				copy(ip[:], d.dest[12:])
				val.hwaddr[i+1] = hwaddr[ip]
			}
		}

		for i, _ := range val.hash {
			d := i % len(dests)
			val.hash[i] = byte(d + 1)
		}

		for _, port := range []uint16{80, 443, 8000} {
			key := bpf_servicekey{
				addr:  vip,
				port:  port,
				proto: uint16(TCP),
			}

			l.destinations.UpdateElem(uP(&key), uP(&val), xdp.BPF_ANY)
		}

		for _, d := range dests {

			nat := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 255, 0, byte(d.index)}

			vip_rip := bpf_vip_rip{
				vip:    vip,
				rip:    d.dest,
				port:   d.tport,
				method: d.flags,
			}

			l.nat_to_vip_rip.UpdateElem(uP(&nat), uP(&vip_rip), xdp.BPF_ANY)
		}
	}
}

func Layer3(tun uint8, nic uint32, h_dest [6]byte, saddr addr4, vip, vip2 netip.Addr, l3port4, l3port6 uint16, sticky bool, dests ...netip.Addr) (*layer3, error) {

	const TCP uint16 = 6
	const UDP uint16 = 17

	//var ZERO uint32 = 0
	var vlanid uint32 = 100

	var native bool

	//info := bpf_info{
	//	vip:    vip,
	//	saddr:  saddr,
	//	h_dest: h_dest,
	//}

	x, err := xdp.LoadBpfFile(layer3_o)

	if err != nil {
		return nil, err
	}

	x.LinkDetach(uint32(nic))

	//	infos, err := x.FindMap("infos", 4, int(unsafe.Sizeof(bpf_info{})))

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

	saddr6 := netip.MustParseAddr("fd6e:eec8:76ac:ac1d:100::3")
	saddr6as16 := saddr6.As16()

	saddr4as4 := saddr
	var saddr4as16 [16]byte
	copy(saddr4as16[12:], saddr[:])

	var vip_ [16]byte
	vip__ := vip.As4()

	copy(vip_[12:], vip__[:])

	vlaninfo := bpf_vlaninfo{
		source_ipv4: saddr,
		source_ipv6: saddr6as16,
		ifindex:     nic,
		hwaddr:      [6]byte{0x00, 0x0c, 0x29, 0xeb, 0xf0, 0xd2},
		router:      [6]byte{0x00, 0x0c, 0x29, 0x6a, 0x44, 0xaa},
	}

	fmt.Println(vlaninfo, vlan_info)

	vlan_info.UpdateElem(uP(&vlanid), uP(&vlaninfo), xdp.BPF_ANY)

	internal := bpf_vlaninfo{
		source_ipv4: ns.addr(),
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

	return &layer3{destinations: destinations, vips: vips, saddr4: saddr, saddr6: saddr6as16, nat_to_vip_rip: nat_to_vip_rip}, nil
}
