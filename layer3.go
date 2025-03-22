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
const F_LAYER3_GENEVE uint8 = 5

const FOU uint8 = 0
const GRE uint8 = 1
const GUE uint8 = 2
const IPIP uint8 = 3
const LAYER2 uint8 = 4
const GENEVE uint8 = 5

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

func Layer3(tun uint8, nic uint32, h_dest [6]byte, saddr addr4, vip, vip2 netip.Addr, l3port4, l3port6 uint16, sticky bool, dests ...netip.Addr) error {

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
		return err
	}

	x.LinkDetach(uint32(nic))

	//	infos, err := x.FindMap("infos", 4, int(unsafe.Sizeof(bpf_info{})))

	if err != nil {
		return err
	}

	redirect_map, err := x.FindMap("redirect_map", 4, 4)

	if err != nil {
		return err
	}

	vips, err := x.FindMap("vips", 16, int(unsafe.Sizeof(bpf_vip_info{})))

	if err != nil {
		return err
	}

	destinations, err := x.FindMap("destinations", int(unsafe.Sizeof(bpf_servicekey{})), int(unsafe.Sizeof(bpf_destinations{})))

	if err != nil {
		return err
	}

	nat_to_vip_rip, err := x.FindMap("nat_to_vip_rip", 16, int(unsafe.Sizeof(bpf_vip_rip{})))

	if err != nil {
		return err
	}

	vlan_info, err := x.FindMap("vlan_info", 4, int(unsafe.Sizeof(bpf_vlaninfo{})))

	if err != nil {
		return err
	}

	ns, err := nat3(x, "xdp_request", "xdp_reply") // checks

	if err != nil {
		return err
	}

	ns.test()

	if err = x.LoadBpfSection("xdp_fwd_func", native, nic); err != nil {
		return err
	}

	tunnel := F_LAYER3_FOU4

	switch tun {
	case FOU:
	case GRE:
		tunnel = F_LAYER3_GRE
	case GUE:
		tunnel = F_LAYER3_GUE
	case IPIP:
		tunnel = F_LAYER3_IPIP4
	case LAYER2:
		tunnel = F_LAYER2_DSR
	case GENEVE:
		tunnel = F_LAYER3_GENEVE
	}

	saddr6 := netip.MustParseAddr("fd6e:eec8:76ac:ac1d:100::3")
	saddr6as16 := saddr6.As16()

	saddr4as4 := saddr
	var saddr4as16 [16]byte
	copy(saddr4as16[12:], saddr[:])

	var vip_ [16]byte
	vip__ := vip.As4()

	copy(vip_[12:], vip__[:])

	for i, d := range dests {

		var rip [16]byte
		nat := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 255, 0, byte(i + 1)}

		if d.Is4() {
			as4 := d.As4()
			copy(rip[12:], as4[:])
		} else {
			rip = d.As16()
		}

		//rip_ := [16]byte{0xfd, 0x6e, 0xee, 0xc8, 0x76, 0xac, 0xac, 0x1d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}

		vip_rip := bpf_vip_rip{
			vip:    vip_,
			rip:    rip,
			port:   l3port4,
			method: tunnel,
		}

		nat_to_vip_rip.UpdateElem(uP(&nat), uP(&vip_rip), xdp.BPF_ANY)

	}

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

	//infos.UpdateElem(uP(&ZERO), uP(&info), xdp.BPF_ANY) // not actually used now

	hwaddr, _ := arp()

	all := []netip.Addr{vip, vip2}

	//h_dest := hwaddr[vip] // use same for both ipv4 and ipv6 in lieu of arp for ipv6

	for _, ip := range all {

		var vip6 addr6
		var port uint16 = l3port4

		vip_info := bpf_vip_info{
			vlanid:   uint16(vlanid),
			h_dest:   h_dest,
			h_source: [6]byte{0x00, 0x0c, 0x29, 0xeb, 0xf0, 0xd2},
		}

		if ip.Is4() {
			i := ip.As4()
			copy(vip6[12:], i[:])
			copy(vip_info.ext_ip[12:], saddr4as4[:])
		} else {
			i := ip.As16()
			copy(vip6[:], i[:])
			copy(vip_info.ext_ip[:], saddr6as16[:])
			port = l3port6
		}

		fmt.Println(vip_info)

		vips.UpdateElem(uP(&vip6), uP(&vip_info), xdp.BPF_ANY)

		var val bpf_destinations

		if sticky {
			val.flag[0] |= F_STICKY
		}

		copy(val.saddr[12:], saddr[:])
		val.saddr6 = saddr6.As16()
		val.h_dest = h_dest
		val.vlanid = uint16(vlanid)

		for i, d := range dests {

			val.flag[i+1] = tunnel
			val.sport[i+1] = port

			var daddr [16]byte

			if d.Is6() {
				daddr = d.As16()
			} else {
				ip := d.As4()
				copy(daddr[12:], ip[:])

				val.hwaddr[i+1] = hwaddr[ip]

			}

			val.daddr[i+1] = daddr
		}

		for i, _ := range val.hash {
			d := i % len(dests)
			val.hash[i] = byte(d + 1)
		}

		for _, port := range []uint16{80, 443, 8000} {
			key := bpf_servicekey{
				addr:  vip6,
				port:  port,
				proto: TCP,
			}
			destinations.UpdateElem(uP(&key), uP(&val), xdp.BPF_ANY)
		}
	}

	return nil
}
