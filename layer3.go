package xvs

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	//"fmt"
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

type bpf_info struct {
	vip    [4]byte
	saddr  [4]byte
	h_dest [6]byte
	pad    [2]byte
}

type bpf_dest4 struct {
	vid  uint16
	mac  [6]byte
	pad  [4]byte
	addr [4]byte
}

type bpf_dest [16]byte

type bpf_destinations struct {
	hash  [8192]uint8
	flag  [256]uint8
	sport [256]uint16
	//daddr  [256]bpf_dest4
	daddr [256]bpf_dest
	//saddr  bpf_dest4
	saddr  bpf_dest
	saddr6 addr6
	h_dest [6]byte
	vlanid uint16
}

type bpf_servicekey struct {
	addr  addr6
	port  uint16
	proto uint16
}

type addr4 = [4]byte
type addr6 = [16]byte

const FOU uint8 = 0
const GRE uint8 = 1
const IPIP uint8 = 2

func Layer3(tun uint8, nic uint32, h_dest [6]byte, saddr addr4, vip, vip2 netip.Addr, l3port4, l3port6 uint16, sticky bool, dests ...netip.Addr) error {

	const TCP uint16 = 6
	const UDP uint16 = 17

	var ZERO uint32 = 0
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

	//	infos, err := x.FindMap("infos", 4, int(unsafe.Sizeof(bpf_info{})))

	if err != nil {
		return err
	}

	redirect_map, err := x.FindMap("redirect_map", 4, 4)

	if err != nil {
		return err
	}

	vips, err := x.FindMap("vips", 16, 4)

	if err != nil {
		return err
	}

	destinations, err := x.FindMap("destinations", int(unsafe.Sizeof(bpf_servicekey{})), int(unsafe.Sizeof(bpf_destinations{})))

	if err != nil {
		return err
	}

	redirect_map.UpdateElem(uP(&vlanid), uP(&nic), xdp.BPF_ANY)

	//infos.UpdateElem(uP(&ZERO), uP(&info), xdp.BPF_ANY) // not actually used now

	const F_LAYER2_DSR uint8 = 0x00
	const F_LAYER3_FOU4 uint8 = 0x01  // IPv4 host with FOU tunnel
	const F_LAYER3_GRE uint8 = 0x02   // IPv6 host with FOU tunnel
	const F_LAYER3_IPIP4 uint8 = 0x03 // IPv4 host with IP-in-IP tunnel

	const F_STICKY uint8 = 0x01

	tunnel := F_LAYER3_FOU4

	switch tun {
	case FOU:
	case GRE:
		tunnel = F_LAYER3_GRE
	case IPIP:
		tunnel = F_LAYER3_IPIP4
	}

	all := []netip.Addr{vip, vip2}

	for _, ip := range all {

		var vip6 addr6
		var port uint16 = l3port4

		if ip.Is4() {
			i := ip.As4()
			copy(vip6[12:], i[:])
		} else {
			i := ip.As16()
			copy(vip6[:], i[:])
			port = l3port6
		}

		vips.UpdateElem(uP(&vip6), uP(&ZERO), xdp.BPF_ANY)

		var val bpf_destinations

		if sticky {
			val.flag[0] |= F_STICKY
		}

		saddr6 := netip.MustParseAddr("fd6e:eec8:76ac:ac1d:100::3")

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

	if err = x.LoadBpfSection("xdp_fwd_func", native, nic); err != nil {
		return err
	}

	return nil
}
