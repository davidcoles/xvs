package xvs

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	//"fmt"
	"io/ioutil"
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
	addr [4]byte
	vid  uint16
	mac  [6]byte
	pad  [4]byte
}

type bpf_service3 struct {
	hash [8192]uint8
	flag [256]uint8
	port [256]uint16
	dest [256]bpf_dest4
}

type bpf_service6 struct {
	addr  addr6
	port  uint16
	proto uint16
}

type addr4 = [4]byte
type addr6 = [16]byte

func Layer3(nic uint32, h_dest [6]byte, saddr addr4, vip addr4, port uint16, sticky bool, dests ...addr4) error {

	var ZERO uint32 = 0

	var native bool

	info := bpf_info{
		vip:    vip,
		saddr:  saddr,
		h_dest: h_dest,
	}

	x, err := xdp.LoadBpfFile(layer3_o)

	if err != nil {
		return err
	}

	var vip6 addr6

	copy(vip6[12:], vip[:])

	s6 := bpf_service6{
		addr:  vip6,
		port:  80,
		proto: 6,
	}

	infos, err := x.FindMap("infos", 4, int(unsafe.Sizeof(bpf_info{})))

	if err != nil {
		return err
	}

	vips, err := x.FindMap("vips", 16, 4)

	if err != nil {
		return err
	}

	destinations, err := x.FindMap("destinations", int(unsafe.Sizeof(bpf_service6{})), int(unsafe.Sizeof(bpf_service3{})))

	if err != nil {
		return err
	}
	var service bpf_service3

	const F_L2 uint8 = 0x00
	const F_FOU uint8 = 0x01
	//const F_FOU uint8 = 0x02
	//const F_FOU uint8 = 0x03
	//const F_FOU uint8 = 0x05
	//const F_FOU uint8 = 0x06
	//const F_FOU uint8 = 0x07

	const F_STICKY uint8 = 0x01

	if sticky {
		service.flag[0] |= F_STICKY
	}

	for i, d := range dests {
		service.flag[i+1] = F_FOU // FOU
		service.port[i+1] = port
		service.dest[i+1] = bpf_dest4{addr: d}
	}

	for i := 0; i < len(service.hash); i++ {
		d := i % len(dests)
		service.hash[i] = byte(d + 1)
	}

	infos.UpdateElem(uP(&ZERO), uP(&info), xdp.BPF_ANY)
	destinations.UpdateElem(uP(&s6), uP(&service), xdp.BPF_ANY)
	vips.UpdateElem(uP(&vip6), uP(&ZERO), xdp.BPF_ANY)

	if err = x.LoadBpfSection("xdp_fwd_func", native, nic); err != nil {
		return err
	}

	return nil
}
