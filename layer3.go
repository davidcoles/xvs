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
	flag [256]byte
	port [256]uint16
	dest [256]bpf_dest4
	hash [8192]byte
}

type addr4 = [4]byte

func Layer3(nic uint32, h_dest [6]byte, vip addr4, port uint16, saddr addr4, dests ...addr4) error {

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

	infos, err := x.FindMap("infos", 4, int(unsafe.Sizeof(bpf_info{})))
	services, err := x.FindMap("services", 4, int(unsafe.Sizeof(bpf_service3{})))

	if err != nil {
		return err
	}

	var service bpf_service3

	for i, d := range dests {
		service.flag[i+1] = 0
		service.port[i+1] = 9999
		service.dest[i+1] = bpf_dest4{addr: d}
	}

	for i := 0; i < len(service.hash); i++ {
		d := i % len(dests)
		service.hash[i] = byte(d + 1)
	}

	//fmt.Println(service)

	infos.UpdateElem(uP(&ZERO), uP(&info), xdp.BPF_ANY)

	services.UpdateElem(uP(&ZERO), uP(&service), xdp.BPF_ANY)

	if err = x.LoadBpfSection("xdp_fwd_func", native, nic); err != nil {
		return err
	}

	return nil
}
