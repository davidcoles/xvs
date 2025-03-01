package xvs

import (
	"bytes"
	"compress/gzip"
	_ "embed"
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
	daddr  [4]byte
	port   uint16
	h_dest [6]byte
}

func Layer3(nic uint32, vip, saddr, daddr [4]byte, port uint16, h_dest [6]byte) error {

	var ZERO uint32 = 0

	var native bool

	info := bpf_info{
		vip:    vip,
		saddr:  saddr,
		daddr:  daddr,
		port:   port,
		h_dest: h_dest,
	}

	x, err := xdp.LoadBpfFile(layer3_o)

	if err != nil {
		return err
	}

	infos, err := x.FindMap("infos", 4, int(unsafe.Sizeof(bpf_info{})))

	if err != nil {
		return err
	}

	infos.UpdateElem(uP(&ZERO), uP(&info), xdp.BPF_ANY)

	if err = x.LoadBpfSection("xdp_fwd_func", native, nic); err != nil {
		return err
	}

	return nil
}
