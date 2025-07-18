/*
 * vc5/xvs load balancer. Copyright (C) 2021-present David Coles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package xdp

/*
#cgo LDFLAGS: -l:libbpf.a -lelf -lz
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "xdp.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"unsafe"
)

const (
	BPF_ANY     = C.BPF_ANY
	BPF_NOEXIST = C.BPF_NOEXIST
	BPF_EXIST   = C.BPF_EXIST
)

type XDP struct {
	p unsafe.Pointer
	s C.int
	m map[string]Map
}

func LoadBpfFile(bindata []byte) (*XDP, error) {

	// get a socket for sending raw packets
	s := C.raw_socket()

	if s == -1 {
		return nil, errors.New("Unable to create raw socket")
	}

	tmpfile, err := ioutil.TempFile("/tmp", "balancer")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write(bindata); err != nil {
		return nil, err
	}

	if err := tmpfile.Close(); err != nil {
		return nil, err
	}

	var x XDP

	x.s = s
	x.m = map[string]Map{}

	x.p = unsafe.Pointer(C.load_bpf_prog(C.CString(tmpfile.Name())))

	if x.p == nil {
		return nil, errors.New("Unable to load eBPF")
	}

	return &x, nil
}

func (x *XDP) LinkDetach(iface uint32) {
	C.xdp_link_detach(C.int(iface))
}

func (x *XDP) LoadBpfSection(section string, native bool, iface uint32) error {
	var n int

	if native {
		n = 1
	}

	//C.xdp_link_detach(C.int(iface))
	if err := C.load_bpf_section(x.p, C.int(iface), C.CString(section), C.int(n)); err != 0 {
		return fmt.Errorf("load_bpf_section() failed: %d", err)
	}

	return nil
}

func BpfNumPossibleCpus() int {
	return int(C.libbpf_num_possible_cpus())
}

func (x *XDP) FindMap(m string, k, v int) (Map, error) {
	r := C.bpf_object__find_map_by_name((*C.struct_bpf_object)(x.p), C.CString(m))
	if r == nil {
		return -1, fmt.Errorf("Couldn't find map %s", m)
	}

	i := int(C.bpf_map__fd(r))

	if C.check_map_fd_info(C.int(i), C.int(k), C.int(v)) != 0 {
		return -1, fmt.Errorf("Key/value size mismatch for map %s", m)
	}

	z := Map(i)
	x.m[m] = z

	return z, nil
}

func (x *XDP) Map(m string) Map {
	return x.m[m]
}

type Map int

func (m Map) LookupElem(k, v unsafe.Pointer) int {
	return int(C.bpf_map_lookup_elem(C.int(m), k, v))
}

func (m Map) UpdateElem(k, v unsafe.Pointer, flags uint64) int {
	return int(C.bpf_map_update_elem(C.int(m), k, v, C.ulonglong(flags)))
}

func (m Map) GetNextKey(k, n unsafe.Pointer) int {
	return int(C.bpf_map_get_next_key(C.int(m), k, n))
}

func (m Map) DeleteElem(k unsafe.Pointer) int {
	return int(C.bpf_map_delete_elem(C.int(m), k))
}

func (m Map) LookupAndDeleteElem(k, v unsafe.Pointer) int {
	return int(C.bpf_map_lookup_and_delete_elem(C.int(m), k, v))
}

func KtimeGet() uint64 {
	return uint64(C.ktime_get())
}

func (m Map) CreateLruHash(index uint32, name string, key, val, max uint32) int {
	return int(C.create_lru_hash(C.int(m), C.int(index), C.CString(name), C.int(key), C.int(val), C.int(max)))
}

func (m Map) MaxEntries() int {
	return int(C.max_entries(C.int(m)))
}

func (x *XDP) SendRawPacket(iface int, h_dest, h_source [6]byte, packet []byte) bool {
	// ethernet frame: dst[6], source[6], transport_protocol[2] #define ETH_P_IP 0x0800
	var pkt [14 + 2048]byte

	pkt[12] = 0x08
	pkt[13] = 0x00

	copy(pkt[0:], h_dest[:])
	copy(pkt[6:], h_source[:])
	copy(pkt[14:], packet[:])

	return C.send_raw_packet(x.s, C.int(iface), (*C.char)(unsafe.Pointer(&pkt)), C.int(len(packet)+14)) == 0
}
