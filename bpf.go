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

package xvs

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io/ioutil"
)

//go:embed bpf/bpf.o.gz
var bpf_gz []byte
var bpf_o []byte

func init() {
	if z, err := gzip.NewReader(bytes.NewReader(bpf_gz)); err == nil {
		bpf_o, _ = ioutil.ReadAll(z)
	}
}

type bpf_nat struct {
	vip [4]byte
	vid uint16
	mac [6]byte
}

func (b *bpf_nat) String() string { return fmt.Sprintf("%s|%s|%d", b4s(b.vip), b6s(b.mac), b.vid) }

type bpf_redirect struct {
	addr   [4]byte
	index  uint32
	dest   [6]byte
	source [6]byte
}

func (b *bpf_redirect) String() string {
	return fmt.Sprintf("%s|%d|%s|%s", b4s(b.addr), b.index, b6s(b.source), b6s(b.dest))
}

type bpf_counter struct {
	packets uint64
	octets  uint64
	flows   uint64
	_pad    uint64
}

func (c *bpf_counter) add(a bpf_counter) {
	c.octets += a.octets
	c.packets += a.packets
	c.flows += a.flows
}

type bpf_service struct {
	vip      [4]byte
	port     [2]byte
	protocol uint8
	_pad     uint8
}
type bpf_vrpp struct {
	vip      [4]byte //__be32 vip;
	rip      [4]byte //__be32 rip;
	port     [2]byte //__be16 port;
	protocol byte    //__u8 protocol;
	pad      byte    //__u8 pad;
}

type bpf_backend struct {
	real [256]bpf_real
	hash [8192]byte
}

type bpf_real struct {
	rip  [4]byte //__be32
	vid  uint16
	mac  [6]byte
	flag [4]byte
}

type bpf_global struct {
	rx_packets     uint64
	rx_octets      uint64
	perf_packets   uint64
	perf_timens    uint64
	perf_timer     uint64
	settings_timer uint64
	new_flows      uint64
	dropped        uint64
	qfailed        uint64
	blocked        uint64
}

func (g *bpf_global) add(a bpf_global) {
	g.rx_packets += a.rx_packets
	g.rx_octets += a.rx_octets
	g.perf_packets += a.perf_packets
	g.perf_timens += a.perf_timens
	g.new_flows += a.new_flows
	g.qfailed += a.qfailed
	g.dropped += a.dropped
	g.blocked += a.blocked
}

func (g *bpf_global) latency() uint64 {
	var latency uint64 = 500 // 500ns target value
	if g.perf_packets > 0 {
		latency = g.perf_timens / g.perf_packets
	}
	return latency
}

type bpf_setting struct {
	heartbeat uint32
	era       uint8
	features  uint8
	pad1      uint8
	pad2      uint8
}
