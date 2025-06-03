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
	"log"
	"net/netip"
	"time"
	"unsafe"

	"github.com/davidcoles/xvs/bpf"
	"github.com/davidcoles/xvs/xdp"
)

//go:embed bpf/layer3.o.gz
var layer3_gz []byte

const ft_size uint32 = 36
const flow_size uint32 = 80
const notLocal uint8 = bpf.F_NOT_LOCAL
const buffer_length = bpf.BUFFER

const (
	NONE TunnelType = bpf.T_NONE
	IPIP TunnelType = bpf.T_IPIP
	GRE  TunnelType = bpf.T_GRE
	FOU  TunnelType = bpf.T_FOU
	GUE  TunnelType = bpf.T_GUE

	Sticky Flags = bpf.F_STICKY

	TunnelEncapNoChecksums TunnelFlags = bpf.F_TUNNEL_ENCAP_NO_CHECKSUMS
)

func ktime() uint64 { return xdp.KtimeGet() * uint64(time.Second) }

func layer3_o() ([]byte, error) {
	z, err := gzip.NewReader(bytes.NewReader(layer3_gz))
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(z)
}

const flow_version = bpf.FLOW_VERSION

type maps struct {
	xdp             *xdp.XDP
	nat_to_vip_rip  xdp.Map
	redirect_map4   xdp.Map
	redirect_map6   xdp.Map
	flow_queue      xdp.Map
	icmp_queue      xdp.Map
	services        xdp.Map
	vlaninfo        xdp.Map
	settings        xdp.Map
	sessions        xdp.Map
	global_metrics  xdp.Map
	service_metrics xdp.Map
	vip_metrics     xdp.Map
	shared          xdp.Map
	stats           xdp.Map
}

func (m *maps) counters(vrpp bpf_vrpp, t uint64) (c bpf_counter) {
	all := make([]bpf_counter, xdp.BpfNumPossibleCpus())

	m.stats.LookupElem(uP(&vrpp), uP(&(all[0])))

	for _, v := range all {
		c.add(v)
	}

	c._current = t

	return c
}

func (m *maps) globals(concurrent uint64) (c bpf_global) {
	var ZERO uint32 = 0
	all := make([]bpf_global_, xdp.BpfNumPossibleCpus()+1)

	m.global_metrics.LookupElem(uP(&ZERO), uP(&(all[0])))

	var b bpf_global_

	for _, v := range all {
		b.add(v)
	}

	c = *((*bpf_global)(uP(&b)))

	c._current = concurrent

	return c
}

func (m *maps) virtualMetrics(a16 addr16, concurrent uint64) (c bpf_global) {
	all := make([]bpf_global_, xdp.BpfNumPossibleCpus()+1)

	m.vip_metrics.LookupElem(uP(&a16), uP(&(all[0])))

	var b bpf_global_

	for _, v := range all {
		b.add(v)
	}

	c = *((*bpf_global)(uP(&b)))

	c._current = concurrent

	return
}

func (m *maps) serviceMetrics(key bpf_servicekey, concurrent uint64) (c bpf_global) {
	all := make([]bpf_global_, xdp.BpfNumPossibleCpus()+1)

	m.service_metrics.LookupElem(uP(&key), uP(&(all[0])))

	var b bpf_global_

	for _, v := range all {
		b.add(v)
	}

	c = *((*bpf_global)(uP(&b)))

	c._current = concurrent

	return
}

func (m *maps) createCounters(vrpp bpf_vrpp) {
	counters := make([]bpf_counter, xdp.BpfNumPossibleCpus())
	m.stats.UpdateElem(uP(&vrpp), uP(&counters[0]), xdp.BPF_NOEXIST)

	sessions := make([]int64, xdp.BpfNumPossibleCpus())
	m.sessions.UpdateElem(uP(&vrpp), uP(&sessions[0]), xdp.BPF_NOEXIST)
	vrpp.protocol |= 0xff00
	m.sessions.UpdateElem(uP(&vrpp), uP(&sessions[0]), xdp.BPF_NOEXIST)
}

func (m *maps) removeCounters(vrpp bpf_vrpp) {
	m.stats.DeleteElem(uP(&vrpp))
	m.sessions.DeleteElem(uP(&vrpp))
	vrpp.protocol |= 0xff00
	m.sessions.DeleteElem(uP(&vrpp))
}

func (m *maps) readAndClearSession(vrpp bpf_vrpp, era bool) (total uint64) {
	all := make([]int64, xdp.BpfNumPossibleCpus())

	if era {
		vrpp.protocol |= 0xff00
	}

	m.sessions.LookupElem(uP(&vrpp), uP(&all[0]))

	for i, v := range all {
		if v > 0 {
			total += uint64(v)
		}
		all[i] = 0
	}

	m.sessions.UpdateElem(uP(&vrpp), uP(&all[0]), xdp.BPF_EXIST)

	return
}

func (m *maps) removeService(key bpf_servicekey) {
	m.services.DeleteElem(uP(&key))
	m.service_metrics.DeleteElem(uP(&key))
}

func (m *maps) setService(key bpf_servicekey, fwd bpf_service) {
	m.services.UpdateElem(uP(&key), uP(&fwd), xdp.BPF_ANY)
	v16 := key.addr
	all := make([]bpf_global, xdp.BpfNumPossibleCpus()+1)
	m.vip_metrics.UpdateElem(uP(&v16), uP(&all[0]), xdp.BPF_NOEXIST)
	m.service_metrics.UpdateElem(uP(&key), uP(&all[0]), xdp.BPF_NOEXIST)
}

func (m *maps) updateSettings(settings bpf_settings) int {
	var ZERO uint32 = 0

	all := make([]bpf_settings, xdp.BpfNumPossibleCpus())
	for i, _ := range all {
		all[i] = settings
	}

	return m.settings.UpdateElem(uP(&ZERO), uP(&all[0]), xdp.BPF_ANY)
}

func (m *maps) nat(key addr16, vip_rip bpf_vip_rip) {
	m.nat_to_vip_rip.UpdateElem(uP(&key), uP(&vip_rip), xdp.BPF_ANY) // FIXME
}

func (m *maps) readLatency() uint64 {
	var ZERO uint32 = 0
	var packets uint64
	var latency uint64

	all := make([]bpf_settings, xdp.BpfNumPossibleCpus())
	m.settings.LookupElem(uP(&ZERO), uP(&all[0]))

	for _, s := range all {
		packets += s.packets
		latency += s.latency
	}

	if packets > 0 {
		return latency / packets
	}

	return 0
}

func (m *maps) writeFlow(f []byte) {
	if len(f) == int(ft_size+flow_size) && f[len(f)-1] == flow_version {
		key := uP(&f[0])
		val := uP(&f[ft_size])
		time := (*uint64)(val)
		*time = ktime() // set first 8 bytes of state to the local kernel time
		m.shared.UpdateElem(key, val, xdp.BPF_ANY)
	}
}

func (m *maps) init(bpf []byte) (err error) {

	if len(bpf) == 0 {
		if bpf, err = layer3_o(); err != nil {
			return err
		}
	}

	x, err := xdp.LoadBpfFile(bpf)

	if err != nil {
		return err
	}

	m.xdp = x

	if unsafe.Sizeof(bpf_global_{}) != unsafe.Sizeof(bpf_global{}) {
		return fmt.Errorf("Inconsistent bpf_global definition")
	}

	if unsafe.Sizeof(bpf_tunnel{}) != 64 {
		return fmt.Errorf("Tunnel size is not 64 bytes")
	}

	if m.redirect_map4, err = x.FindMap("redirect_map4", 4, 4); err != nil {
		return err
	}

	if m.redirect_map6, err = x.FindMap("redirect_map6", 4, 4); err != nil {
		return err
	}

	if m.services, err = x.FindMap("services", int(unsafe.Sizeof(bpf_servicekey{})), int(unsafe.Sizeof(bpf_service{}))); err != nil {
		return err
	}

	if m.service_metrics, err = x.FindMap("service_metrics", int(unsafe.Sizeof(bpf_servicekey{})), int(unsafe.Sizeof(bpf_global{}))); err != nil {
		return err
	}

	if m.nat_to_vip_rip, err = x.FindMap("nat_to_vip_rip", 16, int(unsafe.Sizeof(bpf_vip_rip{}))); err != nil {
		return err
	}

	if m.vlaninfo, err = x.FindMap("vlaninfo", 4, int(unsafe.Sizeof(bpf_vlaninfo{}))); err != nil {
		return err
	}

	if m.settings, err = x.FindMap("settings", 4, int(unsafe.Sizeof(bpf_settings{}))); err != nil {
		return err
	}

	if m.stats, err = x.FindMap("stats", int(unsafe.Sizeof(bpf_vrpp{})), int(unsafe.Sizeof(bpf_counter{}))); err != nil {
		return err
	}

	if m.sessions, err = x.FindMap("vrpp_concurrent", int(unsafe.Sizeof(bpf_vrpp{})), 8); err != nil {
		return err
	}

	if m.flow_queue, err = x.FindMap("flow_queue", 0, int(ft_size+flow_size)); err != nil {
		return err
	}

	if m.icmp_queue, err = x.FindMap("icmp_queue", 0, 2048); err != nil {
		return err
	}

	if m.shared, err = x.FindMap("shared", int(ft_size), int(flow_size)); err != nil {
		return err
	}

	if m.global_metrics, err = x.FindMap("global_metrics", 4, int(unsafe.Sizeof(bpf_global{}))); err != nil {
		return err
	}

	if m.vip_metrics, err = x.FindMap("vip_metrics", 16, int(unsafe.Sizeof(bpf_global{}))); err != nil {
		return err
	}

	return nil
}

func (m *maps) initialiseFlows(max uint32) error {

	flows_tcp, err := m.xdp.FindMap("flows_tcp", 4, 4)

	if err != nil {
		return err
	}

	if max == 0 {
		// default max entries to be the same as the shared map
		max_entries := m.shared.MaxEntries()

		if max_entries < 1 {
			return fmt.Errorf("Error looking up size of the flow state map")
		}

		max = uint32(max_entries)
	}

	max_cpu := flows_tcp.MaxEntries()

	if max_cpu < 1 {
		return fmt.Errorf("Error looking up size of the CPU flow state map")
	}

	num_cpu := xdp.BpfNumPossibleCpus()

	if num_cpu > max_cpu {
		return fmt.Errorf("Number of CPUs is greater than the number compiled in to the ELF object")
	}

	for cpu := 0; cpu < num_cpu; cpu++ {
		name := fmt.Sprintf("flows_tcp_inner_%d", cpu)
		if r := flows_tcp.CreateLruHash(uint32(cpu), name, ft_size, flow_size, max); r != 0 {
			return fmt.Errorf("Unable to create flow state map for CPU %d: %d", cpu, r)
		}
	}

	return nil
}

func (m *maps) clean(vips map[netip.Addr]bool, vrpp map[bpf_vrpp]bool, nats map[netip.Addr]bool, test bool) {

	clean_addr := func(m xdp.Map, a map[netip.Addr]bool) {
		b := map[addr16]bool{}

		for k, _ := range a {
			b[as16(k)] = true
		}

		var key, next, nul addr16
		for r := 0; r == 0; key = next {
			r = m.GetNextKey(uP(&key), uP(&next))
			if _, exists := b[key]; !exists && key != nul {
				m.DeleteElem(uP(&key))
			}
		}
	}

	clean_svc := func(m xdp.Map, all map[bpf_servicekey]bool) {
		var key, next, nul bpf_servicekey
		for r := 0; r == 0; key = next {
			r = m.GetNextKey(uP(&key), uP(&next))
			if _, exists := all[key]; !exists && key != nul {
				m.DeleteElem(uP(&key))
				if test {
					log.Fatal("clean_svc", key)
				}
			}
		}
	}

	clean_vrpp := func(m xdp.Map, a map[bpf_vrpp]bool) {
		var key, next, nul bpf_vrpp
		for r := 0; r == 0; key = next {
			r = m.GetNextKey(uP(&key), uP(&next))
			if _, exists := a[key]; !exists && key != nul {
				m.DeleteElem(uP(&key))
				if test {
					log.Fatal("clean_map2 ", key)
				}
			}
		}
	}

	clean_addr(m.vip_metrics, vips)
	clean_addr(m.nat_to_vip_rip, nats)
	clean_vrpp(m.stats, vrpp)
	clean_vrpp(m.sessions, vrpp)
	clean_svc(m.services, nil)
}
