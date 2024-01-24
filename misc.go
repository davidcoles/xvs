/*
 * VC5 load balancer. Copyright (C) 2021-present David Coles
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
	"fmt"
	"net"
	"sort"

	"github.com/davidcoles/xvs/bpf"
)

type Info struct {
	Packets   uint64
	Octets    uint64
	Flows     uint64
	Latency   uint64
	Dropped   uint64
	Blocked   uint64
	NotQueued uint64
}

type Stats struct {
	Packets uint64
	Octets  uint64
	Flows   uint64
	Current uint64
}

func (s *Stats) add(a Stats) {
	s.Packets += a.Packets
	s.Octets += a.Octets
	s.Flows += a.Flows
	s.Current += a.Current
}

func (s Stats) String() string {
	return fmt.Sprintf("p:%d o:%d f:%d", s.Packets, s.Octets, s.Flows)
}

// func update_backend(curr, prev *be_state) bool {
func (curr *be_state) update_backend(prev *be_state) bool {

	if !curr.diff(prev) {
		return false
	}

	var flag [4]byte

	if curr.sticky {
		flag[0] |= bpf.F_STICKY
	}

	if curr.fallback {
		flag[0] |= bpf.F_FALLBACK
	}

	mapper := map[[4]byte]uint8{}

	var list []IP4

	for ip, _ := range curr.bpf_reals {
		list = append(list, ip)
	}

	sort.SliceStable(list, func(i, j int) bool {
		return nltoh(list[i]) < nltoh(list[j])
	})

	var real [256]bpf_real

	for i, ip := range list {
		if i < 255 {
			idx := uint8(i) + 1
			mapper[ip] = idx
			real[idx] = curr.bpf_reals[ip]
		} else {
			fmt.Println("more than 255 hosts", ip, i)
		}
	}

	curr.bpf_backend.real = real
	curr.bpf_backend.hash, _ = maglev8192(mapper)

	var rip IP4
	var mac MAC
	var vid [2]byte

	if !curr.leastconns.IsNil() {
		if n, ok := mapper[curr.leastconns]; ok {
			flag[1] = curr.weight
			rip = real[n].rip
			mac = real[n].mac
			vid = real[n].vid
		}
	}

	curr.bpf_backend.real[0] = bpf_real{rip: rip, mac: mac, vid: vid, flag: flag}

	return true
}

func (curr *be_state) diff(prev *be_state) bool {

	bpf_reals_differ := func(a, b map[IP4]bpf_real) bool {
		for k, v := range a {
			if x, ok := b[k]; !ok {
				return true
			} else {
				if x != v {
					return true
				}
			}
		}

		for k, _ := range b {
			if _, ok := a[k]; !ok {
				return true
			}
		}

		return false
	}

	if prev == nil {
		return true
	}

	if curr.sticky != prev.sticky ||
		curr.fallback != prev.fallback ||
		curr.leastconns != prev.leastconns ||
		curr.weight != prev.weight {
		return true
	}

	if bpf_reals_differ(curr.bpf_reals, prev.bpf_reals) {
		return true
	}

	return false
}

func DefaultInterface(addr IP4) *net.Interface {

	fmt.Println(addr)

	ADDR := net.IP(addr[:])

	ifaces, err := net.Interfaces()

	if err != nil {
		return nil
	}

	for _, i := range ifaces {

		if i.Flags&net.FlagLoopback != 0 {
			continue
		}

		if i.Flags&net.FlagUp == 0 {
			continue
		}

		if i.Flags&net.FlagBroadcast == 0 {
			continue
		}

		if len(i.HardwareAddr) != 6 {
			continue
		}

		var mac MAC
		copy(mac[:], i.HardwareAddr[:])

		addr, err := i.Addrs()

		if err == nil {
			for _, a := range addr {

				cidr := a.String()
				ip, _, err := net.ParseCIDR(cidr)

				ip4 := ip.To4()

				fmt.Println(err, ip4, ip)

				if err == nil && ip4 != nil && ip.Equal(ADDR) {
					return &i
				}
			}
		}
	}

	return nil
}

func VlanInterfaces(in map[uint16]net.IPNet) map[uint16]iface {
	out := map[uint16]iface{}

	for vid, pref := range in {
		if iface, ok := VlanInterface(pref); ok {
			out[vid] = iface
		}
	}

	return out
}

func VlanInterface(prefix net.IPNet) (ret iface, _ bool) {
	ifaces, err := net.Interfaces()

	if err != nil {
		return
	}

	for _, i := range ifaces {

		if i.Flags&net.FlagLoopback != 0 {
			continue
		}

		if i.Flags&net.FlagUp == 0 {
			continue
		}

		if i.Flags&net.FlagBroadcast == 0 {
			continue
		}

		if len(i.HardwareAddr) != 6 {
			continue
		}

		var mac MAC
		copy(mac[:], i.HardwareAddr[:])

		addr, err := i.Addrs()

		if err == nil {
			for _, a := range addr {
				cidr := a.String()
				ip, ipnet, err := net.ParseCIDR(cidr)

				if err == nil && ipnet.String() == prefix.String() {
					ip4 := ip.To4()
					if len(ip4) == 4 && ip4 != nil {
						return iface{idx: uint32(i.Index), ip4: IP4(ip4), mac: mac, nic: i.Name}, true
					}
				}
			}
		}
	}

	return
}

type natkeyval struct {
	key bpf_natkey
	val bpf_natval
}

type iface struct {
	idx uint32
	ip4 IP4
	mac MAC
	nic string
}

func (i iface) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("%s:%d:%s:%s", i.nic, i.idx, i.ip4, i.mac)), nil
}

type be_state struct {
	sticky      bool
	fallback    bool
	leastconns  IP4
	weight      uint8
	bpf_backend bpf_backend
	bpf_reals   map[IP4]bpf_real
}
