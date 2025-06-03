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
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
)

type netinfo struct {
	vlan4 map[uint16]vlaninfo
	vlan6 map[uint16]vlaninfo
	route map[netip.Prefix]uint16
	mac   map[netip.Addr]mac
}

// could lose this
type neighbor struct {
	dev string
	mac mac
}

func (n *netinfo) config(vlan4, vlan6 map[uint16]netip.Prefix, route map[netip.Prefix]uint16) {
	n.mac = n.hw()
	n.vlan4 = n.conf2(vlan4)
	n.vlan6 = n.conf2(vlan6)
	n.route = map[netip.Prefix]uint16{}
	for k, v := range route {
		n.route[k] = v
	}
}

func (n *netinfo) hw() map[netip.Addr]mac {

	r := n.arp()

	for a, n := range n.hw6() {
		r[a] = n.mac
	}

	return r
}

func (n *netinfo) bestInterface(prefix netip.Prefix) (*net.Interface, netip.Addr) {
	var ok bool
	var bits int
	var best net.Interface
	var foo netip.Addr

	ipv6 := prefix.Addr().Is6()

	if ifaces, err := net.Interfaces(); err == nil {

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

			if addr, err := i.Addrs(); err == nil {
				for _, a := range addr {
					cidr := a.String()

					if p, err := netip.ParsePrefix(cidr); err == nil && p.Addr().Is6() == ipv6 {

						if p.Overlaps(prefix) && p.Bits() > bits {
							ok = true
							best = i
							foo = p.Addr()
						}
					}
				}
			}
		}
	}

	if !ok {
		return nil, foo
	}

	return &best, foo
}

func (n *netinfo) hw6() map[netip.Addr]neighbor {

	hw6 := map[netip.Addr]neighbor{}

	cmd := exec.Command("/bin/sh", "-c", "ip -6 neighbor show")
	_, _ = cmd.StdinPipe()
	//stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()

	re := regexp.MustCompile(`^(\S+)\s+dev\s+(\S+)\s+lladdr\s+(\S+)\s+(\S+)\s*$`)

	if err := cmd.Start(); err != nil {
		return nil
	}

	defer stdout.Close()

	s := bufio.NewScanner(stdout)

	for s.Scan() {
		line := s.Text()

		m := re.FindStringSubmatch(line)

		if len(m) != 5 {
			continue
		}

		addr, err := netip.ParseAddr(m[1])

		if err != nil {
			continue
		}

		dev := m[2]

		hw, err := net.ParseMAC(m[3])

		if err != nil || len(hw) != 6 {
			continue
		}

		var mac mac

		copy(mac[:], hw[:])

		hw6[addr] = neighbor{dev: dev, mac: mac}
	}

	return hw6
}

func (n *netinfo) arp() map[netip.Addr]mac {

	ip2mac := make(map[netip.Addr]mac)

	// flags: https://superuser.com/questions/822054/definition-of-arp-result-flags/822089#822089
	// 0x0 incomplete
	// 0x2 complete
	// 0x6 complete and manually set

	re := regexp.MustCompile(`^(\S+)\s+0x1\s+0x[26]\s+(\S+)\s+\S+\s+(\S+)$`)

	file, err := os.OpenFile("/proc/net/arp", os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil
	}
	defer file.Close()

	s := bufio.NewScanner(file)
	for s.Scan() {
		line := s.Text()

		m := re.FindStringSubmatch(line)

		if len(m) != 4 {
			continue
		}

		ip := net.ParseIP(m[1])

		if ip == nil {
			continue
		}

		ip = ip.To4()

		if ip == nil || len(ip) != 4 {
			continue
		}

		hw, err := net.ParseMAC(m[2])

		if err != nil || len(hw) != 6 {
			continue
		}

		var ip4 [4]byte
		var mac [6]byte

		copy(ip4[:], ip[:])
		copy(mac[:], hw[:])

		if ip4 == [4]byte{0, 0, 0, 0} {
			continue
		}

		if mac == [6]byte{0, 0, 0, 0, 0, 0} {
			continue
		}

		ip2mac[netip.AddrFrom4(ip4)] = mac
	}

	return ip2mac
}

func (n *netinfo) vlaninfo(i uint16) (bpf_vlaninfo, uint32, uint32) {
	v4 := n.vlan4[i]
	v6 := n.vlan6[i]

	return bpf_vlaninfo{
		ip4: as16(v4.ip_addr),
		ip6: as16(v6.ip_addr),
		hw4: v4.hw_addr,
		hw6: v6.hw_addr,
		gh4: v4.gw_hw_addr,
		gh6: v6.gw_hw_addr,
	}, uint32(v4.if_index), uint32(v6.if_index)
}

type vlaninfo struct {
	prefix     netip.Prefix
	ip_addr    netip.Addr
	hw_addr    mac
	if_index   int
	gw_ip_addr netip.Addr
	gw_hw_addr mac
}

func (v vlaninfo) String() string {
	return fmt.Sprint(v.prefix, v.ip_addr, v.hw_addr, v.gw_ip_addr, v.gw_hw_addr)
}

func (n *netinfo) ext(id uint16, v6 bool) netip.Addr {
	if v6 {
		return n.vlan6[id].ip_addr
	}
	return n.vlan4[id].ip_addr
}

func (n *netinfo) routers() (r []netip.Addr) {
	for _, v := range n.vlan4 {
		if v.gw_ip_addr.IsValid() {
			r = append(r, v.gw_ip_addr)
		}
	}
	for _, v := range n.vlan6 {
		if v.gw_ip_addr.IsValid() {
			r = append(r, v.gw_ip_addr)
		}

	}
	return
}

func (n *netinfo) conf2(vlan map[uint16]netip.Prefix) (r map[uint16]vlaninfo) {

	r = map[uint16]vlaninfo{}

	for id, prefix := range vlan {
		if iface, ip_addr := n.bestInterface(prefix.Masked()); iface != nil {

			var hw_addr mac
			copy(hw_addr[:], iface.HardwareAddr[:])

			var gw_ip_addr netip.Addr
			var gw_hw_addr mac

			if prefix.Masked() != prefix {
				gw_ip_addr = prefix.Addr()
				gw_hw_addr = n.mac[prefix.Addr()]
			}

			r[id] = vlaninfo{
				prefix:     prefix,
				if_index:   iface.Index,
				ip_addr:    ip_addr,
				hw_addr:    hw_addr,
				gw_ip_addr: gw_ip_addr,
				gw_hw_addr: gw_hw_addr,
			}
		}
	}

	return
}

func (n *netinfo) find(ip netip.Addr) (c backend) {

	vlan := n.vlan4
	bits := 0

	if ip.Is6() {
		vlan = n.vlan6
	}

	for id, v := range vlan {
		if v.prefix.Contains(ip) {
			return backend{_l: true, vlanid: id, _i: v.if_index, hw_src: v.hw_addr, hw_dst: n.mac[ip], ip_src: v.ip_addr, ip_dst: ip}
		}
	}

	for prefix, id := range n.route {

		if prefix.Contains(ip) && prefix.Bits() > bits {
			//fmt.Println("MATCH?") // need to check if the VLAN has a gateway - or should we just obey?
			if v, ok := vlan[id]; ok && v.gw_ip_addr.IsValid() {
				bits = prefix.Bits()

				//fmt.Println("MATCHED", prefix, id, bits)
				return backend{vlanid: id, _i: v.if_index, hw_src: v.hw_addr, hw_dst: v.gw_hw_addr, ip_src: v.ip_addr, ip_dst: ip}
			}
			return
		}
	}

	// default route
	for id := uint16(1); id < 4095; id++ {
		if v, ok := vlan[id]; ok && v.gw_ip_addr.IsValid() {
			return backend{vlanid: id, _i: v.if_index, hw_src: v.hw_addr, hw_dst: v.gw_hw_addr, ip_src: v.ip_addr, ip_dst: ip}
		}
	}

	return
}

// can probably skip this and go straight to bpf_tunnel
type backend struct {
	vlanid uint16
	hw_src mac
	hw_dst mac
	ip_src netip.Addr
	ip_dst netip.Addr

	_l bool // local
	_i int  // interface
}

func (b backend) remote() bool {
	return !b._l
}

func (b backend) bpf_tunnel(method TunnelType, flags TunnelFlags, dport uint16) (t bpf_tunnel) {
	if !b.ok() {
		return
	}

	if method == NONE && b.remote() {
		return // we can't sent to layer 2 DSR via a router - it must be local
	}

	var hints uint8

	if b.remote() {
		hints |= notLocal
	}

	return bpf_tunnel{
		daddr:      as16(b.ip_dst),
		saddr:      as16(b.ip_src),
		dport:      dport,
		sport:      0,
		vlanid:     b.vlanid,
		method:     uint8(method),
		flags:      uint8(flags),
		h_dest:     b.hw_dst,
		h_source:   b.hw_src,
		hints:      hints,
		_interface: uint32(b._i),
	}
}

func (b backend) ok() bool {
	var nul mac

	if b.vlanid == 0 || b._i == 0 {
		return false
	}

	if b.hw_src == nul || b.hw_dst == nul {
		return false
	}

	if !b.ip_src.IsValid() || !b.ip_dst.IsValid() {
		return false
	}

	return true
}

func (b backend) String() string {
	return fmt.Sprintf("[rem:%v %d(%d) %s->%s %s->%s]", b.remote(), b.vlanid, b._i, b.hw_src, b.hw_dst, b.ip_src, b.ip_dst)
}
