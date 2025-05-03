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
	"log"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
)

type netinfo struct {
	vinfo4  vinfo
	vinfo6  vinfo
	l2info4 l2info
	l2info6 l2info
	l3info4 l3info
	l3info6 l3info
	hwinfo  hwinfo
	rtinfo  rtinfo
}
type neighbor struct {
	dev string
	mac mac
}

type fu struct {
	ifindex uint32
	hw      mac
	ip      netip.Addr
}

type hwinfo = map[netip.Addr]mac
type l2info = map[uint16]fu

// type l3info = map[uint16]mac
type l3info = map[uint16]fu
type vinfo = map[uint16]netip.Prefix
type rtinfo = map[netip.Prefix]uint16

func (n *netinfo) info(a netip.Addr) (ninfo, error) {
	if a.Is4() {
		return n.info2(a, n.vinfo4, n.l2info4, n.l3info4)
	}

	return n.info2(a, n.vinfo6, n.l2info6, n.l3info6)
}

func (n *netinfo) ext(id uint16, v6 bool) netip.Addr {
	if v6 {
		return n.l2info6[id].ip
	}
	return n.l2info4[id].ip
}

func (n *netinfo) info2(a netip.Addr, vinfo vinfo, l2info l2info, l3info l3info) (ninfo, error) {
	var vlan uint16
	var bits int
	var f fu
	var h_dest mac
	var l3 bool
	var gw netip.Addr

	for id, p := range vinfo {
		if p.Contains(a) && p.Bits() > bits {
			bits = p.Bits()
			vlan = id
		}
	}

	if vlan != 0 {
		// local device
		f = l2info[vlan]
		h_dest = n.hwinfo[a]
	} else {
		// not local, work out routing

		l3 = true
		bits = 0

		for p, id := range n.rtinfo {
			if p.Contains(a) && p.Bits() > bits {
				bits = p.Bits()
				vlan = id

				x, ok := l3info[id]
				if !ok {
					return ninfo{}, fmt.Errorf("Desination unreachable")
				}
				h_dest = x.hw
				gw = x.ip
			}
		}

		if vlan == 0 {
			for id, x := range l3info {
				if id > vlan {
					vlan = id
					//h_dest = mac
					h_dest = x.hw
					gw = x.ip
				}
			}
		}

		if vlan == 0 {
			return ninfo{}, fmt.Errorf("Desination unreachable")
		}

		g, ok := vinfo[vlan]

		if !ok {
			return ninfo{}, fmt.Errorf("Desination unreachable")
		}

		gw = g.Addr()
		f = l2info[vlan]
	}

	return ninfo{
		saddr:    f.ip,
		h_source: f.hw,
		ifindex:  f.ifindex,
		daddr:    a,
		h_dest:   h_dest,
		vlanid:   vlan,
		gw:       gw,
		l3:       l3,
	}, nil
}

type ninfo struct {
	saddr    netip.Addr
	daddr    netip.Addr
	h_source mac
	h_dest   mac
	vlanid   uint16
	ifindex  uint32
	gw       netip.Addr
	l3       bool
}

func (n ninfo) String() string {
	return fmt.Sprintf("{%s->%s [%s->%s] %d:%d %v:%s}", n.saddr, n.daddr, n.h_source.String(), n.h_dest.String(), n.vlanid, n.ifindex, n.l3, n.gw)
}

type vinfo2 = map[uint16][2]netip.Prefix

// func (n *netinfo) config(vlans vinfo2, rtinfo rtinfo) error {
func (n *netinfo) config(vlan4, vlan6 vinfo, rtinfo rtinfo) error {

	hw := n.hw()
	n.hwinfo = hw

	n.vinfo4 = vlan4
	n.vinfo6 = vlan6
	n.rtinfo = rtinfo

	l2info4, l3info4 := n.config2(vlan4, hw)
	l2info6, l3info6 := n.config2(vlan6, hw)

	for id, nic := range l2info4 {
		if nic.ifindex == 0 {
			log.Fatal("4: nic.ifindex == 0", id)
		}
		n, ok := l2info6[id]
		if ok && n.ifindex != nic.ifindex {
			log.Fatal("4: n.ifindex != nic.ifindex", id)
		}
	}

	for id, nic := range l2info6 {
		if nic.ifindex == 0 {
			log.Fatal("6: nic.ifindex == 0", id)
		}
		n, ok := l2info4[id]
		if ok && n.ifindex != nic.ifindex {
			log.Fatal("6: n.ifindex != nic.ifindex", id)
		}
	}

	fmt.Println("INFO4", l2info4, l3info4)
	fmt.Println("INFO6", l2info6, l3info6)

	n.l2info4 = l2info4
	n.l2info6 = l2info6
	n.l3info4 = l3info4
	n.l3info6 = l3info6

	return nil
}

func (n *netinfo) config2(vlan map[uint16]netip.Prefix, hw map[netip.Addr]mac) (l2info, l3info) {

	foo := map[uint16]fu{}
	l3 := map[uint16]fu{}

	for id, prefix := range vlan {

		// identify which interface we will use for health probes on this vlan,
		// the address that we should use as source IP, and the source MAC to use
		if i, a := n.bestInterface(prefix.Masked()); i != nil {

			f := fu{
				ifindex: uint32(i.Index),
				ip:      a,
			}

			if len(i.HardwareAddr) == 6 {
				copy(f.hw[:], i.HardwareAddr[:])
			}

			foo[id] = f

			// l3 eligible
			if prefix.Masked() != prefix {
				//l3[id] = hw[prefix.Addr()] // look up mac for address
				mac := hw[prefix.Addr()]
				l3[id] = fu{hw: mac, ip: prefix.Addr()}
			}
		}
	}

	return foo, l3
}

func (n *netinfo) hw() map[netip.Addr]mac {

	r := map[netip.Addr]mac{}

	arp, _ := arp()

	for a, m := range arp {
		r[netip.AddrFrom4(a)] = m
	}

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
							fmt.Println("BEST", i.Name, prefix)
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

	re := regexp.MustCompile(`^(\S+)\s+dev\s+(\S+)\s+lladdr\s+(\S+)\s+(\S+)$`)

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

// should go into netinfo?
func (netinfo *netinfo) vlaninfo(i uint32) (bpf_vlaninfo, uint32, uint32) {
	f4 := netinfo.l2info4[uint16(i)]
	f6 := netinfo.l2info6[uint16(i)]

	g4 := netinfo.l3info4[uint16(i)]
	g6 := netinfo.l3info6[uint16(i)]

	vi := bpf_vlaninfo{
		ip4: as4(f4.ip),
		gw4: as4(g4.ip),
		ip6: as16(f6.ip),
		gw6: as16(g6.ip),
		hw4: f4.hw,
		hw6: f6.hw,
		gh4: g4.hw,
		gh6: g6.hw,
	}
	return vi, f4.ifindex, f6.ifindex
}
