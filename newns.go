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
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"time"

	"github.com/davidcoles/xvs/xdp"
)

type newns struct {
	a, b nic
	ns   string
}

//func (n *newns) namespace() string { return n.ns }
//func (n *newns) addr() [4]byte     { return n.b.ip4 }
//func (n *newns) id() uint32        { return uint32(n.a.idx) }

func (n *newns) nat4(i uint16) (nat [16]byte) {
	nat = n.nat6(i)
	nat[0] = 0
	nat[1] = 0
	return
}
func (n *newns) nat6(i uint16) (nat [16]byte) {
	nat = n.a.ip6 //netip.MustParseAddr(IP6_2).As16()
	nat[13] = 0
	nat[14] = byte(i >> 8)
	nat[15] = byte(i & 0xff)
	return
}

func (n *newns) ipv4() [4]byte  { return n.b.ip4 }
func (n *newns) ipv6() [16]byte { return n.b.ip6 }

func nat3(x *xdp.XDP, inside string, outside string) (*newns, error) {

	const IP6_A = "fefe::ffff:fffd"
	const IP6_B = "fefe::ffff:fffe"

	namespace := "l3"

	var n newns
	n.ns = namespace
	n.a.nic = namespace
	n.b.nic = namespace + "ns"

	n.a.ip6 = netip.MustParseAddr(IP6_A).As16()
	n.b.ip6 = netip.MustParseAddr(IP6_B).As16()

	copy(n.a.ip4[:], n.a.ip6[12:])
	copy(n.b.ip4[:], n.b.ip6[12:])

	if err := n.create_pair(n.a.nic, n.b.nic); err != nil {
		return nil, err
	}

	time.Sleep(time.Second * 1) // TODO race condition with assigned MACs

	if iface, err := net.InterfaceByName(n.a.nic); err != nil {
		return nil, err
	} else {
		copy(n.a.mac[:], iface.HardwareAddr[:])
		n.a.idx = iface.Index
	}

	if iface, err := net.InterfaceByName(n.b.nic); err != nil {
		return nil, err
	} else {
		copy(n.b.mac[:], iface.HardwareAddr[:])
		n.b.idx = iface.Index
	}

	if err := x.LoadBpfSection(inside, false, uint32(n.a.idx)); err != nil {
		return nil, err
	}

	// this seems to be needed to make native mode hardware work
	if err := x.LoadBpfSection(outside, true, uint32(n.b.idx)); err != nil {
		return nil, err
	}

	if err := n.config_pair(n.ns, n.a, n.b); err != nil {
		return nil, err
	}

	return &n, nil
}

func (n *newns) clean() {
	script := `
    ip link del ` + n.a.nic + ` >/dev/null 2>&1 || true
    ip netns del ` + n.ns + ` >/dev/null 2>&1 || true
`
	exec.Command("/bin/sh", "-e", "-c", script).Output()
}

func (n *newns) create_pair(if1, if2 string) error {
	script := `
ip link del ` + if1 + ` >/dev/null 2>&1 || true
ip link add ` + if1 + ` type veth peer name ` + if2 + `
`
	if _, err := exec.Command("/bin/sh", "-e", "-c", script).Output(); err != nil {
		return fmt.Errorf("Error creating netns pair: %s", err.Error())
	}
	return nil
}

// can set mac: ip l set vc5 addr 26:7c:d6:2c:d9:32
func (n *newns) config_pair(ns string, a, b nic) error {
	ip1 := a.ip4.String()
	ip2 := b.ip4.String()
	cb := a.ip4
	cb[1] = 0
	cb[2] = 0
	cb[3] = 0
	cbs := cb.String() + "/8"

	ip6_1 := a.ip6.String()
	ip6_2 := b.ip6.String()
	//cb6 := "fefe::ff00:0"
	cb6x := a.ip6
	cb6x[13] = 0
	cb6x[14] = 0
	cb6x[15] = 0
	cb6 := cb6x.String() + "/104"

	script := `
ip netns del ` + ns + ` >/dev/null 2>&1 || true
ip l set ` + a.nic + ` up
ip a add ` + ip1 + `/30 dev ` + a.nic + `
#ip r replace ` + cbs + ` via ` + ip2 + `

ip netns add ` + ns + `
ip link set ` + b.nic + ` netns ` + ns + `

ip netns exec ` + ns + ` ip l set ` + b.nic + ` up
ip netns exec ` + ns + ` ip a add ` + ip2 + `/30 dev ` + b.nic + `
ip netns exec ` + ns + ` ip r replace default via ` + ip1 + `

ip -6 a add ` + ip6_1 + `/126 dev ` + a.nic + `
#ip -6 r replace ` + cb6 + ` via ` + ip6_2 + `
ip netns exec ` + ns + ` ip -6 a add ` + ip6_2 + `/126 dev ` + b.nic + `
ip netns exec ` + ns + ` ip -6 r replace default via ` + ip6_1 + `

ip netns exec ` + ns + ` ethtool -K ` + b.nic + ` tx off
`

	if out, err := exec.Command("/bin/sh", "-e", "-c", script).Output(); err != nil {
		fmt.Println(out)
		return fmt.Errorf("Error seting up netns: %s", err.Error())
	}

	return nil
}
