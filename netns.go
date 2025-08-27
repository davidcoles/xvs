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

type nic struct {
	idx int
	mac mac
	nic string
	ip4 netip.Addr
	ip6 netip.Addr
}

type netns struct {
	//ns    string
	vetha nic
	vethb nic
}

func (n *netns) nat(idx uint32, wantIPv6 bool) (r netip.Addr) {
	if idx == 0 || idx > 16777210 {
		return
	}

	nat := n.vetha.ip6.As16()
	nat[13] = byte((idx >> 16) & 0xff)
	nat[14] = byte((idx >> 8) & 0xff)
	nat[15] = byte(idx & 0xff)

	if wantIPv6 {
		return netip.AddrFrom16(nat)
	}

	var ip4 [4]byte
	copy(ip4[:], nat[12:])
	return netip.AddrFrom4(ip4)
}

const namespace = "xvs"

func (n *netns) netnsdel() {
	exec.Command("ip", "netns", "del", namespace).Output()
}

func (n *netns) nic() int     { return n.vetha.idx }
func (n *netns) src() [6]byte { return n.vetha.mac }
func (n *netns) dst() [6]byte { return n.vethb.mac }

func (n *netns) ipv4() netip.Addr { return n.vetha.ip4 }
func (n *netns) ipv6() netip.Addr { return n.vetha.ip6 }
func (n *netns) init(x *xdp.XDP) error {

	//	n.ns = namespace

	n.vetha.nic = namespace
	n.vethb.nic = namespace + "_"

	n.vetha.ip4 = netip.MustParseAddr("255.255.255.253")
	n.vetha.ip6 = netip.MustParseAddr("fefe::ffff:fffd")
	n.vethb.ip4 = n.vetha.ip4.Next()
	n.vethb.ip6 = n.vetha.ip6.Next()

	if err := n.create_pair(&n.vetha, &n.vethb); err != nil {
		return fmt.Errorf("Error creating netns: %s", err.Error())
	}

	if err := x.LoadBpfSection("xdp_request_func", false, uint32(n.vetha.idx)); err != nil {
		return err
	}

	if err := x.LoadBpfSection("xdp_mirror_func", false, uint32(n.vethb.idx)); err != nil {
		return err
	}

	if _, err := n.config_pair(namespace, n.vetha, n.vethb); err != nil {
		return fmt.Errorf("Error seting up netns: %s", err.Error())
	}

	return nil
}

func (n *netns) create_pair(a, b *nic) (err error) {
	script := `
ip link del ` + a.nic + ` >/dev/null 2>&1 || true
ip link add ` + a.nic + ` type veth peer name ` + b.nic + `
`
	if _, err = exec.Command("/bin/sh", "-e", "-c", script).Output(); err != nil {
		return err
	}

	time.Sleep(time.Second * 1) // TODO race condition with assigned MACs?

	if iface, err := net.InterfaceByName(a.nic); err != nil {
		return err
	} else {
		a.idx = iface.Index
		copy(a.mac[:], iface.HardwareAddr[:])
	}

	if iface, err := net.InterfaceByName(b.nic); err != nil {
		return err
	} else {
		b.idx = iface.Index
		copy(b.mac[:], iface.HardwareAddr[:])
	}

	return nil
}

// can set mac: ip l set vc5 addr 26:7c:d6:2c:d9:32
func (n *netns) config_pair(ns string, a, b nic) ([]byte, error) {
	a4 := a.ip4.String()
	b4 := b.ip4.String()
	p4, _ := a.ip4.Prefix(8)
	prefix4 := p4.String()

	a6 := a.ip6.String()
	b6 := b.ip6.String()
	p6, _ := a.ip6.Prefix(96)
	prefix6 := p6.String()

	script := `
ip netns del ` + ns + ` >/dev/null 2>&1 || true
ip netns add ` + ns + `

ip l set ` + a.nic + ` up
ip a add ` + a4 + `/30 dev ` + a.nic + `
ip -6 a add ` + a6 + `/126 dev ` + a.nic + `

ip link set ` + b.nic + ` netns ` + ns + `
ip netns exec ` + ns + ` ip l set ` + b.nic + ` up
ip netns exec ` + ns + ` ip a add ` + b4 + `/30 dev ` + b.nic + `
ip netns exec ` + ns + ` ip -6 a add ` + b6 + `/126 dev ` + b.nic + `

ip r replace ` + prefix4 + ` via ` + b4 + `
ip -6 r replace ` + prefix6 + ` via ` + b6 + `

#ip netns exec ` + ns + ` ethtool -K ` + b.nic + ` tx off
#ip netns exec ` + ns + ` ethtool -K ` + b.nic + ` rx off
ethtool -K ` + a.nic + ` tx off
ethtool -K ` + a.nic + ` rx off
`

	if out, err := exec.Command("/bin/sh", "-e", "-c", script).Output(); err != nil {
		return out, err
	}

	return nil, nil
}
