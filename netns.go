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
	ns string
	//i0 nic
	//i1 nic
	i2 nic
	i3 nic
}

func (n *netns) nat(idx uint32, wantIPv6 bool) (r netip.Addr) {
	if idx == 0 || idx > 16777210 {
		return
	}

	nat := n.i2.ip6.As16()
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

//func (n *netns) nic() uint32     { return uint32(n.i0.idx) }
//func (n *netns) src() [6]byte    { return n.i0.mac }
//func (n *netns) dst() [6]byte    { return n.i1.mac }

func (n *netns) nic() int     { return n.i2.idx }
func (n *netns) src() [6]byte { return n.i2.mac }
func (n *netns) dst() [6]byte { return n.i3.mac }

func (n *netns) ipv4() netip.Addr { return n.i2.ip4 }
func (n *netns) ipv6() netip.Addr { return n.i2.ip6 }
func (n *netns) init(x *xdp.XDP) error {

	//namespace := "xvs"

	n.ns = namespace
	//n.i0.nic = namespace + "0"
	//n.i1.nic = namespace + "1"
	//n.i2.nic = namespace + "2"
	//n.i3.nic = namespace + "3"
	n.i2.nic = namespace
	n.i3.nic = namespace + "_"

	n.i2.ip4 = netip.MustParseAddr("255.255.255.253")
	n.i2.ip6 = netip.MustParseAddr("fefe::ffff:fffd")
	n.i3.ip4 = n.i2.ip4.Next()
	n.i3.ip6 = n.i2.ip6.Next()

	/*
		if err := n.create_pair(&n.i0, &n.i1); err != nil {
			return fmt.Errorf("Error creating netns: %s", err.Error())
		}

		if err := x.LoadBpfSection("xdp_pass", false, uint32(n.i0.idx)); err != nil {
			return err
		}

		//if err := x.LoadBpfSection("xdp_reply_func", true, uint32(n.i1.idx)); err != nil {
		if err := x.LoadBpfSection("xdp_pass", true, uint32(n.i1.idx)); err != nil {
			return err
		}

		exec.Command("/bin/sh", "-e", "-c", "ip l set "+n.i0.nic+" up").Output()
		exec.Command("/bin/sh", "-e", "-c", "ip l set "+n.i1.nic+" up").Output()
		exec.Command("/bin/sh", "-e", "-c", "sysctl -w net.ipv4.conf.all.rp_filter=0").Output()
		exec.Command("/bin/sh", "-e", "-c", "sysctl -w net.ipv4.conf."+n.i1.nic+".rp_filter=0").Output()
	*/

	if err := n.create_pair(&n.i2, &n.i3); err != nil {
		return fmt.Errorf("Error creating netns: %s", err.Error())
	}

	if err := x.LoadBpfSection("xdp_request_func", false, uint32(n.i2.idx)); err != nil {
		return err
	}

	if err := x.LoadBpfSection("xdp_mirror_func", false, uint32(n.i3.idx)); err != nil {
		return err
	}

	if _, err := n.config_pair(namespace, n.i2, n.i3); err != nil {
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
