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
	"net"
	"os/exec"
)

const NAMESPACE = "vc5"

var IP ip4 = ip4{10, 255, 255, 254}

type netns struct {
	IdA      int
	IfA, IfB string
	IpA, IpB ip4
	HwA, HwB MAC
	//Index    int
	NS string

	//xPhysif uint32
	//xPhyshw MAC
	//xPhysip ip4
	phys iface
}

func (n *netns) Init(ip ip4, out *net.Interface) error {

	//n.xPhysip = ip
	//n.xPhysif = uint32(out.Index)
	//copy(n.xPhyshw[:], out.HardwareAddr[:])

	if out != nil {
		n.phys.ip4 = ip
		n.phys.idx = uint32(out.Index)
		copy(n.phys.mac[:], out.HardwareAddr[:])
	}

	n.NS = NAMESPACE
	n.IfA = NAMESPACE
	n.IfB = NAMESPACE + "ns"

	n.IpA = [4]byte{IP[0], IP[1], 255, 253}
	n.IpB = [4]byte{IP[0], IP[1], 255, 254}

	clean(n.IfA, n.NS)

	err := setup1(n.IfA, n.IfB)
	if err != nil {
		return err
	}

	iface, err := net.InterfaceByName(n.IfA)
	if err != nil {
		return err
	}
	copy(n.HwA[:], iface.HardwareAddr[:])

	//n.Index = iface.Index
	n.IdA = iface.Index

	iface, err = net.InterfaceByName(n.IfB)
	if err != nil {
		return err
	}
	copy(n.HwB[:], iface.HardwareAddr[:])

	return nil
}

func (n *netns) Open() error {
	return setup2(n.NS, n.IfA, n.IfB, n.IpA, n.IpB)
}

func (n *netns) Close() { clean(n.IfA, n.NS) }

/**********************************************************************/

func clean(if1, ns string) {
	script := `
    ip link del ` + if1 + ` >/dev/null 2>&1 || true
    ip netns del ` + ns + ` >/dev/null 2>&1 || true
`
	exec.Command("/bin/sh", "-e", "-c", script).Output()
}

func setup1(if1, if2 string) error {
	script := `
ip link del ` + if1 + ` >/dev/null 2>&1 || true
ip link add ` + if1 + ` type veth peer name ` + if2 + `
`
	_, err := exec.Command("/bin/sh", "-e", "-c", script).Output()
	return err
}

func setup2(ns, if1, if2 string, i1, i2 ip4) error {
	ip1 := i1.String()
	ip2 := i2.String()
	cb := i1
	cb[2] = 0
	cb[3] = 0
	cbs := cb.String()

	script := `
ip netns del ` + ns + ` >/dev/null 2>&1 || true
ip l set ` + if1 + ` up
ip a add ` + ip1 + `/30 dev ` + if1 + `
ip netns add ` + ns + `
ip link set ` + if2 + ` netns ` + ns + `
ip netns exec vc5 /bin/sh -c "ip l set ` + if2 + ` up && ip a add ` + ip2 + `/30 dev ` + if2 + ` && ip r replace default via ` + ip1 + ` && ip netns exec ` + ns + ` ethtool -K ` + if2 + ` tx off"
ip r replace ` + cbs + `/16 via ` + ip2 + `
`
	_, err := exec.Command("/bin/sh", "-e", "-c", script).Output()
	return err
}
