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
	"os"
	"regexp"
	"sync"
)

func htons(p uint16) [2]byte {
	var hl [2]byte
	hl[0] = byte(p >> 8)
	hl[1] = byte(p & 0xff)
	return hl
}

func nltoh(n [4]byte) uint32 {
	return uint32(n[0])<<24 | uint32(n[1])<<16 | uint32(n[2])<<8 | uint32(n[3])
}

func defaultInterface(wanted net.IP) *net.Interface {

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

		var mac mac
		copy(mac[:], i.HardwareAddr[:])

		addr, err := i.Addrs()

		if err == nil {
			for _, a := range addr {
				cidr := a.String()
				ip, _, err := net.ParseCIDR(cidr)
				ip4 := ip.To4()
				if err == nil && ip4 != nil && ip.Equal(wanted) {
					return &i
				}
			}
		}
	}

	return nil
}

type nic struct {
	idx int
	ip4 ip4
	mac mac
	nic string
}

func (n *nic) String() string {
	return fmt.Sprintf("%s|%d|%s|%s", n.nic, n.idx, b4s(n.ip4), b6s(n.mac))
}

func vlanInterfaces(in map[uint16]net.IPNet) map[uint16]nic {
	out := map[uint16]nic{}

	for vid, prefix := range in {

		if vid < 1 || vid > 4094 {
			continue
		}

		if iface, ok := vlanInterface(prefix); ok {
			//fmt.Println("SCAN", vid, prefix.String(), iface.String())
			out[vid] = iface
		}
	}

	return out
}

func vlanInterface(prefix net.IPNet) (ret nic, _ bool) {
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

		var mac mac
		copy(mac[:], i.HardwareAddr[:])

		addr, err := i.Addrs()

		if err == nil {
			for _, a := range addr {
				cidr := a.String()
				ip, ipnet, err := net.ParseCIDR(cidr)

				if err == nil && ipnet.String() == prefix.String() {
					to4 := ip.To4()
					if len(to4) == 4 && to4 != nil {
						ip4 := [4]byte{to4[0], to4[1], to4[2], to4[3]}
						return nic{idx: i.Index, ip4: ip4, mac: mac, nic: i.Name}, true
					}
				}
			}
		}
	}

	return
}

var snoop sync.Mutex
var ipnic map[ip4]*net.Interface

func arp() map[ip4]mac {

	ip2mac := make(map[ip4]mac)
	ip2nic := make(map[ip4]*net.Interface)

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

		if len(m) > 3 {

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

			iface, err := net.InterfaceByName(m[3])

			if err != nil {
				continue
			}

			var ip4 ip4
			var mac [6]byte

			copy(ip4[:], ip[:])
			copy(mac[:], hw[:])

			if ip4.String() == "0.0.0.0" {
				continue
			}

			if mac == [6]byte{0, 0, 0, 0, 0, 0} {
				continue
			}

			ip2mac[ip4] = mac
			ip2nic[ip4] = iface
		}
	}

	snoop.Lock()
	ipnic = ip2nic
	snoop.Unlock()

	return ip2mac
}
