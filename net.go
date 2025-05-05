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
	"regexp"
)

type b4 = [4]byte
type b6 = [6]byte

const _b4s = "%d.%d.%d.%d"
const _b6s = "%02x:%02x:%02x:%02x:%02x:%02x"

func b4s(i b4) string { return fmt.Sprintf(_b4s, i[0], i[1], i[2], i[3]) }
func b6s(i b6) string { return fmt.Sprintf(_b6s, i[0], i[1], i[2], i[3], i[4], i[5]) }

type mac [6]byte
type ip4 [4]byte

func (i *ip4) String() string { return b4s(*i) }
func (m *mac) String() string { return b6s(*m) }

type Protocol = uint8

const (
	TCP Protocol = 0x06
	UDP Protocol = 0x11
)

type MAC = mac

type Info struct {
	Packets   uint64 // Total number of packets received by XDP hooks
	Octets    uint64 // Total number of bytes received by XDP hooks
	Flows     uint64 // Total number of new flow entries created in hash tables
	Latency   uint64 // Average measurable latency for XDP hook
	Dropped   uint64 // Number of non-conforming packets dropped
	Blocked   uint64 // Number of packets dropped by prefix
	NotQueued uint64 // Failed attempts to queue flow state updates to userspace
	TooBig    uint64 // ICMP destination unreachable/fragmentation needed
}

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

type ip6 [16]byte

func (i *ip6) String() string {
	return netip.AddrFrom16(*i).String()
}

type nic struct {
	idx int
	ip4 ip4
	ip6 ip6
	mac mac
	nic string
}

// how to send raw packets
type raw struct {
	idx int // interface index
	src mac // source MAC (local interface HW address)
	dst mac // dest MAC (backend's HW address)
	//nic string // interface name
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

func arp() (map[ip4]mac, map[ip4]raw) {

	var nul mac

	ip2mac := make(map[ip4]mac)
	ip2nic := make(map[ip4]*net.Interface)
	ip2raw := make(map[ip4]raw)

	// flags: https://superuser.com/questions/822054/definition-of-arp-result-flags/822089#822089
	// 0x0 incomplete
	// 0x2 complete
	// 0x6 complete and manually set

	re := regexp.MustCompile(`^(\S+)\s+0x1\s+0x[26]\s+(\S+)\s+\S+\s+(\S+)$`)

	file, err := os.OpenFile("/proc/net/arp", os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, nil
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

			if iface != nil && len(iface.HardwareAddr) == 6 {

				var src MAC

				copy(src[:], iface.HardwareAddr[:])

				if mac != nul {
					ip2raw[ip4] = raw{
						idx: iface.Index,
						src: src,
						dst: mac,
					}
				}
			}
		}
	}

	return ip2mac, ip2raw
}
