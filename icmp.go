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
	//"fmt"
	"net"
	"net/netip"
	"time"
)

type icmp struct {
	submit chan netip.Addr
}

func (i *icmp) start() error {

	conn, err := net.ListenIP("ip4:icmp", nil)
	if err != nil {
		return err
	}

	conn6, err := net.ListenIP("ip6:ipv6-icmp", nil)
	if err != nil {
		return err
	}

	i.submit = make(chan netip.Addr, 65536)

	go func(conn, conn6 net.PacketConn, submit chan netip.Addr) {
		defer conn.Close()

		for ip := range submit {
			if ip.Is4() {
				a4 := ip.As4()
				conn.SetWriteDeadline(time.Now().Add(time.Second))
				conn.WriteTo(i.payload4(), &net.IPAddr{IP: net.IP(a4[:])})
			}
			if ip.Is6() {
				addr, payload := i.payload6(ip, netip.Addr{}) // turns out we don't need the source for the pseudoheader
				conn6.SetWriteDeadline(time.Now().Add(time.Second))
				conn6.WriteTo(payload, &addr)
			}
		}
	}(conn, conn6, i.submit)

	return nil
}

// we have to calculate the checksum ourselves
func (i *icmp) payload4() []byte {
	var wb [8]byte
	var csum uint32
	var cs uint16
	var id uint16 = 123
	var sn uint16 = 45678

	wb[0], wb[1] = 8, 0 // Echo Request
	wb[4], wb[5] = byte(id>>8), byte(id&0xff)
	wb[6], wb[7] = byte(sn>>8), byte(sn&0xff)

	for n := 0; n < len(wb); n += 2 {
		csum += uint32(uint16(wb[n])<<8 | uint16(wb[n+1]))
	}

	cs = uint16(csum>>16) + uint16(csum&0xffff)
	cs = ^cs

	wb[2], wb[3] = byte(cs>>8), byte(cs&0xff)

	return wb[:]
}

// looks like Go/Linux calculates the checksum for us, which means we
// don't have to predict the source IP to use in the pseudoheader
func (i *icmp) payload6(dst, src netip.Addr) (net.IPAddr, []byte) {
	var wb [8]byte
	var id uint16 = 123
	var sn uint16 = 45678

	wb[0], wb[1] = 128, 0 // Echo Request
	//wb[0], wb[1] = 100, 0 // or, if we don't want a reply - Private experimentation
	wb[4], wb[5] = byte(id>>8), byte(id&0xff)
	wb[6], wb[7] = byte(sn>>8), byte(sn&0xff)

	d := dst.As16()

	/*
		s := src.As16()

		var csum uint32
		var cs uint16
		var ph [40]byte

		copy(ph[0:], s[:])
		copy(ph[16:], d[:])
		ph[35] = 8
		ph[39] = 58

		for n := 0; n < len(ph); n += 2 {
			csum += uint32(uint16(ph[n])<<8 | uint16(ph[n+1]))
		}

		for n := 0; n < len(wb); n += 2 {
			csum += uint32(uint16(wb[n])<<8 | uint16(wb[n+1]))
		}

		cs = uint16(csum>>16) + uint16(csum&0xffff)
		cs = ^cs

		wb[2], wb[3] = byte(cs>>8), byte(cs&0xff)
	*/

	//ip := net.IP{d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]}
	ip := net.IP(d[:])
	return net.IPAddr{IP: ip, Zone: dst.Zone()}, wb[:]
}

func (i *icmp) ping(target netip.Addr) {
	select {
	case i.submit <- target:
	default:
	}
}

func (s *icmp) stop() {
	close(s.submit)
}
