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
	"net"
	"time"
)

type icmp struct {
	submit chan string
}

func (i *icmp) start() error {

	conn, err := net.ListenPacket("ip4:icmp", "")
	if err != nil {
		return err
	}

	i.submit = make(chan string, 1000)

	payload := func() []byte {
		var wb [8]byte
		var csum uint32
		var cs uint16

		wb[0], wb[1] = 8, 0 // Echo Request

		for n := 0; n < 8; n += 2 {
			csum += uint32(uint16(wb[n])<<8 | uint16(wb[n+1]))
		}

		cs = uint16(csum>>16) + uint16(csum&0xffff)
		cs = ^cs

		wb[2], wb[3] = byte(cs>>8), byte(cs&0xff)

		return wb[:]
	}

	go func(conn net.PacketConn, submit chan string) {
		defer conn.Close()

		for t := range submit {
			conn.SetWriteDeadline(time.Now().Add(time.Second))
			go func(target string) {
				conn.WriteTo(payload(), &net.IPAddr{IP: net.ParseIP(target)})
			}(t)
		}
	}(conn, i.submit)

	return nil
}

func (i *icmp) ping(target string) {
	select {
	case i.submit <- target:
	default:
	}
}

func (s *icmp) stop() {
	close(s.submit)
}
