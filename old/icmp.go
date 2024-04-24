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
	"time"
)

type icmp struct {
	submit chan string
}

func (i *icmp) Start() error {

	conn, err := net.ListenPacket("ip4:icmp", "")
	if err != nil {
		return err
	}

	i.submit = make(chan string, 1000)
	go i.probe(conn)

	return nil
}

func (s *icmp) Ping(target string) {
	select {
	case s.submit <- target:
	default:
	}
}

func (s *icmp) Stop() {
	close(s.submit)
}

func (s *icmp) echoRequest() []byte {

	var csum uint32
	wb := make([]byte, 8)

	wb[0] = 8
	wb[1] = 0

	for n := 0; n < 8; n += 2 {
		csum += uint32(uint16(wb[n])<<8 | uint16(wb[n+1]))
	}

	var cs uint16

	cs = uint16(csum>>16) + uint16(csum&0xffff)
	cs = ^cs

	wb[2] = byte(cs >> 8)
	wb[3] = byte(cs & 0xff)

	return wb
}

func (s *icmp) probe(conn net.PacketConn) {

	defer conn.Close()

	for t := range s.submit {
		conn.SetWriteDeadline(time.Now().Add(time.Second))
		go func(target string) {
			conn.WriteTo(s.echoRequest(), &net.IPAddr{IP: net.ParseIP(target)})
		}(t)
	}
}
