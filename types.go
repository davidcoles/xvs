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
//"fmt"
//"net"
//"sync"
//"unsafe"
)

//var mutex sync.Mutex

/*
type nat_map map[[2]IP4]uint16

	func (n *nat_map) set(tuples map[[2]IP4]bool) {
		mutex.Lock()
		defer mutex.Unlock()

		nm := natmap(tuples, *n)

		*n = nm
	}

	func (n *nat_map) get() map[[2]IP4]uint16 {
		mutex.Lock()
		defer mutex.Unlock()

		r := map[[2]IP4]uint16{}

		for k, v := range *n {
			r[k] = v
		}

		return r
	}

	func (n *nat_map) rip() (r []IP4) {
		mutex.Lock()
		defer mutex.Unlock()

		m := map[IP4]bool{}

		for k, _ := range *n {
			m[k[1]] = true
		}

		for k, _ := range m {
			r = append(r, k)
		}

		return r
	}

	func (n *nat_map) ent(vip, rip IP4) uint16 {
		mutex.Lock()
		defer mutex.Unlock()

		x := (map[[2]IP4]uint16)(*n)

		i, _ := x[[2]IP4{vip, rip}]

		return i
	}

type tag_map map[IP4]uint16

	func (t tag_map) set(ip IP4, id uint16) {
		mutex.Lock()
		defer mutex.Unlock()
		x := (map[IP4]uint16)(t)
		x[ip] = id
	}

	func (n *tag_map) get() map[IP4]uint16 {
		mutex.Lock()
		defer mutex.Unlock()

		r := map[IP4]uint16{}

		for k, v := range *n {
			r[k] = v
		}

		return r
	}

	func (t tag_map) ent(ip IP4) (uint16, bool) {
		mutex.Lock()
		defer mutex.Unlock()

		x := (map[IP4]uint16)(t)

		r, ok := x[ip]

		return r, ok
	}

func natmap(tuples map[[2]IP4]bool, previous map[[2]IP4]uint16) (mapping map[[2]IP4]uint16) {

		mapping = map[[2]IP4]uint16{}
		inverse := map[uint16][2]IP4{}

		for k, v := range previous {
			if _, ok := tuples[k]; ok {
				if _, exists := inverse[v]; !exists {
					inverse[v] = k
					mapping[k] = v
				}
			}
		}

		var n uint16
		for k, _ := range tuples {
			if _, ok := mapping[k]; ok {
				continue
			}

		find:
			n++
			if n > 65000 {
				return
			}

			if _, ok := inverse[n]; ok {
				goto find
			}

			mapping[k] = n
		}

		return
	}
*/
