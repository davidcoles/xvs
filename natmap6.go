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
	"errors"
	"net/netip"
	"sync"
)

var mutex6 sync.RWMutex

type natmap6 map[[2]netip.Addr]uint16

func (f natmap6) add(v, r netip.Addr) uint16 {
	mutex6.Lock()
	defer mutex6.Unlock()
	k := [2]netip.Addr{v, r}
	n := f[k]
	f[k] = n // existing value if exists, 0 otherwise
	return n
}

func (f natmap6) get(v, r netip.Addr) uint16 {
	mutex6.RLock()
	defer mutex6.RUnlock()
	k := [2]netip.Addr{v, r}
	return f[k]
}

func (f natmap6) all() map[[2]netip.Addr]uint16 {
	mutex6.RLock()
	defer mutex6.RUnlock()
	m := map[[2]netip.Addr]uint16{}
	for k, v := range f {
		m[k] = v
	}
	return m
}

func (f natmap6) index() (b bool, e error) {
	mutex6.Lock()
	defer mutex6.Unlock()
	m := map[uint16]bool{}
	var n uint16
	for _, v := range f {
		m[v] = true
	}

	for k, v := range f {
		for v == 0 {
			b = true
			if n >= 65530 {
				return b, errors.New("Too many hosts")
			}
			n++

			if _, exists := m[n]; !exists {
				v = n
				f[k] = v
			}
		}
	}

	return b, e
}
func (f natmap6) rips() map[netip.Addr]bool {
	mutex6.RLock()
	defer mutex6.RUnlock()
	rips := map[netip.Addr]bool{}
	for k, _ := range f {
		r := k[1]
		rips[r] = true
	}
	return rips
}

func (f natmap6) clean(m map[[2]netip.Addr]bool) (c bool) {
	mutex6.Lock()
	defer mutex6.Unlock()
	for k, _ := range f {
		if _, exists := m[k]; !exists {
			c = true
			delete(f, k)
		}
	}
	return
}
