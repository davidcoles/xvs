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

var natmapMutex sync.RWMutex

type natmap map[[2]netip.Addr]uint32

func (f natmap) add(v, r netip.Addr) uint32 {
	natmapMutex.Lock()
	defer natmapMutex.Unlock()
	k := [2]netip.Addr{v, r}
	n := f[k]
	f[k] = n // existing value if exists, 0 otherwise
	return n
}

func (f natmap) del(v, r netip.Addr) {
	natmapMutex.Lock()
	defer natmapMutex.Unlock()
	delete(f, [2]netip.Addr{v, r})
}

func (f natmap) get(v, r netip.Addr) uint32 {
	natmapMutex.RLock()
	defer natmapMutex.RUnlock()
	k := [2]netip.Addr{v, r}
	return f[k]
}

func (f natmap) all() map[[2]netip.Addr]uint32 {
	natmapMutex.RLock()
	defer natmapMutex.RUnlock()
	m := map[[2]netip.Addr]uint32{}
	for k, v := range f {
		m[k] = v
	}
	return m
}

func (f natmap) index() (b bool, e error) {
	natmapMutex.Lock()
	defer natmapMutex.Unlock()
	m := map[uint32]bool{}
	var n uint32
	for _, v := range f {
		m[v] = true
	}

	for k, v := range f {
		for v == 0 {
			/*
				b = true
				if n >= 65530 {
					return b, errors.New("Too many hosts")
				}
				n++
			*/

			n++
			if n >= 16777210 {
				return b, errors.New("Too many hosts")
			}

			if _, exists := m[n]; !exists {
				v = n
				f[k] = v
			}
		}
	}

	return b, e
}
func (f natmap) rips() map[netip.Addr]bool {
	natmapMutex.RLock()
	defer natmapMutex.RUnlock()
	rips := map[netip.Addr]bool{}
	for k, _ := range f {
		r := k[1]
		rips[r] = true
	}
	return rips
}

func (f natmap) clean(m map[[2]netip.Addr]bool) (c bool) {
	natmapMutex.Lock()
	defer natmapMutex.Unlock()
	for k, _ := range f {
		if _, exists := m[k]; !exists {
			c = true
			delete(f, k)
		}
	}
	return
}
