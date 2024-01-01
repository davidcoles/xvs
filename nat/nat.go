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

package nat

import (
	"errors"
	"sync"
)

var mutex sync.RWMutex

type IP4 = [4]byte
type NatMap map[[2]IP4]uint16

func (f NatMap) Add(v, r IP4) uint16 {
	mutex.Lock()
	defer mutex.Unlock()
	k := [2]IP4{v, r}
	n := f[k]
	f[k] = n // existing value if exists, 0 otherwise
	return n
}

func (f NatMap) Get(v, r IP4) uint16 {
	mutex.RLock()
	defer mutex.RUnlock()
	k := [2]IP4{v, r}
	return f[k]
}

func (f NatMap) Del(v, r IP4) {
	mutex.Lock()
	defer mutex.Unlock()
	k := [2]IP4{v, r}
	delete(f, k)
}

func (f NatMap) All() map[[2]IP4]uint16 {
	mutex.RLock()
	defer mutex.RUnlock()
	m := map[[2]IP4]uint16{}
	for k, v := range f {
		m[k] = v
	}
	return m
}

func (f NatMap) Index() (b bool, e error) {
	mutex.Lock()
	defer mutex.Unlock()
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

func (f NatMap) RIPs() map[IP4]bool {
	mutex.RLock()
	defer mutex.RUnlock()
	rips := map[IP4]bool{}
	for k, _ := range f {
		r := k[1]
		rips[r] = true
	}
	return rips
}

func (f NatMap) Clean(m map[[2]IP4]bool) (c bool) {
	for k, _ := range f {
		if _, exists := m[k]; !exists {
			c = true
			delete(f, k)
		}
	}
	return
}
