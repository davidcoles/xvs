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
	"errors"
	//"fmt"
	"sync"
)

var mutex sync.RWMutex

type natmap map[[2]b4]uint16

func (f natmap) Add(v, r b4) uint16 {
	mutex.Lock()
	defer mutex.Unlock()
	k := [2]b4{v, r}
	n := f[k]
	f[k] = n // existing value if exists, 0 otherwise
	return n
}

func (f natmap) Get(v, r b4) uint16 {
	mutex.RLock()
	defer mutex.RUnlock()
	k := [2]b4{v, r}
	return f[k]
}

func (f natmap) Del(v, r b4) {
	mutex.Lock()
	defer mutex.Unlock()
	k := [2]b4{v, r}
	delete(f, k)
}

func (f natmap) All() map[[2]b4]uint16 {
	mutex.RLock()
	defer mutex.RUnlock()
	m := map[[2]b4]uint16{}
	for k, v := range f {
		m[k] = v
	}
	return m
}

func (f natmap) Index() (b bool, e error) {
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

func (f natmap) RIPs() map[b4]bool {
	mutex.RLock()
	defer mutex.RUnlock()
	rips := map[b4]bool{}
	for k, _ := range f {
		r := k[1]
		rips[r] = true
	}
	return rips
}

func (f natmap) Clean(m map[[2]b4]bool) (c bool) {
	mutex.Lock()
	defer mutex.Unlock()
	for k, _ := range f {
		if _, exists := m[k]; !exists {
			c = true
			delete(f, k)
			//fmt.Println("REMOVING", k)
		}
	}
	return
}
