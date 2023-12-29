package nat

import (
	"errors"
	"sync"
)

var mutex sync.RWMutex

type IP4 = [4]byte
type NatMap = Foo
type Foo map[[2]IP4]uint16

func (f Foo) Add(v, r IP4) uint16 {
	mutex.Lock()
	defer mutex.Unlock()
	k := [2]IP4{v, r}
	n := f[k]
	f[k] = n // existing value if exists, 0 otherwise
	return n
}

func (f Foo) Get(v, r IP4) uint16 {
	mutex.RLock()
	defer mutex.RUnlock()
	k := [2]IP4{v, r}
	return f[k]
}

func (f Foo) del(v, r IP4) {
	mutex.Lock()
	defer mutex.Unlock()
	k := [2]IP4{v, r}
	delete(f, k)
}

func (f Foo) All() map[[2]IP4]uint16 {
	mutex.RLock()
	defer mutex.RUnlock()
	m := map[[2]IP4]uint16{}
	for k, v := range f {
		m[k] = v
	}
	return m
}

func (f Foo) Index() (b bool, e error) {
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
				println(n)
				v = n
				f[k] = v
			}
		}
	}

	return b, e
}

func (f Foo) RIPs() map[IP4]bool {
	mutex.RLock()
	defer mutex.RUnlock()
	rips := map[IP4]bool{}
	for k, _ := range f {
		r := k[1]
		rips[r] = true
	}
	return rips
}
