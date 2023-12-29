package xvs

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/davidcoles/xvs/xdp"
)

type Service struct {
	Address  netip.Addr
	Port     uint16
	Protocol protocol

	Sticky bool

	backend map[IP4]*Destination
	state   *be_state
}

func (s *Service) Service(x svc) Service {
	var r Service
	r = *s
	r.backend = map[IP4]*Destination{}
	r.state = nil
	return r
}

type ServiceExtended struct {
	Service Service
	Stats   Stats
}

func (s *Service) update(u Service) {
	s.Sticky = u.Sticky
}

func (s *Service) svc() (svc, error) {
	if !s.Address.Is4() {
		return svc{}, errors.New("Not IPv4")
	}
	ip := s.Address.As4()
	return svc{IP: ip, Port: s.Port, Protocol: s.Protocol}, nil
}

func (s *Service) dup() Service {
	var r Service
	r = *s
	r.backend = map[IP4]*Destination{}
	r.state = nil
	return r
}

func (s *Service) key() (key, error) {
	return key{addr: s.Address, port: s.Port, prot: uint8(s.Protocol)}, nil
}

func (s *Service) sync(arp map[IP4]MAC, tag map[netip.Addr]uint16, maps *Maps) {

	port := s.Port
	protocol := uint8(s.Protocol)

	if s.Address.Is4() {

		vip := s.Address.As4()
		bpf_reals := map[IP4]bpf_real{}

		for ip, real := range s.backend {
			mac := arp[ip]
			vid := tag[netip.AddrFrom4(ip)]
			if !ip.IsNil() && !mac.IsNil() && real.Weight > 0 && vid < 4095 {
				bpf_reals[ip] = bpf_real{rip: ip, mac: mac, vid: htons(vid)}
			} else {
				fmt.Println("UNAVAILABLE", ip, mac, real.Weight, vid)
			}
		}

		key := &bpf_service{vip: vip, port: htons(port), protocol: protocol}
		val := &be_state{fallback: false, sticky: s.Sticky, bpf_reals: bpf_reals}

		now := time.Now()

		if update_backend(val, s.state) {
			maps.update_service_backend(key, &(val.bpf_backend), xdp.BPF_ANY)
			fmt.Println("FWD:", vip, port, protocol, val.bpf_backend.hash[:32], time.Now().Sub(now))
			s.state = val
		}
	}
}

/**********************************************************************/

type Destination struct {
	Address netip.Addr
	Weight  uint8
}

func (d *Destination) rip() (IP4, error) {
	if !d.Address.Is4() {
		return IP4{}, errors.New("Not IPv4")
	}

	return d.Address.As4(), nil
}

func (d *Destination) extend(ip IP4) DestinationExtended {
	var de DestinationExtended
	de.Destination.Address = netip.AddrFrom4(ip)
	de.Destination.Weight = d.Weight
	return de
}
