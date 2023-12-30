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

// TODO: manage record for VIP

package xvs

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
	"unsafe"

	"github.com/davidcoles/xvs/nat"
	"github.com/davidcoles/xvs/xdp"
)

type uP = unsafe.Pointer

type vc struct {
	vid uint16
	net net.IPNet
}

type key struct {
	addr netip.Addr
	port uint16
	prot uint8
}

type Client2 struct {
	Interfaces []string
	VLANs      map[uint16]net.IPNet
	NAT        bool
	Native     bool
	Redirect   bool
	Address    netip.Addr // find default interface when not in VLAN mode

	service map[key]*Service
	ifaces  map[uint16]iface
	hwaddr  map[IP4]MAC // IPv4 only
	tags    map[netip.Addr]uint16

	maps  *maps
	icmp  *ICMP
	netns *netns

	natMap nat.NatMap

	update_fwd chan bool
	update_nat chan bool
	mutex      sync.Mutex

	nat []natkeyval
}

func (c *Client2) vlanIDs() []vc {
	var vlans []vc

	for k, v := range c.VLANs {
		vlans = append(vlans, vc{k, v})
	}
	sort.SliceStable(vlans, func(i, j int) bool {
		return vlans[i].vid < vlans[j].vid
	})

	return vlans
}

func (c *Client2) tag(i netip.Addr) uint16 {
	vlans := c.vlanIDs()

	if !i.Is4() {
		return 0
	}

	ip4 := i.As4()

	ip := net.IP(ip4[:])
	for _, v := range vlans {
		if v.net.Contains(ip) {
			return v.vid
		}
	}

	return 0
}

func (c *Client2) CreateService(s Service) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.setService(&s, nil)
}

func (c *Client2) RemoveService(s Service) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	svc, err := s.key()

	if err != nil {
		return err
	}

	service, ok := c.service[svc]

	if !ok {
		return errors.New("Service does not exist")
	}

	for ip, _ := range service.backend {
		c.maps.removeDestination(svc, ip)
	}

	if svc.addr.Is4() {
		sb := bpf_service{vip: svc.addr.As4(), port: htons(svc.port), protocol: svc.prot}
		xdp.BpfMapDeleteElem(c.maps.service_backend(), uP(&sb))
		// TODO //xdp.BpfMapDeleteElem(c.maps.vrpp_counter(), uP(&bpf_vrpp{vip: s.Address.As4()}))
	}

	delete(c.service, svc)

	select {
	case c.update_nat <- true:
	default:
	}

	select {
	case c.update_fwd <- true:
	default:
	}

	return nil
}

func (c *Client2) CreateDestination(s Service, d Destination) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	svc, err := s.key()

	if err != nil {
		return err
	}

	service, ok := c.service[svc]

	if !ok {
		return errors.New("Service does not exist")
	}

	if !d.Address.Is4() {
		return errors.New("Not IPv4")
	}

	ip := d.Address.As4()

	if _, exists := service.backend[ip]; exists {
		return errors.New("Desination exists")
	}

	var dst []Destination

	for _, d := range service.backend {
		dst = append(dst, *d)
	}

	dst = append(dst, d)

	return c.setService(service, dst)
}

func (m *Maps) removeDestination(svc key, rip IP4) {

	if svc.addr.Is4() {
		vr := bpf_vrpp{vip: svc.addr.As4(), rip: rip, port: htons(svc.port), protocol: svc.prot}
		xdp.BpfMapDeleteElem(m.vrpp_counter(), uP(&vr))
		xdp.BpfMapDeleteElem(m.vrpp_concurrent(), uP(&vr))
		vr.pad = 1
		xdp.BpfMapDeleteElem(m.vrpp_concurrent(), uP(&vr))
	}
}

func (c *Client2) SetService(s Service, dst []Destination) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.setService(&s, dst)
}

func (c *Client2) setService(xns *Service, dst []Destination) error {

	foo := *xns
	ns := &foo

	svc, err := ns.key()

	if err != nil {
		return err
	}

	if !svc.addr.Is4() {
		return errors.New("Not IPv4")
	}

	vip := svc.addr.As4()
	port := svc.port
	protocol := svc.prot

	var changed bool

	service, ok := c.service[svc]

	if !ok {
		changed = true
		service = ns
		fmt.Println("NEW:", vip, port, protocol)
		ns.backend = map[IP4]*Destination{}
		ns.state = nil
		c.service[svc] = service

		c.maps.update_vrpp_counter(&bpf_vrpp{vip: vip}, &bpf_counter{}, xdp.BPF_NOEXIST)
	} else {
		service.update(*ns)
	}

	new := map[IP4]*Destination{}

	for _, d := range dst {

		if !d.Address.Is4() {
			continue
		}

		rip := IP4(d.Address.As4())

		x := d
		new[rip] = &x

		if _, ok := service.backend[rip]; !ok {
			// create map entries (if they don't already exist)
			vr := bpf_vrpp{vip: vip, rip: rip, port: htons(port), protocol: uint8(protocol)}
			c.maps.update_vrpp_counter(&vr, &bpf_counter{}, xdp.BPF_NOEXIST)
			c.maps.update_vrpp_concurrent(0, &vr, nil, xdp.BPF_NOEXIST)
			c.maps.update_vrpp_concurrent(1, &vr, nil, xdp.BPF_NOEXIST)
		}

		n := c.natMap.Add(vip, rip)

		if n == 0 { // vip/rip combination wasn't in NAT map exist - fire off a ping and signal to rebuild index
			c.icmp.Ping(rip.String())
			changed = true
		}

		if _, exists := c.tags[d.Address]; !exists {
			tag := c.tag(d.Address)
			fmt.Println("TAG:", d.Address, tag)
			c.tags[d.Address] = tag
		}
	}

	for rip, _ := range service.backend {
		if _, ok := new[rip]; !ok {
			// delete map entries
			v0 := bpf_vrpp{vip: vip, rip: rip, port: htons(port), protocol: uint8(protocol), pad: 0}
			v1 := bpf_vrpp{vip: vip, rip: rip, port: htons(port), protocol: uint8(protocol), pad: 1}
			xdp.BpfMapDeleteElem(c.maps.vrpp_counter(), uP(&v0))
			xdp.BpfMapDeleteElem(c.maps.vrpp_concurrent(), uP(&v0))
			xdp.BpfMapDeleteElem(c.maps.vrpp_concurrent(), uP(&v1))
			changed = true
		}

	}

	service.backend = new

	if changed {
		select {
		case c.update_nat <- true:
		default:
		}
	}

	//select {
	//case c.update_fwd <- true:
	//default:
	//}

	service.sync(c.hwaddr, c.tags, c.maps)

	return nil
}

func (c *Client2) Start() error {

	phy := c.Interfaces

	c.service = map[key]*Service{}
	c.hwaddr = map[IP4]MAC{}
	c.ifaces = map[uint16]iface{}
	c.tags = map[netip.Addr]uint16{}
	c.natMap = nat.NatMap{}

	c.update_fwd = make(chan bool, 1)
	c.update_nat = make(chan bool, 1)

	var vetha, vethb string

	if c.NAT {

		var default_ip IP4
		var default_if *net.Interface

		if len(c.VLANs) < 1 {
			// address must be present

			addr := c.Address

			if !addr.IsValid() {
				return errors.New("Not an IPv4 address")
			}

			if !addr.Is4() {
				return errors.New("Not an IPv4 address: " + addr.String())
			}

			default_ip = IP4(addr.As4())
			default_if = DefaultInterface(default_ip)

			if default_if == nil {
				return errors.New("Couldn't locate interface for IP: " + addr.String())
			}
		}

		c.netns = &netns{}

		err := c.netns.Init(default_ip, default_if)

		if err != nil {
			return err
		}

		vetha = c.netns.IfA
		vethb = c.netns.IfB

		fmt.Println(c.netns)
	}

	c.icmp = &ICMP{}
	err := c.icmp.Start()

	if err != nil {
		return err
	}

	bpf, err := BPF()

	if err != nil {
		return err
	}

	c.maps, err = open(bpf, c.Native, len(c.VLANs) > 0 && c.Redirect, vetha, vethb, phy...)

	if err != nil {
		return err
	}

	if c.netns != nil {
		err = c.netns.Open()

		if err != nil {
			return err
		}
	}

	c.scan_interfaces()
	c.update_redirects()

	go c.maps.background()
	go c.background()

	return nil
}

func (c *Client2) background() {

	ticker := time.NewTicker(200 * time.Millisecond)
	nic_ticker := time.NewTicker(time.Minute)
	arp_ticker := time.NewTicker(10 * time.Second)
	mac_ticker := time.NewTicker(10 * time.Second)

	for {
		var update_nic bool
		var update_arp bool
		var update_mac bool
		var update_fwd bool
		var update_nat bool

		select {
		case <-ticker.C:
		}

		var done bool

		for !done {
			select {
			case <-nic_ticker.C:
				update_nic = true
			case <-arp_ticker.C:
				update_arp = true
			case <-mac_ticker.C:
				update_mac = true
			case <-c.update_fwd:
				update_mac = true
				update_fwd = true
			case <-c.update_nat:
				update_mac = true
				update_nat = true
			default:
				done = true
			}
		}

		c.mutex.Lock()

		if update_nic {
			if c.scan_interfaces() {
				c.update_redirects()
				update_fwd = true
				update_nat = true
				// retag
				for ip, _ := range c.natMap.RIPs() {
					addr := netip.AddrFrom4(ip)
					c.tags[addr] = c.tag(addr)
				}
			}
		}

		if update_arp {
			c.arp()
		}

		if update_mac {
			if c.update_mac(c.natMap.RIPs()) { // true if something changed
				update_fwd = true
				update_nat = true
			}
		}

		if update_nat {
			c.natMap.Clean(c.tuples())
			c.natMap.Index()
			//deleted := c.natMap.Clean(c.tuples())
			//changed, _ := c.natMap.Index()
			//if deleted || changed {
			c.updateNAT()
			//}
		}

		if update_fwd {
			for _, service := range c.service {
				service.sync(c.hwaddr, c.tags, c.maps)
			}
		}

		c.mutex.Unlock()
	}
}

type ip4 = [4]byte

func (c *Client2) tuples() map[[2]ip4]bool {
	m := map[[2]ip4]bool{}
	for _, s := range c.service {
		for r, _ := range s.backend {
			if s.Address.Is4() {
				v := s.Address.As4()
				m[[2]ip4{v, r}] = true
			}
		}
	}
	return m
}

func (c *Client2) arp() {
	// ping all real IP addresses, causing an ARP lookup if not fresh
	for ip, _ := range c.natMap.RIPs() {
		c.icmp.Ping(IP4(ip).String())
	}
}

func (b *Client2) update_mac(ips map[[4]byte]bool) bool {
	hwaddr := map[IP4]MAC{}

	var changed bool

	arp := arp()

	//fmt.Println(arp, ips)

	for ip, _ := range ips {
		//fmt.Println("ARPPING:", ip)

		new, ok := arp[ip]

		if !ok {
			continue
		}

		old, ok := b.hwaddr[ip]

		if !ok || new != old {
			changed = true
		}

		hwaddr[ip] = new

		delete(b.hwaddr, ip)
	}

	if len(b.hwaddr) != 0 {
		changed = true
	}

	b.hwaddr = hwaddr

	if changed {
		fmt.Println("MAC:", hwaddr)
	}

	return changed
}

func (c *Client2) scan_interfaces() bool {

	var changed bool

	old := c.ifaces
	c.ifaces = VlanInterfaces(c.VLANs)

	for k, v := range c.ifaces {
		o, exists := old[k]

		if !exists || v != o {
			changed = true
		}

		delete(old, k)
	}

	if len(old) > 0 {
		changed = true
	}

	fmt.Println("IFS:", changed)

	return changed
}

func (b *Client2) Services() ([]ServiceExtended, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	var services []ServiceExtended

	for _, service := range b.service {
		var se ServiceExtended
		se.Service = service.dup()

		if !service.Address.Is4() {
			continue
		}

		for rip, _ := range service.backend {
			v := bpf_vrpp{vip: service.Address.As4(), rip: rip, port: htons(service.Port), protocol: uint8(service.Protocol)}
			c := bpf_counter{}
			b.maps.lookup_vrpp_counter(&v, &c)
			se.Stats.Packets += c.packets
			se.Stats.Octets += c.octets
			se.Stats.Flows += c.flows
		}

		services = append(services, se)
	}

	return services, nil
}

func (b *Client2) Destinations(s Service) ([]DestinationExtended, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	var destinations []DestinationExtended

	svc, err := s.key()

	if err != nil {
		return destinations, err
	}

	service, ok := b.service[svc]

	if !ok {
		return destinations, errors.New("Service does not exist")
	}

	if !svc.addr.Is4() {
		return destinations, errors.New("Not IPv4")
	}

	vip := svc.addr.As4()
	port := svc.port
	protocol := svc.prot

	for rip, d := range service.backend {
		de := d.extend(rip)
		v := bpf_vrpp{vip: vip, rip: rip, port: htons(port), protocol: protocol}
		c := bpf_counter{}
		b.maps.lookup_vrpp_counter(&v, &c)
		de.Stats.Packets = c.packets
		de.Stats.Octets = c.octets
		de.Stats.Flows = c.flows
		de.MAC = b.hwaddr[rip]
		destinations = append(destinations, de)
	}

	sort.SliceStable(destinations, func(i, j int) bool {
		return destinations[i].Destination.Address.Compare(destinations[j].Destination.Address) < 0
	})

	return destinations, nil
}

/**********************************************************************/

func (c *Client2) natAddr(i uint16) IP4 {
	ns := htons(i)
	return IP4{10, 255, ns[0], ns[1]}
}

func (b *Client2) natEntry(vip, rip, nat IP4, realhw MAC, vlanid uint16, idx iface) (ret []natkeyval) {

	vlanip := idx.ip4
	vlanhw := idx.mac
	vlanif := idx.idx

	var vc5bip IP4 = b.netns.IpB
	var vc5bhw MAC = b.netns.HwB
	var vc5ahw MAC = b.netns.HwA
	var vethif uint32 = uint32(b.netns.IdA)

	if realhw.IsNil() {
		return
	}

	key := bpf_natkey{src_ip: vc5bip, dst_ip: nat, src_mac: vc5bhw, dst_mac: vc5ahw}
	val := bpf_natval{src_ip: vlanip, dst_ip: vip, src_mac: vlanhw, dst_mac: realhw, ifindex: vlanif, vlan: vlanid}

	ret = append(ret, natkeyval{key: key, val: val})

	key = bpf_natkey{src_ip: vip, src_mac: realhw, dst_ip: vlanip, dst_mac: vlanhw}
	val = bpf_natval{src_ip: nat, src_mac: vc5ahw, dst_ip: vc5bip, dst_mac: vc5bhw, ifindex: vethif}

	ret = append(ret, natkeyval{key: key, val: val})

	return
}

func (c *Client2) natEntries() (nkv []natkeyval) {

	if c.netns == nil {
		return
	}

	for k, v := range c.natMap.All() {
		vip := k[0]
		rip := k[1]
		nat := c.natAddr(v)
		mac := c.hwaddr[rip]
		vid := c.tags[netip.AddrFrom4(rip)]
		idx := c.ifaces[vid]

		if mac.IsNil() {
			continue
		}

		if (len(c.VLANs) != 0 && vid == 0) || (len(c.VLANs) == 0 && vid != 0) {
			continue
		}

		if vid == 0 && c.netns.phys.idx == 0 {
			continue
		}

		if vid == 0 {
			idx = c.netns.phys
		}

		nkv = append(nkv, c.natEntry(vip, rip, nat, mac, vid, idx)...)
	}

	return
}

func (c *Client2) updateNAT() {

	if c.netns == nil {
		return
	}

	var nat []natkeyval

	if c.netns != nil {
		nat = c.natEntries()
	}

	var updated, deleted int

	old := map[bpf_natkey]bpf_natval{}
	for _, e := range c.nat {
		old[e.key] = e.val
	}

	// apply all entries
	for _, e := range nat {
		k := e.key
		v := e.val

		if x, ok := old[k]; !ok || v != x {
			updated++
			xdp.BpfMapUpdateElem(c.maps.nat(), uP(&(e.key)), uP(&(e.val)), xdp.BPF_ANY)
		}

		delete(old, k)
	}

	for k, _ := range old {
		deleted++
		xdp.BpfMapDeleteElem(c.maps.nat(), uP(&(k)))
	}

	c.nat = nat

	fmt.Println("NAT: entries", len(nat), "updated", updated, "deleted", deleted)
}

func (c *Client2) update_redirects() {
	for vid := uint16(0); vid < 4096; vid++ {
		iface, exists := c.ifaces[vid]
		if exists {
			fmt.Println("RDR:", vid, iface.mac, iface.idx)
		}
		c.maps.update_redirect(vid, iface.mac, iface.idx) // write nil value if not founc
	}

	//for vid, iface := range c.ifaces {
	//	fmt.Println("RDR:", vid, iface.mac, iface.idx)
	//	c.maps.update_redirect(vid, iface.mac, iface.idx)
	//}
}

func (c *Client2) NATAddress(vip, rip netip.Addr) (r netip.Addr, _ bool) {
	if !vip.Is4() || !rip.Is4() {
		return r, false
	}

	ip, ok := c.NATAddr(vip.As4(), rip.As4())

	return netip.AddrFrom4(ip), ok
}

func (c *Client2) NATAddr(vip, rip IP4) (r IP4, _ bool) {
	i := c.natMap.Get(vip, rip)

	if i == 0 {
		return r, false
	}

	return c.natAddr(i), true
}

func (c *Client2) Namespace() string {
	return NAMESPACE
}

func (c *Client2) NamespaceAddress() string {
	return IP.String()
}

func (c *Client2) Info() (i Info) {
	/*
	   rx_packets     uint64
	   rx_octets      uint64
	   perf_packets   uint64
	   perf_timens    uint64
	   perf_timer     uint64
	   settings_timer uint64
	   new_flows      uint64
	   dropped        uint64
	   qfailed        uint64
	   blocked        uint64
	*/
	g := c.maps.lookup_globals()
	i.Packets = g.rx_packets
	i.Octets = g.rx_octets
	i.Flows = g.new_flows
	i.Latency = g.latency()
	i.Dropped = g.dropped
	i.Blocked = g.blocked
	i.NotQueued = g.qfailed
	return
}

func (c *Client2) UpdateVLANs(vlans map[uint16]net.IPNet) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.VLANs = vlans

	c.scan_interfaces()

	for ip, _ := range c.natMap.RIPs() {
		addr := netip.AddrFrom4(ip)
		c.tags[addr] = c.tag(addr)
	}
}

func (c *Client2) Prefixes() [PREFIXES]uint64 {
	return c.maps.ReadPrefixCounters()
}

func (c *Client2) Service(s Service) (se ServiceExtended, e error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !s.Address.Is4() {
		return se, errors.New("Not IPv4")
	}

	svc, err := s.key()

	if err != nil {
		return se, err
	}

	service, ok := c.service[svc]

	if !ok {
		return se, errors.New("Service does not exist")
	}

	se.Service = service.dup()

	for rip, _ := range service.backend {
		v := bpf_vrpp{vip: svc.addr.As4(), rip: rip, port: htons(svc.port), protocol: svc.prot}
		s := bpf_counter{}
		c.maps.lookup_vrpp_counter(&v, &s)
		se.Stats.Packets += s.packets
		se.Stats.Octets += s.octets
		se.Stats.Flows += s.flows
	}

	return se, nil
}
