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
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/davidcoles/xvs/bpf"
	"github.com/davidcoles/xvs/xdp"
)

type be_state struct {
	sticky      bool
	fallback    bool
	leastconns  IP4
	weight      uint8
	bpf_backend bpf_backend
	bpf_reals   map[IP4]bpf_real
}

type Client struct {
	Interfaces []string
	VLANs      map[uint16]net.IPNet
	NAT        bool
	Native     bool
	Redirect   bool
	Address    netip.Addr // find default interface when not in VLAN mode

	mutex sync.Mutex

	service map[svc]*Service
	ifaces  map[uint16]iface
	hwaddr  map[IP4]MAC
	vlans   map[uint16]net.IPNet // only gets updated by config change

	netns *netns
	maps  *maps
	icmp  *ICMP
	nat   []natkeyval

	update chan bool

	tag_map tag_map
	nat_map nat_map
}

func (c *Client) Namespace() string {
	return NAMESPACE
}

func (c *Client) NamespaceAddress() string {
	return IP.String()
}

func (c *Client) arp() map[IP4]MAC {
	return arp()
}

func (c *Client) Prefixes() [PREFIXES]uint64 {
	return c.maps.ReadPrefixCounters()
}

func (c *Client) Info() (i Info) {
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

func (b *Client) Start() error {

	phy := b.Interfaces

	b.vlans = map[uint16]net.IPNet{}
	b.nat_map = map[[2]IP4]uint16{}
	b.tag_map = map[IP4]uint16{}
	b.service = map[svc]*Service{}
	b.hwaddr = map[IP4]MAC{}
	b.update = make(chan bool, 1)

	if b.VLANs != nil {
		b.vlans = b.VLANs
	}

	var vetha, vethb string

	if b.NAT {

		var default_ip IP4
		var default_if *net.Interface

		if len(b.vlans) < 1 {
			// address must be present

			addr := b.Address

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

		b.netns = &netns{}

		err := b.netns.Init(default_ip, default_if)

		if err != nil {
			return err
		}

		vetha = b.netns.IfA
		vethb = b.netns.IfB

		fmt.Println(b.netns)
	}

	b.icmp = &ICMP{}
	err := b.icmp.Start()

	if err != nil {
		return err
	}

	bpf, err := BPF()

	if err != nil {
		return errors.New("Couldn't decompress eBPF code")
	}

	b.maps, err = open(bpf, b.Native, len(b.vlans) > 0 && b.Redirect, vetha, vethb, phy...)

	if err != nil {
		return err
	}

	if b.netns != nil {
		err = b.netns.Open()

		if err != nil {
			return err
		}
	}

	b.scan_interfaces()

	go b.background()

	return nil
}

func (b *Client) ping() {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	addr := map[IP4]bool{}

	for _, service := range b.service {
		for ip, _ := range service.backend {
			addr[ip] = true
		}
	}

	for ip, _ := range addr {
		b.icmp.Ping(ip.String())
	}
}

func (b *Client) background() {
	var era uint8
	b.maps.Era(era)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	arp := time.NewTicker(2 * time.Second)
	defer arp.Stop()

	ifaces := time.NewTicker(time.Minute)
	defer ifaces.Stop()

	for {
		select {
		case <-ticker.C:
			b.ping()

			era++
			b.maps.Era(era)

		case <-arp.C:
			if b.update_arp() {
				b.trigger_update()
			}

		case <-ifaces.C:
			b.scan_interfaces() // check for changes?
			b.trigger_update()

		case <-b.update:
			b.update_redirects()
			b.update_nat()
			b.update_services()
		}
	}
}

func (c *Client) trigger_update() {
	select {
	case c.update <- true:
	default:
	}
}

func (b *Client) update_arp() bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	hwaddr := map[IP4]MAC{}

	var changed bool

	arp := b.arp()

	for _, ip := range b.nat_map.rip() {
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
		fmt.Println("ARP:", hwaddr)
	}

	return changed
}

func (c *Client) scan_interfaces() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	fmt.Println("IFS:")
	c.ifaces = VlanInterfaces(c.vlans)
}

func (c *Client) update_redirects() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for vid, iface := range c.ifaces {
		c.maps.update_redirect(vid, iface.mac, iface.idx)
	}
}

func (c *Client) update_nat() {

	if c.netns == nil {
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	var nat []natkeyval

	nat_map := c.nat_map.get()
	tag_map := c.tag_map.get()

	if c.netns != nil {
		nat = c.nat_entries(c.ifaces, nat_map, tag_map, c.hwaddr)
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

func (c *Client) update_services() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for svc, service := range c.service {
		c.update_service(svc, service, c.hwaddr, false)
	}
}

func (c *Client) update_nat_map() {

	nm := map[[2]IP4]bool{}

	for svc, service := range c.service {
		for rip, _ := range service.backend {
			vip := svc.IP
			nm[[2]IP4{vip, rip}] = true
		}
	}

	c.nat_map.set(nm)

	go func() {
		time.Sleep(time.Second)
		select {
		case c.update <- true:
		default:
		}
	}()
}

/********************************************************************************/

func (b *Client) UpdateVLANs(vlans map[uint16]net.IPNet) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.vlans = vlans
}

func (b *Client) Services() ([]ServiceExtended, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	var services []ServiceExtended

	for svc, service := range b.service {
		var se ServiceExtended
		se.Service = service.Service(svc)

		for rip, _ := range service.backend {
			v := bpf_vrpp{vip: svc.IP, rip: rip, port: htons(svc.Port), protocol: uint8(svc.Protocol)}
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

func (b *Client) CreateService(s Service) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	svc, err := s.svc()

	if err != nil {
		return err
	}

	_, ok := b.service[svc]

	if ok {
		return errors.New("Exists")
	}

	s.backend = map[IP4]*Destination{}
	s.state = nil

	b.service[svc] = &s

	b.maps.update_vrpp_counter(&bpf_vrpp{vip: svc.IP}, &bpf_counter{}, xdp.BPF_NOEXIST)

	b.update_service(svc, &s, b.hwaddr, true)

	return nil
}

func (b *Client) UpdateService(s Service) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	svc, err := s.svc()

	if err != nil {
		return err
	}

	service, ok := b.service[svc]

	if !ok {
		return errors.New("Service does not exist")
	}

	service.update(s)

	return nil
}

func (b *Client) Service(s Service) (se ServiceExtended, e error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	svc, err := s.svc()

	if err != nil {
		return se, err
	}

	service, ok := b.service[svc]

	if !ok {
		return se, errors.New("Service does not exist")
	}

	se.Service = service.Service(svc)

	for rip, _ := range service.backend {
		v := bpf_vrpp{vip: svc.IP, rip: rip, port: htons(svc.Port), protocol: uint8(svc.Protocol)}
		c := bpf_counter{}
		b.maps.lookup_vrpp_counter(&v, &c)
		se.Stats.Packets += c.packets
		se.Stats.Octets += c.octets
		se.Stats.Flows += c.flows
	}

	return se, nil
}

func (b *Client) RemoveService(s Service) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	svc, err := s.svc()

	if err != nil {
		return err
	}

	service, ok := b.service[svc]

	if !ok {
		return errors.New("Service does not exist")
	}

	for ip, _ := range service.backend {
		b.removeDestination(svc, service, ip, true)
	}

	sb := bpf_service{vip: svc.IP, port: htons(s.Port), protocol: uint8(s.Protocol)}
	xdp.BpfMapDeleteElem(b.maps.service_backend(), uP(&sb))
	xdp.BpfMapDeleteElem(b.maps.vrpp_counter(), uP(&bpf_vrpp{vip: svc.IP}))

	delete(b.service, svc)

	b.update_nat_map()

	return nil
}

func (b *Client) CreateDestination(s Service, d Destination) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	svc, err := s.svc()

	if err != nil {
		return err
	}

	service, ok := b.service[svc]

	if !ok {
		return errors.New("Service does not exist")
	}

	rip, err := d.rip()

	if err != nil {
		return err
	}

	_, ok = service.backend[rip]

	if ok {
		return errors.New("Destination exists")
	}

	vid := b.tag1(rip)

	b.tag_map.set(rip, vid)

	service.backend[rip] = &d

	b.icmp.Ping(rip.String())

	b.update_service(svc, service, b.hwaddr, false)

	vr := bpf_vrpp{vip: svc.IP, rip: rip, port: htons(svc.Port), protocol: uint8(svc.Protocol)}
	b.maps.update_vrpp_counter(&vr, &bpf_counter{}, xdp.BPF_NOEXIST)
	b.maps.update_vrpp_concurrent(0, &vr, nil, xdp.BPF_NOEXIST)
	b.maps.update_vrpp_concurrent(1, &vr, nil, xdp.BPF_NOEXIST)

	b.update_nat_map()

	return nil
}

func (b *Client) Destinations(s Service) ([]DestinationExtended, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	var destinations []DestinationExtended

	svc, err := s.svc()

	if err != nil {
		return destinations, err
	}

	service, ok := b.service[svc]

	if !ok {
		return destinations, errors.New("Service does not exist")
	}

	vip := svc.IP
	port := htons(svc.Port)
	protocol := uint8(svc.Protocol)

	for rip, d := range service.backend {
		de := d.extend(rip)
		v := bpf_vrpp{vip: vip, rip: rip, port: port, protocol: protocol}
		c := bpf_counter{}
		b.maps.lookup_vrpp_counter(&v, &c)
		de.Stats.Packets = c.packets
		de.Stats.Octets = c.octets
		de.Stats.Flows = c.flows
		de.MAC = b.hwaddr[rip]
		destinations = append(destinations, de)
	}

	sort.SliceStable(destinations, func(i, j int) bool {
		//return nltoh(a[i]) < nltoh(a[j])
		return destinations[i].Destination.Address.Compare(destinations[j].Destination.Address) < 0
	})

	return destinations, nil
}

func (b *Client) UpdateDestination(s Service, d Destination) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	svc, err := s.svc()

	if err != nil {
		return err
	}

	service, ok := b.service[svc]

	if !ok {
		return errors.New("Service does not exist")
	}

	rip, err := d.rip()

	if err != nil {
		return err
	}

	dest, ok := service.backend[rip]

	if !ok {
		return errors.New("Destination does not exist")
	}

	dest.Weight = d.Weight

	select {
	case b.update <- true:
	default:
	}

	return nil
}

func (b *Client) RemoveDestination(s Service, d Destination) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	svc, err := s.svc()

	if err != nil {
		return err
	}

	service, ok := b.service[svc]

	if !ok {
		return errors.New("Service does not exist")
	}

	rip, err := d.rip()

	if err != nil {
		return err
	}

	_, ok = service.backend[rip]

	if !ok {
		return errors.New("Destination does not exist")
	}

	b.removeDestination(svc, service, rip, false)

	b.update_service(svc, service, b.hwaddr, false)

	b.update_nat_map()

	return nil
}

/********************************************************************************/

func (b *Client) removeDestination(svc svc, s *Service, rip IP4, bulk bool) {

	delete(s.backend, rip)

	if !bulk {
		b.update_service(svc, s, b.hwaddr, false)
	}

	vr := bpf_vrpp{vip: svc.IP, rip: rip, port: htons(svc.Port), protocol: uint8(svc.Protocol)}
	xdp.BpfMapDeleteElem(b.maps.vrpp_counter(), uP(&vr))
	xdp.BpfMapDeleteElem(b.maps.vrpp_concurrent(), uP(&vr))
	vr.pad = 1
	xdp.BpfMapDeleteElem(b.maps.vrpp_concurrent(), uP(&vr))
}

func (b *Client) update_service(svc svc, s *Service, arp map[IP4]MAC, force bool) {

	bpf_reals := map[IP4]bpf_real{}

	for ip, real := range s.backend {
		mac := arp[ip]
		vid := b.tag1(ip)
		if !ip.IsNil() && !mac.IsNil() && real.Weight > 0 && vid < 4095 {
			bpf_reals[ip] = bpf_real{rip: ip, mac: mac, vid: htons(vid)}
		} else {
			fmt.Println(ip, mac, real.Weight, vid)
		}

	}

	key := &bpf_service{vip: svc.IP, port: htons(svc.Port), protocol: uint8(svc.Protocol)}
	val := &be_state{fallback: false, sticky: s.Sticky, bpf_reals: bpf_reals}

	//if s.Leastconns {
	//	val.leastconns = s.LeastconnsIP
	//	val.weight = s.LeastconnsWeight
	//}

	now := time.Now()

	if force || update_backend(val, s.state) {
		b.maps.update_service_backend(key, &(val.bpf_backend), xdp.BPF_ANY)
		fmt.Println("FWD:", svc, val.bpf_backend.hash[:32], time.Now().Sub(now))
		s.state = val
	}
}

// func update_backend(curr, prev *be_state, l types.Logger) bool {
func update_backend(curr, prev *be_state) bool {

	if !curr.diff(prev) {
		return false
	}

	var flag [4]byte

	if curr.sticky {
		flag[0] |= bpf.F_STICKY
	}

	if curr.fallback {
		flag[0] |= bpf.F_FALLBACK
	}

	mapper := map[[4]byte]uint8{}

	var list []IP4

	for ip, _ := range curr.bpf_reals {
		list = append(list, ip)
	}

	sort.SliceStable(list, func(i, j int) bool {
		return nltoh(list[i]) < nltoh(list[j])
	})

	var real [256]bpf_real

	for i, ip := range list {
		if i < 255 {
			idx := uint8(i) + 1
			mapper[ip] = idx
			real[idx] = curr.bpf_reals[ip]
		} else {
			fmt.Println("more than 255 hosts", ip, i)
		}
	}

	curr.bpf_backend.real = real
	curr.bpf_backend.hash, _ = maglev8192(mapper)

	var rip IP4
	var mac MAC
	var vid [2]byte

	if !curr.leastconns.IsNil() {
		if n, ok := mapper[curr.leastconns]; ok {
			flag[1] = curr.weight
			rip = real[n].rip
			mac = real[n].mac
			vid = real[n].vid
		}
	}

	curr.bpf_backend.real[0] = bpf_real{rip: rip, mac: mac, vid: vid, flag: flag}

	return true
}

func (curr *be_state) diff(prev *be_state) bool {

	if prev == nil {
		return true
	}

	if curr.sticky != prev.sticky ||
		curr.fallback != prev.fallback ||
		curr.leastconns != prev.leastconns ||
		curr.weight != prev.weight {
		return true
	}

	if bpf_reals_differ(curr.bpf_reals, prev.bpf_reals) {
		return true
	}

	return false
}

func bpf_reals_differ(a, b map[IP4]bpf_real) bool {
	for k, v := range a {
		if x, ok := b[k]; !ok {
			return true
		} else {
			if x != v {
				return true
			}
		}
	}

	for k, _ := range b {
		if _, ok := a[k]; !ok {
			return true
		}
	}

	return false
}

type iface struct {
	idx uint32
	ip4 IP4
	mac MAC
}

func (b *Client) nat_entries(ifaces map[uint16]iface, nat_map nat_map, tag_map tag_map, arp map[IP4]MAC) (nkv []natkeyval) {

	if b.netns == nil {
		return
	}

	for k, v := range nat_map {
		vip := k[0]
		rip := k[1]
		nat := b.natAddr(v)
		mac := arp[rip]
		vid := tag_map[rip]
		idx := ifaces[vid]

		if mac.IsNil() {
			continue
		}

		if (len(b.vlans) != 0 && vid == 0) || (len(b.vlans) == 0 && vid != 0) {
			continue
		}

		if vid == 0 && b.netns.phys.idx == 0 {
			continue
		}

		if vid == 0 {
			idx = b.netns.phys
		}

		nkv = append(nkv, b.natEntry(vip, rip, nat, mac, vid, idx)...)
	}

	return
}

type natkeyval struct {
	key bpf_natkey
	val bpf_natval
}

func (b *Client) NATAddr(vip, rip IP4) (r IP4, _ bool) {
	i := b.nat_map.ent(vip, rip)

	if i == 0 {
		return r, false
	}

	return b.natAddr(i), true
}

func (b *Client) NATAddress(vip, rip netip.Addr) (r netip.Addr, _ bool) {
	if !vip.Is4() || !rip.Is4() {
		return r, false
	}

	ip, ok := b.NATAddr(vip.As4(), rip.As4())

	return netip.AddrFrom4(ip), ok
}

func (b *Client) natAddr(i uint16) IP4 {
	ns := htons(i)
	return IP4{10, 255, ns[0], ns[1]}
}

func (b *Client) natEntry(vip, rip, nat IP4, realhw MAC, vlanid uint16, idx iface) (ret []natkeyval) {

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

func VlanInterfaces(in map[uint16]net.IPNet) map[uint16]iface {
	out := map[uint16]iface{}

	for vid, pref := range in {
		if iface, ok := VlanInterface(pref); ok {
			out[vid] = iface
		}
	}

	return out
}

func VlanInterface(prefix net.IPNet) (ret iface, _ bool) {
	ifaces, err := net.Interfaces()

	if err != nil {
		return
	}

	for _, i := range ifaces {

		if i.Flags&net.FlagLoopback != 0 {
			continue
		}

		if i.Flags&net.FlagUp == 0 {
			continue
		}

		if i.Flags&net.FlagBroadcast == 0 {
			continue
		}

		if len(i.HardwareAddr) != 6 {
			continue
		}

		var mac MAC
		copy(mac[:], i.HardwareAddr[:])

		addr, err := i.Addrs()

		if err == nil {
			for _, a := range addr {
				cidr := a.String()
				ip, ipnet, err := net.ParseCIDR(cidr)

				if err == nil && ipnet.String() == prefix.String() {
					ip4 := ip.To4()
					if len(ip4) == 4 && ip4 != nil {
						return iface{idx: uint32(i.Index), ip4: IP4(ip4), mac: mac}, true
					}
				}
			}
		}
	}

	return
}

func DefaultInterface(addr IP4) *net.Interface {

	fmt.Println(addr)

	ADDR := net.IP(addr[:])

	ifaces, err := net.Interfaces()

	if err != nil {
		return nil
	}

	for _, i := range ifaces {

		if i.Flags&net.FlagLoopback != 0 {
			continue
		}

		if i.Flags&net.FlagUp == 0 {
			continue
		}

		if i.Flags&net.FlagBroadcast == 0 {
			continue
		}

		if len(i.HardwareAddr) != 6 {
			continue
		}

		var mac MAC
		copy(mac[:], i.HardwareAddr[:])

		addr, err := i.Addrs()

		if err == nil {
			for _, a := range addr {

				cidr := a.String()
				ip, _, err := net.ParseCIDR(cidr)

				ip4 := ip.To4()

				fmt.Println(err, ip4, ip)

				if err == nil && ip4 != nil && ip.Equal(ADDR) {
					return &i
				}
			}
		}
	}

	return nil
}

func (c *Client) SetService(s Service, dst []Destination) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	svc, err := s.svc()

	if err != nil {
		return err
	}

	vip := svc.IP
	port := svc.Port
	protocol := svc.Protocol

	service, ok := c.service[svc]

	if !ok {
		s.backend = map[IP4]*Destination{}
		s.state = nil

		service = &s
		c.service[svc] = &s

		c.maps.update_vrpp_counter(&bpf_vrpp{vip: vip}, &bpf_counter{}, xdp.BPF_NOEXIST)
	}

	service.update(s)

	new := map[IP4]*Destination{}

	for _, d := range dst {

		if !d.Address.Is4() {
			continue
		}

		rip := IP4(d.Address.As4())

		x := d
		new[rip] = &x

		if _, ok := s.backend[rip]; !ok {
			// create map entries (if they don't already exist)
			vr := bpf_vrpp{vip: vip, rip: rip, port: htons(port), protocol: uint8(protocol)}
			c.maps.update_vrpp_counter(&vr, &bpf_counter{}, xdp.BPF_NOEXIST)
			c.maps.update_vrpp_concurrent(0, &vr, nil, xdp.BPF_NOEXIST)
			c.maps.update_vrpp_concurrent(1, &vr, nil, xdp.BPF_NOEXIST)
		}

		// calculate VLAN ID if it does not already exist
		if _, ok := c.tag_map.ent(rip); !ok {
			c.tag_map.set(rip, c.tag(rip))
		}
	}

	for rip, _ := range s.backend {
		if _, ok := new[rip]; !ok {
			// delete map entries
			vr := bpf_vrpp{vip: vip, rip: rip, port: htons(port), protocol: uint8(protocol)}
			xdp.BpfMapDeleteElem(c.maps.vrpp_counter(), uP(&vr))
			xdp.BpfMapDeleteElem(c.maps.vrpp_concurrent(), uP(&vr))
			vr.pad = 1
			xdp.BpfMapDeleteElem(c.maps.vrpp_concurrent(), uP(&vr))
		}
	}

	service.backend = new

	// TODO
	// write vip/rip to map if it does not exist - trigger update of nat->kernel

	// to index nat - scan all services and remove ununsed vip/rip
	// delete old nat rules
	// rebuild nat map
	// install new rules

	c.update_nat_map()
	//for vid, iface := range c.ifaces {
	//	c.maps.update_redirect(vid, iface.mac, iface.idx)
	//}
	///////c.update_redirects()
	//c.update_nat_no_lock()
	service.state = nil
	c.update_service(svc, service, c.hwaddr, false)

	return nil
}

func (c *Client) update_nat_no_lock() {

	if c.netns == nil {
		return
	}

	var nat []natkeyval

	nat_map := c.nat_map.get()
	tag_map := c.tag_map.get()

	if c.netns != nil {
		nat = c.nat_entries(c.ifaces, nat_map, tag_map, c.hwaddr)
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
