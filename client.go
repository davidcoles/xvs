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
	"unsafe"

	"github.com/davidcoles/xvs/xdp"
)

type uP = unsafe.Pointer
type kv = map[string]any

type vc struct {
	vid uint16
	net net.IPNet
}

type key struct {
	addr netip.Addr
	port uint16
	prot uint8
}

func prot(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	}
	return fmt.Sprint(p)
}

type Client struct {
	Interfaces []string             // Name of Interfaces which should programmed with eBPF code
	VLANs      map[uint16]net.IPNet // VLAN ID to IP subnet prefix mappings
	NAT        bool                 // Create interfaces and namespace for performing healthchecks
	Native     bool                 // Load eBPF program in native driver mode
	Redirect   bool                 // Don't use VLAN tagging; use bpf_redirect_map() instead
	Address    netip.Addr           // Address of the default interface when not in VLAN mode
	Share      bool                 // Share connection state via flow queue
	Logger     Log                  // Simple logging class

	service map[key]*Service
	ifaces  map[uint16]iface
	hwaddr  map[ip4]mac // IPv4 only
	tags    map[netip.Addr]uint16

	maps  *maps
	icmp  *icmp
	netns *netns

	natMap natmap

	update_fwd chan bool
	update_nat chan bool
	mutex      sync.Mutex

	nat []natkeyval
}

func (c *Client) log() Log {
	l := c.Logger

	if l == nil {
		return &nul{}
	}

	return l
}

func (c *Client) vlanIDs() []vc {
	var vlans []vc

	for k, v := range c.VLANs {
		vlans = append(vlans, vc{k, v})
	}
	sort.SliceStable(vlans, func(i, j int) bool {
		return vlans[i].vid < vlans[j].vid
	})

	return vlans
}

func (c *Client) tag(i netip.Addr) uint16 {
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

func (c *Client) exists(s Service) bool {

	_, ok := c.service[s.key_()]

	return ok
}

func (c *Client) CreateService(s Service) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.exists(s) {
		return errors.New("Service exists")
	}

	return c.setService(s, nil)
}

func (c *Client) RemoveService(s Service) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !s.Address.Is4() {
		return errors.New("Not IPv4")
	}

	key := s.key_()

	service, ok := c.service[key]

	if !ok {
		return errors.New("Service does not exist")
	}

	delete(c.service, key)

	var more bool

	for k, _ := range c.service {
		if k.addr == service.Address {
			more = true
		}
	}

	service.remove(c.maps, more)

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

func (c *Client) CreateDestination(s Service, d Destination) error {
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

	return c.setService(s, dst)
}

func (c *Client) SetService(s Service, dst []Destination) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.setService(s, dst)
}

func (c *Client) setService(s Service, dst []Destination) error {

	svc, err := s.key()

	if err != nil {
		return err
	}

	if !svc.addr.Is4() {
		return errors.New("Not IPv4")
	}

	vip := svc.addr.As4()

	service, ok := c.service[svc]

	if !ok {
		service = s.dupp()
		c.log().INFO("service", kv{"event": "new-service", "vip": b4s(vip), "port": svc.port, "protocol": svc.prot})
		c.service[svc] = service
	}

	add, del := service.set(c.maps, s, dst)

	var changed bool

	for _, rip := range add {

		if c.natMap.Add(vip, rip) == 0 {
			// vip/rip combination wasn't in NAT map - fire off a ping and signal to rebuild index
			c.icmp.Ping(rip.String())
			changed = true
		}

		d := netip.AddrFrom4(rip)
		if _, exists := c.tags[d]; !exists {
			tag := c.tag(d)
			c.log().INFO("tag", d, tag)
			c.tags[d] = tag
		}
	}

	// we don't delete entries from NAT map because other servies
	// might have the same vip/rip combination - we should rebuild
	// from scratch

	if changed || len(del) > 0 {
		select {
		case c.update_nat <- true:
		default:
		}
	}

	service.sync(c.hwaddr, c.tags, c.maps)

	return nil
}

func (c *Client) Start() error {

	phy := c.Interfaces

	c.service = map[key]*Service{}
	c.hwaddr = map[ip4]mac{}
	c.ifaces = map[uint16]iface{}
	c.tags = map[netip.Addr]uint16{}
	c.natMap = natmap{}

	c.update_fwd = make(chan bool, 1)
	c.update_nat = make(chan bool, 1)

	var vetha, vethb string

	if c.NAT {

		var default_ip ip4
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

			default_ip = ip4(addr.As4())
			default_if = defaultInterface(default_ip)

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

		//fmt.Println(c.netns)
		c.log().INFO("netns", c.netns)
	}

	c.icmp = &icmp{}
	err := c.icmp.Start()

	if err != nil {
		return err
	}

	bpf, err := BPF()

	if err != nil {
		return err
	}

	c.maps, err = open(c.Logger, bpf, c.Native, len(c.VLANs) > 0 && c.Redirect, vetha, vethb, phy...)

	if err != nil {
		return err
	}

	c.maps.Distributed(c.Share)

	if c.netns != nil {
		err = c.netns.Open()

		if err != nil {
			return err
		}
	}

	c.scan_interfaces()
	c.update_redirects()

	go c.background()

	return nil
}

func (c *Client) background() {

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
		case <-c.maps.C:
			// era changed - update concurrents
			c.mutex.Lock()
			for _, s := range c.service {
				s.concurrent(c.maps)
			}
			c.mutex.Unlock()
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
				// all this probably not necessary? ...
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
			c.updateNAT()
		}

		if update_fwd {
			for _, service := range c.service {
				service.sync(c.hwaddr, c.tags, c.maps)
			}
		}

		c.mutex.Unlock()
	}
}

//func (c *Client) tuples_() map[[2]b4]bool {
//	m := map[[2]b4]bool{}
//	for _, s := range c.service {
//		for r, _ := range s.backend {
//			if s.Address.Is4() {
//				v := s.Address.As4()
//				m[[2]b4{v, r}] = true
//			}
//		}
//	}
//	return m
//}

func (c *Client) tuples() map[[2]b4]bool {
	tuples := map[[2]b4]bool{}
	for _, s := range c.service {
		for _, t := range s.tuples() {
			tuples[t] = true
		}
	}
	return tuples
}

func (c *Client) arp() {
	// ping all real IP addresses, causing an ARP lookup if not fresh
	for ip, _ := range c.natMap.RIPs() {
		c.icmp.Ping(ip4(ip).String())
	}
}

func (c *Client) update_mac(ips map[[4]byte]bool) bool {
	hwaddr := map[ip4]mac{}

	var changed bool

	arp := arp()

	for ip, _ := range ips {

		new, ok := arp[ip]

		if !ok {
			continue
		}

		old, ok := c.hwaddr[ip]

		if !ok || new != old {

			c.log().DEBUG("arp", kv{"ip": b4s(ip), "mac": b6s(new)})

			changed = true
		}

		hwaddr[ip] = new

		delete(c.hwaddr, ip)
	}

	if len(c.hwaddr) != 0 {
		changed = true
	}

	c.hwaddr = hwaddr

	//if changed {
	//	c.log().DEBUG("mac", kv{"hwaddr": hwaddr})
	//}

	return changed
}

func (c *Client) scan_interfaces() bool {

	var changed bool

	old := c.ifaces
	c.ifaces = vlanInterfaces(c.VLANs)

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

	//fmt.Println("IFS:", changed)

	return changed
}

func (c *Client) Services() (services []ServiceExtended, e error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, s := range c.service {
		services = append(services, s.extend(c.maps))
	}

	return
}

func (c *Client) Destinations(s Service) (destinations []DestinationExtended, e error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	svc, err := s.key()

	if err != nil {
		return destinations, err
	}

	service, ok := c.service[svc]

	if !ok {
		return destinations, errors.New("Service does not exist")
	}

	if !svc.addr.Is4() {
		return destinations, errors.New("Not IPv4")
	}

	for rip, d := range service.destinations(c.maps) {
		//mac := c.hwaddr[rip]
		//d.MAC = mac[:]
		d.MAC = MAC(c.hwaddr[rip])
		destinations = append(destinations, d)
	}

	sort.SliceStable(destinations, func(i, j int) bool {
		return destinations[i].Destination.Address.Compare(destinations[j].Destination.Address) < 0
	})

	return destinations, nil
}

/**********************************************************************/

func (c *Client) natAddr(i uint16) ip4 {
	ns := htons(i)
	return ip4{10, 255, ns[0], ns[1]}
}

func (b *Client) natEntry(vip, rip, nat ip4, realhw mac, vlanid uint16, idx iface) (ret []natkeyval) {

	vlanip := idx.ip4
	vlanhw := idx.mac
	vlanif := idx.idx

	var vc5bip ip4 = b.netns.IpB
	var vc5bhw mac = b.netns.HwB
	var vc5ahw mac = b.netns.HwA
	var vethif uint32 = uint32(b.netns.IdA)

	if realhw.isnil() {
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

func (c *Client) natEntries() (nkv []natkeyval) {

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

		if mac.isnil() {
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

func (c *Client) updateNAT() {

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

	c.log().DEBUG("nat", kv{"entries": len(nat), "updated": updated, "deleted,": deleted})
}

func (c *Client) update_redirects() {
	for vid := uint16(0); vid < 4096; vid++ {
		iface, _ := c.ifaces[vid]
		iface, exists := c.ifaces[vid]
		if exists {
			log := kv{"vlan": vid, "mac": b6s(iface.mac), "index": iface.idx, "interface": iface.nic, "ip": b4s(iface.ip4)}
			c.log().DEBUG("redirect", log)
		}
		c.maps.update_redirect(vid, iface.mac, iface.idx) // write nil value if not found
	}
}

func (c *Client) NATAddress(vip, rip netip.Addr) (r netip.Addr, _ bool) {
	if !vip.Is4() || !rip.Is4() {
		return r, false
	}

	ip, ok := c.nataddr(vip.As4(), rip.As4())

	return netip.AddrFrom4(ip), ok
}

func (c *Client) nataddr(vip, rip ip4) (r ip4, _ bool) {
	i := c.natMap.Get(vip, rip)

	if i == 0 {
		return r, false
	}

	return c.natAddr(i), true
}

func (c *Client) Namespace() string {
	return _NAMESPACE
}

func (c *Client) NamespaceAddress() string {
	return _IP.String()
}

func (c *Client) Info() (i Info) {
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

func (c *Client) UpdateVLANs(vlans map[uint16]net.IPNet) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.VLANs = vlans

	c.scan_interfaces()

	for ip, _ := range c.natMap.RIPs() {
		addr := netip.AddrFrom4(ip)
		c.tags[addr] = c.tag(addr)
	}
}

func (c *Client) Prefixes() [PREFIXES]uint64 {
	return c.maps.ReadPrefixCounters()
}

func (c *Client) Service(s Service) (se ServiceExtended, e error) {
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

	return service.extend(c.maps), nil
}

// Return a slice of bytes representing a flow from the eBPF program
// in the kernel. This can be distributed (eg. via multicast) to other
// load balancers and used to preserve flows during failover. When no
// flows are available in the queue the slice returned will have
// length zero.
func (c *Client) ReadFlow() []byte {
	var entry [_FLOW_S + _STATE_S]byte

	if xdp.BpfMapLookupAndDeleteElem(c.maps.flow_queue(), nil, uP(&entry)) != 0 {
		return nil
	}

	return entry[:]
}

// Make a flow returned from ReadFlow() known to the local eBPF program.
func (c *Client) WriteFlow(fs []byte) {

	if len(fs) != _FLOW_S+_STATE_S {
		return
	}

	flow := uP(&fs[0])
	state := uP(&fs[_FLOW_S])
	time := (*uint32)(state)
	*time = uint32(xdp.KtimeGet()) // set first 4 bytes of state to the local kernel time
	xdp.BpfMapUpdateElem(c.maps.flow_share(), flow, state, xdp.BPF_ANY)
}
