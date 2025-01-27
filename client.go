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
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"sync"
	"time"
	"unsafe"

	"github.com/davidcoles/xvs/bpf"
	"github.com/davidcoles/xvs/xdp"
)

const VETH = bpf.VETH_ID

const (
	F_NO_SHARE_FLOWS    = bpf.F_NO_SHARE_FLOWS
	F_NO_TRACK_FLOWS    = bpf.F_NO_TRACK_FLOWS
	F_NO_ESTIMATE_CONNS = bpf.F_NO_ESTIMATE_CONNS
	F_NO_STORE_STATS    = bpf.F_NO_STORE_STATS
)

type uP = unsafe.Pointer
type b4 = [4]byte
type b6 = [6]byte

const _b4s = "%d.%d.%d.%d"
const _b6s = "%02x:%02x:%02x:%02x:%02x:%02x"

func b4s(i b4) string { return fmt.Sprintf(_b4s, i[0], i[1], i[2], i[3]) }
func b6s(i b6) string { return fmt.Sprintf(_b6s, i[0], i[1], i[2], i[3], i[4], i[5]) }

type Info struct {
	Packets   uint64 // Total number of packets received by XDP hooks
	Octets    uint64 // Total number of bytes received by XDP hooks
	Flows     uint64 // Total number of new flow entries created in hash tables
	Latency   uint64 // Average measurable latency for XDP hook
	Dropped   uint64 // Number of non-conforming packets dropped
	Blocked   uint64 // Number of packets dropped by prefix
	NotQueued uint64 // Failed attempts to queue flow state updates to userspace
}

type Stats struct {
	Packets uint64
	Octets  uint64
	Flows   uint64
	Current uint64
}

func (s *Stats) add(a Stats) {
	s.Packets += a.Packets
	s.Octets += a.Octets
	s.Flows += a.Flows
	s.Current += a.Current
}

type Client struct {
	NAT        bool                 // Create interfaces and a network namespace to probe backend servers
	Native     bool                 // Attach XDP functions with the XDP_FLAGS_DRV_MODE flag
	Interfaces []string             // List of interfaces to attach XDP function
	Address    netip.Addr           // Address of primary interface in single-VLAN mode
	VLANs      map[uint16]net.IPNet // VLAN ID to subnet mapping
	Debug      Debug                // Debug interface
	InitDelay  uint8                // Pause for InitDelay seconds between each XDP attach/detach
	MaxFlows   uint32               // Override size of the flow tracking hash table if non-zero
	Frags      bool                 // Experimental: Send ICMP_DEST_UNREACH / ICMP_FRAG_NEEDED to all backends when true

	icmp   *icmp
	xdp    *xdp.XDP
	netns  *netns
	mutex  sync.Mutex
	_mutex sync.Mutex

	natmap natmap

	service map[key]*service
	tags    map[netip.Addr]int16
	hwaddr  map[ip4]mac // IPv4 only
	vlans   map[uint16]nic
	nics    map[string]nic

	phys    nic
	veth    bpf_redirect
	setting bpf_setting

	update_tuples chan bool
	update_vlans  chan bool
}

func (c *Client) Flags(f uint8) {
	c._mutex.Lock()
	c.setting.features = f
	c.write_settings()
	c._mutex.Unlock()
}

func (c *Client) Start() error {

	c.natmap = natmap{}
	c.service = map[key]*service{}
	c.tags = map[netip.Addr]int16{}
	c.nics = map[string]nic{}
	c.hwaddr = arp()
	c.vlans = vlanInterfaces(c.VLANs)
	c.icmp = &icmp{}

	c.update_tuples = make(chan bool, 1)
	c.update_vlans = make(chan bool, 1)

	if !c.Address.Is4() {
		return fmt.Errorf("Address must be a valid IPv4 address")
	}

	addr := c.Address.As4()

	//nics := map[string]nic{}

	if len(c.Interfaces) < 1 {
		return fmt.Errorf("At least one network interface must be supplied")
	}

	for _, i := range c.Interfaces {
		iface, err := net.InterfaceByName(i)

		if err != nil {
			return err
		}

		n := nic{idx: iface.Index, nic: i}
		copy(n.mac[:], iface.HardwareAddr[:])
		c.nics[i] = n
	}

	iface := defaultInterface(net.IP(addr[:]))
	if iface == nil {
		return fmt.Errorf("Couldn't find an interface with address %s", c.Address)
	}

	c.phys = nic{nic: iface.Name, idx: iface.Index, ip4: addr}
	copy(c.phys.mac[:], iface.HardwareAddr[:])

	/**********************************************************************/

	var err error

	if err = c.icmp.start(); err != nil {
		return err
	}

	delay := time.Duration(c.InitDelay) * time.Second

	for _, n := range c.nics {
		c.xdp.LinkDetach(uint32(n.idx))
		time.Sleep(delay)
	}

	if c.xdp, err = xdp.LoadBpfFile(bpf_o); err != nil {
		return err
	}

	if err = c.find_maps(); err != nil {
		return err
	}

	// flow_share map has the same size as the inner map, so use this as a reference
	max_entries := c.flow_share().MaxEntries()

	if max_entries < 0 {
		return fmt.Errorf("Error looking up size of the flow state map")
	}

	if c.MaxFlows > 0 {
		max_entries = int(c.MaxFlows)
	}

	max_cpu := c.flow_states().MaxEntries()

	if max_cpu < 0 {
		return fmt.Errorf("Error looking up size of the CPU flow state map")
	}

	num_cpu := uint32(runtime.NumCPU())

	if num_cpu > uint32(max_cpu) {
		return fmt.Errorf("Number of CPUs is greater than the number compiled in to the ELF object")
	}

	for cpu := uint32(0); cpu < num_cpu; cpu++ {
		name := fmt.Sprintf("flow_state_inner_%d", cpu)
		if r := c.flow_states().CreateLruHash(cpu, name, bpf.FLOW_S, bpf.STATE_S, uint32(max_entries)); r != 0 {
			return fmt.Errorf("Unable to create flow state map for CPU %d: %d", cpu, r)
		}
	}

	if c.NAT {
		if c.netns, err = nat(c.xdp, "xdp_fwd_func", "xdp_pass_func"); err != nil {
			return err
		}
	}

	for _, n := range c.nics {
		if err = c.xdp.LoadBpfSection("xdp_fwd_func", c.Native, uint32(n.idx)); err != nil {
			return err
		}
		time.Sleep(delay)
	}

	if c.netns != nil {
		c.veth = bpf_redirect{
			index:  uint32(c.netns.a.idx), // virtual interface on the host side
			source: c.netns.a.mac,         // source mac is from the virtual interface on the host side
			addr:   c.netns.b.ip4,         // addr is sent *to* in this case (from a nat ip addr)
			dest:   c.netns.b.mac,         // dest hw addr is the netns side mac
		}
	} // empty otherwise

	c.write_bpf_redirects()

	go c.pings()
	go c.background()
	go c.concurrent()

	if c.Frags {
		go c.watchICMPQueue()
	}

	return nil
}

// Rerun bpf_xdp_attach with the XDP forwarding eBPF code. This can be
// used to correct an issue with some network cards/drivers which seem
// to forget about the XDP hook (eg.: Intel X710) after being poked
// with ethtool (ethtool -r was problematic for me). In a bonded
// ethernet setup I have had sucess with removing a member from the
// bond, running ethtool -r, reattaching eBPF and then re-introducting
// to the bond, with short pauses between each step.
func (c *Client) ReattachBPF(nic string) error {

	n, ok := c.nics[nic]

	if !ok {
		return fmt.Errorf("Interface %s was not previously initialised", nic)
	}

	c.xdp.LinkDetach(uint32(n.idx))

	return c.xdp.LoadBpfSection("xdp_fwd_func", c.Native, uint32(n.idx))
}

func (c *Client) write_bpf_redirects() {

	debug := map[uint16]nic{}

	phys := bpf_redirect{index: uint32(c.phys.idx), addr: c.phys.ip4, source: c.phys.mac}

	key := uint32(0)
	val := uint32(phys.index)
	c.redirect_map().UpdateElem(uP(&key), uP(&val), xdp.BPF_ANY)
	c.redirect_mac().UpdateElem(uP(&key), uP(&phys), xdp.BPF_ANY)
	debug[0] = c.phys

	// write empty entries for the interfaces which exist
	for vid := uint16(1); vid < 4095; vid++ {
		nic, ok := c.vlans[vid]
		eth := bpf_redirect{addr: nic.ip4, source: nic.mac, index: uint32(nic.idx)}

		key = uint32(vid)
		val = uint32(eth.index)
		c.redirect_map().UpdateElem(uP(&key), uP(&val), xdp.BPF_ANY)
		c.redirect_mac().UpdateElem(uP(&key), uP(&eth), xdp.BPF_ANY)

		if ok {
			debug[vid] = nic
		}
	}

	veth := c.veth
	key = uint32(VETH)
	val = uint32(veth.index)
	c.redirect_map().UpdateElem(uP(&key), uP(&val), xdp.BPF_ANY)
	c.redirect_mac().UpdateElem(uP(&key), uP(&veth), xdp.BPF_ANY)

	if c.netns != nil {
		debug[VETH] = c.netns.a
		debug[VETH+1] = c.netns.b
	}

	c.debug_redirects(debug)
}

func (c *Client) concurrent() {

	ticker := time.NewTicker(time.Second * 30)
	defer ticker.Stop()

	for {
		<-ticker.C
		c._mutex.Lock()
		c.setting.era++
		c.write_settings()
		c._mutex.Unlock()

		c.mutex.Lock()
		for _, s := range c.service {
			s.concurrent(c)
		}
		c.mutex.Unlock()
	}
}

func (c *Client) era() uint8 {
	c._mutex.Lock()
	defer c._mutex.Unlock()
	//return c._era
	return c.setting.era
}

func (c *Client) pings() {
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()
	for {
		<-ticker.C
		for r, _ := range c.natmap.rips() {
			c.icmp.ping(b4s(r))
		}
	}
}

func (c *Client) background() {

	ticker := time.NewTicker(time.Second * 15)
	defer ticker.Stop()

	scanner := time.NewTicker(time.Second * 60)
	defer scanner.Stop()

	for {
		var update_vlans bool
		var update_tuples bool
		var scan_interfaces bool

		select {
		case <-c.update_vlans:
			update_vlans = true
		case <-c.update_tuples:
			update_tuples = true
		case <-scanner.C:
			scan_interfaces = true
		case <-ticker.C:
		}

		time.Sleep(time.Second) // wait breifly and then collect any upates which have clustered together

	batch:
		for {
			select {
			case <-c.update_vlans:
				update_vlans = true
			case <-c.update_tuples:
				update_tuples = true
			case <-scanner.C:
				scan_interfaces = true
			case <-ticker.C:
			default:
				break batch
			}
		}

		c.mutex.Lock()

		if update_tuples {
			c.natmap.clean(c.tuples()) // remove any tuples that no longer exist
			c.natmap.index()           // make sure that all tuples are indexed
		}

		if update_vlans {
			c.retag_reals()
		}

		if update_vlans || scan_interfaces {
			c.vlans = vlanInterfaces(c.VLANs) // scan interfaces
			c.write_bpf_redirects()           // rebuild vlan -> interface forward in kernel
		}

		old := c.arp_entries()
		c.hwaddr = arp() // reread arp table
		new := c.arp_entries()

		if update_vlans || update_tuples || c.arp_diff(old, new) {

			// rebuild bpf_nat mappings
			nat := c.bpf_nat_entries()
			out, in := c.write_nat(nat)

			c.debug_nat(new, nat, out, in)

			// resync vlan/mac entries in services
			for _, s := range c.service {
				s.sync(c, c.hwaddr, c.tags)
			}
		}

		c.mutex.Unlock()
	}
}

func (c *Client) arp_diff(old map[ip4]mac, new map[ip4]mac) bool {
	if len(new) != len(old) {
		return true
	}

	for i, n := range new {
		if o, ok := old[i]; !ok || o != n {
			return true
		}
	}

	for i, o := range old {
		if n, ok := new[i]; !ok || o != n {
			return true
		}
	}

	return false
}

func (c *Client) arp_entries() map[ip4]mac {
	ret := map[ip4]mac{}
	for ip, _ := range c.natmap.rips() {
		ret[ip] = c.hwaddr[ip]
	}
	return ret
}

func (c *Client) bpf_nat_entries() map[ip4]bpf_nat {

	natmap := map[ip4]bpf_nat{}

	if c.netns == nil {
		return natmap
	}

	for pair, index := range c.natmap.all() {
		vip := pair[0]
		rip := pair[1]
		vid, ok := c.tags[netip.AddrFrom4(rip)]

		if !ok || vid < 0 || vid > 4094 {
			continue
		}

		mac, ok := c.hwaddr[rip]

		if !ok {
			continue
		}

		nat := c.netns.nat(index)
		bpf := bpf_nat{vip: vip, mac: mac, vid: uint16(vid)}

		natmap[nat] = bpf
	}

	return natmap
}

func (c *Client) retag_reals() {
	c.tags = map[netip.Addr]int16{}

	vlans := c.vlanIDs()

	for r, _ := range c.natmap.rips() {
		i := netip.AddrFrom4(r)
		c.tags[i] = c.tag_real(i, vlans) // re-tag RIPs
	}
}

func (c *Client) tuples() map[[2]b4]bool {
	nm := map[[2]b4]bool{}
	for k, s := range c.service {
		if k.addr.Is4() {
			vip := k.addr.As4()
			for d, _ := range s.backend {
				nm[[2]b4{vip, d}] = true
			}
		}
	}
	return nm
}

func (c *Client) write_nat(natmap map[ip4]bpf_nat) (out []ip4, in []bpf_nat) {

	var list []ip4

	for k, _ := range natmap {
		list = append(list, k)
	}

	sort.SliceStable(list, func(i, j int) bool {
		return nltoh(list[i]) < nltoh(list[j])
	})

	rev := map[bpf_nat]ip4{}

	for _, nat := range list {
		real := natmap[nat]
		c.nat_out().UpdateElem(uP(&nat), uP(&real), xdp.BPF_ANY)
		real.vid = 0 // bpf.c: struct nat in = { .vip = ipv4->saddr, .vid = 0 };
		c.nat_in().UpdateElem(uP(&real), uP(&nat), xdp.BPF_ANY)

		rev[real] = nat
	}

	{
		var key, next ip4

		for {
			if c.nat_out().GetNextKey(uP(&key), uP(&next)) != 0 {
				break
			}

			if _, ok := natmap[next]; !ok {
				out = append(out, next)
			}

			key = next
		}

		for _, k := range out {
			c.nat_out().DeleteElem(uP(&k))
		}
	}

	{
		var key, next bpf_nat

		for {
			if c.nat_in().GetNextKey(uP(&key), uP(&next)) != 0 {
				break
			}

			if _, ok := rev[next]; !ok {
				in = append(in, next)
			}

			key = next
		}

		for _, k := range in {
			c.nat_in().DeleteElem(uP(&k))
		}
	}

	return
}

func (c *Client) debug_nat(arp map[ip4]mac, nat map[ip4]bpf_nat, out []ip4, in []bpf_nat) {

	tag := map[netip.Addr]int16{}
	for r, _ := range c.natmap.rips() {
		addr := netip.AddrFrom4(r)
		t := c.tags[addr]
		tag[addr] = t
	}

	hwa := map[netip.Addr][6]byte{}
	for k, v := range arp {
		a := netip.AddrFrom4(k)
		hwa[a] = v
		//fmt.Println("ARP", a, b6s(v))
	}

	vrn := map[[2]netip.Addr]netip.Addr{}
	if c.netns != nil {
		for k, v := range c.natmap.all() {
			k0 := netip.AddrFrom4(k[0])
			k1 := netip.AddrFrom4(k[1])
			vrn[[2]netip.Addr{k0, k1}] = netip.AddrFrom4(c.netns.nat(v))
		}
	}

	bar := map[netip.Addr]string{}
	for k, v := range nat {
		a := netip.AddrFrom4(k)
		i := v.String()
		bar[a] = i
		//fmt.Println("NAT", a, i)
	}

	var o []netip.Addr
	for _, k := range out {
		o = append(o, netip.AddrFrom4(k))
		//fmt.Println("DEL out", netip.AddrFrom4(k))
	}

	var i []string
	for _, k := range in {
		//fmt.Println("DEL in", k.String())
		i = append(i, k.String())
	}

	if c.Debug != nil {
		c.Debug.NAT(tag, hwa, vrn, bar, o, i)
	}
}

func (c *Client) debug_redirects(m map[uint16]nic) {

	if c.Debug == nil {
		return
	}

	out := map[uint16]string{}
	for vid, nic := range m {
		out[vid] = nic.String()
	}

	c.Debug.Redirects(out)
}

type Debug interface {
	NAT(tag map[netip.Addr]int16, arp map[netip.Addr][6]byte, vrn map[[2]netip.Addr]netip.Addr, nat map[netip.Addr]string, out []netip.Addr, in []string)
	Redirects(vlans map[uint16]string)
	Backend(vip netip.Addr, port uint16, protocol uint8, backends []byte, took time.Duration)
}

type vc struct {
	vid uint16
	net net.IPNet
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

func (c *Client) tag(i netip.Addr) int16 {
	vlans := c.vlanIDs()
	return c.tag_real(i, vlans)
}

func (c *Client) tag_real(i netip.Addr, vlans []vc) int16 {

	if len(vlans) < 1 {
		return 0 // no VLANs listed - untagged
	}

	if !i.Is4() {
		return -1 // bad IP - return an invalid VLAN
	}

	ip4 := i.As4()

	for _, v := range vlans {
		if v.net.Contains(net.IP(ip4[:])) {
			return int16(v.vid)
		}
	}

	return -1 // not found
}

func (c *Client) nataddr(vip, rip ip4) (r ip4, _ bool) {

	if c.netns == nil {
		return r, false
	}

	i := c.natmap.get(vip, rip)

	if i == 0 {
		return r, false
	}

	return c.netns.nat(i), true
}

/**********************************************************************/

const (
	_redirect_map    = "redirect_map"
	_redirect_mac    = "redirect_mac"
	_nat_out         = "nat_out"
	_nat_in          = "nat_in"
	_vrpp_counter    = "vrpp_counter"
	_vrpp_concurrent = "vrpp_concurrent"
	_service_backend = "service_backend"
	_globals         = "globals"
	_settings        = "settings"
	_flow_queue      = "flow_queue"
	_flow_share      = "flow_share"
	_prefix_counters = "prefix_counters"
	_prefix_drop     = "prefix_drop"
	_flow_states     = "flow_states"
	_snoop_queue     = "snoop_queue"
	_icmp_queue      = "icmp_queue"
)

func (c *Client) find_maps() error {
	int_s := 4
	int64_s := 8
	nat_s := int(unsafe.Sizeof(bpf_nat{}))
	vrpp_s := int(unsafe.Sizeof(bpf_vrpp{}))
	global_s := int(unsafe.Sizeof(bpf_global{}))
	counter_s := int(unsafe.Sizeof(bpf_counter{}))
	backend_s := int(unsafe.Sizeof(bpf_backend{}))
	service_s := int(unsafe.Sizeof(bpf_service{}))
	redirect_s := int(unsafe.Sizeof(bpf_redirect{}))
	setting_s := int(unsafe.Sizeof(bpf_setting{}))

	maps := []struct {
		name string
		klen int
		vlen int
	}{
		{_redirect_map, int_s, int_s},
		{_redirect_mac, int_s, redirect_s},
		{_nat_out, int_s, nat_s},
		{_nat_in, nat_s, int_s},
		{_vrpp_counter, vrpp_s, counter_s},
		{_vrpp_concurrent, vrpp_s, int64_s},
		{_service_backend, service_s, backend_s},
		{_globals, int_s, global_s},
		{_settings, int_s, setting_s},
		{_flow_queue, 0, bpf.FLOW_S + bpf.STATE_S},
		{_snoop_queue, 0, bpf.SNOOP_BUFFER_SIZE},
		{_icmp_queue, 0, bpf.SNOOP_BUFFER_SIZE},
		{_flow_share, bpf.FLOW_S, bpf.STATE_S},
		{_prefix_counters, int_s, 2 * int64_s}, // FIXME - create a struct
		{_prefix_drop, int_s, int64_s},
		{_flow_states, int_s, int_s},
	}

	for _, m := range maps {
		_, err := c.xdp.FindMap(m.name, m.klen, m.vlen)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) redirect_map() xdp.Map    { return c.xdp.Map(_redirect_map) }
func (c *Client) redirect_mac() xdp.Map    { return c.xdp.Map(_redirect_mac) }
func (c *Client) vrpp_counter() xdp.Map    { return c.xdp.Map(_vrpp_counter) }
func (c *Client) vrpp_concurrent() xdp.Map { return c.xdp.Map(_vrpp_concurrent) }
func (c *Client) service_backend() xdp.Map { return c.xdp.Map(_service_backend) }
func (c *Client) nat_out() xdp.Map         { return c.xdp.Map(_nat_out) }
func (c *Client) nat_in() xdp.Map          { return c.xdp.Map(_nat_in) }
func (c *Client) globals() xdp.Map         { return c.xdp.Map(_globals) }
func (c *Client) settings() xdp.Map        { return c.xdp.Map(_settings) }
func (c *Client) flow_queue() xdp.Map      { return c.xdp.Map(_flow_queue) }
func (c *Client) snoop_queue() xdp.Map     { return c.xdp.Map(_snoop_queue) }
func (c *Client) icmp_queue() xdp.Map      { return c.xdp.Map(_icmp_queue) }
func (c *Client) flow_share() xdp.Map      { return c.xdp.Map(_flow_share) }
func (c *Client) prefix_counters() xdp.Map { return c.xdp.Map(_prefix_counters) }
func (c *Client) prefix_drop() xdp.Map     { return c.xdp.Map(_prefix_drop) }
func (c *Client) flow_states() xdp.Map     { return c.xdp.Map(_flow_states) }

func (c *Client) lookup_vrpp_counter(v *bpf_vrpp, bc *bpf_counter) int {

	all := make([]bpf_counter, xdp.BpfNumPossibleCpus())

	ret := c.vrpp_counter().LookupElem(uP(v), uP(&(all[0])))

	var x bpf_counter

	for _, v := range all {
		x.add(v)
	}

	*bc = x

	return ret
}

func (c *Client) update_vrpp_concurrent(v *bpf_vrpp, a *int64, flag uint64) int {

	all := make([]int64, xdp.BpfNumPossibleCpus())

	for n, _ := range all {
		if a != nil {
			all[n] = *a
		}
	}

	return c.vrpp_concurrent().UpdateElem(uP(v), uP(&(all[0])), flag)
}

func (c *Client) update_vrpp_counter(v *bpf_vrpp, bc *bpf_counter, flag uint64) int {

	all := make([]bpf_counter, xdp.BpfNumPossibleCpus())

	for n, _ := range all {
		all[n] = *bc
	}

	return c.vrpp_counter().UpdateElem(uP(v), uP(&(all[0])), flag)
}

func (c *Client) read_and_clear_concurrent(vip, rip ip4, port uint16, protocol uint8) uint64 {

	v := &bpf_vrpp{vip: vip, rip: rip, port: htons(port), protocol: protocol, pad: (c.era() + 1) % 2}
	var a, n int64
	c.lookup_vrpp_concurrent(v, &a)
	c.update_vrpp_concurrent(v, &n, xdp.BPF_ANY)

	if a < 0 {
		return 0
	}

	return uint64(a)
}

func (c *Client) lookup_vrpp_concurrent(v *bpf_vrpp, a *int64) int {

	all := make([]int64, xdp.BpfNumPossibleCpus())

	ret := c.vrpp_concurrent().LookupElem(uP(v), uP(&(all[0])))

	var x int64

	for _, v := range all {
		if v > 0 {
			x += v
		}
	}

	*a = x

	return ret
}

func (c *Client) update_service_backend(key *bpf_service, b *bpf_backend, flag uint64) int {
	/*
		// no longer a percpu map
		all := make([]bpf_backend, xdp.BpfNumPossibleCpus())

		for n, _ := range all {
			all[n] = *b
		}

		return c.service_backend().UpdateElem(uP(key), uP(&(all[0])), flag)
	*/
	val := *b
	return c.service_backend().UpdateElem(uP(key), uP(&val), flag)
}

func (c *Client) lookup_globals() bpf_global {

	all := make([]bpf_global, xdp.BpfNumPossibleCpus())
	var zero uint32

	c.globals().LookupElem(uP(&zero), uP(&(all[0])))

	var g bpf_global

	for _, v := range all {
		g.add(v)
	}

	return g
}

func (c *Client) write_settings() int {
	var zero uint32

	/*
		// no longer a percpu map
		all := make([]bpf_setting, xdp.BpfNumPossibleCpus())

		for n, _ := range all {
			all[n] = c.setting
		}

		return c.settings().UpdateElem(uP(&zero), uP(&(all[0])), xdp.BPF_ANY)
	*/

	s := c.setting
	return c.settings().UpdateElem(uP(&zero), uP(&s), xdp.BPF_ANY)
}

/**********************************************************************/

func (c *Client) UpdateVLANs(vlans map[uint16]net.IPNet) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.VLANs = vlans

	select {
	case c.update_vlans <- true:
	default:
	}
}

// Retrieve the name of the network namespace that xvs is using
func (c *Client) Namespace() string {
	if c.netns == nil {
		return ""
	}
	return c.netns.namespace()
}

// Retrieve the IP address of the interface in the network namespace
// that xvs is using
func (c *Client) NamespaceAddress() string {
	if c.netns == nil {
		return ""
	}
	a := c.netns.addr()
	return fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3])
}

// Return the NAT address of a virtual and real IP address pair -
// traffic to this address will be translated to target the services
// on the real server. This address can be used to query the services
// for health checking purposes.
func (c *Client) NATAddress(vip, rip netip.Addr) (r netip.Addr, _ bool) {
	if !vip.Is4() || !rip.Is4() {
		return r, false
	}

	ip, ok := c.nataddr(vip.As4(), rip.As4())

	return netip.AddrFrom4(ip), ok
}

func (c *Client) Services() (services []ServiceExtended, e error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, s := range c.service {
		services = append(services, s.extend(c))
	}

	return
}

func (c *Client) SetService(s Service, dst ...Destination) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.setService(s, dst)
}

//func (c *Client) SetService(s Service, dst []Destination) error {
//	c.mutex.Lock()
//	defer c.mutex.Unlock()
//	return c.setService(s, dst)
//}

func (c *Client) CreateService(s Service) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, ok := c.service[s.key()]; ok {
		return fmt.Errorf("Service exists")
	}

	return c.setService(s, nil)
}

func (c *Client) setService(s Service, dst []Destination) error {

	if !s.Address.Is4() {
		return fmt.Errorf("Not IPv4")
	}

	svc := s.key()

	vip := svc.addr.As4()

	service, ok := c.service[svc]

	if !ok {
		service = s.service()
		c.service[svc] = service
	}

	add, del := service.set(c, s, dst)

	var changed bool

	for _, rip := range add {

		if c.natmap.add(vip, rip) == 0 {
			// vip/rip combination wasn't in NAT map - fire off a ping and signal to rebuild index
			c.icmp.ping(rip.String())
			changed = true
		}

		d := netip.AddrFrom4(rip)
		if _, exists := c.tags[d]; !exists {
			c.tags[d] = c.tag(d)
		}
	}

	// we don't delete entries from NAT map because other servies
	// might have the same vip/rip combination - we should rebuild
	// from scratch

	if changed || len(del) > 0 {
		select {
		case c.update_tuples <- true:
		default:
		}
	}

	service.sync(c, c.hwaddr, c.tags)

	return nil
}

func (c *Client) RemoveDestination(s Service, d Destination) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !s.Address.Is4() {
		return fmt.Errorf("Not IPv4")
	}

	key := s.key()

	service, ok := c.service[key]

	if !ok {
		return fmt.Errorf("Service does not exist")
	}

	return service.removeDestination(c, d)
}

func (c *Client) RemoveService(s Service) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !s.Address.Is4() {
		return fmt.Errorf("Not IPv4")
	}

	key := s.key()

	service, ok := c.service[key]

	if !ok {
		return fmt.Errorf("Service does not exist")
	}

	delete(c.service, key)

	var more bool

	for k, _ := range c.service {
		if k.addr == service.Address {
			more = true
		}
	}

	service.remove(c, more)

	select {
	case c.update_tuples <- true:
	default:
	}

	return nil
}

func (c *Client) CreateDestination(s Service, d Destination) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !s.Address.Is4() || !d.Address.Is4() {
		return fmt.Errorf("Not IPv4")
	}

	svc := s.key()

	service, ok := c.service[svc]

	if !ok {
		return fmt.Errorf("Service does not exist")
	}

	ip := d.Address.As4()

	if _, exists := service.backend[ip]; exists {
		return fmt.Errorf("Destination exists")
	}

	var dst []Destination

	for _, d := range service.backend {
		dst = append(dst, *d)
	}

	dst = append(dst, d)

	return c.setService(s, dst)
}

func (c *Client) Destinations(s Service) (destinations []DestinationExtended, e error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	svc := s.key()

	service, ok := c.service[svc]

	if !ok {
		return destinations, fmt.Errorf("Service does not exist")
	}

	if !svc.addr.Is4() {
		return destinations, fmt.Errorf("Not IPv4")
	}

	for rip, d := range service.destinations(c) {
		d.MAC = MAC(c.hwaddr[rip])
		destinations = append(destinations, d)
	}

	sort.SliceStable(destinations, func(i, j int) bool {
		return destinations[i].Destination.Address.Compare(destinations[j].Destination.Address) < 0
	})

	return destinations, nil
}

func (c *Client) Service(s Service) (se ServiceExtended, e error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !s.Address.Is4() {
		return se, fmt.Errorf("Not IPv4")
	}

	svc := s.key()

	service, ok := c.service[svc]

	if !ok {
		return se, fmt.Errorf("Service does not exist")
	}

	return service.extend(c), nil
}

func (c *Client) Info() (i Info) {
	g := c.lookup_globals()
	i.Packets = g.rx_packets
	i.Octets = g.rx_octets
	i.Flows = g.new_flows
	i.Latency = g.latency()
	i.Dropped = g.dropped
	i.Blocked = g.blocked
	i.NotQueued = g.qfailed
	return
}

const PREFIXES = 1048576

func (c *Client) Prefixes() [PREFIXES]uint64 {

	var prefixes [PREFIXES]uint64

	for i, _ := range prefixes {

		j := uint32(i)
		p := make([][2]uint64, xdp.BpfNumPossibleCpus())

		c.prefix_counters().LookupElem(uP(&j), uP(&(p[0])))

		var x uint64

		for _, v := range p {
			x += v[0]
		}

		prefixes[i] = x
	}

	return prefixes
}

func (c *Client) Block(b [PREFIXES]bool) {
	for i := uint32(0); i < PREFIXES/64; i++ {
		var val uint64
		for j := 0; j < 64; j++ {
			if b[(int(i)*64)+j] {
				val |= bpf.Pow64(uint8(j))
			}
		}

		c.prefix_drop().UpdateElem(uP(&i), uP(&val), xdp.BPF_ANY)
	}
}

// Retrive a flow state descriptor from the kernel via a
// queue. Retrieved descriptors can be shared with other load
// balancers in a cluster to facilitate failover. If no more flows are
// currently available then the length of the byte slice returned will
// be zero.
func (c *Client) ReadFlow() []byte {
	var entry [bpf.FLOW_S + bpf.STATE_S]byte

	if c.flow_queue().LookupAndDeleteElem(nil, uP(&entry)) != 0 {
		return nil
	}

	return entry[:]
}

// Make a flow returned from ReadFlow() known to the local eBPF
// program to facilitate cluster failover.
func (c *Client) WriteFlow(fs []byte) {

	if len(fs) != bpf.FLOW_S+bpf.STATE_S {
		return
	}

	flow := uP(&fs[0])
	state := uP(&fs[bpf.FLOW_S])
	time := (*uint32)(state)
	*time = uint32(xdp.KtimeGet()) // set first 4 bytes of state to the local kernel time
	c.flow_share().UpdateElem(flow, state, xdp.BPF_ANY)
}

func (c *Client) readSnoop() []byte {
	var r [bpf.SNOOP_BUFFER_SIZE]byte

	if c.snoop_queue().LookupAndDeleteElem(nil, uP(&r)) != 0 {
		return nil
	}

	return r[:]
}

func (c *Client) readICMPQueue() []byte {
	var r [bpf.SNOOP_BUFFER_SIZE]byte

	if c.icmp_queue().LookupAndDeleteElem(nil, uP(&r)) != 0 {
		return nil
	}

	return r[:]
}

func (c *Client) watchICMPQueue() {

	proto := func(b bool) Protocol { return map[bool]Protocol{false: TCP, true: UDP}[b] }

	tries := c.icmp_queue().MaxEntries() / 10        // process 1/10th of the icmp queue
	ticker := time.NewTicker(100 * time.Millisecond) // ... every 1/10th of a second

	for {
		<-ticker.C

		for try := 0; try < tries; try++ {

			r := c.readICMPQueue()

			if r == nil {
				break
			}

			var ip [4]byte
			copy(ip[:], r[:])
			port := uint16(r[4])<<8 | uint16(r[5])
			size := (uint16(r[6])<<8 | uint16(r[7])) & 0x7ff // restricted to 2047 bytes
			//reason := uint8(r[6]) >> 4 // not used yet
			protocol := proto((uint8(r[6]&0x08) >> 3) > 0)
			icmp := r[8 : 8+size]

			c.repeatIP(Service{Address: netip.AddrFrom4(ip), Port: port, Protocol: protocol}, icmp)
		}
	}
}

// repeat raw IP packet to all backend (healthy or not) for a service
func (c *Client) repeatIP(service Service, packet []byte) {
	c.mutex.Lock()
	s, ok := c.service[service.key()]
	c.mutex.Unlock()

	if ok {
		s.repeatIP(c.xdp, packet)
	}
}
