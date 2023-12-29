package xvs

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/davidcoles/xvs/foo"
	"github.com/davidcoles/xvs/xdp"
)

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

	mutex   sync.Mutex
	service map[key]*Service

	ifaces map[uint16]iface
	hwaddr map[IP4]MAC // IPv4 only
	maps   *maps
	icmp   *ICMP
	netns  *netns
	tags   map[netip.Addr]uint16

	foo foo.Foo

	update chan bool
}

func (c *Client2) tag(netip.Addr) uint16 {
	return 0
}

func (c *Client2) SetService(s Service, dst []Destination) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	svc, err := s.key()

	if err != nil {
		return err
	}

	if !svc.addr.Is4() {
		return errors.New("Not IPv4")
	}

	vip := svc.addr.As4()
	port := svc.port
	protocol := svc.prot

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
		//if _, ok := c.tag_map.ent(rip); !ok {
		//	c.tag_map.set(rip, c.tag(rip))
		//}
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

	//c.update_nat_map()
	//for vid, iface := range c.ifaces {
	//	c.maps.update_redirect(vid, iface.mac, iface.idx)
	//}
	///////c.update_redirects()
	//c.update_nat_no_lock()
	//service.state = nil
	//c.update_service(svc, service, c.hwaddr, false)

	service.sync(c.hwaddr, c.tags, c.maps)

	return nil
}

func (c *Client2) Start() error {

	phy := c.Interfaces

	//c.nat_map = map[[2]IP4]uint16{}
	//c.tag_map = map[IP4]uint16{}
	c.service = map[key]*Service{}
	c.hwaddr = map[IP4]MAC{}
	c.update = make(chan bool, 1)
	c.tags = map[netip.Addr]uint16{}

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

	go c.background()

	return nil
}

func (c *Client2) background() {
	ticker := time.NewTicker(time.Second)
	for {
		select {
		case <-ticker.C:
			c.mutex.Lock()

			ips := map[IP4]bool{}

			for _, s := range c.service {
				for ip, _ := range s.backend {
					c.icmp.Ping(ip.String())
					ips[ip] = true
				}
			}

			c.update_arp(ips)

			for _, service := range c.service {
				service.sync(c.hwaddr, c.tags, c.maps)
			}

			c.mutex.Unlock()

		case <-c.update:
		}
	}
}

func (b *Client2) update_arp(ips map[IP4]bool) bool {
	hwaddr := map[IP4]MAC{}

	var changed bool

	arp := arp()

	fmt.Println(arp, ips)

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
		fmt.Println("ARP:", hwaddr)
	}

	return changed
}

func (c *Client2) scan_interfaces() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	fmt.Println("IFS:")
	c.ifaces = VlanInterfaces(c.VLANs)
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
		//return nltoh(a[i]) < nltoh(a[j])
		return destinations[i].Destination.Address.Compare(destinations[j].Destination.Address) < 0
	})

	return destinations, nil
}
