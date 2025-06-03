package xvs

import (
	//"fmt"
	"net"
	"net/netip"
	"testing"
	//"time"
)

var c *client

func mustParseMAC(s string) (m mac) {
	hw, err := net.ParseMAC(s)
	if err != nil {
		panic(err.Error())
	}
	if len(hw) != 6 {
		panic(`mac.mustParse("` + s + `"): length not six bytes`)
	}

	copy(m[:], hw[:])
	return m
}

func TestClientInit(t *testing.T) {
	var ZERO uint32 = 0

	var m maps

	err := m.init(nil)

	if err != nil {
		t.Error(err)
	}

	settings := bpf_settings{active: 99}

	if r := m.updateSettings(settings); r != 0 {
		t.Error("m.updateSettings", r)
	}

	var foo bpf_settings

	if r := m.settings.LookupElem(uP(&ZERO), uP(&foo)); r != 0 {
		t.Error("m.settings.LookupElem", r)
	}

	if foo.active != 99 {
		t.Error("foo.active", foo.active)
	}

	if err = m.initialiseFlows(1000); err != nil {
		t.Error("m.initialiseFlows", err)
	}

	if x := m.global_metrics; x == 0 {
		t.Error("m.global_metrics == 0")
	}

	c = &client{services: map[threetuple]*service{}, natmap: natmap{}, maps: m, test: true}
}

func TestRouting(t *testing.T) {

	ip1 := netip.MustParseAddr("172.16.1.10")
	hw1 := mustParseMAC("00:00:01:16:01:10")
	ip2 := netip.MustParseAddr("172.16.2.10")
	hw2 := mustParseMAC("00:00:01:16:02:10")
	ip3 := netip.MustParseAddr("172.16.3.10")
	ip4 := netip.MustParseAddr("172.16.4.10")

	lb1ip := netip.MustParseAddr("172.16.1.1")
	lb1hw := mustParseMAC("00:00:01:16:01:fe")
	gw1ip := netip.MustParsePrefix("172.16.1.254/24")
	gw1hw := mustParseMAC("00:00:01:16:01:fe")

	lb2ip := netip.MustParseAddr("172.16.2.1")
	lb2hw := mustParseMAC("00:00:01:16:02:01")
	gw2ip := netip.MustParsePrefix("172.16.2.254/24")
	gw2hw := mustParseMAC("00:00:01:16:02:fe")

	vlan1 := vlaninfo{prefix: gw1ip, if_index: -1, ip_addr: lb1ip, hw_addr: lb1hw, gw_ip_addr: gw1ip.Addr(), gw_hw_addr: gw1hw}
	vlan2 := vlaninfo{prefix: gw2ip, if_index: -2, ip_addr: lb2ip, hw_addr: lb2hw, gw_ip_addr: gw2ip.Addr(), gw_hw_addr: gw2hw}

	n := netinfo{
		vlan4: map[uint16]vlaninfo{1: vlan1, 2: vlan2},
		mac:   map[netip.Addr]mac{ip1: hw1, ip2: hw2},
		route: map[netip.Prefix]uint16{netip.MustParsePrefix("172.16.4.0/24"): 2},
	}

	var tests = []struct {
		input netip.Addr
		want  backend
	}{
		{ip1, backend{vlanid: 1, hw_src: lb1hw, hw_dst: hw1, ip_src: lb1ip, ip_dst: ip1, local: true, _i: -1}},    // local
		{ip2, backend{vlanid: 2, hw_src: lb2hw, hw_dst: hw2, ip_src: lb2ip, ip_dst: ip2, local: true, _i: -2}},    // local
		{ip3, backend{vlanid: 1, hw_src: lb1hw, hw_dst: gw1hw, ip_src: lb1ip, ip_dst: ip3, local: false, _i: -1}}, // via vlan1
		{ip4, backend{vlanid: 2, hw_src: lb2hw, hw_dst: gw2hw, ip_src: lb2ip, ip_dst: ip4, local: false, _i: -2}}, // via vlan2
	}

	for _, tt := range tests {
		t.Run(tt.input.String(), func(t *testing.T) {
			ans := n.find(tt.input)
			if ans != tt.want {
				t.Errorf("got %s, want %s", ans, tt.want)
			}
		})
	}
}

func TestClient1(t *testing.T) {

	vip := netip.MustParseAddr("192.168.101.1")
	rip := netip.MustParseAddr("172.16.1.1")
	service := Service{Address: vip, Port: 80, Protocol: TCP}
	destination := Destination{Address: rip}

	if err := c.CreateService(service); err != nil {
		t.Error("c.CreateService", err)
	}

	if services, err := c.Services(); err != nil {
		t.Error("c.Services", err)
	} else {
		if len(services) != 1 {
			t.Error("c.Services != 1")
		}

		if services[0].Service != service {
			t.Error("services[0] != service")
		}
	}

	if err := c.CreateDestination(service, destination); err != nil {
		t.Error("c.CreateDestination", err)
	}

	if destinations, err := c.Destinations(service); err != nil {
		t.Error("c.Destinations", err)
	} else {
		if len(destinations) != 1 {
			t.Error("c.Destinations != 1")
		}

		if destinations[0].Destination != destination {
			t.Error("c.Destinations rip")
		}
	}

	if err := c.RemoveService(service); err != nil {
		t.Error("c.RemoveService", err)
	}

	if services, err := c.Services(); err != nil {
		t.Error("c.Services", err)
	} else {
		if len(services) != 0 {
			t.Error("c.Services != 0")
		}
	}
}

func TestClient2(t *testing.T) {

	vip := netip.MustParseAddr("192.168.101.1")
	rip := netip.MustParseAddr("172.16.1.1")

	service := Service{Address: vip, Port: 80, Protocol: TCP}
	destination := Destination{Address: rip, TunnelType: GRE}

	if err := c.SetService(service, destination); err != nil {
		t.Error("c.SetService", err)
	}

	if services, err := c.Services(); err != nil {
		t.Error("c.Services", err)
	} else {
		if len(services) != 1 {
			t.Error("len(services) != 1")
		}

		if services[0].Service != service {
			t.Error("services[0].Service != service")
		}
	}

	if destinations, err := c.Destinations(service); err != nil {
		t.Error("c.Destinations", err)
	} else {
		if len(destinations) != 1 {
			t.Error("c.Destinations != 1")
		}

		if destinations[0].Destination != destination {
			t.Error("destinations[0].Destination != destination")
		}
	}

	if err := c.RemoveService(service); err != nil {
		t.Error("c.RemoveService", err)
	}

	if services, err := c.Services(); err != nil {
		t.Error("c.Services", err)
	} else {
		if len(services) != 0 {
			t.Error("len(services) != 0")
		}
	}
}
