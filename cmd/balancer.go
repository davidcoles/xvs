package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/davidcoles/xvs"
)

type list []string

func (i *list) String() string         { return strings.Join(*i, ",") }
func (i *list) Set(value string) error { *i = append(*i, value); return nil }

var extra list
var vlans list

// balancer <interface> <lb-ip-address> <virtual-ip-address> <real-ip-address>...

func mac(m [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

func main() {
	main_()
	fmt.Println("exited")
	time.Sleep(10 * time.Second)
}

func main_() {

	port := flag.Int("p", 80, "Port to run service on")
	udp := flag.Bool("u", false, "Use UDP instead of TCP")
	nat := flag.Bool("n", false, "NAT (creates a network namespace and interfaces)")
	flag.Var(&extra, "i", "extra interfaces")
	flag.Var(&vlans, "v", "extra interfaces")
	flag.Parse()

	args := flag.Args()

	protocol := xvs.TCP

	if *udp {
		protocol = xvs.UDP
	}

	if *port < 1 || *port > 65535 {
		log.Fatal("Port not in range 1-65535")
	}

	link := args[0]
	addr := netip.MustParseAddr(args[1])
	vip := netip.MustParseAddr(args[2])
	rip := args[3:]

	links := append([]string{link}, extra...)

	for _, i := range links {
		ethtool(i)
	}

	var err error

	client := &xvs.Client{
		Interfaces: links,
		Address:    addr,
		Debug:      &Debug{},
		VLANs:      parsevlans(vlans),
		NAT:        *nat,
	}

	err = client.Start()

	if err != nil {
		log.Fatal(err)
	}

	defcon := 5
	switch defcon {
	case 1:
		client.Flags(xvs.F_NO_SHARE_FLOWS | xvs.F_NO_ESTIMATE_CONNS | xvs.F_NO_TRACK_FLOWS | xvs.F_NO_STORE_STATS)
	case 2:
		client.Flags(xvs.F_NO_SHARE_FLOWS | xvs.F_NO_ESTIMATE_CONNS | xvs.F_NO_TRACK_FLOWS)
	case 3:
		client.Flags(xvs.F_NO_SHARE_FLOWS | xvs.F_NO_ESTIMATE_CONNS)
	case 4:
		client.Flags(xvs.F_NO_SHARE_FLOWS)
	default:
		client.Flags(0)
	}

	svc := xvs.Service{Address: vip, Port: uint16(*port), Protocol: protocol}
	err = client.CreateService(svc)

	if err != nil {
		log.Fatal(err)
	}

	defer client.RemoveService(svc)

	for _, r := range rip {
		time.Sleep(5 * time.Second)
		dst := xvs.Destination{Address: netip.MustParseAddr(r), Weight: 1}

		fmt.Println("ADDING", r)
		client.CreateDestination(svc, dst)
	}

	go func() {
		for {
			ticker := time.NewTicker(time.Millisecond * 10)

			for {
				select {
				case <-ticker.C:
				read_flow:
					f := client.ReadFlow()
					if len(f) > 0 {
						fmt.Printf("+")
						goto read_flow
					}
				}
			}
		}
	}()

	time.Sleep(12 * time.Second)

	services, _ := client.Services()

	for _, s := range services {

		log.Println(s)

		destinations, _ := client.Destinations(s.Service)

		for _, d := range destinations {

			log.Printf("%s: Packets %d, Octets %d, Flows %d\n", d.Destination.Address, d.Stats.Packets, d.Stats.Octets, d.Stats.Flows)

			if err = client.RemoveDestination(s.Service, d.Destination); err != nil {
				log.Println(d.Destination.Address, err)
			}
		}
	}
}

func parsevlans(vlans []string) map[uint16]net.IPNet {

	ret := map[uint16]net.IPNet{}

	for _, v := range vlans {
		s := strings.Split(v, ":")

		if len(s) != 2 {
			goto fail
		}

		i, err := strconv.Atoi(s[0])

		if err != nil {
			goto fail
		}

		if i < 1 || i > 4094 {
			goto fail
		}

		_, ipnet, err := net.ParseCIDR(s[1])

		if err != nil {
			goto fail
		}

		ret[uint16(i)] = *ipnet
	}

	return ret

fail:
	log.Fatal("VLAN argument must be <1-4094>:<cidr-prefix>, eg., 100:10.1.2.0/24")
	return nil
}

func ethtool(i string) {
	exec.Command("ethtool", "-K", i, "rx", "off").Output()
	exec.Command("ethtool", "-K", i, "tx", "off").Output()
	exec.Command("ethtool", "-K", i, "rxvlan", "off").Output()
	exec.Command("ethtool", "-K", i, "txvlan", "off").Output()
}

type Debug struct{}

func (d *Debug) NAT(tag map[netip.Addr]int16, arp map[netip.Addr][6]byte, vrn map[[2]netip.Addr]netip.Addr, nat map[netip.Addr]string, out []netip.Addr, in []string) {

	for k, v := range tag {
		fmt.Printf("TAG %s -> %d\n", k, v)
	}

	for k, v := range arp {
		fmt.Printf("ARP %s -> %v\n", k, mac(v))
	}

	for k, v := range vrn {
		fmt.Printf("MAP %s|%s -> %s\n", k[0], k[1], v)
	}

	for k, v := range nat {
		fmt.Printf("NAT %s -> %s\n", k, v)
	}

	for _, v := range out {
		fmt.Println("DEL nat_out", v)
	}

	for _, v := range in {
		fmt.Println("DEL nat_in", v)
	}
}

func (d *Debug) Redirects(vlans map[uint16]string) {
	for k, v := range vlans {
		fmt.Println("NIC", k, v)
	}
}

func (d *Debug) Backend(vip netip.Addr, port uint16, protocol uint8, backends []byte, took time.Duration) {
	const max = 32
	if len(backends) > max {
		backends = backends[:max]
	}
	fmt.Println(vip, port, protocol, backends, took)
}
