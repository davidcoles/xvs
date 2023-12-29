package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/davidcoles/xvs"
)

type strings []string

func (i *strings) String() string {
	return "my string representation"
}

func (i *strings) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var extra strings

/*

vlan argument needs to be a file which contains something like:

{
    "10": "10.1.10.0/24",
    "20": "10.1.20.0/24",
    "30": "10.1.30.0/24"
}

*/

func main() {

	file := flag.String("v", "", "JSON file to read VLAN info from")
	port := flag.Int("p", 80, "Port to run service on")
	udp := flag.Bool("u", false, "Use UDP instead of TCP")
	tags := flag.Bool("t", false, "Tagged VLANs")
	nat := flag.Bool("n", false, "NAT (creates a network namespace and interfaces)")
	flag.Var(&extra, "i", "extra interfaces")
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

	var vlans map[uint16]net.IPNet

	var err error

	if *file != "" {
		vlans, err = load(*file)

		if err != nil {
			log.Fatal(err)
		}
	}

	client := &xvs.Client2{
		Interfaces: links,
		Address:    addr,
		VLANs:      vlans,
		NAT:        *nat,
		Redirect:   !*tags,
	}

	err = client.Start()

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(vlans)

	svc := xvs.Service{Address: vip, Port: uint16(*port), Protocol: protocol}
	err = client.CreateService(svc)

	if err != nil {
		log.Fatal(err)
	}

	defer client.RemoveService(svc)

	for _, r := range rip {
		sleep(5)
		dst := xvs.Destination{Address: netip.MustParseAddr(r), Weight: 1}

		fmt.Println("ADDING", r)
		client.CreateDestination(svc, dst)
	}

	/*
		var dst []xvs.Destination
		for _, r := range rip {
			dst = append(dst, xvs.Destination{Address: netip.MustParseAddr(r), Weight: 1})
		}

		svc := xvs.Service{Address: vip, Port: uint16(*port), Protocol: protocol}
		err = client.CreateService(svc)

		if err != nil {
			log.Fatal(err)
		}

		err = client.SetService(svc, dst)

		if err != nil {
			log.Fatal(err)
		}
	*/

	sleep(60)

	ss, _ := client.Services()

	for _, s := range ss {

		log.Println(s)

		ds, _ := client.Destinations(svc)

		for _, d := range ds {
			log.Println(d)
		}
	}
}

func sleep(t time.Duration) {
	time.Sleep(t * time.Second)
}

type Prefix net.IPNet

func (p *Prefix) String() string {
	return (*net.IPNet)(p).String()
}

func (p *Prefix) Contains(i net.IP) bool {
	return (*net.IPNet)(p).Contains(i)
}

func (p *Prefix) UnmarshalJSON(data []byte) error {

	l := len(data)

	if l < 3 || data[0] != '"' || data[l-1] != '"' {
		return errors.New("CIDR address should be a string: " + string(data))
	}

	cidr := string(data[1 : l-1])

	ip, ipnet, err := net.ParseCIDR(cidr)

	if err != nil {
		return err
	}

	if ip.String() != ipnet.IP.String() {
		return errors.New("CIDR address contains host portion: " + cidr)
	}

	*p = Prefix(*ipnet)

	return nil
}

func load(file string) (map[uint16]net.IPNet, error) {

	f, err := os.Open(file)

	if err != nil {
		return nil, err
	}

	defer f.Close()

	b, err := ioutil.ReadAll(f)

	if err != nil {
		return nil, err
	}

	var prefixes map[uint16]Prefix

	err = json.Unmarshal(b, &prefixes)

	if err != nil {
		return nil, err
	}

	vlans := map[uint16]net.IPNet{}

	for vlanid, prefix := range prefixes {
		vlans[vlanid] = net.IPNet(prefix)
	}

	return vlans, nil
}
