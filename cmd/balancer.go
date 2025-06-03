package main

import (
	"flag"
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/davidcoles/xvs"
)

type list []string

func (i *list) String() string         { return strings.Join(*i, ",") }
func (i *list) Set(value string) error { *i = append(*i, value); return nil }

func main() {
	var vips list
	var serv list

	remove := flag.Uint("r", 60, "If non-zero, remove services after this many seconds")
	sticky := flag.Bool("s", false, "Sticky")
	tunnel := flag.String("t", "none", "Tunnel type none|fou|gre|gue|ipip")
	tport4 := flag.Uint("4", 9999, "Port to use for FOU IPv4 VIPs")
	tport6 := flag.Uint("6", 6666, "Port to use for FOU IPv6 VIPs")
	tportg := flag.Uint("G", 8888, "Port to use for GUE")
	extra := flag.String("V", "", "Extra VLAN")

	flag.Var(&vips, "v", "extra vips")
	flag.Var(&serv, "p", "ports to add to vips")

	flag.Parse()

	args := flag.Args()

	iface := args[0]
	vlan := args[1]
	vip := args[2]
	rips := args[3:]

	tun := xvs.NONE

	switch *tunnel {
	case "none":
		tun = xvs.NONE
	case "fou":
		tun = xvs.FOU
	case "gre":
		tun = xvs.GRE
	case "gue":
		tun = xvs.GUE
	case "ipip":
		tun = xvs.IPIP
	default:
		log.Fatal("Unknown tunnel type")
	}

	/**********************************************************************/

	vlan4 := map[uint16]netip.Prefix{}
	vlan6 := map[uint16]netip.Prefix{}

	prefix := netip.MustParsePrefix(vlan)

	if prefix.Addr().Is4() {
		vlan4[1] = prefix
	} else {
		vlan6[1] = prefix
	}

	if *extra != "" {
		prefix = netip.MustParsePrefix(*extra)

		if prefix.Addr().Is4() {
			vlan4[1] = prefix
		} else {
			vlan6[1] = prefix
		}
	}

	options := xvs.Options{VLANs4: vlan4, VLANs6: vlan6}

	fmt.Println("Starting ...")

	client, err := xvs.NewWithOptions(options, iface)

	if err != nil {
		log.Fatal(err)
	}

	err = client.SetConfig(xvs.Config{VLANs4: vlan4, VLANs6: vlan6})

	if err != nil {
		log.Fatal(err)
	}

	/**********************************************************************/

	vips = append(vips, vip)

	var ports []uint16

	if len(serv) < 1 {
		ports = []uint16{80}
	} else {
		for _, port := range serv {
			p, err := strconv.Atoi(port)
			if err != nil {
				log.Fatal(err)
			}
			ports = append(ports, uint16(p))
		}
	}

	var sflags xvs.Flags

	if *sticky {
		sflags |= xvs.Sticky
	}

	for _, vip := range vips {

		for _, port := range ports {

			service := xvs.Service{Address: netip.MustParseAddr(vip), Port: port, Protocol: xvs.TCP, Flags: sflags}

			if err := client.CreateService(service); err != nil {
				log.Fatal(service, err)
			}

			for _, rip := range rips {

				tport := uint16(*tport4)

				if service.Address.Is6() {
					tport = uint16(*tport6)
				}

				if tun == xvs.GUE {
					tport = uint16(*tportg)
				}

				destination := xvs.Destination{Address: netip.MustParseAddr(rip), TunnelType: tun, TunnelPort: tport}

				if err := client.CreateDestination(service, destination); err != nil {
					log.Fatal(service, destination, err)
				}
			}
		}
	}

	if *remove != 0 {

		for n := uint(0); n < *remove; n++ {

			info, _ := client.Info()
			fmt.Println("Global", info.Stats, info.Metrics)

			vips := client.VIPs()
			for _, vip := range vips {
				fmt.Println("VIP", vip.Address, vip.Metrics)
			}

			services, _ := client.Services()

			for _, service := range services {

				s, _ := client.Service(service.Service)

				fmt.Println(s.Service.Address, s.Service.Port, s.Service.Protocol, s.Stats, s.Metrics)

				destinations, _ := client.Destinations(s.Service)

				for _, d := range destinations {
					fmt.Println("\t", d.Destination.Address, d.Stats, d.Metrics)
				}

			}

			fmt.Println()

			time.Sleep(time.Second)
		}

		fmt.Println("REMOVING")

		services, _ := client.Services()

		for _, service := range services {
			client.RemoveService(service.Service)
		}
	}

	fmt.Println("OK")
}
