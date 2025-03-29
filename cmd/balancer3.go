package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/davidcoles/xvs"
)

type list []string

func (i *list) String() string         { return strings.Join(*i, ",") }
func (i *list) Set(value string) error { *i = append(*i, value); return nil }

func main() {
	var vips list
	var serv list

	sticky := flag.Bool("s", false, "Sticky")
	tunnel := flag.String("t", "layer2", "Tunnel type layer2|fou|gre|gue|ipip")
	tport4 := flag.Uint("4", 9999, "Port to use for FOU/GUE on IPv4")
	tport6 := flag.Uint("6", 6666, "Port to use for FOU/GUE on IPv6")

	flag.Var(&vips, "v", "extra vips")
	flag.Var(&serv, "p", "ports to add to vips")

	flag.Parse()

	args := flag.Args()

	iface := args[0]
	dmac, _ := net.ParseMAC(args[1])
	vip := args[2]
	rips := args[3:]

	var h_dest [6]byte
	copy(h_dest[:], dmac[:])

	tun := xvs.LAYER2

	switch *tunnel {
	case "layer2":
		tun = xvs.LAYER2
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

	fmt.Println("Starting ...")

	client, err := xvs.New(iface)

	if err != nil {
		log.Fatal(err)
	}

	client.SetConfig(xvs.Config{Router: h_dest})

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

			service := xvs.Service3{Address: netip.MustParseAddr(vip), Port: port, Protocol: xvs.TCP, Flags: sflags}

			if err := client.CreateService(service); err != nil {
				log.Fatal(service, err)
			}

			for _, rip := range rips {
				tport := uint16(*tport4)

				if service.Address.Is6() {
					tport = uint16(*tport6)
				}

				destination := xvs.Destination3{Address: netip.MustParseAddr(rip), TunnelType: tun, TunnelPort: tport}

				if err := client.CreateDestination(service, destination); err != nil {
					log.Fatal(service, destination, err)
				}
			}
		}
	}

	client.Info()

	fmt.Println("OK")
}
