# NAT

Healthchecking DSR services is tricky. You can, for example, sent an
HTTPS request to the backend server's real IP address with the correct
host header and and SNI information to make sure that the webserver is
running, but if the virtual IP address is not configured on the
server's loopback interface then load balanced traffic which is
forwarded to the server will be black holed because the server does
not recognise itself as the intended destination.

To truly check that the server is willing to accept traffic, the load
balancer must send healthcheck packets to the backend server with the
MAC address of the server's ethernet interface as the destination MAC
in the header of the thernet frame, and the virtual IP address of the
service as the desination address in the IP header.

The problem is that there is no simple way (that I'm aware of) to
override these fields with the standard socket API.

To address this, xvs can create a virtual ethernet device pair, place
one end into a network namespace and attach an XDP program to the
other end.

We then create a mapping for each unique virtual (service) and real
(server) IP address pair to a NAT address. When requests are made to
one of these NAT addresses inside the network namespace the XDP
function maps the ethernet and IP header destination address to the
corresponding MAC address for the destination server and the
destination IP address for the service, and then forward the packet
out to the correct physical interface.

When receiving a reply, the source MAC address can be used to identify
the real server from which the reply came. This, along with the source
(service) IP address can be used to determine corresponding NAT
address with which to update the packet's source IP and then forward
it to the network namespace.

The upshot is that if you know the corresponding NAT address for a VIP
on a particular backend, then you can perform a healthcheck by sending
a request to the NAT address inside the network namespace and XDP will
perform all of the MAC and IP address mapping for you. Eg., if a VIP
192.168.101.1 is on real server 10.1.2.3 and the NAT address for this
IP pair is 10.255.0.1, then you could check that a webserver is
healthy with:

`ip netns exec vc5 curl http://10.255.0.1/`
