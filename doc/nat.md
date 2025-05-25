# NAT

Healthchecking DSR services is tricky. You can, for example, sent an
HTTPS request to the backend server's real IP address with the correct
host header and and SNI information to make sure that the webserver is
running, but if the virtual IP address is not configured on the
server's loopback interface then when real traffic is forwarded to the
server by the load balancer it will be black holed because the server
does not recognise itself as the intended destination.

To truly check that the server is willing to accept traffic, the load
balancer must send healthcheck packets to the backend server with the
virtual IP address of the service as the desination address in the IP
header.

The problem is that there is no simple way (that I'm aware of) to do
this.

To address this, xvs can create a virtual ethernet device pair, attach
an XDP program, and place one end into a network namespace. Packets
routed into the visible interface can then be manipulated by XDP.

We then create a mapping for each unique virtual (service) and real
(server) IP address pair to a NAT address. When requests are made to
one of these NAT addresses the XDP function maps ethernet and IP
addresses to that of the corresponding host and sets tunnel parameters
for the service, and then forwards the packet out to the correct
physical interface.

When receiving a reply, the packet is matched against a state table
and the reverse operation performed, completing the connection.

The upshot is that if you know the corresponding NAT address for a VIP
on a particular backend, then you can perform a healthcheck by sending
a request to the NAT address inside the network namespace and XDP will
perform all of the address and tunnel mapping for you. Eg., if a VIP
192.168.101.1 is on real server 10.1.2.3 and the NAT address for this
IP pair is 255.0.0.1, then you could check that a webserver is healthy
with:

`curl http://255.0.0.1/`
