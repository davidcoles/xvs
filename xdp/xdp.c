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

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <net/if.h>


#include <netinet/in.h>
#include <sys/ioctl.h>        // macro ioctl is defined

#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "xdp.h"

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd) {
    LIBBPF_OPTS(bpf_xdp_attach_opts, opts, .old_prog_fd = 0);
    return bpf_xdp_attach(ifindex, prog_fd, xdp_flags, &opts);
}

int xdp_link_detach(int ifindex) {
    LIBBPF_OPTS(bpf_xdp_attach_opts, opts, .old_prog_fd = 0);
    bpf_xdp_attach(ifindex, -1, XDP_FLAGS_DRV_MODE, &opts);
    bpf_xdp_attach(ifindex, -1, XDP_FLAGS_SKB_MODE, &opts);
    return 0;
}


void *load_bpf_prog(char *filename) {
    struct bpf_object *obj_prog = NULL;
    int ret;

    obj_prog = bpf_object__open(filename);
    if (!obj_prog) {
        ret = -errno;
        fprintf(stderr, "Couldn't open file: %s\n", strerror(-ret));
        return NULL;
    }

    ret = bpf_object__load(obj_prog);
    if (ret) {
        ret = -errno;
        fprintf(stderr, "Couldn't load object: %s\n", strerror(-ret));
        return NULL;
    }

    return obj_prog;
}

int load_bpf_section(void *o, int ifindex, char *name, int native) {
    struct bpf_object *obj = o;
    struct bpf_program *bpf_prog;
    int prog_fd = -1;
    int err;

    //xdp_link_detach(ifindex);

    __u32 xdp_flags = XDP_FLAGS_SKB_MODE;
    
    if (native) {
        xdp_flags = XDP_FLAGS_DRV_MODE;
    }
    
    bpf_prog = bpf_object__find_program_by_name(obj, name);
    if (!bpf_prog) {
        fprintf(stderr, "ERR: finding progsec: %s\n", name);
        return -1;
    }

    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd <= 0) {
        fprintf(stderr, "ERR: bpf_program__fd failed\n");
        return -1;
    }

    err = xdp_link_attach(ifindex, xdp_flags, prog_fd);
    if(err) {
        return -1;
    }

    return 0;
}

int max_entries(int map_fd) {
    struct bpf_map_info info = { 0 };
    __u32 info_len = sizeof(info);
    int err;
    
    if (map_fd < 0)
        return -1;

    err = bpf_obj_get_info_by_fd(map_fd, &info, &info_len);
    if (err != 0)
        return -1;

    return info.max_entries;
}

int check_map_fd_info(int map_fd, int ks, int vs) {
    struct bpf_map_info info = { 0 };
    __u32 info_len = sizeof(info);
    int err;
    
    if (map_fd < 0)
        return -1;

    err = bpf_obj_get_info_by_fd(map_fd, &info, &info_len);
    if (err != 0)
        return -1;

    if (ks && ks != info.key_size) {
        fprintf(stderr, "ERR: %s() "
                "Map key size(%d) mismatch expected size(%d)\n",
                __func__, info.key_size, ks);
        return -1;
    }

    if (vs && vs != info.value_size) {
        fprintf(stderr, "ERR: %s() "
                "Map value size(%d) mismatch expected size(%d)\n",
                __func__, info.value_size, vs);
        return -1;
    }

    return 0;
}

__u64 ktime_get() {
    struct timespec tp;

    clock_gettime(CLOCK_MONOTONIC, &tp);

    if(tp.tv_sec < 0)
        return 0;

    return (__u64) tp.tv_sec;
}

int create_lru_hash(int outer_fd, int index, const char *name, int key_size, int val_size, int max_entries) {
    int fd;

    fd = bpf_map_create(BPF_MAP_TYPE_LRU_HASH, name, key_size, val_size, max_entries, NULL);

    if (fd < 0)
	return fd;
    
    return bpf_map_update_elem(outer_fd, &index, &fd, BPF_ANY);
}

#include <linux/if_packet.h> // SOCK_RAW
#include <linux/if_ether.h> // SOCK_RAW
#include <linux/in.h> // SOCK_RAW
//#include <net/ethernet.h> // SOCK_RAW

int raw_socket() {
    return socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
}

int _send_raw_packet(int sockfd, int ifindex, char *packet, int len) {
    // https://www.pdbuchan.com/rawsock/icmp6_ll.c
    // https://stackoverflow.com/questions/21411851/how-to-send-data-over-a-raw-ethernet-socket-using-sendto-without-using-sockaddr
    // setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 4); // doesn't seem to be needed
    
    /* packet(7)
       When you send packets, it is enough to specify sll_family,
       sll_addr, sll_halen, sll_ifindex, and sll_protocol.  The other
       fields should be 0.  sll_hatype and sll_pkttype are set on
       received packets for your information.
    */

    struct ethhdr *eth = (struct ethhdr *) packet;
    struct sockaddr_ll socket_address = { .sll_family = AF_PACKET,
					  .sll_protocol = eth->h_proto,
					  .sll_ifindex = ifindex,
					  .sll_halen = ETH_ALEN };
    
    memcpy(socket_address.sll_addr, eth->h_dest, ETH_ALEN);
    
    return sendto(sockfd, packet, len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll));
}

int send_raw_packet(int sockfd, int ifindex, char *packet, int len) {
    char *interface = "xvs";
    int sd = 0;
    struct ifreq ifr;
    struct sockaddr_ll device;
    char src_mac[6];
      
    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
	perror ("socket() failed to get socket descriptor for using ioctl() ");
	return -1;
    }

    // Use ioctl() to look up interface name and get its MAC address.
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
	perror ("ioctl() failed to get source MAC address ");
	return -1;
    }
    close (sd);

    // Find interface index from interface name and store index in
    // struct sockaddr_ll device, which will be used as an argument of sendto().
    memset (&device, 0, sizeof (device));
    if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
	perror ("if_nametoindex() failed to obtain interface index ");
	return -1;
    }
    printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

    memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));


    int i;
    // Report source MAC address to stdout.
    printf ("MAC address for interface %s is ", interface);
    for (i=0; i<5; i++) {
	printf ("%02x:", src_mac[i]);
    }
    printf ("%02x\n", src_mac[5]);
    
    // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
    device.sll_halen = 6;


    // Submit request for a raw socket descriptor.
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
	perror ("socket() failed ");
	return -1;
    }

    int bytes = 0;
    // Send ethernet frame to socket.
    if ((bytes = sendto (sd, packet, len, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
	perror ("sendto() failed");
	return -1;
    }
    
    // Close socket descriptor.
    close (sd);
    
    return bytes;
}

/*
struct sockaddr_ll {
        unsigned short  sll_family;
        __be16          sll_protocol;
        int             sll_ifindex; //
        unsigned short  sll_hatype;  
        unsigned char   sll_pkttype;
        unsigned char   sll_halen;   //
        unsigned char   sll_addr[8]; //
};
*/

int load_tail_call(void *o, char *name, int map, int index) {
    struct bpf_object *obj = o;
    struct bpf_program *bpf_prog;
    int prog_fd = -1;

    bpf_prog = bpf_object__find_program_by_name(obj, name);
    if (!bpf_prog) {
        fprintf(stderr, "ERR: finding progsec: %s\n", name);
        return -1;
    }

    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd <= 0) {
        fprintf(stderr, "ERR: bpf_program__fd failed\n");
        return -1;
    }

    return bpf_map_update_elem(map, &index, &prog_fd, BPF_ANY);
}

int program_fd(void *o, char *name, int map, int index) {
    struct bpf_object *obj = o;
    struct bpf_program *bpf_prog;
    int prog_fd = -1;

    bpf_prog = bpf_object__find_program_by_name(obj, name);
    if (!bpf_prog) {
        fprintf(stderr, "ERR: finding progsec: %s\n", name);
        return -1;
    }

    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd <= 0) {
        fprintf(stderr, "ERR: bpf_program__fd failed\n");
        return -1;
    }

    return bpf_map_update_elem(map, &index, &prog_fd, BPF_ANY);
}
