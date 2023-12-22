#include <bpf.h>
#include <libbpf.h>

#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <net/if.h>

#include <time.h>
#include <errno.h>
#include <stdlib.h>

#include "xdp.h"

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd) {
    LIBBPF_OPTS(bpf_xdp_attach_opts, opts, .old_prog_fd = 0);
    return bpf_xdp_attach(ifindex, prog_fd, xdp_flags, &opts);
}

//static int xdp_link_detach_(int ifindex, __u32 xdp_flags)
//{
//    LIBBPF_OPTS(bpf_xdp_attach_opts, opts, .old_prog_fd = 0);
//    return bpf_xdp_attach(ifindex, -1, xdp_flags, &opts);
//}


int xdp_link_detach(char *interface) {
    int ifindex = if_nametoindex(interface);
    //xdp_link_detach_(ifindex, XDP_FLAGS_DRV_MODE);
    //xdp_link_detach_(ifindex, XDP_FLAGS_SKB_MODE);
    LIBBPF_OPTS(bpf_xdp_attach_opts, opts, .old_prog_fd = 0);
    bpf_xdp_attach(ifindex, -1, XDP_FLAGS_DRV_MODE, &opts);
    bpf_xdp_attach(ifindex, -1, XDP_FLAGS_SKB_MODE, &opts);
    return 0;
}

void *load_bpf_file(char *filename) {
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


int load_bpf_section(void *o, char *interface, char *section, int native) {
    struct bpf_object *obj = o;
    struct bpf_program *bpf_prog;
    int prog_fd = -1;
    int ifindex = if_nametoindex(interface);
    int err;

    printf("ifindex %s %d\n", interface, ifindex);
    
    __u32 xdp_flags = XDP_FLAGS_SKB_MODE;
    
    if (native) {
	xdp_flags = XDP_FLAGS_DRV_MODE;
    }
    
    bpf_prog = bpf_object__find_program_by_name(obj, section);
    if (!bpf_prog) {
	fprintf(stderr, "ERR: finding progsec: %s\n", section);
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
