

struct iphdr *parse(struct xdp_md *ctx, struct ethhdr *eth, struct vlan_hdr *vlan,  struct iphdr *ip)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *e = data;
    struct vlan_hdr *v = NULL;
    struct iphdr *i = NULL;
    
    if (e + 1 > data_end)
	return NULL;

    *eth = *e;

    if (e->h_proto == bpf_htons(ETH_P_8021Q)) {
	v = (void *)(eth + 1);
	
	if (v + 1 > data_end)
	    return NULL;
	
	*vlan = *v;
	
	i = (void *)(v + 1);
    } else {
	i = (void *)(e + 1);
    }
    
    if (i + 1 > data_end)
	return NULL;

    *ip = *i;

    return i;
}


    /*
    if (eth + 1 > data_end)
	return XDP_ABORTED;
    
    if(vlan) {
	vlan = (struct vlan_hdr *)(eth + 1);
	
	if (vlan + 1 > data_end)
	    return XDP_ABORTED;
	
	ip = (void *) (vlan + 1);
    } else {
	ip = (void *) (eth + 1);
    }
    
    if (ip + 1 > data_end)
        return XDP_ABORTED;
    */


struct pointers {
    struct ethhdr *eth, eth_copy;
    struct vlan_hdr *vlan, vlan_copy;
    struct iphdr *ip, ip_copy;
};

#define PARSE_FRAME(eth, vlan, ip, data_end) ((eth + 1 > data_end) ? -1 : \
        (vlan ? \
        (((vlan = (struct vlan_hdr *)(eth + 1)) + 1 > data_end) ? -1 : \
         (((ip = (void *)(vlan + 1)) + 1 > data_end) ? -1 : 0)) : (((ip = (void *)(eth + 1)) + 1 > data_end) ? -1 : 0))) \

int parse_frame1(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    struct vlan_hdr *vlan = NULL;
    struct iphdr *ip = NULL;
    
    if (eth + 1 > data_end)
	return -1;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
	vlan = (void *)(eth + 1);

	if (vlan + 1 > data_end)
            return -1;

	ip = (void *)(vlan + 1);
    } else {
	ip = (void *)(eth + 1);
    }

    if (ip + 1 > data_end)
	return -1;

    return 0;
}

int parse_frame2(struct xdp_md *ctx, struct pointers *p)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    p->eth = data;
    
    if (p->eth + 1 > data_end)
        return -1;
    
    if (p->eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        p->vlan = (void *)(p->eth + 1);
	
	if (p->vlan + 1 > data_end)
	    return -1;
	
	p->ip = (void *)(p->vlan + 1);
    } else {
        p->ip = (void *)(p->eth + 1);
    }

    if (p->ip + 1 > data_end)
	return -1;

    p->eth_copy = *(p->eth);
    if (p->vlan) p->vlan_copy = *(p->vlan);
    p->ip_copy = *(p->ip);
    
     return 0;
}


int reparse_frame1(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    struct vlan_hdr *vlan = NULL;
    struct iphdr *ip = NULL;
    
    if (eth + 1 > data_end)
        return -1;
    
    if(vlan) {
        vlan = (void *)(eth + 1);

	if (vlan + 1 > data_end)
            return -1;
	
	ip = (void *)(vlan + 1);
    } else {
	ip = (void *)(eth + 1);
    }
    
    if (ip + 1 > data_end)
	return -1;
    
    return 0;
}

int reparse_frame2(struct xdp_md *ctx, struct pointers *p)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    p->eth = data;
    
    if (p->eth + 1 > data_end)
        return -1;
    
    if(p->vlan) {
        p->vlan = (void *)(p->eth + 1);

	if (p->vlan + 1 > data_end)
            return -1;
	
	p->ip = (void *)(p->vlan + 1);
    } else {
	p->ip = (void *)(p->eth + 1);
    }
    
    if (p->ip + 1 > data_end)
	return -1;

    //*(p->eth) = p->eth_copy;
    //if (p->vlan) *(p->vlan) = p->vlan_copy;
    //*(p->ip) = p->ip_copy;
    
    return 0;
}

int preserve_headers(struct xdp_md *ctx, struct pointers *p)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    p->vlan = NULL;
    
    p->eth = data;
    
    if (p->eth + 1 > data_end)
        return -1;
    
    if (p->eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        p->vlan = (void *)(p->eth + 1);
	
	if (p->vlan + 1 > data_end)
	    return -1;
	
	p->ip = (void *)(p->vlan + 1);
    } else {
        p->ip = (void *)(p->eth + 1);
    }

    if (p->ip + 1 > data_end)
	return -1;

    p->eth_copy = *(p->eth);
    if (p->vlan) p->vlan_copy = *(p->vlan);
    p->ip_copy = *(p->ip);
    
     return 0;
}

int restore_headers(struct xdp_md *ctx, struct pointers *p)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    p->eth = data;
    
    if (p->eth + 1 > data_end)
        return -1;
    
    if(p->vlan) {
        p->vlan = (void *)(p->eth + 1);

	if (p->vlan + 1 > data_end)
            return -1;
	
	p->ip = (void *)(p->vlan + 1);
    } else {
	p->ip = (void *)(p->eth + 1);
    }
    
    if (p->ip + 1 > data_end)
	return -1;

    *(p->eth) = p->eth_copy;
    if (p->vlan) *(p->vlan) = p->vlan_copy;
    *(p->ip) = p->ip_copy;
    
    return 0;
}
