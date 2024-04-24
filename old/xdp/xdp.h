void *load_bpf_file(char *);
int xdp_link_detach(char *);
int load_bpf_section(void *, char *, char *, int);
int check_map_fd_info(int, int, int);
__u64 ktime_get();
