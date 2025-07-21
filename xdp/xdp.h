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

int xdp_link_detach(int);
void *load_bpf_prog(char *);
int load_bpf_section(void *, int, char *, int);
int check_map_fd_info(int, int, int);
__u64 ktime_get();
int create_lru_hash(int, int, const char *, int, int, int);
int max_entries(int);
int raw_socket();
int send_raw_packet(int, int, char *, int);
int load_tail_call(void *, char *, int, int);
