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

enum {
    F_STICKY    = 0x01,
    F_NOT_LOCAL = 0x80,
};

enum {
    F_TUNNEL_ENCAP_NO_CHECKSUMS =  0x01,
};

enum {
    FLOW_VERSION = 2,
    BUFFER = 2048,
};

enum tunnel_type {
		  T_NONE  = 0,
		  T_IPIP  = 1,
		  T_GRE   = 2,
		  T_FOU   = 3,
		  T_GUE   = 4,
		  //T_FOU_GRE = 5, // maybe - not sure that GRE in FOU gives any advantage over GUE for load balancing
};



// https://github.com/davidcoles/xvs/issues/2
static __always_inline
__u64 pow64(__u8 n)
{
    if (n < 0 || n > 63)
	return 0;
    
    return ((__u64) 1) << n;
}
