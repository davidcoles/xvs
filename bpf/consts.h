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
      F_STICKY     = 0x01,
};

enum {
      VETH_ID = 4095,
};

enum {
      F_NO_SHARE_FLOWS     = 0x01,
      F_NO_TRACK_FLOWS     = 0x02,	    
      F_NO_ESTIMATE_CONNS  = 0x04,
      F_NO_STORE_STATS     = 0x08,
      //F_BLOCKLIST   = 0x10,
      //F_MULTINIC    = 0x20,
      //F_DISABLED    = 0x40,
};
