/*
 * lisp_output.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Packet output path declarations for LISP module.
 * 
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 * Written or modified by:
 *    Chris White       <chris@logicalelegance.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *
 */

#pragma once

unsigned int lisp_output4(unsigned int hooknum, struct sk_buff *packet_buf,
			 const struct net_device *input_dev,
			 const struct net_device *output_dev,
			  int (*okfunc)(struct sk_buff*));

unsigned int lisp_output6(unsigned int hooknum, struct sk_buff *packet_buf,
			 const struct net_device *input_dev,
			 const struct net_device *output_dev,
			 int (*okfunc)(struct sk_buff*));

bool is_v4addr_local(struct iphdr *iph);

