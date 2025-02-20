/*
 * lispd_map_request.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Send a map request.
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
 *    David Meyer		<dmm@cisco.com>
 *    Vina Ermagan		<vermagan@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *
 */

/*
 *	Send this packet on UDP 4342
 *
 *
 * Encapsulated control message header. This is followed by the IP
 * header of the encapsulated LISP control message.
 *
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Type=8 |                   Reserved                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *	Next is the inner IP header, either struct ip6_hdr or struct
 *	iphdr. 
 *
 *	This is follwed by a UDP header, random source port, 4342 
 *	dest port.
 *
 *	Followed by a struct lisp_pkt_map_request_t:
 *
 * Map-Request Message Format
 *   
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=1 |A|M|P|S|      Reserved       |   IRC   | Record Count  |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         Nonce . . .                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         . . . Nonce                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         Source-EID-AFI        |    Source EID Address  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         ITR-RLOC-AFI 1        |    ITR-RLOC Address 1  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         ITR-RLOC-AFI n        |    ITR-RLOC Address n  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
 *  Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    \ |                        EID-prefix ...                         |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                      Mappping Record ...                      |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                     Mapping Protocol Data                     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *	<source EID address>
 *	IRC = 0 --> one source rloc
 *      lisp_pkt_map_request_eid_prefix_record_t
 *      EID
 *
 */

#include "lispd_external.h"

uint8_t *build_map_request_pkt(eid_prefix, eid_prefix_afi, eid_prefix_length,
        len, nonce, encap, solicit_map_request, smr_invoked, islocal)
    lisp_addr_t *eid_prefix;
    uint16_t eid_prefix_afi;
    uint8_t eid_prefix_length;
    int *len; /* return length here */
    uint64_t                 *nonce;			/* return nonce here */
    uint8_t encap;
    uint8_t solicit_map_request; /* boolean really */
    uint8_t	               islocal;

{

    struct udphdr				*udph;
    lispd_addr_t				*my_addr;
    uint8_t					*packet;
    lispd_pkt_map_request_t			*mrp;
    lispd_pkt_encapsulated_control_t		*ecm;
    lispd_pkt_map_request_itr_rloc_t		*itr_rloc;
    lispd_pkt_map_request_eid_prefix_record_t   *eid;
    datacache_t				        *dcache_ptr;
    patricia_node_t				*node;
    void					*cur_ptr;
    void					*iphptr;	/* v4 or v6 */

    uint16_t					udpsum               = 0;
    uint16_t					eid_afi             = 0;
    int						packet_len          = 0;
    int						eid_len             = 0;
    int						ip_len              = 0;
    int						udp_len             = 0;
    int						map_request_msg_len = 0;
    int						ip_header_len       = 0;
    int						my_addr_len         = 0;
    int						alen                = 0;

    eid_afi = get_lisp_afi(eid_prefix_afi, &eid_len);

    /* my_addr must have same afi as requested EID */
    if (!(ctrl_iface) || !(ctrl_iface->AF4_locators->head)) {
        /* 
         * No physical interface available for control messages
         */
        syslog(LOG_DAEMON, "(build_map_request_pkt): Unable to find valid physical interface\n");
        return (0);
    }

    if ((my_addr = get_my_addr(ctrl_iface->iface_name,lisp2inetafi(eid_afi))) == 0) { 
        syslog(LOG_DAEMON,"can't find suitable source address (%s,%d)",
               ctrl_iface->iface_name,lisp2inetafi(eid_afi));
        return(0);
    }

    if ((my_addr_len = get_addr_len(my_addr->afi)) == 0) {
	free(my_addr);
	return (0);
    }

    if ((ip_header_len = get_ip_header_len(my_addr->afi)) == 0) {
	free(my_addr);
	return (0);
    }

    /* 
     * caclulate sizes of interest
     */

    map_request_msg_len = sizeof(lispd_pkt_map_request_t) + /* map request */
	eid_len                                           + /* source eid */
	sizeof(lispd_pkt_map_request_itr_rloc_t)          + /* IRC = 1 */
	my_addr_len                                       + /* ITR RLOC */
	sizeof(lispd_pkt_map_request_eid_prefix_record_t) + 
        eid_len;                                            /* EID prefix */

    if (encap) {
        udp_len = sizeof(struct udphdr) + map_request_msg_len;  /* udp header */

    ip_len     = ip_header_len + udp_len;
    packet_len = sizeof(lispd_pkt_encapsulated_control_t) + ip_len;
	} else {
	packet_len = map_request_msg_len;
    }

    *len       = packet_len;				    /* return this */

    if ((packet = (uint8_t *) malloc(packet_len)) == NULL) {
		syslog(LOG_DAEMON, "malloc(packet_len): %s", strerror(errno));
		return (0);
    }
	memset(packet, 0, packet_len);

    /*
     *	build the encapsulated control message header
     */
    if (encap) {
        ecm       = (lispd_pkt_encapsulated_control_t *) packet;
        ecm->type = LISP_ENCAP_CONTROL_TYPE;

        /*
         * point cur_ptr at the start of the IP header
         */
	cur_ptr = CO(ecm, sizeof(lispd_pkt_encapsulated_control_t));
        iphptr = cur_ptr;					/* save for ip checksum */

        /*
         * build IPvX header
         */

	if ((udph = build_ip_header(cur_ptr, my_addr, eid_prefix, ip_len)) == 0) {
		syslog(LOG_DAEMON, "Can't build IP header (unknown AFI %d)",
	                my_addr->afi);
	        free(my_addr);
		return (0);
        }
    
        /*
         * fill in the UDP header. checksum\ later.
         *
         * Note src port == dest port == LISP_CONTROL_PORT (4342)
         */

#ifdef BSD
        udph->uh_sport = htons(LISP_CONTROL_PORT);
        udph->uh_dport = htons(LISP_CONTROL_PORT);
        udph->uh_ulen  = htons(udp_len);
        udph->uh_sum   = 0;
#else
        udph->source = htons(LISP_CONTROL_PORT);
        udph->dest   = htons(LISP_CONTROL_PORT);
        udph->len    = htons(udp_len);
        udph->check  = 0;
#endif

    }
    /*
     * build the map request
     */

    /*
     * first, point mrp at map-request packet
     * pointer is set based on whether map request is encapsulated or not
     */

    if (encap)
        mrp = (lispd_pkt_map_request_t *) CO(udph, sizeof(struct udphdr));
    else
        mrp = (lispd_pkt_map_request_t *) packet;

    mrp->type                      = LISP_MAP_REQUEST;
    mrp->authoritative             = 0;
    mrp->map_data_present          = 0;
    mrp->rloc_probe                = 0;

    if (solicit_map_request)
        mrp->solicit_map_request   = 1;
    else
        mrp->solicit_map_request   = 0;

    if (smr_invoked)
        mrp->smr_invoked           = 1;
    else
        mrp->smr_invoked           = 0;

    mrp->additional_itr_rloc_count = 0;		/* 0 --> 1 */
    mrp->record_count              = 1;		/* XXX: assume 1 record */
    mrp->nonce = build_nonce((unsigned int) time(NULL));
    *nonce                         = mrp->nonce;
    mrp->source_eid_afi = htons(get_lisp_afi(eid_prefix_afi, NULL));

    /*
     * Source-EID address goes here.
     *
     *	point cur_ptr at where the variable length Source-EID 
     *  address goes, namely, CO(mrp,sizeof(lispd_pkt_map_request_t))
     */    

    /* TODO
     * VE:
     * This should be my_eid instead of the eid_prefix.
     */

    cur_ptr = CO(mrp, sizeof(lispd_pkt_map_request_t));
    if ((alen = copy_addr(cur_ptr, eid_prefix, eid_prefix_afi, 0)) == 0) {
        free(packet);
        free(dcache_ptr);
	return (0);
    }

    /*
     * now the ITR-RLOC (XXX: assumes only one)
     */

    itr_rloc = (lispd_pkt_map_request_itr_rloc_t *) CO(cur_ptr, alen);
    itr_rloc->afi = htons(get_lisp_afi(my_addr->afi, NULL));
    cur_ptr = CO(itr_rloc, sizeof(lispd_pkt_map_request_itr_rloc_t));
    if ((alen = copy_addr(cur_ptr, (lisp_addr_t *) &(my_addr->address.address),
			my_addr->afi, 0)) == 0) {
	free(packet);
        free(dcache_ptr);
	return (0);
    }

    /* 
     *	finally, the requested EID prefix
     */

    eid = (lispd_pkt_map_request_eid_prefix_record_t *) CO(cur_ptr, alen);
    eid->eid_prefix_mask_length = eid_prefix_length;
    eid->eid_prefix_afi = htons(get_lisp_afi(eid_prefix_afi, NULL));
    cur_ptr = CO(eid, sizeof(lispd_pkt_map_request_eid_prefix_record_t));
    if (copy_addr(cur_ptr,				/* EID */
	eid_prefix, eid_prefix_afi, 0) == 0) {
	free(packet);
        free(dcache_ptr);
	return (0);
    }
    
    /*
     * now compute the checksums if encapsulated...
     */

    if (encap) {
        if (my_addr->afi == AF_INET)
	    ((struct ip *) iphptr)->ip_sum = ip_checksum(iphptr, ip_header_len);
	if ((udpsum = udp_checksum(udph, udp_len, iphptr, my_addr->afi)) == -1) {
	    return (0);
        }
	udpsum( udph) = udpsum;
    }
    free(my_addr);
    return (packet);
}

/*
 *	send_map_request
 *
 */

send_map_request(packet, packet_len, resolver)
    uint8_t *packet;
    int packet_len;
    lispd_addr_t *resolver; 
{

    struct sockaddr_in   map_resolver;
    int			s;		/*socket */
    int			nbytes = 0;
    int			md_len = 0;
    struct sockaddr_in  ctrl_saddr;

    /* XXX: assume v4 transport */

    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
	syslog(LOG_DAEMON, "socket (send_map_request): %s", strerror(errno));
	return (0);
    }

    /*
     * PN: Bind the UDP socket to a valid rloc on the ctrl_iface
     * (assume v4 transport)
     */
    if (!(ctrl_iface) || !(ctrl_iface->AF4_locators->head)) {
        /* 
         * No physical interface available for control messages
         */
        syslog(LOG_DAEMON, "(send_map_request): Unable to find valid physical interface\n");
        close(s);
        return (0);
    }
    memset((char *) &ctrl_saddr, 0, sizeof(struct sockaddr_in));
    ctrl_saddr.sin_family       = AF_INET;
    ctrl_saddr.sin_port         = htons(INADDR_ANY);
    ctrl_saddr.sin_addr.s_addr  = (ctrl_iface->AF4_locators->head->db_entry->locator).address.ip.s_addr;

    if (bind(s, (struct sockaddr *)&ctrl_saddr, sizeof(struct sockaddr_in)) < 0) {
        syslog(LOG_DAEMON, "bind (send_map_request): %s", strerror(errno));
        close(s);
        return(0);
    }

    memset((char *) &map_resolver, 0, sizeof(map_resolver));

    map_resolver.sin_family      = AF_INET;	/* XXX: assume v4 transport */
    map_resolver.sin_addr.s_addr = resolver->address.address.ip.s_addr;
    map_resolver.sin_port        = htons(LISP_CONTROL_PORT);

    if ((nbytes = sendto(s, 
                         (const void *) packet, packet_len, 0,
                         (struct sockaddr *) &map_resolver, sizeof(struct sockaddr))) < 0) {
	syslog(LOG_DAEMON, "sendto (send_map_request): %s", strerror(errno));
        close(s);
	return (0);
    }

    if (nbytes != packet_len) {
	syslog(LOG_DAEMON,
                "send_map_request: nbytes (%d) != packet_len (%d)\n", 
                nbytes, packet_len);
        close(s);
	return (0);
    }

    close(s);
    free(packet);
    return (1);
}

/*
 *	build_and_send_map_request --
 *
 *	Put a wrapper around build_map_request_pkt and send_map_request
 *
 */

build_and_send_map_request_msg(dest, eid_prefix, eid_prefix_afi,
        eid_prefix_length, eid_name, encap, solicit_map_request,
        smr_invoked, islocal,retries,timeout,search)
    lispd_addr_t *dest;
    lisp_addr_t *eid_prefix;
    uint16_t eid_prefix_afi;
    uint8_t eid_prefix_length;
    char *eid_name;
    uint8_t encap;                  /* "boolean" */
    uint8_t solicit_map_request;    /* "boolean" */
    uint8_t smr_invoked;            /* "boolean" */
    uint8_t islocal;                /* "boolean" */
    uint8_t retries;
    uint16_t timeout;
    uint8_t search;
{

    uint8_t *packet;
    uint64_t nonce;
    int      len;				/* return the length here */
	datacache_elt_t *res_elt;

	if (search) {
		if (search_datacache_entry_eid (eid_prefix_afi,eid_prefix,res_elt)) {
			// We have already sent a Map-Request towards this destination
			// We should wait until the ongoing Map-Request expires to re-send
			// another one
			return (1);
		}
	}

	packet = build_map_request_pkt(eid_prefix, eid_prefix_afi,
			eid_prefix_length, &len, &nonce, encap, solicit_map_request,
			smr_invoked, islocal,retries);


    if (!packet) {
		syslog(LOG_DAEMON, "Could not build map-request packet for %s/%d",
				eid_name, eid_prefix_length);
		return (0);
    }

    if (!send_map_request(packet, len, dest)) {
		syslog(LOG_DAEMON, "Could not send map-request for %s/%d", eid_name,
	       eid_prefix_length);
		return (0);
    }

    /*
     * Add outstanding nonce to datacache, unless SMR
     */

    if (!solicit_map_request) {
        if (!build_datacache_entry(dest,eid_prefix, eid_prefix_afi, eid_prefix_length,
                    nonce, islocal, solicit_map_request, retries,timeout,encap)) {
            syslog(LOG_DAEMON, "Couldn't build datacache_entry");
            return (0);
        }
    }
    return (1);
}

/*
 *	process Map_Request Message
 *	Receive a Map_request message and process based on control bits
 *
 *	For first phase just accept (encapsulated) SMR. Proxy bit is set to avoid receiving ecm, and all other types are ignored.
 *
 *
 */

int process_map_request_msg(uint8_t *packet, int s, struct sockaddr *from, int afi) {

    lisp_addr_t *src_eid_prefix;
    int src_eid_afi;
    void *cur_ptr;
    int alen = 0;
    int afi_len = 0;
    int ip_header_len = 0;
    int len = 0;
    char eid_name[128];
    lispd_pkt_map_request_t *msg;
    struct ip *iph;
    struct ip6_hdr *ip6h;
    struct udphdr *udph;
    int encap_afi;
    uint16_t udpsum = 0;
    uint16_t ipsum = 0;
    int udp_len = 0;
    lisp_addr_t my_rloc;
    map_reply_opts opts;

    if (((lispd_pkt_encapsulated_control_t *) packet)->type == LISP_ENCAP_CONTROL_TYPE) {

        /*
         * Read IP header.
         */

        iph = (struct ip *) CO(packet, sizeof(lispd_pkt_encapsulated_control_t));

        switch (iph->ip_v) {
        case IPVERSION:
            ip_header_len = (iph->ip_hl) * 4;
            udph = (struct udphdr *) CO(iph, ip_header_len);
            encap_afi = AF_INET;
            break;
        case IP6VERSION:
            ip6h = (struct ip6_hdr *) CO(packet, sizeof(lispd_pkt_encapsulated_control_t));
            if ((ip_header_len = get_ip_header_len(AF_INET6)) == 0)
                return(0);
            udph = (struct udphdr *) CO(ip6h, ip_header_len);
            encap_afi = AF_INET6;
            break;
        default:
            syslog(LOG_DAEMON, "process_map_request_msg: couldn't read incoming Encapsulated Map-Request: IP header corrupted.");
            return(0);
        }

#ifdef BSD
        udp_len = ntohs(udph->uh_ulen);
#else
        udp_len = ntohs(udph->len);
#endif

        /*
	 * Verify the checksums.
	 */

        if (iph->ip_v == IPVERSION) {
            ipsum = ip_checksum(iph, ip_header_len);
            if (ipsum != 0) {
                syslog(LOG_DAEMON, " Map-Request: IP checksum failed.");
            }

            if ((udpsum = udp_checksum(udph, udp_len, iph, encap_afi)) == -1) {
                    return(0);
            }

            if (udpsum != 0) {
                    syslog(LOG_DAEMON, " Map-Request: UDP checksum failed.");
                    return(0);

            }
        }

        /*
	 * Point cur_ptr at the start of the Map-Request payload.
	 */

        len = ip_header_len + sizeof(struct udphdr);
        msg = (lispd_pkt_map_request_t *) CO(iph, len);

    } else if (((lispd_pkt_map_request_t *) packet)->type == LISP_MAP_REQUEST) {
        msg = (lispd_pkt_map_request_t *) packet;
    } else
        return(0); //we should never reach this return()

    /* Source EID is optional in general, but required for SMRs */
    src_eid_afi = lisp2inetafi(ntohs(msg->source_eid_afi));
    if (src_eid_afi != 0) {
        src_eid_prefix = (lisp_addr_t *) CO(msg, sizeof(lispd_pkt_map_request_t));
        inet_ntop(src_eid_afi, &(src_eid_prefix->address), eid_name, 128);
        afi_len = (get_addr_len(src_eid_afi)) * 8;

        if (msg->solicit_map_request) {
            if(!build_and_send_map_request_msg(map_resolvers->address,
                        src_eid_prefix, src_eid_afi, afi_len, eid_name,
                        1, 0, 1, 0, 0, LISPD_INITIAL_MRQ_TIMEOUT, 1)) {
                syslog(LOG_DAEMON, "process_map_request_msg: couldn't build/send SMR triggered Map-Request");
                return(0);
            }
            syslog(LOG_DAEMON, "Sent SMR triggered Map-Request for %s", eid_name);
        }
    }

    if (msg->rloc_probe) {
        if(lispd2lisp(&source_rloc, &my_rloc) < 0) {
            syslog(LOG_DAEMON, "process_map_request_msg: lispd2lisp failed");
            return(0);
        }

        opts.send_rec   = 1;
        opts.rloc_probe = 1;
        opts.echo_nonce = 0;
        if(!build_and_send_map_reply_msg(&my_rloc, from, s, msg->nonce, opts)) {
            syslog(LOG_DAEMON, "process_map_request_msg: couldn't build/send RLOC-probe reply");
            return(0);
        }
        syslog(LOG_DAEMON, "Sent RLOC-probe reply");
    }

    /*
     *  Encapsulated Map-Requests are ignored at this time due to the
     *  Map-Server proxy-replying for us.
     *  TODO: For generic ETR functionality this should be implemented
     */
    return(1);
}
