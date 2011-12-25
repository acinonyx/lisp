/*
 * lispd_map_reply.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Necessary logic to handle incoming map replies.
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
 *    Kari Okamoto	    <okamotok@stanford.edu>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *
 */

/*
 * Map-Reply Message Format from lisp draft-ietf-lisp-08
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=2 |P|E|           Reserved                | Record Count  |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         Nonce . . .                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         . . . Nonce                           |
 *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   |                          Record  TTL                          |
 *  |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
 *  e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  c   | Rsvd  |  Map-Version Number   |            EID-AFI            |
 *  o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  r   |                          EID-prefix                           |
 *  d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *  | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | o |        Unused Flags     |L|p|R|           Loc-AFI             |
 *  | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  \|                            Locator                            |
 *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                     Mapping Protocol Data                     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */


#include "lispd_external.h"


process_map_reply(packet)
    uint8_t *packet;

{
    lispd_pkt_map_reply_t       			*mrp;
    lispd_pkt_map_reply_eid_prefix_record_t 		*record;
    lispd_pkt_map_reply_locator_t			*loc_pkt;
    lispd_map_cache_entry_t     			*map_cache_entry;
    datacache_elt_t             			*itr, *prev;
    datacache_elt_t                         *elt = NULL;
    lisp_addr_t						*eid;
    lisp_addr_t						*loc;
    int                                                 eid_afi;
    uint64_t                                            nonce;
    int							i;
    int                                                 match = 0;
    int                                                 ret;

    mrp = (lispd_pkt_map_reply_t *)packet;
    nonce = mrp->nonce;

    /*
     * Advance ptrs to point to their corresponding locations
     * within the incoming packet
     *
     * VE:
     * Assumption is Map Reply has only one record
     */

    record = (lispd_pkt_map_reply_eid_prefix_record_t *)CO(mrp, sizeof(lispd_pkt_map_reply_t));
    eid = (lisp_addr_t *)CO(record, sizeof(lispd_pkt_map_reply_eid_prefix_record_t));
    eid_afi = lisp2inetafi(ntohs(record->eid_prefix_afi));

    if(record->locator_count > 0){
    switch (eid_afi) {
        case AF_INET: //ipv4: 4B
            loc_pkt = (lispd_pkt_map_reply_locator_t *)CO(eid, sizeof(struct in_addr));
            break;
        case AF_INET6: //ipv6: 16B
            loc_pkt = (lispd_pkt_map_reply_locator_t *)CO(eid, sizeof(struct in6_addr));
            break;
        default:
            syslog (LOG_DAEMON, "process_map_reply(), unknown AFI");
            return (0);
    }

    loc = (lisp_addr_t *)CO(loc_pkt, sizeof(lispd_pkt_map_reply_locator_t));
    }
    /*
     * Check for rloc probing bit?
     * Can calculate RTT if we want to know
     */

    /*
     * Search datacache for the corresponding entry
     */
    // Modified by acabello
    if (!search_datacache_entry_nonce(nonce,&elt)) {
    syslog(LOG_DAEMON,"Map-Reply: Datacache not found for nonce:\n");
    lispd_print_nonce(nonce);
        return 0;
    }
    if (!is_eid_included(elt,eid_afi,record->eid_prefix_mask_length,eid)) {
    syslog(LOG_DAEMON,"Map-Reply: EID does not match for MRp with nonce:\n");
    lispd_print_nonce(nonce);
        return 0;
    }
    delete_datacache_entry(elt);

    /*
     * Allocate memory for the new map cache entry, fill it in
     */
    if ((map_cache_entry = (lispd_map_cache_entry_t *) malloc(sizeof(lispd_map_cache_entry_t))) == NULL) {
        syslog(LOG_DAEMON, "process_map_reply(), malloc (map-cache entry): %s", strerror(errno));
        return(0);
    }

    memset(map_cache_entry, 0, sizeof(lispd_map_cache_entry_t));

    map_cache_entry->eid_prefix = *eid;
    map_cache_entry->eid_prefix_length = record->eid_prefix_mask_length;
    map_cache_entry->eid_prefix_afi = eid_afi;
    map_cache_entry->locator_type = 2;     /* 2 --> map reply */
    map_cache_entry->how_learned = DYNAMIC_MAP_CACHE_ENTRY;      
    map_cache_entry->ttl = ntohl(record->record_ttl);
    map_cache_entry->actions = record->actions;


    /*
     *  VE:
     * If there are none -> negative map reply.
     */

    if((record->locator_count) == 0){
        /*
	 * LJ:   We add the first PETR in the list as locator
         * TODO: We should iterate list, and adjust weights accordingly
	 */
        if (proxy_etrs) {
            map_cache_entry->locator = proxy_etrs->address->address;
            map_cache_entry->locator_name = "locator_name";
            map_cache_entry->locator_afi = proxy_etrs->address->afi;
            map_cache_entry->priority = 1;
            map_cache_entry->weight = 100;
            map_cache_entry->mpriority = 255;
            map_cache_entry->mweight = 100;
        }
	ret = install_map_cache_entry(map_cache_entry);
#ifdef DEBUG
	syslog (LOG_DAEMON, "Negative  Map cache installed, ret =%d", ret);
#endif
	if (ret < 0) {
		syslog (LOG_DAEMON, "Map cache install failed; ret=%d", ret);
	}
#if (DEBUG > 3)
        dump_map_cache();
#endif
    }

 /*
  * Loop through locators if there is more than one provided.
  */

    for(i = 0; i < record->locator_count; i++) {

        /*
         * VE:
         * Don't we need to use copy_addr for IPv6?
         */
        map_cache_entry->locator = *loc;

        /* PN, DM:
         * "locator_name" is currently used by lispd for debug messages
         * Not used by data plane.
         * Probably best to remove this member from map_cache_entry structure?
         */
        map_cache_entry->locator_name = "locator_name"; //where is the actual name?
        map_cache_entry->locator_afi = lisp2inetafi(ntohs(loc_pkt->locator_afi));
        map_cache_entry->priority = loc_pkt->priority;
        map_cache_entry->weight = loc_pkt->weight;
        map_cache_entry->mpriority = loc_pkt->m_priority;
        map_cache_entry->mweight = loc_pkt->m_weight;

	/*
	 * Advance the ptrs for the next locator
	 */
	if(i+1 < record->locator_count) {

	    if(eid_afi == AF_INET) { //ipv4: 4B
		loc_pkt = (lispd_pkt_map_reply_locator_t *)CO(loc, sizeof(struct in_addr));
	    } else if(eid_afi == AF_INET6){ //ipv6: 16B
		loc_pkt = (lispd_pkt_map_reply_locator_t *)CO(loc, sizeof(struct in6_addr));
	    } else
		return(0);

	    loc = (lisp_addr_t *)CO(loc_pkt, sizeof(lispd_pkt_map_reply_locator_t));
	}


        /*
         * Send the cache entry to the data plane via netlink
         */

        /* PN, DM:
         * install_map_cache_entry installs one map cache entry/rloc
         * per call.
         * After this code was written, the data plane was modified
         * to take a bunch of LispMapCacheAdd cmds in a single netlink msg.
         * Do we want to modify install_map_cache_entry to send down
         * a bunch of cmds instead of one at a time?
         */
        ret = install_map_cache_entry(map_cache_entry);

#ifdef DEBUG
        syslog (LOG_DAEMON, "Map cache installed, ret =%d", ret);
#endif
        if (ret < 0) {
            syslog (LOG_DAEMON, "Map cache install failed; ret=%d", ret);
        }
    }//for locator_count

    free(map_cache_entry);
    map_cache_entry = NULL;
    return(0);
}


/*
 * TODO (LJ): There should be a build_mapping_record() function, shared with
 *            the Map-Register code, and the appropriate structure in lispd.h
 *            should be shared as well
 */

uint8_t *build_map_reply_pkt(lisp_addr_t *src, lisp_addr_t *dst, uint64_t nonce,
        map_reply_opts opts, lispd_locator_chain_t *locator_chain, int *len) {
    lispd_addr_t source;
    uint8_t *packet;
    int packet_len = 0;
    int iph_len = 0;
    struct udphdr *udph;
    int udpsum = 0;
    lispd_pkt_map_reply_t *map_reply_msg;
    int map_reply_msg_len = 0;
    lispd_pkt_map_reply_eid_prefix_record_t *mr_msg_eid;
    lispd_pkt_map_reply_locator_t *loc_ptr;
    lispd_locator_chain_elt_t *locator_chain_elt;
    lispd_db_entry_t *db_entry;
    int eid_afi = 0;
    int afi_len = 0;
    int loc_len = 0;
    int cpy_len = 0;

    map_reply_msg_len = sizeof(lispd_pkt_map_reply_t);
    if ((iph_len = get_ip_header_len(src->afi)) == 0)
        return(0);

    /* If the options ask for a mapping record, calculate addtional length */
    if (opts.send_rec)
        if (locator_chain) {
            locator_chain_elt = locator_chain->head;
            loc_len = get_locator_length(locator_chain_elt);
            eid_afi = get_lisp_afi(locator_chain->eid_prefix_afi, &afi_len);

            map_reply_msg_len += sizeof(lispd_pkt_map_reply_eid_prefix_record_t) +
                                 afi_len +
                                 (locator_chain->locator_count *
                                 sizeof(lispd_pkt_map_reply_locator_t)) +
                                 loc_len;

        }

    packet_len = iph_len + sizeof(struct udphdr) + map_reply_msg_len;

    if ((packet = malloc(packet_len)) == NULL) {
        syslog(LOG_DAEMON, "build_and_send_map_reply_msg: malloc(%d) %s",
                map_reply_msg_len, strerror(errno));
        return(0);
    }
    memset(packet, 0, packet_len);

    lisp2lispd(src, &source);
    udph = build_ip_header((void *)packet, &source, dst, iph_len);

#ifdef BSD
    udph->uh_sport = htons(LISP_CONTROL_PORT);
    udph->uh_dport = htons(LISP_CONTROL_PORT);
    udph->uh_ulen  = htons(sizeof(struct udphdr) + map_reply_msg_len);
    udph->uh_sum   = 0;
#else
    udph->source = htons(LISP_CONTROL_PORT);
    udph->dest   = htons(LISP_CONTROL_PORT);
    udph->len    = htons(sizeof(struct udphdr) + map_reply_msg_len);
    udph->check  = 0;
#endif

    map_reply_msg = (lispd_pkt_map_reply_t *) CO(udph, sizeof(struct udphdr));

    map_reply_msg->type = 2;
    if (opts.rloc_probe)
        map_reply_msg->rloc_probe = 1;
    if (opts.echo_nonce)
        map_reply_msg->echo_nonce = 1;
    map_reply_msg->nonce = nonce;

    if (opts.send_rec) {
        /*
         * Optionally, we send a Map Reply record. For RLOC Probing,
         * the language in the spec is SHOULD
         */
        map_reply_msg->record_count = 1;
        mr_msg_eid = (lispd_pkt_map_reply_eid_prefix_record_t *)
                     CO(map_reply_msg, sizeof(lispd_pkt_map_reply_t));
        mr_msg_eid->record_ttl             = htonl(DEFAULT_MAP_REGISTER_TIMEOUT);
        mr_msg_eid->locator_count          = locator_chain->locator_count;
        mr_msg_eid->eid_prefix_mask_length = locator_chain->eid_prefix_length;
        mr_msg_eid->actions                = 0;
        mr_msg_eid->authoritative          = 1;
        mr_msg_eid->version_number         = 0;
        mr_msg_eid->eid_prefix_afi         = htons(eid_afi);

        if ((cpy_len = copy_addr((void *) CO(mr_msg_eid,
                sizeof(lispd_pkt_map_reply_eid_prefix_record_t)),
                &(locator_chain->eid_prefix), locator_chain->eid_prefix_afi, 0)) == 0) {
            syslog(LOG_DAEMON, "build_map_reply_pkt: copy_addr failed");
        }

        loc_ptr = (lispd_pkt_map_reply_locator_t *) CO(mr_msg_eid,
             sizeof(lispd_pkt_map_reply_eid_prefix_record_t) + cpy_len);

        while (locator_chain_elt) {
            db_entry             = locator_chain_elt->db_entry;
            loc_ptr->priority    = db_entry->priority;
            loc_ptr->weight      = db_entry->weight;
            loc_ptr->m_priority  = db_entry->mpriority;
            loc_ptr->m_weight    = db_entry->mweight;
            loc_ptr->local       = 1;
            if (opts.rloc_probe)
                loc_ptr->p       = 1;       /* XXX probed locator, should check addresses */
            loc_ptr->reachable   = 1;       /* XXX should be computed */
            loc_ptr->locator_afi = htons(get_lisp_afi(db_entry->locator_afi, &afi_len));

            if ((cpy_len = copy_addr((void *) CO(loc_ptr,
                    sizeof(lispd_pkt_map_reply_locator_t)), &(db_entry->locator),
                    db_entry->locator_afi, 0)) == 0) {
                syslog(LOG_DAEMON, "build_map_reply_pkt: copy_addr failed for locator %s",
                        db_entry->locator_name);
                return(0);
            }

            loc_ptr = (lispd_pkt_map_reply_locator_t *)
                CO(loc_ptr, (sizeof(lispd_pkt_map_reply_locator_t) + cpy_len));
            locator_chain_elt = locator_chain_elt->next;
        }
    }

    /* Compute checksums */
    if (src->afi == AF_INET)
        ((struct ip *) packet)->ip_sum = ip_checksum(packet, iph_len);
    if ((udpsum = udp_checksum(udph, packet_len - iph_len, packet, src->afi)) == -1) {
        return (0);
    }
    udpsum(udph) = udpsum;
    *len = packet_len;
    return(packet);
}

int send_map_reply(struct sockaddr *dst, uint8_t *packet, int packet_len) {
    struct ifreq ifr;
    int s, nbytes, one = 1;

    if ((s = socket(dst->sa_family, SOCK_RAW, IPPROTO_UDP)) < 0) {
        syslog(LOG_DAEMON, "send_map_reply: socket: %s", strerror(errno));
        return(0);
    }

    /*
     * By default, raw sockets create the IP header automatically, with operating
     * system defaults and the protocol number specified in the socket() function
     * call. If IP header values need to be customized, the socket option
     * IP_HDRINCL must be set and the header built manually.
     */
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1) {
        syslog(LOG_DAEMON, "send_map_reply: setsockopt IP_HDRINCL: %s", strerror(errno));
        close(s);
        return(0);
    }

    /* XXX (LJ): Even with source routing set up, the packet leaves on lmn0, unless
     *           we specificly ask for the output device to be the control interface
     */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ctrl_iface->iface_name);
    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) == -1) {
        syslog(LOG_DAEMON, "send_map_reply: setsockopt SO_BINDTODEVICE: %s", strerror(errno));
        close(s);
        return(0);
    }

    if ((nbytes = sendto(s, (const void *) packet, packet_len, 0,
                    dst, sizeof(struct sockaddr))) < 0) {
        syslog(LOG_DAEMON, "send_map_reply: sendto: %s", strerror(errno));
        close(s);
        return (0);
    }

    if (nbytes != packet_len) {
        syslog(LOG_DAEMON, "send_map_reply: nbytes (%d) != packet_len (%d)\n",
                nbytes, packet_len);
        close(s);
        return (0);
    }

    close(s);
    free(packet);
    return (1);
}

/*
 * build_and_send_map_reply_msg()
 *
 */

int build_and_send_map_reply_msg(lisp_addr_t *src, struct sockaddr *dst, int s,
        uint64_t nonce, map_reply_opts opts) {
    lisp_addr_t destination;
    patricia_node_t *node;
    lispd_locator_chain_t *locator_chain = NULL;
    uint8_t *packet;
    int len = 0;

    if (sockaddr2lisp(dst, &destination) < 0) {
        syslog(LOG_DAEMON, "build_and_send_map_reply_msg: sockaddr2lisp failed");
        return(0);
    }

    if (opts.send_rec) {
    /* LJ: For now, IPv4 EIDs only. TODO IPv6 */
        PATRICIA_WALK(AF4_database->head, node) {
            locator_chain = ((lispd_locator_chain_t *)(node->data));
        } PATRICIA_WALK_END;
    }

    packet = build_map_reply_pkt(src, &destination, nonce, opts, locator_chain, &len);

    /* Send the packet over a raw socket */
    if (!send_map_reply(dst, packet, len)) {
        syslog(LOG_DAEMON, "Could not send Map-Reply!");
        free(packet);
        return (0);
    }

    /* LJ: The code below is for the case when we reuse the receiving socket.
     *     However, since it is bound to INADDR_ANY, it selects source
     *     address based on exit interface, and because of that it will
     *     use our EID on lmn0. Because we want source port 4342, and it is
     *     already bound, we need to use raw sockets in send_map_reply()
     */
/*
    if ((nbytes = sendto(s, (const void *) packet, map_reply_msg_len, 0,
                    dst, sizeof(struct sockaddr))) < 0) {
        syslog(LOG_DAEMON, "send_map_reply: sendto: %s", strerror(errno));
        free(packet);
        return (0);
    }

    if (nbytes != map_reply_msg_len) {
        syslog(LOG_DAEMON, "build_and_send_map_reply_msg: nbytes (%d) != map_reply_msg_len (%d)\n",
                nbytes, map_reply_msg_len);
        return (0);
    }
    free(packet);
*/

    return(1);
}

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
