/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/* $Id$ */
/** @file common.h
    @brief Common constants and other bits
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _COMMON_H_
#define _COMMON_H_

/** @brief Read buffer for socket read? */
#define MAX_BUF 4096
#define IEEE80211_NWID_LEN              32
time_t wd_get_redirect_timestamp(unsigned char *mac);
unsigned char wd_get_redirect_cpauthstatus(unsigned char *mac);
#define COPY_MACADDRESS(from,to,count) for(count=0;count<6;count++) \
                to[count] = from[count];

#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

typedef struct disassoc_Trap {
        char            disassocMacAddr[18];
        char            disassocBssid[18];
        char            disassocSsid[32];
        int             disassocReason;
        unsigned int    ns_tx_payload;      /* payload bytes sent to the client */
        unsigned int    ns_rx_payload;      /* payload bytes received from the client */
        char            ipaddr[18];         /* IP Address of client */ 
}disassoc_Trap;

struct notification_info
{
    u_int8_t                ssidlen;  /*ssid len to which station is(was) connected*/
    u_int8_t                ssid[IEEE80211_NWID_LEN+1]; /* ssid to which station is(was) connected*/
    u_int32_t               ns_rx_payload;      /*payload bytes received from the client*/
    u_int32_t               ns_tx_payload;      /*payload bytes sent to the client*/
    u_int32_t               ipaddr; /*IP Address of client*/
    /*ADD ANY OTHER INFO NEEDED HERE*/
};

struct custom_event_data
{
   u_int8_t addr[6];
   u_int8_t reason;
   u_int8_t rssi;
   struct notification_info xinfo;
};
#endif /* _COMMON_H_ */
