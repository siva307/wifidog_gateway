/*
 *	Wireless Tools
 *
 *		Jean II - HPL 99->04
 *
 * Main code for "iwevent". This listent for wireless events on rtnetlink.
 * You need to link this code against "iwcommon.c" and "-lm".
 *
 * Part of this code is from Alexey Kuznetsov, part is from Casey Carter,
 * I've just put the pieces together...
 * By the way, if you know a way to remove the root restrictions, tell me
 * about it...
 *
 * This file is released under the GPL license.
 *     Copyright (c) 1997-2004 Jean Tourrilhes <jt@hpl.hp.com>
 */

/***************************** INCLUDES *****************************/

#include "iwlib.h"		/* Header */
#include <linux/ip.h>
#include "br_event.h"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include<linux/if_bridge.h>

#include <getopt.h>
#include <time.h>
#include <sys/time.h>

#include <syslog.h>
#include "debug.h"
#include "common.h"

/* Ugly backward compatibility :-( */
#ifndef IFLA_WIRELESS
#define IFLA_WIRELESS	(IFLA_MASTER + 1)
#endif /* IFLA_WIRELESS */

#ifndef IFLA_HTTPREDIR
#define IFLA_HTTPREDIR  (IFLA_MASTER + 9)
#endif /* IFLA_HTTPREDIR */

#if 0 /* Old Atheroes driver macros */
#define	IWEVCUST_STA_DISASSOCIATED 105	 // Disassociation happend
#define IWEVCUST_STA_DEAUTHENTICATED 106    // Deauthentication is happend
#else /* New macros, for qca-wifi-10.4 driver */
#define IEEE80211_EV_AUTH_IND_AP     10
#define IEEE80211_EV_DEAUTH_IND_AP   19
#define IEEE80211_EV_DISASSOC_IND_AP 20
#endif

/****************************** TYPES ******************************/

/*
 * Static information about wireless interface.
 * We cache this info for performance reason.
 */
typedef struct wireless_iface
{
  /* Linked list */
  struct wireless_iface *	next;

  /* Interface identification */
  int		ifindex;		/* Interface index == black magic */

  /* Interface data */
  char			ifname[IFNAMSIZ + 1];	/* Interface name */
  struct iw_range	range;			/* Wireless static data */
  int			has_range;
} wireless_iface;

/**************************** VARIABLES ****************************/

/* Cache of wireless interfaces */
struct wireless_iface *	interface_cache = NULL;

//char bridge[IFNAMSIZ+1];

/************************ RTNETLINK HELPERS ************************/
/*
 * The following code is extracted from :
 * ----------------------------------------------
 * libnetlink.c	RTnetlink service routines.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 * -----------------------------------------------
 */

struct rtnl_handle
{
	int			fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	__u32			seq;
	__u32			dump;
};

/* Taken from qca-wifi-10.4/os/linux/include/ieee80211_ev.h */
struct ev_msg {
    u_int8_t addr[6];
    u_int32_t status;
    u_int32_t reason;
};

static inline void rtnl_close(struct rtnl_handle *rth)
{
	close(rth->fd);
}

static inline int rtnl_open(struct rtnl_handle *rth, unsigned subscriptions)
{
	int addr_len;

	memset(rth, 0, sizeof(rth));

	rth->fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (rth->fd < 0) {
		perror("Cannot open netlink socket");
		return -1;
	}

	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = subscriptions;

	if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
		perror("Cannot bind netlink socket");
		return -1;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr*)&rth->local,
			(socklen_t *) &addr_len) < 0) {
		perror("Cannot getsockname");
		return -1;
	}
	if (addr_len != sizeof(rth->local)) {
		fprintf(stderr, "Wrong address length %d\n", addr_len);
		return -1;
	}
	if (rth->local.nl_family != AF_NETLINK) {
		fprintf(stderr, "Wrong address family %d\n", rth->local.nl_family);
		return -1;
	}
	rth->seq = time(NULL);
	return 0;
}

/******************* WIRELESS INTERFACE DATABASE *******************/
/*
 * We keep a few information about each wireless interface on the
 * system. This avoid to query this info at each event, therefore
 * reducing overhead.
 *
 * Each interface is indexed by the 'ifindex'. As opposed to interface
 * names, 'ifindex' are never reused (even if you reactivate the same
 * hardware), so the data we cache will never apply to the wrong
 * interface.
 * Because of that, we are pretty lazy when it come to purging the
 * cache...
 */

/*------------------------------------------------------------------*/
/*
 * Get name of interface based on interface index...
 */
static inline int
index2name(int		skfd,
	   int		ifindex,
	   char *	name)
{
  struct ifreq	irq;
  int		ret = 0;

  memset(name, 0, IFNAMSIZ + 1);

  /* Get interface name */
  irq.ifr_ifindex = ifindex;
  if(ioctl(skfd, SIOCGIFNAME, &irq) < 0)
    ret = -1;
  else
    strncpy(name, irq.ifr_name, IFNAMSIZ);

  return(ret);
}

/*------------------------------------------------------------------*/
/*
 * Get interface data from cache or live interface
 */
static struct wireless_iface *
iw_get_interface_data(int	ifindex)
{
  struct wireless_iface *	curr;
  int				skfd = -1;	/* ioctl socket */

  /* Search for it in the database */
  curr = interface_cache;
  while(curr != NULL)
    {
      /* Match ? */
      if(curr->ifindex == ifindex)
	{
	  //printf("Cache : found %d-%s\n", curr->ifindex, curr->ifname);

	  /* Return */
	  return(curr);
	}
      /* Next entry */
      curr = curr->next;
    }

  /* Create a channel to the NET kernel. Doesn't happen too often, so
   * socket creation overhead is minimal... */
  if((skfd = iw_sockets_open()) < 0)
    {
      perror("iw_sockets_open");
      return(NULL);
    }

  /* Create new entry, zero, init */
  curr = calloc(1, sizeof(struct wireless_iface));
  if(!curr)
    {
      fprintf(stderr, "Malloc failed\n");
      return(NULL);
    }
  curr->ifindex = ifindex;

  /* Extract static data */
  if(index2name(skfd, ifindex, curr->ifname) < 0)
    {
      perror("index2name");
      free(curr);
      return(NULL);
    }
  curr->has_range = (iw_get_range_info(skfd, curr->ifname, &curr->range) >= 0);
  //printf("Cache : create %d-%s\n", curr->ifindex, curr->ifname);

  /* Done */
  iw_sockets_close(skfd);

  /* Link it */
  curr->next = interface_cache;
  interface_cache = curr;

  return(curr);
}

/*------------------------------------------------------------------*/
/*
 * Remove interface data from cache (if it exist)
 */
static void
iw_del_interface_data(int	ifindex)
{
  struct wireless_iface *	curr;
  struct wireless_iface *	prev = NULL;
  struct wireless_iface *	next;

  /* Go through the list, find the interface, kills it */
  curr = interface_cache;
  while(curr)
    {
      next = curr->next;

      /* Got a match ? */
      if(curr->ifindex == ifindex)
	{
	  /* Unlink. Root ? */
	  if(!prev)
	    interface_cache = next;
	  else
	    prev->next = next;
	  //printf("Cache : purge %d-%s\n", curr->ifindex, curr->ifname);

	  /* Destroy */
	  free(curr);
	}
      else
	{
	  /* Keep as previous */
	  prev = curr;
	}

      /* Next entry */
      curr = next;
    }
}

/********************* WIRELESS EVENT DECODING *********************/
/*
 * Parse the Wireless Event and print it out
 */

/*------------------------------------------------------------------*/
/*
 * Dump a buffer as a serie of hex
 * Maybe should go in iwlib...
 * Maybe we should have better formatting like iw_print_key...
 */
static char *
iw_hexdump(char *		buf,
	   size_t		buflen,
	   const unsigned char *data,
	   size_t		datalen)
{
  size_t	i;
  char *	pos = buf;

  for(i = 0; i < datalen; i++)
    pos += snprintf(pos, buf + buflen - pos, "%02X", data[i]);
  return buf;
}

/*------------------------------------------------------------------*/
/*
 * Print one element from the scanning results
 */

extern void notify_client_connect(char *mac, char *);
extern void notify_client_disconnect(char *mac, char *);
extern void notify_add_route(struct brreq *brreq, char *mac);
extern void notify_mark_cpauthstatus(struct brreq *brreq, char *buf);
extern void wd_PostEventToCloud(char *mac, char *ifname, struct disassoc_Trap *);
extern const char *ether_sprintf(const u_int8_t *mac);
static inline int
print_event_token(struct iw_event *	event,		/* Extracted token */
		  struct iw_range *	iw_range,	/* Range info */
		  int			has_range,
		  char *		ifname)
{
  char		buffer[128];	/* Temporary buffer */
  char		buffer2[30];	/* Temporary buffer */
  char *	prefix = (IW_IS_GET(event->cmd) ? "New" : "Set");

  debug(LOG_NOTICE, "event->cmd = 0x%x \n",event->cmd);
  /* Now, let's decode the event */
  switch(event->cmd)
    {
#if 0 /* Handled in IWEVCUSTOM */
    case IWEVREGISTERED:
      notify_client_connect(iw_saether_ntop(&event->u.addr, buffer), ifname);
      break;
#endif
    case IWEVEXPIRED:
      notify_client_disconnect(iw_saether_ntop(&event->u.addr, buffer), ifname);
      break;
    /* case IWEVASSOCREQIE: No need to handle this event, handle via
     * IWEVCUSTOM instead */
    case IWEVCUSTOM:
        {
            char custom[IW_CUSTOM_MAX+1];
            struct sockaddr * sap;
	    int countMac;	
            if(event->u.data.length == 0){
                printf("length is 0");
                return 0;
            }
            if(event->u.data.pointer == NULL){
                printf("pointer is NULL");
                return 0;
            }

            memset(custom, '\0', sizeof(custom));
            if ((event->u.data.pointer) && (event->u.data.length))
            {
                memcpy(custom, event->u.data.pointer, event->u.data.length);
                custom[event->u.data.length] = '\0';
            }

            debug(LOG_NOTICE, "event->u.data.flags = %d \n",event->u.data.flags);

            switch(event->u.data.flags)
            {
#if 0 /* Commenting out for now, as the IWEVEXPIRED event will handle
       * the disassoc event */
		/* case IWEVCUST_STA_DEAUTHENTICATED: */
		/* case IWEVCUST_STA_DISASSOCIATED: */
	        case IEEE80211_EV_DISASSOC_IND_AP:
	        case IEEE80211_EV_DEAUTH_IND_AP:
		{
			disassoc_Trap disassoc_ctrl_list;
			struct custom_event_data *event_data;

			memset(&disassoc_ctrl_list, 0, sizeof(disassoc_ctrl_list));
                        event_data = (struct custom_event_data *)custom;

			COPY_MACADDRESS(event_data->addr, disassoc_ctrl_list.disassocMacAddr, countMac);
			disassoc_ctrl_list.disassocReason = event_data->reason;
			strncpy(disassoc_ctrl_list.disassocSsid, event_data->xinfo.ssid, event_data->xinfo.ssidlen);
			disassoc_ctrl_list.disassocSsid[event_data->xinfo.ssidlen] = '\0';

            /*wd_PostEventToCloud(ether_sprintf(event_data->addr), ifname, &disassoc_ctrl_list);*/
		}
		break;
#endif
	        case IEEE80211_EV_AUTH_IND_AP:
		{
		    struct ev_msg *msg = (struct ev_msg *) custom;
		    iw_ether_ntop((struct ether_addr *)msg->addr, buffer);
		    notify_client_connect(buffer, ifname);
		    break;
		}
		default:
			break;
	    }
	}		//Switch CUSTOM Event
	break;		
    default:
      break;
    }	/* switch(event->cmd) */

  return(0);
}

/*------------------------------------------------------------------*/
/*
 * Print out all Wireless Events part of the RTNetlink message
 * Most often, there will be only one event per message, but
 * just make sure we read everything...
 */
static inline int
print_event_stream(int		ifindex,
		   char *	data,
		   int		len)
{
  struct iw_event	iwe;
  struct stream_descr	stream;
  int			i = 0;
  int			ret;
  char			buffer[64];
  struct timeval	recv_time;
  struct timezone	tz;
  struct wireless_iface *	wireless_data;

  /* Get data from cache */
  wireless_data = iw_get_interface_data(ifindex);
  if(wireless_data == NULL)
    return(-1);
  iw_init_event_stream(&stream, data, len);
  do
    {
      /* Extract an event and print it */
      ret = iw_extract_event_stream(&stream, &iwe,
				    wireless_data->range.we_version_compiled);
      if(ret != 0)
	{
	  if(ret > 0)
	    print_event_token(&iwe,
			      &wireless_data->range, wireless_data->has_range, wireless_data->ifname);
	}
    }
  while(ret > 0);

  return(0);
}

/*********************** RTNETLINK EVENT DUMP***********************/
/*
 * Dump the events we receive from rtnetlink
 * This code is mostly from Casey
 */

/*------------------------------------------------------------------*/
/*
 * Respond to a single RTM_NEWLINK event from the rtnetlink socket.
 */
static int
LinkCatcher(struct nlmsghdr *nlh)
{
  struct ifinfomsg* ifi;
#if 0
  int bridge_socket = -1;
#define MAX_PORTS 16
  int ifindices[MAX_PORTS];
  unsigned long args[4] = {BRCTL_GET_PORT_LIST, (unsigned long)ifindices, MAX_PORTS, 0};
  struct ifreq ifr;
  int i;
#endif

#if 0
  fprintf(stderr, "nlmsg_type = %d.\n", nlh->nlmsg_type);
#endif

  ifi = NLMSG_DATA(nlh);
#if 0
  bridge_socket = socket(AF_INET, SOCK_STREAM, 0);
  if(bridge_socket == -1) {
    return 0;
  }	

  memset(ifindices, 0, sizeof(ifindices));
  strcpy(ifr.ifr_name, bridge);
  ifr.ifr_data = (char *) &args;

  if (ioctl(bridge_socket, SIOCDEVPRIVATE, &ifr) < 0) {
    return 0;
  }

  for (i = 0; i < MAX_PORTS; i++) {
    if(ifindices[i] == ifi->ifi_index) {
      break;
    }
  }
  if (i == MAX_PORTS)
	  return;
#endif
  /* Code is ugly, but sort of works - Jean II */

  /* If interface is getting destoyed */
  if(nlh->nlmsg_type == RTM_DELLINK)
    {
      /* Remove from cache (if in cache) */
      iw_del_interface_data(ifi->ifi_index);
      return 0;
    }

  /* Only keep add/change events */
  if(nlh->nlmsg_type != RTM_NEWLINK)
    return 0;

  /* Check for attributes */
  if (nlh->nlmsg_len > NLMSG_ALIGN(sizeof(struct ifinfomsg)))
    {
      int attrlen = nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct ifinfomsg));
      struct rtattr *attr = (void *) ((char *) ifi +
				      NLMSG_ALIGN(sizeof(struct ifinfomsg)));

      while (RTA_OK(attr, attrlen))
	{
	  /* Check if the Wireless kind */
	  if(attr->rta_type == IFLA_WIRELESS)
	    {
	      /* Go to display it */
	      print_event_stream(ifi->ifi_index,
				 (char *) attr + RTA_ALIGN(sizeof(struct rtattr)),
				 attr->rta_len - RTA_ALIGN(sizeof(struct rtattr)));
	    }
	  else if(attr->rta_type == IFLA_HTTPREDIR)
	    {
	      void *rtadata;
	      struct http_redir_event *event;
	      struct brreq *brreq;
	      char buf[20];
	      event = (struct http_redir_event *)malloc(sizeof(*event));
	      if(!event){
                  debug(LOG_DEBUG, "Allcation failed (event), returning silently");
	          return 0;		
	      }
	      brreq = (struct brreq *)malloc(sizeof(*brreq));
	      if(!brreq){
                  debug(LOG_DEBUG, "Allcation failed (brreq), returning silently");
	          return 0;		
	      }			
	      rtadata = RTA_DATA(attr);
	      memcpy(event, (struct http_redir_event *) rtadata, sizeof(struct http_redir_event));
	      memcpy(brreq, (struct brreq *)&event->u, sizeof(struct brreq));
	      iw_ether_ntop(brreq->mac, buf);
	      sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
		  brreq->mac[0], brreq->mac[1],
		  brreq->mac[2], brreq->mac[3],
		  brreq->mac[4], brreq->mac[5]);
	      if(!brreq->cpauthstatus){	
		debug(LOG_NOTICE, "adding route for %s ",buf);
		   notify_add_route(brreq, buf);
	      }else{	
		debug(LOG_NOTICE, "Captive Portal authstatus %d for %s ", brreq->cpauthstatus,buf);
		   notify_mark_cpauthstatus(brreq, buf);
	      }
	      free(event);
	      free(brreq);	
	    }		
	  attr = RTA_NEXT(attr, attrlen);
	}
    }

  return 0;
}

/* ---------------------------------------------------------------- */
/*
 * We must watch the rtnelink socket for events.
 * This routine handles those events (i.e., call this when rth.fd
 * is ready to read).
 */
static inline void
handle_netlink_events(struct rtnl_handle *	rth)
{
  while(1)
    {
      struct sockaddr_nl sanl;
      socklen_t sanllen = sizeof(struct sockaddr_nl);

      struct nlmsghdr *h;
      int amt;
      char buf[8192];

      amt = recvfrom(rth->fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*)&sanl, &sanllen);
      if(amt < 0)
	{
	  if(errno != EINTR && errno != EAGAIN)
	    {
	      fprintf(stderr, "%s: error reading netlink: %s.\n",
		      __PRETTY_FUNCTION__, strerror(errno));
	    }
	  return;
	}

      if(amt == 0)
	{
	  fprintf(stderr, "%s: EOF on netlink??\n", __PRETTY_FUNCTION__);
	  return;
	}

      h = (struct nlmsghdr*)buf;
      while(amt >= (int)sizeof(*h))
	{
	  int len = h->nlmsg_len;
	  int l = len - sizeof(*h);

	  if(l < 0 || len > amt)
	    {
	      fprintf(stderr, "%s: malformed netlink message: len=%d\n", __PRETTY_FUNCTION__, len);
	      break;
	    }

	  switch(h->nlmsg_type)
	    {
	    case RTM_NEWLINK:
	    case RTM_DELLINK:
	      LinkCatcher(h);
	      break;
	    default:
#if 0
	      fprintf(stderr, "%s: got nlmsg of type %#x.\n", __PRETTY_FUNCTION__, h->nlmsg_type);
#endif
	      break;
	    }

	  len = NLMSG_ALIGN(len);
	  amt -= len;
	  h = (struct nlmsghdr*)((char*)h + len);
	}

      if(amt > 0)
	fprintf(stderr, "%s: remnant of size %d on netlink\n", __PRETTY_FUNCTION__, amt);
    }
}

/**************************** MAIN LOOP ****************************/

/* ---------------------------------------------------------------- */
/*
 * Wait until we get an event
 */
static inline int
wait_for_event(struct rtnl_handle *rth)
{
#if 0
  struct timeval	tv;	/* Select timeout */
#endif

  /* Forever */
  while(1)
    {
      fd_set		rfds;		/* File descriptors for select */
      int		last_fd;	/* Last fd */
      int		ret;

      /* Guess what ? We must re-generate rfds each time */
      FD_ZERO(&rfds);
      FD_SET(rth->fd, &rfds);
      last_fd = rth->fd;

      /* Wait until something happens */
      ret = select(last_fd + 1, &rfds, NULL, NULL, NULL);

      /* Check if there was an error */
      if(ret < 0)
	{
	  if(errno == EAGAIN || errno == EINTR)
	    continue;
	  fprintf(stderr, "Unhandled signal - exiting...\n");
	  break;
	}

      /* Check if there was a timeout */
      if(ret == 0)
	{
	  continue;
	}

      /* Check for interface discovery events. */
      if(FD_ISSET(rth->fd, &rfds))
	handle_netlink_events(rth);
    }

  return(0);
}

/******************************* MAIN *******************************/

int thread_wireless_event(char *gw_interface)
{
  struct rtnl_handle	rth;
  int opt;

  /* Open netlink channel */
  if(rtnl_open(&rth, RTMGRP_LINK) < 0)
    {
      perror("Can't initialize rtnetlink socket");
      return(1);
    }

//  strncpy(bridge, gw_interface, IFNAMSIZ);

  /* Do what we have to do */
  wait_for_event(&rth);

  /* Cleanup - only if you are pedantic */
  rtnl_close(&rth);

  return(0);
}
