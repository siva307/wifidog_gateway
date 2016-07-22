/*
 * br_event.h
 *
 * Copyright (c) Arada Systems, 1996-2007
 *
 */


struct	brreq
{
	char	dev[IFNAMSIZ];
	struct iphdr iph;
	unsigned char mac[ETH_ALEN];
	unsigned char cpauthstatus;
	char	ifname[IFNAMSIZ];
};	

struct http_redir_event
{
	__u16		len;			/* Real lenght of this stuff */
	struct brreq	u;		/* Http Redirect Payload */
};
