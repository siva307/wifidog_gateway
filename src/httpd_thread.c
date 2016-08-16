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

/** @file httpd_thread.c
    @brief Handles on web request.
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#define HAVE_SSL 1

#include "httpd.h"
#include "ssl.h"
#include "../config.h"
#include "common.h"
#include "debug.h"
#include "httpd_thread.h"




int nsec_redirect_window(unsigned char *mac)
{
#define NSEC_REDIR_WINDOW 6
	time_t timestamp;
	unsigned char cpAuthstatus;
	
	if(!mac)
		return 2;
	timestamp = wd_get_redirect_timestamp(mac);

	debug(LOG_DEBUG, "assocstamp = %lu for sta %s",(time(NULL) - timestamp),mac);
	while((time(NULL) - timestamp) <= NSEC_REDIR_WINDOW){
		cpAuthstatus = wd_get_redirect_cpauthstatus(mac);
                if(cpAuthstatus == 0){
                        return cpAuthstatus;
                }
                sleep(1);
	}
	cpAuthstatus = wd_get_redirect_cpauthstatus(mac);
	debug(LOG_DEBUG, "cpauthstatus = %d for sta %s",cpAuthstatus,mac);
	if(mac)
		free(mac);

	return cpAuthstatus;
}

int handleHttpsRequest(httpd * server, request * r)
{
    /* Hardcode to google.com */
    strcpy(r->request.host,"google.com");
    strcpy(r->request.path,"/");
    r->request.query[0] = '\0';

    http_callback_404(server, r, 0);
}

int httpsReadRequest(httpd * server, request * r)
{
    openssl_con *sslcon;
    char buffer[HTTP_MAX_LEN];
    int ret;

    sslcon = openssl_accept_fd(initssl(), r->clientSock, 10, NULL);
    if (sslcon == NULL) {
	debug(LOG_INFO, "openssl_accept_fd() returned shutdown");
	return (-1);
    }

    r->ssl_conn = (void *) sslcon;

    ret = openssl_read(sslcon, buffer, HTTP_MAX_LEN-1, 1);
    if (ret < 1) {
	debug (LOG_ERR, "SSL read failed, ret = %d", ret);
	return ret;
    }
    buffer[ret] = '\0';

    handleHttpsRequest(buffer, r);

    close(r->clientSock);
    if (sslcon) {
        openssl_shutdown(sslcon, 2);
        openssl_free(sslcon);
        sslcon = NULL;
	r->ssl_conn = NULL;
    }
}

/** Main request handling thread.
@param args Two item array of void-cast pointers to the httpd and request struct
*/
void
thread_httpd(void *args)
{
	void	**params;
	httpd	*webserver;
	request	*r;
	int is_ssl;
	
	params = (void **)args;
	webserver = *params;
	r = *(params + 1);
	is_ssl = *(params + 2);
	free(params); /* XXX We must release this ourselves. */
	if(nsec_redirect_window(arp_get(r->clientAddr)) == 2)
	{
		debug(LOG_DEBUG, "Probably error occurred or CpAuthStatus is zero hence closing connection with %s", r->clientAddr);
		httpdEndRequest(r);
		return 0;	
	}

	if (is_ssl) {
	    if (httpsReadRequest(webserver, r) == 0) {
		/*
		 * We read the request fine
		 */
		debug(LOG_DEBUG, "Processing request from %s", r->clientAddr);
		debug(LOG_DEBUG, "Calling httpsProcessRequest() for %s", r->clientAddr);
		httpsProcessRequest(webserver, r);
		debug(LOG_DEBUG, "Returned from httpsProcessRequest() for %s", r->clientAddr);
	    }
	    else {
		debug(LOG_DEBUG, "No valid request received from %s", r->clientAddr);
	    }
	} else {
	    if (httpdReadRequest(webserver, r) == 0) {
		/*
		 * We read the request fine
		 */
		debug(LOG_DEBUG, "Processing request from %s", r->clientAddr);
		debug(LOG_DEBUG, "Calling httpdProcessRequest() for %s", r->clientAddr);
		httpdProcessRequest(webserver, r);
		debug(LOG_DEBUG, "Returned from httpdProcessRequest() for %s", r->clientAddr);
	    }
	    else {
		debug(LOG_DEBUG, "No valid request received from %s", r->clientAddr);
	    }
	}

	debug(LOG_DEBUG, "Closing connection with %s", r->clientAddr);
	httpdEndRequest(r);
}
