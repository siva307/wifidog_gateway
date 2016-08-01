/* vim: set et sw=4 ts=4 sts=4 : */
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
/** @file http.c
  @brief HTTP IO functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire
  @author Copyright (C) 2007 David Bird <david@coova.com>

 */
/* Note that libcs other than GLIBC also use this macro to enable vasprintf */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/types.h>        /* for "caddr_t" et al      */
#include <net/if.h>
#include <netinet/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include "httpd.h"

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "auth.h"
#include "firewall.h"
#include "http.h"
#include "client_list.h"
#include "common.h"
#include "centralserver.h"
#include "util.h"
#include "wd_util.h"
#include "br_event.h"
#include "fw_iptables.h"

#include "../config.h"

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <sys/time.h>
#include <sys/un.h>

#define IS_NULL(x)  ((x) ? (x) : "<NULL>")

extern pthread_mutex_t  client_list_mutex;

typedef struct __t_redir_node {
    struct __t_redir_node *next;
    char *mac;
    char redir_pending;
    char route_added;
    char dev[IFNAMSIZ];
    char host_ip[32];
    char dev_ip[32];
    time_t expiry;
    int ifindex;
    int wlindex;
    unsigned char cpAuthstatus;
} t_redir_node;

t_redir_node *first_redir_node = NULL;
//int redir_pending = 0;
pthread_mutex_t redir_mutex = PTHREAD_MUTEX_INITIALIZER;

#define LOCK_REDIR() do { \
            pthread_mutex_lock(&redir_mutex); \
} while (0)

#define UNLOCK_REDIR() do { \
            pthread_mutex_unlock(&redir_mutex); \
} while (0)

#define TRYLOCK_REDIR() pthread_mutex_trylock(&redir_mutex) 
#define MAX_HOSTNAME_RESOLVE_TIMEOUT 300

static struct cphostname_resolver{
        int index;
        time_t timestamp;
}timekeeper[16];

t_redir_node *
redir_list_find(char *mac)
{
    t_redir_node *ptr;

    ptr = first_redir_node;
    while (NULL != ptr) {
        if (!strcasecmp(ptr->mac, mac))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

time_t wd_get_redirect_timestamp(unsigned char *mac)
{
	time_t assoctime;
	t_redir_node *node;

	LOCK_REDIR();
	node = redir_list_find(mac);
	if(node){
		assoctime = node->expiry;	
	}else{
		assoctime = time(NULL);
	}
	UNLOCK_REDIR(); 
	return assoctime;
}

unsigned char wd_get_redirect_cpauthstatus(unsigned char *mac)
{
	t_redir_node *node;
	unsigned char status;

	LOCK_REDIR();
	node = redir_list_find(mac);
	if(node){
		status = node->cpAuthstatus;	
	}else{
		status = 2;
	}
	UNLOCK_REDIR();
	return status;
}

t_redir_node *redir_list_append(char *mac)
{
    t_redir_node *curnode, *prevnode;
    prevnode = NULL;
    curnode = first_redir_node;

    while (curnode != NULL) {
        prevnode = curnode;
        curnode = curnode->next;
    }

    curnode = malloc(sizeof(t_redir_node));
    if (curnode == NULL)
        return NULL;
    memset(curnode, 0, sizeof(t_redir_node));
    curnode->mac = strdup(mac);
    curnode->ifindex = 20;
    curnode->cpAuthstatus = 1;
    if (prevnode == NULL) {
        first_redir_node = curnode;
    } else {
        prevnode->next = curnode;
    }

    return curnode;
}

void
free_redir_node(t_redir_node *node)
{

    if (node->mac != NULL)
	free(node->mac);

    free(node);
}



void
redir_list_delete(t_redir_node *node)
{
    t_redir_node *ptr;

    ptr = first_redir_node;

    if (ptr == NULL) {
        debug(LOG_ERR, "Node list empty!");
    } else if (ptr == node) {
        first_redir_node = ptr->next;
        free_redir_node(node);
    } else {
        /* Loop forward until we reach our point in the list. */
        while (ptr->next != NULL && ptr->next != node) {
            ptr = ptr->next;
        }
        /* If we reach the end before finding out element, complain. */
        if (ptr->next == NULL) {
            debug(LOG_ERR, "Node to delete could not be found.");
        /* Free element. */
        } else {
            ptr->next = node->next;
            free_redir_node(node);
        }
    }
}

void notify_add_route(struct brreq *brreq, char *mac)
{
    t_client *client;
    t_redir_node *node;

    LOCK_REDIR();

    node = redir_list_find(mac);
    if (!node) {
        debug(LOG_NOTICE, "%s: %s node not present, creating it with src interface %s\n",__func__,mac, brreq->ifname);
        node = redir_list_append(mac);
        if(node){
            node->expiry = time(NULL);
            fw_mark_mangle(mac,1);
        }
    }
    if (!node) {
        UNLOCK_REDIR();
        return;
    }

    node->ifindex = get_ifIndex(brreq->ifname);
    node->redir_pending = 1;

    //  if (!node->redir_pending) {
    {
        struct in_addr src_ip;
        char cmd[256];
        char *tmp_ptr;
        /* Get the Host IP address */
        src_ip.s_addr = brreq->iph.saddr;
        memset(node->host_ip, 0, sizeof(node->host_ip));
        tmp_ptr = inet_ntoa(src_ip);
        if (tmp_ptr)
            strcpy(node->host_ip, tmp_ptr);
        /* Copy the device name to node */
        strcpy(node->dev, brreq->dev);
        /* Get the interface IP address */
        memset(node->dev_ip, 0, sizeof(node->dev_ip));
        tmp_ptr = get_iface_ip(node->dev);
        if (tmp_ptr)
            strcpy(node->dev_ip, tmp_ptr);
        /* Set the host route */
        memset(cmd, 0, sizeof(cmd));
        sprintf(cmd, "/sbin/ip route add %s/32 src %s dev %s", node->host_ip, node->dev_ip, node->dev);
        //printf("\nexecuting %s\n", cmd);
        execute(cmd, 0);
        node->route_added = 1;
        free(tmp_ptr);
    }
    UNLOCK_REDIR();
}

void notify_mark_cpauthstatus(struct brreq *brreq, char *mac)
{
    t_redir_node *node;

    LOCK_REDIR();
    node = redir_list_find(mac);
    if(!node){
        UNLOCK_REDIR();
        return;
    }
    node->cpAuthstatus = (brreq->cpauthstatus == 1)? 1 : 0;
    debug(LOG_ERR, "**************cpauthstatus = %d*************",node->cpAuthstatus);
    UNLOCK_REDIR();
}
int get_ifIndex(char *ifname){

    if(!ifname)
        return 0;                      /* Safe to return atleast a valid value */
    else if(!strcmp(ifname, "wifi0vap0"))
        return 0;
    else if(!strcmp(ifname, "wifi0vap1"))
        return 1;
    else if(!strcmp(ifname, "wifi0vap2"))
        return 2;
    else if(!strcmp(ifname, "wifi0vap3"))
        return 3;
    else if(!strcmp(ifname, "wifi1vap0"))
        return 4;
    else if(!strcmp(ifname, "wifi1vap1"))
        return 5;
    else if(!strcmp(ifname, "wifi1vap2"))
        return 6;
    else if(!strcmp(ifname, "wifi1vap3"))
        return 7;
    else
        return 0 ;
}
void make_proc_entry_for_url(char *hoststr, int ifIndex)
{
        struct hostent *he = NULL;
        struct in_addr **addr_list = NULL;
        char cmd[100] = {'\0'};
        int i = 0;
        char *host , *tmp;
        host = tmp = safe_strdup(hoststr);
        /* Get host name only*/
        if(strstr(host, "http://"))
                host = host + 7;
        else if(strstr(host, "https://"))
                host = host + 8;
        while(host[i]) {
                if ((host[i] == '/') || (host[i] ==':')) {
                        host[i] = '\0';
                        break;
                }
                i++;
        }
        debug(LOG_NOTICE,"Getting addresses for host %s", host);
        if ( (he = gethostbyname(host) ) == NULL) {
        free(tmp);
                return;
        }
        addr_list = (struct in_addr **) he->h_addr_list;
        for(i = 0; addr_list[i] != NULL; i++) {
                sprintf(cmd, "echo \"%u\" > /proc/sys/net/bridge/bridge-http-redirect-add-ip", htonl(addr_list[i]->s_addr));
                debug(LOG_NOTICE,"Adding host %s with ip %s",host,inet_ntoa(*addr_list[i]));
                system(cmd);
        }
    free(tmp);
}

void notify_client_connect(char *mac, char *ifname)
{
    t_client *client;
    t_redir_node *node;
    s_config *config = config_get_config();
    int ifIndex = get_ifIndex(ifname);

    if( !config->status[ifIndex] ) {
        debug(LOG_NOTICE, "Captive Portal is not enabled for %s", ifname);
        return;
    }
    LOCK_REDIR();
    //  config_cp_auth_status(ifname, mac, 1); /* Updating the cpAuthStatus to 1 */
    node = redir_list_find(mac);
    if (!node) {
        node = redir_list_append(mac);
    }
    if (!node) {
        UNLOCK_REDIR();
        return;
    }
    debug(LOG_NOTICE,"%s recv'd association req from mac %s  %p\n",__func__,mac, node);
    
    /*post_event(ifname, mac, 1 << 0); *//* BIT0 is set which is a session query notification */
    node->ifindex = ifIndex;
    node->wlindex = config->profile[ifIndex];
    if (ifname) strncpy(node->dev, ifname, sizeof(node->dev));
    node->cpAuthstatus = 1;
    node->expiry = time(NULL);

    if (!node->redir_pending) {
        char command[100];
        char fmac[13];
        formatmacaddr(mac, &fmac);
        node->redir_pending = 1;
        snprintf(command,100,"echo %s > /proc/sys/net/bridge/bridge-http-redirect-add-mac",fmac);
        //      printf("%s",command);
        execute(command,0);
        fw_mark_mangle(mac,1);
    }
    if(config->operate_mode){
        if((time(NULL) - timekeeper[0].timestamp) > MAX_HOSTNAME_RESOLVE_TIMEOUT){
            make_proc_entry_for_url(config->portal[0], 0);
            timekeeper[0].timestamp = time(NULL);
        }
    }else{
        if((time(NULL) - timekeeper[ifIndex].timestamp) > MAX_HOSTNAME_RESOLVE_TIMEOUT){
            make_proc_entry_for_url(config->portal[ifIndex], ifIndex);
            timekeeper[ifIndex].timestamp = time(NULL);
        }
    }
    timekeeper[ifIndex].timestamp = time(NULL);

    UNLOCK_REDIR();

    LOCK_CLIENT_LIST();

    client = client_list_find_by_mac(mac);
    if (client) {
        /*fw_deny_raw(client->ip, client->mac, client->fw_connection_state);      *//*PRATIK: Commented so that it doesn't invoke the firewall*/
    iptables_fw_access(FW_ACCESS_DENY, client->ip, client->mac, client->fw_connection_state);    
    client_list_delete(client);
    }

    UNLOCK_CLIENT_LIST();
}
void notify_client_disconnect(char *mac, char *ifname)
{
    t_client *client;
    t_redir_node *node;
    int ifIndex = get_ifIndex(ifname);
    //     printf("Client Disconnected\n");
    LOCK_REDIR();

    node = redir_list_find(mac);

    if(node)
        if(node->ifindex != ifIndex)
            debug(LOG_NOTICE,"%s: %s connected to idx %d, recv'd disconnect evt from idx %d\n",__func__, mac, node->ifindex, ifIndex);

    if (node && (node->ifindex == ifIndex)) {
        if (node->redir_pending) {
            char command[100];
            char fmac[13];
            formatmacaddr(mac, &fmac);
            node->redir_pending = 0;
            debug(LOG_NOTICE,"%s: recv'd disconnect evt for %s from idx %d\n",__func__, mac, node->ifindex);
            snprintf(command,100,"echo %s > /proc/sys/net/bridge/bridge-http-redirect-del-mac",fmac);
            //      printf("%s",command);
            execute(command,0);
            if (node->route_added) {
                memset(command, 0, sizeof(command));
                sprintf(command, "/bin/ip route del %s/32 src %s dev %s", node->host_ip, node->dev_ip, node->dev);
                //printf("\nexecuting %s\n", command);
                execute(command, 0);
            }
            fw_mark_mangle(mac,0);
        }
        debug(LOG_NOTICE,"%s: removing node list for %s from idx %d\n",__func__, mac, node->ifindex);
        redir_list_delete(node);
    }

    UNLOCK_REDIR();

    LOCK_CLIENT_LIST();
    client = client_list_find_by_mac(mac);
    if (client) {
        /*fw_deny_raw(client->ip, client->mac, client->fw_connection_state);*/
        iptables_fw_access(FW_ACCESS_DENY, client->ip, client->mac, client->fw_connection_state);
        client_list_delete(client);
    }
    UNLOCK_CLIENT_LIST();
}

/** The 404 handler is also responsible for redirecting to the auth server */
void
http_callback_404(httpd * webserver, request * r, int error_code)
{
    char tmp_url[MAX_BUF], *url, *mac;
    int index = 0;
    t_redir_node *node;
    s_config *config = config_get_config();
    t_auth_serv *auth_server = get_auth_server();

    memset(tmp_url, 0, sizeof(tmp_url));
    /* 
     * XXX Note the code below assumes that the client's request is a plain
     * http request to a standard port. At any rate, this handler is called only
     * if the internet/auth server is down so it's not a huge loss, but still.
     */
    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
             r->request.host, r->request.path, r->request.query[0] ? "?" : "", r->request.query);
    url = httpdUrlEncode(tmp_url);

    if (!is_online()) {
        /* The internet connection is down at the moment  - apologize and do not redirect anywhere */
        char *buf;
        safe_asprintf(&buf,
                      "<p>We apologize, but it seems that the internet connection that powers this hotspot is temporarily unavailable.</p>"
                      "<p>If at all possible, please notify the owners of this hotspot that the internet connection is out of service.</p>"
                      "<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>"
                      "<p>In a while please <a href='%s'>click here</a> to try your request again.</p>", tmp_url);

        send_http_page(r, "Uh oh! Internet access unavailable!", buf);
        free(buf);
        debug(LOG_INFO, "Sent %s an apology since I am not online - no point sending them to auth server",
              r->clientAddr);
    } else if (!is_auth_online()) {
        /* The auth server is down at the moment - apologize and do not redirect anywhere */
        char *buf;
        safe_asprintf(&buf,
                      "<p>We apologize, but it seems that we are currently unable to re-direct you to the login screen.</p>"
                      "<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>"
                      "<p>In a couple of minutes please <a href='%s'>click here</a> to try your request again.</p>",
                      tmp_url);

        send_http_page(r, "Uh oh! Login screen unavailable!", buf);
        free(buf);
        debug(LOG_INFO, "Sent %s an apology since auth server not online - no point sending them to auth server",
              r->clientAddr);
    } else {
        /* Re-direct them to auth server */
        char *urlFragment;

        if (!(mac = arp_get(r->clientAddr))) {
            /* We could not get their MAC address */
            debug(LOG_INFO, "Failed to retrieve MAC address for ip %s, so not putting in the login request",
                  r->clientAddr);
            safe_asprintf(&urlFragment, "%sgw_address=%s&gw_port=%d&gw_id=%s&ip=%s&url=%s",
                          auth_server->authserv_login_script_path_fragment, config->gw_address, config->gw_port,
                          config->gw_id, r->clientAddr, url);
        } else {
            debug(LOG_INFO, "Got client MAC address for ip %s: %s", r->clientAddr, mac);	
	    node = redir_list_find(mac);
	    if (node) {
		index = node->wlindex; 
	    }
            safe_asprintf(&urlFragment, "%sgw_address=%s&gw_port=%d&gw_id=%s&ip=%s&mac=%s&url=%s&wlanindex=%d",
                          auth_server->authserv_login_script_path_fragment,
                          config->gw_address, config->gw_port, config->gw_id, r->clientAddr, mac, url, index);
            free(mac);
        }

        // if host is not in whitelist, maybe not in conf or domain'IP changed, it will go to here.
        debug(LOG_INFO, "Check host %s is in whitelist or not", r->request.host);       // e.g. www.example.com
        t_firewall_rule *rule;
        //e.g. example.com is in whitelist
        // if request http://www.example.com/, it's not equal example.com.
        for (rule = get_ruleset("global"); rule != NULL; rule = rule->next) {
            debug(LOG_INFO, "rule mask %s", rule->mask);
            if (strstr(r->request.host, rule->mask) == NULL) {
                debug(LOG_INFO, "host %s is not in %s, continue", r->request.host, rule->mask);
                continue;
            }
            int host_length = strlen(r->request.host);
            int mask_length = strlen(rule->mask);
            if (host_length != mask_length) {
                char prefix[1024] = { 0 };
                // must be *.example.com, if not have ".", maybe Phishing. e.g. phishingexample.com
                strncpy(prefix, r->request.host, host_length - mask_length - 1);        // e.g. www
                strcat(prefix, ".");    // www.
                strcat(prefix, rule->mask);     // www.example.com
                if (strcasecmp(r->request.host, prefix) == 0) {
                    debug(LOG_INFO, "allow subdomain");
                    fw_allow_host(r->request.host);
                    http_send_redirect(r, tmp_url, "allow subdomain");
                    free(url);
                    free(urlFragment);
                    return;
                }
            } else {
                // e.g. "example.com" is in conf, so it had been parse to IP and added into "iptables allow" when wifidog start. but then its' A record(IP) changed, it will go to here.
                debug(LOG_INFO, "allow domain again, because IP changed");
                fw_allow_host(r->request.host);
                http_send_redirect(r, tmp_url, "allow domain");
                free(url);
                free(urlFragment);
                return;
            }
        }

        debug(LOG_INFO, "Captured %s requesting [%s] and re-directing them to login page", r->clientAddr, url);
        http_send_redirect_to_auth(r, urlFragment, "Redirect to login page");
        free(urlFragment);
    }
    free(url);
}

void
http_callback_wifidog(httpd * webserver, request * r)
{
    send_http_page(r, "WiFiDog", "Please use the menu to navigate the features of this WiFiDog installation.");
}

void
http_callback_about(httpd * webserver, request * r)
{
    send_http_page(r, "About WiFiDog", "This is WiFiDog version <strong>" VERSION "</strong>");
}

void
http_callback_status(httpd * webserver, request * r)
{
    const s_config *config = config_get_config();
    char *status = NULL;
    char *buf;

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Status page requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    status = get_status_text();
    safe_asprintf(&buf, "<pre>%s</pre>", status);
    send_http_page(r, "WiFiDog Status", buf);
    free(buf);
    free(status);
}

/** @brief Convenience function to redirect the web browser to the auth server
 * @param r The request
 * @param urlFragment The end of the auth server URL to redirect to (the part after path)
 * @param text The text to include in the redirect header ant the mnual redirect title */
void
http_send_redirect_to_auth(request * r, const char *urlFragment, const char *text)
{
    char *protocol = NULL;
    int port = 80;
    t_auth_serv *auth_server = get_auth_server();

    if (auth_server->authserv_use_ssl) {
        protocol = "https";
        port = auth_server->authserv_ssl_port;
    } else {
        protocol = "http";
        port = auth_server->authserv_http_port;
    }

    char *url = NULL;
    safe_asprintf(&url, "%s://%s:%d%s%s",
                  protocol, auth_server->authserv_hostname, port, auth_server->authserv_path, urlFragment);
    http_send_redirect(r, url, text);
    free(url);
}

/** @brief Sends a redirect to the web browser 
 * @param r The request
 * @param url The url to redirect to
 * @param text The text to include in the redirect header and the manual redirect link title.  NULL is acceptable */
void
http_send_redirect(request * r, const char *url, const char *text)
{
    char *message = NULL;
    char *header = NULL;
    char *response = NULL;
    /* Re-direct them to auth server */
    debug(LOG_DEBUG, "Redirecting client browser to %s", url);
    safe_asprintf(&header, "Location: %s", url);
    safe_asprintf(&response, "302 %s\n", text ? text : "Redirecting");
    httpdSetResponse(r, response);
    httpdAddHeader(r, header);
    free(response);
    free(header);
    safe_asprintf(&message, "Please <a href='%s'>click here</a>.", url);
    send_http_page(r, text ? text : "Redirection to message", message);
    free(message);
}

void
http_callback_auth(httpd * webserver, request * r)
{
    t_client *client;
    httpVar *token;
    char *mac;
    httpVar *logout = httpdGetVariableByName(r, "logout");

    if ((token = httpdGetVariableByName(r, "token"))) {
        /* They supplied variable "token" */
        if (!(mac = arp_get(r->clientAddr))) {
            /* We could not get their MAC address */
            debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
            send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
        } else {
            /* We have their MAC address */
            LOCK_CLIENT_LIST();

            if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
                debug(LOG_DEBUG, "New client for %s", r->clientAddr);
                client = client_list_add(r->clientAddr, mac, token->value);
		client->fw_connection_state = FW_MARK_REDIR;
            } else if (logout) {
                logout_client(client);
            } else {
                debug(LOG_DEBUG, "Client for %s is already in the client list", client->ip);
            }

            UNLOCK_CLIENT_LIST();
            if (!logout) { /* applies for case 1 and 3 from above if */
                authenticate_client(r);
            }
            free(mac);
        }
    } else {
        /* They did not supply variable "token" */
        send_http_page(r, "WiFiDog error", "Invalid token");
    }
}

void
http_callback_disconnect(httpd * webserver, request * r)
{
    const s_config *config = config_get_config();
    /* XXX How do you change the status code for the response?? */
    httpVar *token = httpdGetVariableByName(r, "token");
    httpVar *mac = httpdGetVariableByName(r, "mac");

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Disconnect requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    if (token && mac) {
        t_client *client;

        LOCK_CLIENT_LIST();
        client = client_list_find_by_mac(mac->value);

        if (!client || strcmp(client->token, token->value)) {
            UNLOCK_CLIENT_LIST();
            debug(LOG_INFO, "Disconnect %s with incorrect token %s", mac->value, token->value);
            httpdOutput(r, "Invalid token for MAC");
            return;
        }

        /* TODO: get current firewall counters */
        logout_client(client);
        UNLOCK_CLIENT_LIST();

    } else {
        debug(LOG_INFO, "Disconnect called without both token and MAC given");
        httpdOutput(r, "Both the token and MAC need to be specified");
        return;
    }

    return;
}

void
send_http_page(request * r, const char *title, const char *message)
{
    s_config *config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;

    fd = open(config->htmlmsgfile, O_RDONLY);
    if (fd == -1) {
        debug(LOG_CRIT, "Failed to open HTML message file %s: %s", config->htmlmsgfile, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info) == -1) {
        debug(LOG_CRIT, "Failed to stat HTML message file: %s", strerror(errno));
        close(fd);
        return;
    }
    // Cast from long to unsigned int
    buffer = (char *)safe_malloc((size_t) stat_info.st_size + 1);
    written = read(fd, buffer, (size_t) stat_info.st_size);
    if (written == -1) {
        debug(LOG_CRIT, "Failed to read HTML message file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);

    buffer[written] = 0;
    httpdAddVariable(r, "title", title);
    httpdAddVariable(r, "message", message);
    httpdAddVariable(r, "nodeID", config->gw_id);
    httpdOutput(r, buffer);
    free(buffer);
}
