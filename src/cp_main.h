#ifndef _CP_MAIN_H
#define _CP_MAIN_H 1

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>	/* for NF_ACCEPT */
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
//#include <lsqlquery/connector.h>
#include <syslog.h>
#include <signal.h>
#include <sys/un.h>
#include "cp_debug.h"
/* #include "capportald.h" */

/*Common Return Value*/
#define SUCCESS 0
#define FAILURE -1

#define TRUE  1
#define FALSE !TRUE

/*daemon PID file*/
#define CPID_FILE "/var/run/captive.pid"
/*port declaration*/

#define DNS_PORT 1000
#define CP_HOSTAPD_SOCK  "/tmp/cpd_hostapd_comm"
#define CP_DMAN_SOCK  "/tmp/cportald_dman_sock"

#ifdef USE_DOT1X
#define DOT1X_PORT 2000
#endif /*USE_DOT1X */

/*HTTP method*/
#define AUTH_TOKEN "authtoke"
#define LANDING_URL "landing_url"
#define SESSION_TIMEOUT "sessiontimout"
#define SOCIAL_URL "url"
#define TIME_INTERVAL "time-interval"
#define LOGIN "/logon"
#define LOGOFF "/logoff"
#define SOCIAL "/social"

#define SOCIAL_CODE 2
#define LOGIN_CODE 1
#define LOGOFF_CODE 0

#define USE_SSL
#define HAVE_SSL 1

#define MAX_VAP_NAME_LEN 11
#define MAX_DOMAIN_NUM   25
#define MAX_DOMAIN_LEN   127

#define REDIR_MAXTIME 120

#define MAX_RETRY 10000

/* These are the names(options) of the 
 * supported clouds for captive-portal.
 * These strings are to be used as it is, 
 * in the commands for setting cloud-provider */
#define CLOUD_NAME_CLOUD4WI		"cloud4wi"
#define CLOUD_NAME_MERU_CONNECT		"meruconnect"
#define CLOUD_NAME_UCOPIA		"ucopia"

typedef enum {
	CLOUD_PROVIDER_START,
	CLOUD_PROVIDER_EXPRESS_CLOUD,
	CLOUD_PROVIDER_MERUCONNECT,
	CLOUD_PROVIDER_UCOPIA_CLOUD,
	CLOUD_PROVIDER_MAX
} cloud_provider;

typedef enum vap_if_index_e
{
  WLAN0 = 0,
  WLAN0VAP1,
  WLAN0VAP2,
  WLAN0VAP3,
  WLAN0VAP4,
  WLAN0VAP5,
  WLAN0VAP6,
  WLAN0VAP7,
  WLAN0VAP8,
  WLAN0VAP9,
  WLAN0VAP10,
  WLAN0VAP11,
  WLAN0VAP12,
  WLAN0VAP13,
  WLAN0VAP14,
  WLAN0VAP15,
  WLAN1,
  WLAN1VAP1,
  WLAN1VAP2,
  WLAN1VAP3,
  WLAN1VAP4,
  WLAN1VAP5,
  WLAN1VAP6,
  WLAN1VAP7,
  WLAN1VAP8,
  WLAN1VAP9,
  WLAN1VAP10,
  WLAN1VAP11,
  WLAN1VAP12,
  WLAN1VAP13,
  WLAN1VAP14,
  WLAN1VAP15,
  VAP_END			/* Should be in the bottom */
} vap_if_index_t;

extern const char gVapWlanMap[VAP_END][MAX_VAP_NAME_LEN];

int _cp_init_socket (int i);
int dns_init (void);
int toggle_ctf (vap_if_index_t if_index, unsigned char enable);

#endif
