#include<stdio.h>
#include<string.h>
#include<stdarg.h>
#include<syslog.h>
#include<stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


/* #define CP_DEBUG */
#ifdef CP_DEBUG
#define DEBUG_LEVEL 7
void cp_error (int level, char *fmt,...)
  __attribute__ ((format (printf, 2, 3)));

#define CP_ERROR cp_error
#else
#define CP_ERROR cp_error_empty
void cp_error_empty (int level, char *fmt,...)
  __attribute__ ((format (printf, 2, 3)));
#endif /*CP_DEBUG */




/* #define CP_DEBUG_INFO */
#ifdef CP_DEBUG_INFO
#define INFO_DEBUG_LEVEL 7
void cp_info (int level, char *fmt,...)
  __attribute__ ((format (printf, 2, 3)));
#define CP_INFO cp_info
#else
#define CP_INFO cp_info_empty
void cp_info_empty (int level, char *fmt,...)
  __attribute__ ((format (printf, 2, 3)));
#endif /*CP_DEBUG_INFO */


#define CP_LOG_FILE
#ifdef CP_LOG_FILE
#define CP_LOG_FILE_NAME "/tmp/captive.dbg"
#endif

void cp_syslog (int level, char *fmt,...)
  __attribute__ ((format (printf, 2, 3)));
