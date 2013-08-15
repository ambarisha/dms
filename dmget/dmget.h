#ifndef _DMCLIENT_H
#define _DMCLIENT_H

#include <sys/param.h>
#include <sys/time.h>

#include <stdio.h>

#include "dm.h"

#define AUTH_USERLEN 256
#define AUTH_PWDLEN 256


struct dmauth {
	int	 port;
	char 	*scheme;
	char	*host;
	char	 user[AUTH_USERLEN+1];
	char	 pwd[AUTH_PWDLEN+1];
};

extern int		 dmLastErrCode;
extern int		 dmRestartCalls;
extern char 		 dmLastErrString[];

typedef int (*dm_auth_t)(struct dmauth *);
extern dm_auth_t		 dmAuthMethod;
typedef void (*stat_display_t) (struct xferstat *, int);
extern stat_display_t	 dmStatDisplayMethod;

int dmget(struct dmreq);
void dmSigHandler(int sig);

#endif /* _DMCLIENT_H */
