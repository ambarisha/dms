#ifndef _DMCLIENT_H
#define _DMCLIENT_H

#include <sys/param.h>
#include <sys/time.h>

#include <stdio.h>
#include <fetch.h>

#include "dm.h"

extern int		 dmLastErrCode;
extern int		 dmRestartCalls;
extern char 		 dmLastErrString[];

typedef int (*auth_t)(struct url *);
extern auth_t		 dmAuthMethod;
typedef void (*stat_display_t) (struct xferstat *, int);
extern stat_display_t	 dmStatDisplayMethod;

int dm_request(struct dmreq);
void dm_sighandler(int sig);

#endif /* _DMCLIENT_H */
