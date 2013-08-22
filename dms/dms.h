#ifndef _DMS_H
#define	_DMS_H

#include <sys/types.h>

#define MAX_LISTEN_QUEUE	5
#define MINBUFSIZE		4096
#define MAX_SAMPLES		256

#include "dm.h"

struct dmjob {
	int		 ofd;
	int	 	 client;
	int		 sigint;
	int	 	 sigalrm;
	int	 	 siginfo;
	int	 	 siginfo_en;
	unsigned	 timeout;
	int		 preempted;

	enum {
		RUNNING = 0,
		DONE,
		DUPLICATE
	} state;

	pthread_t	 worker;
	struct dmreq 	*request;
	struct url	*url;
	struct dmmirr	*mirror;
	struct xferstat	 oldstat;

	struct dmjob 	*next;
	struct dmjob	*prev;
};

struct dmrep {
	int 	 status;
	int 	 errcode;
	char 	*errstr;
};

struct dmmirr {
	char		name[512];
	int		index;

	enum {
		NOT_TRIED = 0,
		ACTIVE,
		FAILED
	} remark;

	struct timeval	timestamps[MAX_SAMPLES];
	double		samples[MAX_SAMPLES];
	int		nconns;

	struct dmmirr 	*next;
	struct dmmirr	*prev;
};

#define DEBUG			1

#endif
