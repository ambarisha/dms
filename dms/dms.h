#ifndef _DMS_H
#define	_DMS_H

#include <sys/types.h>

typedef enum {RUNNING=0, DONE, DUPLICATE} state_t;

struct dmjob {
	int		 ofd;
	int	 	 client;
	state_t	 	 state;
	int		 sigint;
	int	 	 sigalrm;
	int	 	 siginfo;
	int	 	 siginfo_en;
	unsigned	 timeout;
	pthread_t	 worker;
	struct dmreq 	*request;
	struct url	*url;

	struct dmjob 	*next;
	struct dmjob	*prev;
};

struct dmrep {
	int 	 status;
	int 	 errcode;
	char 	*errstr;
};

#define DEBUG			1

#define MAX_LISTEN_QUEUE	5
#define MINBUFSIZE		4096

#endif
