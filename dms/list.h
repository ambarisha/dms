#include <pthread.h>
#include "dms.h"

struct conn {
	struct conn 	*prev;
	struct conn 	*next;
	pthread_t	*worker;
	struct url	*url;
	struct dmjob	*job;
	int 		 client;
	state_t		 state;
};

struct conn *
add_conn(struct conn *head, int client, int worker);

struct conn *
rm_conn(struct conn *head, struct conn *conn);

