#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>

#include "dm.h"

/* Utils for handling messages */

int
send_dmmsg(int socket, struct dmmsg msg);

struct dmmsg *
recv_dmmsg(int sock);

void
free_dmmsg(struct dmmsg **msg);

long
get_eta(struct xferstat *xs);
