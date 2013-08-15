#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>

#include "dm.h"

/* Utils for handling messages */

int
send_dmmsg(int socket, struct dmmsg msg)
{
	int bufsize = sizeof(bufsize);	// Buffer size
	bufsize += 1; 			// Op
	bufsize += msg.len;		// Signal number

	char *sndbuf = (char *) malloc(bufsize);
	if (sndbuf == NULL) {
		fprintf(stderr, "send_dmmsg: malloc: insufficient memory\n");
		return -1;
	}
	
	int i = 0;
	memcpy(sndbuf + i, &bufsize, sizeof(bufsize));	
	i += sizeof(bufsize);

	*(sndbuf + i) = msg.op;
	i++;

	memcpy(sndbuf + i, msg.buf, msg.len);
	i += msg.len;

	int nbytes = write(socket, sndbuf, bufsize);
	free(sndbuf);
	
	if (nbytes == -1) {
		fprintf(stderr, "send_dmmsg: write: %s\n",
				strerror(errno));
	}

	return (nbytes);
}

struct dmmsg *
recv_dmmsg(int sock)
{
	int bufsize = 0;
	int err;
	struct dmmsg *msg = (struct dmmsg *) malloc(sizeof(struct dmmsg));
	if (msg == NULL) {
		fprintf(stderr, "send_dmmsg: malloc: insufficient memory\n");
		return NULL;
	}
	
	err = read(sock, &bufsize, sizeof(bufsize));
	if (err == 0) {
		fprintf(stderr, "recv_dmmsg: remote end"
					" closed connection\n");
		goto error;
	} else if (err == -1) {
		fprintf(stderr, "recv_dmmsg: %s\n", strerror(errno));
		goto error;
	}


	bufsize -= sizeof(bufsize);

	err = read(sock, &(msg->op), sizeof(msg->op));
	if (err == 0) {
		fprintf(stderr, "recv_dmmsg: remote end"
					" closed connection\n");
		goto error;
	} else if (err == -1) {
		fprintf(stderr, "recv_dmmsg: %s\n", strerror(errno));
		goto error;
	}

	bufsize -= sizeof(msg->op);

	msg->buf = (char *) malloc(bufsize);
	if (msg == NULL) {
		fprintf(stderr, "send_dmmsg: malloc: insufficient memory\n");
		goto error;
	}
	
	msg->len = bufsize;

	err = read(sock, msg->buf, bufsize);
	if (err == 0) {
		msg->len = 0;
		fprintf(stderr,"recv_dmmsg: remote end"
					" closed connection\n");
		free(msg->buf);
		free(msg);
		return (NULL);
	} else if (err == -1) {
		fprintf(stderr, "recv_dmmsg: %s\n", strerror(errno));
		free(msg->buf);
		goto error;
	}


	return msg;
error:
	free(msg);
	return NULL;
}

void
free_dmmsg(struct dmmsg **msg)
{
	if (*msg == NULL)
		return;
	free((*msg)->buf);
	free(*msg);
	*msg = NULL;
}
