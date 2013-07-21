#include <sys/socket.h>
#include <sys/un.h>
#include <sys/param.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <fetch.h>
#include <pthread.h>

#include "dm.h"
#include "list.h"
#include "dms.h"

int	 	 stop;
struct conn	*conns;

void *run_worker(struct conn *conn);

static int
read_fd(int sock)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t n;
	char c;
	int newfd;

	union {
		struct cmsghdr cm;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr *cmptr;

	msg.msg_control = control_un.control;
	msg.msg_controllen = sizeof(control_un.control);

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	iov[0].iov_base = &c;
	iov[0].iov_len = sizeof(c);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	if ( (n = recvmsg(sock, &msg, 0)) <= 0)
		return (n);

	if ( (cmptr = CMSG_FIRSTHDR(&msg)) != NULL &&
		cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
		if (cmptr->cmsg_level != SOL_SOCKET)
			/* ERROR : control level != SOL_SOCKET */;

		if (cmptr->cmsg_type != SCM_RIGHTS)
			 /* ERROR : control type != SCM_RIGHTS */;

		newfd = *((int *) CMSG_DATA(cmptr));
	} else {
		newfd = -1;
	}

	return newfd;
}

static struct dmjob *
mk_dmjob(int sock, struct dmreq dmreq)
{
	struct dmjob *dmjob = (struct dmjob *) Malloc(sizeof(struct dmjob));

	/* Right now dmjob and dmreq are same */
	dmjob->v_level = dmreq.v_level;
	dmjob->family = dmreq.family;
	dmjob->ftp_timeout = dmreq.ftp_timeout;
	dmjob->http_timeout = dmreq.http_timeout;
	dmjob->B_size = dmreq.B_size;

	dmjob->S_size = dmreq.S_size;
	dmjob->T_secs = dmreq.T_secs;
	dmjob->flags = dmreq.flags;

	dmjob->i_filename = (char *) Malloc(strlen(dmreq.i_filename) + 1);
	strcpy(dmjob->i_filename, dmreq.i_filename);

	dmjob->URL = (char *) Malloc(strlen(dmreq.URL) + 1);
	strcpy(dmjob->URL, dmreq.URL);

	dmjob->path = (char *) Malloc(strlen(dmreq.path) + 1);
	strcpy(dmjob->path, dmreq.path);

	dmjob->fd = read_fd(sock);
	dmjob->csock = sock;

#if DEBUG
	if (dmjob == NULL)
		perror("mk_dmjob():");
	else
		printf("mk_dmjob(): Success\n");
#endif
	return dmjob;
}

static void
rm_dmjob(struct dmjob **dmjob)
{
	free((*dmjob)->i_filename);
	free((*dmjob)->path);
	free((*dmjob)->URL);
	free(*dmjob);
	*dmjob = NULL;
}

static int
mk_dmreq(char *rcvbuf, int bufsize)
{
	int i = 0;

	struct dmreq *dmreq = (struct dmreq *) Malloc(sizeof(struct dmreq));
	if (dmreq == NULL) 
		return NULL;
	memcpy(&(dmreq->v_level), rcvbuf + i, sizeof(dmreq->v_level));
	i += sizeof(dmreq->v_level);

	memcpy(&(dmreq->family), rcvbuf + i, sizeof(dmreq->family));
	i += sizeof(dmreq->family);

	memcpy(&(dmreq->ftp_timeout), rcvbuf + i, sizeof(dmreq->ftp_timeout));
	i += sizeof(dmreq->ftp_timeout);
	
	memcpy(&(dmreq->http_timeout), rcvbuf + i, sizeof(dmreq->http_timeout));
	i += sizeof(dmreq->http_timeout);
	
	memcpy(&(dmreq->B_size), rcvbuf + i, sizeof(dmreq->B_size));
	i += sizeof(dmreq->B_size);
	
	memcpy(&(dmreq->S_size), rcvbuf + i, sizeof(dmreq->S_size));
	i += sizeof(dmreq->S_size);
	
	memcpy(&(dmreq->T_secs), rcvbuf + i, sizeof(dmreq->T_secs));
	i += sizeof(dmreq->T_secs);
	
	memcpy(&(dmreq->flags), rcvbuf + i, sizeof(dmreq->flags));
	i += sizeof(dmreq->flags);

	int sz = strlen(rcvbuf+i);
	dmreq->i_filename = (char *) Malloc(sz);
	strcpy(dmreq->i_filename, rcvbuf+i);
	i += sz + 1;
	
	sz = strlen(rcvbuf+i);
	dmreq->URL = (char *) Malloc(sz); 
	strcpy(dmreq->URL, rcvbuf+i);
	i += sz + 1;
	
	sz = strlen(rcvbuf+i);
	dmreq->path = (char *) Malloc(sz);
	strcpy(dmreq->path, rcvbuf+i);
	i += sz + 1;
	
	return dmreq;
}

static void
Rm_dmreq(struct dmreq **dmreq)
{
	free((*dmreq)->i_filename);
	free((*dmreq)->URL);
	free((*dmreq)->path);
	free(*dmreq);
	*dmreq = NULL;
}

static int
handle_request(int csock, struct conn **conns)
{
	struct dmjob 	*dmjob;
	struct dmreq 	*dmreq;
	struct dmmsg 	*msg;
	pthread_t	 worker;
	struct conn	*conn;
	int ret;
	pid_t pid;

	msg = recv_msg(csock);
	if (msg == NULL) {
		/* set dms_error */
		return -1;
	}
	
	switch (msg->op) {
	case DMREQ:
 		dmreq = mk_dmreq(msg->buf, msg->len);
		dmjob = mk_dmjob(csock, *dmreq);
		Rm_dmreq(&dmreq);

		pthread_create(&worker, NULL, run_worker, dmjob);
		default:
			goto error;
		break;
	}
success:
	ret = 0;
	goto done;
error:
	ret = -1;	
done:
	free_msg(msg);
	return ret;
}

void
sigint_handler(int sig)
{
	stop = 1;
	exit(1); // Temporary
}

static int
service_conn(struct conn *conn, fd_set *fdset)
{
	int ret = 0;
	if (FD_ISSET(conn->client, fdset)) {
		/* Received msg from client
		 * Intimate worker with SIGUSR1
		 */
	}

	if (conn->state == DONE)
		ret = 1;
	return (ret);
}

static void
run_event_loop(int socket)
{
	int i, ret, maxfd = socket;
	struct conn *cur;
	void *retptr;
	conns = NULL;
	fd_set fdset;

	signal(SIGINT, sigint_handler);
	while (!stop) {

		/* Prepare fdset and make select call */
		FD_ZERO(&fdset);
		FD_SET(socket, &fdset);

		cur = conns;
		while (cur != NULL) {
			FD_SET(cur->client, &fdset);
			if (cur->client > maxfd)
				maxfd = cur->client;
			cur = cur->next;
		}
		
		Select(maxfd + 1, &fdset, NULL, NULL, NULL);

		if (FD_ISSET(socket, &fdset)) {
			struct sockaddr_un cliaddr;
			size_t cliaddrlen = sizeof(cliaddr);
			int csock = Accept(socket, (struct sockaddr *) &cliaddr,
					&cliaddrlen);
			handle_request(csock, &conns);
		}
		
		cur = conns;
		while (cur != NULL) {
			ret = service_conn(cur, &fdset);
			if (ret == 1) {
				close(cur->client);
				pthread_join(cur->worker, &retptr);
				conns = rm_conn(conns, cur);
			}
			cur = cur->next;
		}
			
	}

	cur = conns;
	while (cur != NULL) {	
		close(cur->client);
		ret = service_conn(cur, &fdset);
		/* TODO: Force the worker to quit as well */
		conns = rm_conn(conns, cur);
		cur = conns;
	}
}

int main(int argc, char **argv)
{
	int sock = Socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un sunaddr;
	sunaddr.sun_family = AF_UNIX;
	strcpy(sunaddr.sun_path, DMS_UDS_PATH);
	int err = Bind(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr));

	err = Listen(sock, MAX_LISTEN_QUEUE);
	
	run_event_loop(sock);

	close(sock);

	exit(0);
}
