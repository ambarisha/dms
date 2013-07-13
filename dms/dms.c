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

#include "dm.h"
#include "list.h"
#include "dms.h"

#define	MAX_ALIVE_CONNECTIONS	256

static int	sigint;

static int
mk_dmjob(int sock, struct dmreq dmreq, struct dmjob *dmjob)
{
	/* Right now dmjob and dmreq are same */
	dmjob->v_level = dmreq.v_level;
	dmjob->family = dmreq.family;
	dmjob->ftp_timeout = dmreq.ftp_timeout;
	dmjob->http_timeout = dmreq.http_timeout;
	dmjob->B_size = dmreq.B_size;
	dmjob->S_size = dmreq.S_size;
	dmjob->T_secs = dmreq.T_secs;
	dmjob->flags = dmreq.flags;
	dmjob->i_filename = dmreq.i_filename;
	dmjob->URL = dmreq.URL;
	dmjob->path = dmreq.path;
	return 0;
}

static int
Mk_dmjob(int sock, struct dmreq dmreq, struct dmjob *dmjob)
{
	int err = mk_dmjob(sock, dmreq, dmjob);
	if (err == -1) {
		perror("mk_dmjob():");
#if DEBUG
	} else {
		printf("mk_dmjob(): Success\n");
#endif
	}
	return err;
}

static int
parse_request(char *rcvbuf, int bufsize, struct dmreq *dmreq)
{
	int i = 0;

	memcpy(&(dmreq->v_level), rcvbuf + i, sizeof(dmreq->v_level));
	i += sizeof(dmreq->v_level);

	memcpy(&(dmreq->family), rcvbuf + i, sizeof(dmreq->family));
	i += sizeof(dmreq->family);

	memcpy(&(dmreq->ftp_timeout), rcvbuf, sizeof(dmreq->ftp_timeout));
	i += sizeof(dmreq->ftp_timeout);
	
	memcpy(&(dmreq->http_timeout), rcvbuf, sizeof(dmreq->http_timeout));
	i += sizeof(dmreq->http_timeout);
	
	memcpy(&(dmreq->B_size), rcvbuf, sizeof(dmreq->B_size));
	i += sizeof(dmreq->B_size);
	
	memcpy(&(dmreq->S_size), rcvbuf, sizeof(dmreq->S_size));
	i += sizeof(dmreq->S_size);
	
	memcpy(&(dmreq->T_secs), rcvbuf, sizeof(dmreq->T_secs));
	i += sizeof(dmreq->T_secs);
	
	memcpy(&(dmreq->flags), rcvbuf, sizeof(dmreq->flags));
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
	
	return (0);
}

static int
Parse_request(char *rcvbuf, int bufsize, struct dmreq *dmreq)
{
	int err = parse_request(rcvbuf, bufsize, dmreq);
	if (err == -1) {
		perror("Parse_request():");
#if DEBUG
	} else {
		printf("Parse_reqeust(): Success\n");
#endif
	}
	return err;
}

static int
handle_request(int csock, struct conn **conns)
{
	struct dmjob dmjob;
	struct dmreq dmreq;
	struct dmmsg msg;
	int err;
	pid_t pid;

	Peel(csock, &msg);
	
	switch (msg.op) {
	case DMREQ:
 		err = Parse_request(msg.buf, msg.len, &dmreq);
		err = Mk_dmjob(csock, dmreq, &dmjob);

		int sockets[2];
		Socketpair(AF_LOCAL, SOCK_STREAM, 0, sockets);

		pid = fork();
		if (pid == 0) {
			/* Close all unwanted fds */
			struct conn *cur = *conns;
			while (cur != NULL) {
				close(cur->client);
				close(cur->worker);
				*conns = rm_conn(*conns, cur);
				cur = *conns;
			}

			close(csock);
			close(sockets[0]);

			/* Enter sandbox mode */
			// if(cap_enter() < 0) 
			//	errx(2, "Worker: Couldn't enter sandbox mode");
			/* Can't do this till libfetch is modified */

			run_worker(dmjob, sockets[1]);
			exit(0);
		} else {
			//close(sockets[1]);
			*conns = add_conn(*conns, csock, sockets[0]);
		}

		default:
			/* Unknown opcode recieved */
			return -1;
		break;
	}
	
	return 1;
}

void
sigint_handler(int sig)
{
	sigint = 1;
	exit(1); // Temporary
}

static int
handle_client_msg(struct conn *conn)
{
	struct dmmsg msg;
	int ret = Peel(conn->client, &msg);
	if (ret == 0)
		 return(1);
	
	switch(msg.op) {
	case DMSIG:
		send_msg(conn->worker, msg);
		break;
	case DMAUTHRESP:
		/* TODO: Implement these */
		break;
	default:
		/* Unrecognized opcode */
		break;
	}
	return(0);
}

static int
handle_worker_msg(struct conn *conn)
{
	struct dmmsg msg;

	int ret = Peel(conn->worker, &msg);
	if (ret == 0) /* Worker closed the socket !! */
		return(1);
	
	switch(msg.op) {
	case DMRESP:
		send_msg(conn->client, msg);
		ret = 1;
		break;
	case DMAUTHREQ:	
		/* TODO: Implement these */
		break;
	default:
		/* Unrecoginized opcode */
		break;	
	}
	return (0);
}

static int
service_conn(struct conn *conn, fd_set *fdset)
{
	int ret = 0;
	if (FD_ISSET(conn->client, fdset)) {
		ret = handle_client_msg(conn);
	}
	
	if (FD_ISSET(conn->worker, fdset)) {
		ret |= handle_worker_msg(conn);
		/* TODO: Do this better */
	}

	return (ret);
}

static void
run_event_loop(int socket)
{
	int i, maxfd = socket;

	struct conn *conns = NULL, *cur;

	fd_set fdset;

	sigint = 0;
	signal(SIGINT, sigint_handler);

	while (!sigint) {

		/* Prepare fdset and make select call */
		FD_ZERO(&fdset);
		FD_SET(socket, &fdset);

		cur = conns;
		while (cur != NULL) {
			FD_SET(cur->client, &fdset);
			FD_SET(cur->worker, &fdset);

			if (cur->client > maxfd)
				maxfd = cur->client;
			if (cur->worker > maxfd)
				maxfd = cur->worker;
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
			int ret = service_conn(cur, &fdset);
			if (ret == 1) {
				close(cur->client);
				close(cur->worker);
				conns = rm_conn(conns, cur);
			}
			cur = cur->next;
		}
			
	}

	cur = conns;
	while (cur != NULL) {	
		close(cur->client);
		close(cur->worker);
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
