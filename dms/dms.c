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

int	 stop;

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

static int
Read_fd(int sock)
{
	int ret = read_fd(sock);
	if (ret == -1) {
		perror("Read_fd():");
	} else {
		printf("Read_fd(): Success\n");
	}
	return(ret);
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

	if (dmjob->flags & V_TTY)
		printf("v_tty is set :)\n");
	else 	
		printf("v_tty is already gone\n");
	printf("HELLO???\n");

	dmjob->i_filename = (char *) Malloc(strlen(dmreq.i_filename) + 1);
	strcpy(dmjob->i_filename, dmreq.i_filename);

	dmjob->URL = (char *) Malloc(strlen(dmreq.URL) + 1);
	strcpy(dmjob->URL, dmreq.URL);

	dmjob->path = (char *) Malloc(strlen(dmreq.path) + 1);
	strcpy(dmjob->path, dmreq.path);

	dmjob->fd = Read_fd(sock);
	dmjob->csock = sock;

	return dmjob;
}

static struct dmjob *
Mk_dmjob(int sock, struct dmreq dmreq)
{
	struct dmjob *dmjob = mk_dmjob(sock, dmreq);
	if (dmjob == NULL) {
		perror("mk_dmjob():");
#if DEBUG
	} else {
		printf("mk_dmjob(): Success\n");
#endif
	}
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
parse_request(char *rcvbuf, int bufsize)
{
	int i = 0;

	struct dmreq *dmreq = (struct dmreq *) Malloc(sizeof(struct dmreq));

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

	printf("flags = %d\n", *(int *)(rcvbuf + i));
	i += sizeof(dmreq->flags);
	printf("i after flags == %d\n honey", i);

	if (dmreq->flags & V_TTY)
		printf("v_tty is STTIIIIIILLL set :)\n");
	else 	
		printf("v_tty is already gone\n");
	printf("RARRRR\n");

	write(1, rcvbuf, bufsize);

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

static int
Parse_request(char *rcvbuf, int bufsize)
{
	struct dmreq *dmreq = parse_request(rcvbuf, bufsize);
	if (dmreq == NULL) {
		perror("Parse_request():");
#if DEBUG
	} else {
		printf("Parse_reqeust(): Success\n");
#endif
	}
	return dmreq;
}

static void
Free_request(struct dmreq **dmreq)
{
	free((*dmreq)->i_filename);
	free((*dmreq)->URL);
	free((*dmreq)->path);
	free(*dmreq);
	*dmreq = NULL;
}

static void
send_report(int sock, struct dmrep report, char op)
{
	char *buf;
	int bufsize = sizeof(report) - sizeof(report.errstr);
	int errlen = strlen(report.errstr);
	bufsize +=  errlen;	

	buf = (char *) Malloc(bufsize);
	int i = 0;
	
	memcpy(buf + i, &(report.status), sizeof(report.status));
	i += sizeof(report.status);

	memcpy(buf + i, &(report.errcode), sizeof(report.errcode));
	i += sizeof(report.errcode);

	strcpy(buf + i, report.errstr);
	i += errlen;
	
	struct dmmsg msg;
	msg.op = op;
	msg.buf = buf;
	msg.len = bufsize;
	send_msg(sock, msg);
	
	free(buf);
}

static int
handle_request(int csock, struct conn **conns)
{
	struct dmjob *dmjob;
	struct dmreq *dmreq;
	struct dmmsg msg;
	struct dmrep report;
	int err;
	pid_t pid;

	Peel(csock, &msg);
	
	switch (msg.op) {
	case DMREQ:
 		dmreq = Parse_request(msg.buf, msg.len);
		dmjob = Mk_dmjob(csock, *dmreq);
		Free_request(&dmreq);
		do_job(*dmjob, &report);
		send_report(csock, report, DMRESP);
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
	stop = 1;
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

	signal(SIGINT, sigint_handler);

	while (!stop) {

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
				/* What should happen to the worker */
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
