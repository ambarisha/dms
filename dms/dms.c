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
#include "dms.h"

int	 	 stop;
struct dmjob	*jobs;

void *run_worker(struct dmjob *job);

static struct dmjob *
add_job(struct dmjob *head, struct dmjob *new)
{ 
	new->prev = NULL;
	new->next = NULL;

	if (head == NULL)
		return new;

	head->prev = new;
	new->next = head;	
}

static struct dmjob *
rm_job(struct dmjob *head, struct dmjob *job)
{
	if (head == NULL)
		return NULL;
	
	if (job == NULL)
		return head;
		
	if (job->next != NULL) 
		job->next->prev = job->prev;

	if (job->prev != NULL)
		job->prev->next = job->next;
	
	if (job == head) 
		return job->next;

	return head;
}

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
mk_dmjob(struct dmreq *dmreq, int client)
{
	struct dmjob *dmjob = (struct dmjob *) Malloc(sizeof(struct dmjob));
	dmjob->request = dmreq;
	dmjob->ofd = read_fd(client);
	if (dmjob->ofd == -1) {
		/* Handle error */
		free(dmjob);
		return NULL;
	}
	dmjob->client = client;
	dmjob->sigint = 0;
	dmjob->sigalrm = 0;
	dmjob->siginfo = 0;
	dmjob->siginfo_en = 0;
	dmjob->state = RUNNING;
	dmjob->url = NULL;
	return dmjob;
}

static struct dmreq *
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
rm_dmreq(struct dmreq **dmreq)
{
	free((*dmreq)->i_filename);
	free((*dmreq)->URL);
	free((*dmreq)->path);
	free(*dmreq);
	*dmreq = NULL;
}

static int
handle_request(int csock)
{
	struct dmreq 	*dmreq;
	struct dmmsg 	*msg;
	struct dmjob	*dmjob;
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
		dmjob = mk_dmjob(dmreq, csock);
		jobs = add_job(jobs, dmjob);
		pthread_create(&(dmjob->worker), NULL, run_worker, dmjob);
		pthread_detach(dmjob->worker);
		break;
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
	free_msg(&msg);
	return ret;
}

void
sigint_handler(int sig)
{
	stop = 1;
	exit(1); // Temporary
}

static state_t
service_job(struct dmjob *job, fd_set *fdset)
{
	int ret = 0;
	if (FD_ISSET(job->client, fdset)) {
		/* TODO: Worker can't handle this signal yet */
		//pthread_kill(job->worker, SIGUSR1);
	}
	return (job->state);
}

static void
run_event_loop(int socket)
{
	int i, ret, maxfd = socket;
	struct dmjob *cur;
	void *retptr;
	jobs = NULL;
	fd_set fdset;

	signal(SIGINT, sigint_handler);
	while (!stop) {

		/* Prepare fdset and make select call */
		FD_ZERO(&fdset);
		maxfd = socket;
		FD_SET(socket, &fdset);

		cur = jobs;
		while (cur != NULL) {
			FD_SET(cur->client, &fdset);
			if (cur->client > maxfd)
				maxfd = cur->client;
			cur = cur->next;
		}
		
		Select(maxfd + 1, &fdset, NULL, NULL, NULL);

		cur = jobs;
		while (cur != NULL) {
			ret = service_job(cur, &fdset);
			if (ret == DONE) {
				close(cur->client);
				jobs = rm_job(jobs, cur);
			}
			cur = cur->next;
		}

		if (FD_ISSET(socket, &fdset)) {
			struct sockaddr_un cliaddr;
			size_t cliaddrlen = sizeof(cliaddr);
			int csock = Accept(socket, (struct sockaddr *) &cliaddr,
					&cliaddrlen);
			handle_request(csock);
		}
	}

	/* Notify all running workers that we've to wrap up */
	cur = jobs;
	while (cur != NULL) {
		if (cur->state == RUNNING)
			pthread_kill(cur->worker, SIGINT);

		rm_dmreq(&(cur->request));	
		jobs = rm_job(jobs, cur);
		cur = cur->next;
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
