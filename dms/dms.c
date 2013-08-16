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
#include <signal.h>

#include "dm.h"
#include "dms.h"
#include "utils.h"
#include "mirror.h"

static int	dm_err;
static char	dm_errstr[512];

int	 	 	 stop;
struct dmjob		*jobs;
pthread_mutex_t	 	 job_queue_mutex;

extern struct dmmirr		*mirrors;
extern pthread_mutex_t		 mirror_list_mutex;

extern void *run_worker(void *);
extern int send_report(int, struct dmrep);

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

	if ( (n = recvmsg(sock, &msg, 0)) <= 0) {
		strcpy(dm_errstr, "Couldn't recieve output file descriptor");
		fprintf(stderr, "read_fd: recvmsg: %s\n", strerror(errno));
		return -1;
	}

	if ( (cmptr = CMSG_FIRSTHDR(&msg)) != NULL &&
		cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
		if (cmptr->cmsg_level != SOL_SOCKET) {
			strcpy(dm_errstr, "Couldn't recieve"
					"output file descriptor");
			fprintf(stderr, "read_fd: recvmsg:"
					"control level != SOL_SOCKET\n");
			return -1;
		}

		if (cmptr->cmsg_type != SCM_RIGHTS) {
			strcpy(dm_errstr, "Couldn't recieve"
					"output file descriptor");
			fprintf(stderr, "read_fd: recvmsg:"
					"control type != SCM_RIGHTS\n");
			return -1;
		}

		newfd = *((int *) CMSG_DATA(cmptr));
	} else {
		strcpy(dm_errstr, "Couldn't recieve output file descriptor");
		fprintf(stderr, "read_fd: Invalid control message header\n");
		newfd = -1;
	}

	return newfd;
}

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
	if (job->next != NULL) 
		job->next->prev = job->prev;

	if (job->prev != NULL)
		job->prev->next = job->next;
	
	if (job == head) 
		return job->next;

	return head;
}

static struct dmjob *
mk_dmjob(struct dmreq *dmreq, int client)
{
	int ret;
	struct dmmirr *cur;
	struct dmjob *dmjob = (struct dmjob *) malloc(sizeof(struct dmjob));
	if (dmjob == NULL) {
		fprintf(stderr, "mk_dmjob: malloc: insufficient memory\n");
		strcpy(dm_errstr, "Insufficient memory\n");
	}

	dmjob->request = dmreq;

	dmjob->ofd = read_fd(client);
	if (dmjob->ofd == -1) {
		free(dmjob);
		return NULL;
	}

	dmjob->mirror = get_mirror();
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

	struct dmreq *dmreq = (struct dmreq *) malloc(sizeof(struct dmreq));
	if (dmreq == NULL) {
		fprintf(stderr, "mk_dmreq: malloc: insufficient memory\n");
		strcpy(dm_errstr, "Insufficient memory");
		return NULL;
	}

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

	memcpy(&(dmreq->chksum_type), rcvbuf + i, sizeof(dmreq->chksum_type));
	i += sizeof(dmreq->chksum_type);

	switch(dmreq->chksum_type) {
	case SHA1_CHKSUM:
		memcpy(dmreq->chksum.sha1sum, rcvbuf + i, SHA_DIGEST_LENGTH);
		i += SHA_DIGEST_LENGTH;
		break;
	case MD5_CHKSUM:
		memcpy(dmreq->chksum.md5sum, rcvbuf + i, MD5_DIGEST_LENGTH);
		i += MD5_DIGEST_LENGTH;
		break;
	case NO_CHKSUM:
		break;
	}

	
	memcpy(&(dmreq->flags), rcvbuf + i, sizeof(dmreq->flags));
	i += sizeof(dmreq->flags);

	int sz = strlen(rcvbuf+i);
	dmreq->i_filename = (char *) malloc(sz);
	if (dmreq->i_filename == NULL) {
		fprintf(stderr, "mk_dmreq: malloc: insufficient memory\n");
		strcpy(dm_errstr, "Insufficient memory");
		free(dmreq);
		return NULL;
	}
	strcpy(dmreq->i_filename, rcvbuf+i);
	i += sz + 1;
	
	sz = strlen(rcvbuf+i);
	dmreq->URL = (char *) malloc(sz); 
	if (dmreq->URL == NULL) {
		fprintf(stderr, "mk_dmreq: malloc: insufficient memory\n");
		strcpy(dm_errstr, "Insufficient memory");
		free(dmreq->i_filename);
		free(dmreq);
		return NULL;
	}
	strcpy(dmreq->URL, rcvbuf+i);
	i += sz + 1;
	
	sz = strlen(rcvbuf+i);
	dmreq->path = (char *) malloc(sz);
	if (dmreq->path == NULL) {
		fprintf(stderr, "mk_dmreq: malloc: insufficient memory\n");
		strcpy(dm_errstr, "Insufficient memory");
		free(dmreq->i_filename);
		free(dmreq->URL);
		free(dmreq);
		return NULL;
	}
	strcpy(dmreq->path, rcvbuf+i);
	i += sz + 1;
	
	return dmreq;
}

static void
rm_dmreq(struct dmreq **dmreq)
{
	if (*dmreq == NULL)
		return;

	free((*dmreq)->i_filename);
	free((*dmreq)->URL);
	free((*dmreq)->path);
	free(*dmreq);
	*dmreq = NULL;
}

static void
rm_dmjob(struct dmjob **dmjob)
{
	if (*dmjob == NULL)
		return;
	rm_dmreq(&((*dmjob)->request));	
	free((*dmjob)->url);
}

static int
handle_request(int csock)
{
	struct dmreq 	*dmreq;
	struct dmmsg 	*msg;
	struct dmjob	*dmjob;
	struct dmrep	report;
	int ret;
	pid_t pid;

	msg = recv_dmmsg(csock);
	if (msg == NULL) {
		report.status = -1;
		report.errcode = FETCH_UNKNOWN;
		report.errstr = dm_errstr;
		send_report(csock, report);
		return -1;
	}
	
	switch (msg->op) {
	case DMREQ:
 		if ((dmreq = mk_dmreq(msg->buf, msg->len)) == NULL)
			goto error;

		if ((dmjob = mk_dmjob(dmreq, csock)) == NULL)
			goto error;

		/* Acquire job queue lock */
		ret = pthread_mutex_lock(&job_queue_mutex);
		if (ret == -1) {
			fprintf(stderr, "handle_request: Attempt to acquire"
					" job queue mutex failed\n");
			goto error;
		}

		jobs = add_job(jobs, dmjob);

		ret = pthread_mutex_unlock(&job_queue_mutex);
		if (ret == -1) {
			fprintf(stderr, "handle_request: Couldn't release "
					"job queue lock\n");
			goto error;
		}
		/* Job queue lock released */

		pthread_create(&(dmjob->worker), NULL, run_worker, dmjob);
		pthread_detach(dmjob->worker);
		goto done;
	default:
		free_dmmsg(&msg);
		goto error;
	}

error:
	report.status = -1;
	report.errcode = FETCH_UNKNOWN;
	report.errstr = dm_errstr;
	send_report(csock, report);

	rm_dmreq(&dmreq);
	rm_dmjob(&dmjob);
	ret = -1;	
done:
	free_dmmsg(&msg);
	return ret;
}

void
sigint_handler(int sig)
{
	save_mirrors();
	stop = 1;
	exit(1); // Temporary
}

static int
service_job(struct dmjob *job, fd_set *fdset)
{
	int ret = 0;
	if (FD_ISSET(job->client, fdset)) {
		/* TODO: Worker can't handle this signal yet */
		//pthread_kill(job->worker, SIGUSR1);
	}

	return ret;
}

static void
run_event_loop(int socket)
{
	int ret, csock;
	struct sockaddr_un cliaddr;
	size_t cliaddrlen;
	struct dmjob *cur;
	void *retptr;

	jobs = NULL;
	job_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

	mirrors = NULL;
	mirror_list_mutex = PTHREAD_MUTEX_INITIALIZER;
	load_mirrors();

	signal(SIGINT, sigint_handler);
	while (!stop) {
		cliaddrlen = sizeof(cliaddr);
		csock = accept(socket, (struct sockaddr *) &cliaddr,
				&cliaddrlen);
		if (csock == -1) {
			fprintf(stderr, "run_event_loop: "
				"select: %s\n", strerror(errno));
			goto wrap_up;
		}

		handle_request(csock);
	}

wrap_up:
	/* Notify all running workers that we've to wrap up */
	/* Acquire job queue lock */
	ret = pthread_mutex_lock(&job_queue_mutex);
	if (ret == -1) {
		fprintf(stderr, "handle_request: Attempt to acquire"
				" job queue mutex failed\n");
		return;
	}

	cur = jobs;
	while (cur != NULL) {
		if (cur->state == RUNNING)
			pthread_kill(cur->worker, SIGINT);

		rm_dmreq(&(cur->request));	
		jobs = rm_job(jobs, cur);
		cur = cur->next;
	}

	ret = pthread_mutex_unlock(&job_queue_mutex);
	if (ret == -1) {
		fprintf(stderr, "handle_request: Couldn't release "
				"job queue lock\n");

		return;
	}
	/* Job queue lock released */

}

int main(int argc, char **argv)
{
	int sock, err; 
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		fprintf(stderr, "main: socket: %s\n", strerror(errno));
		exit(1);
	}

	struct sockaddr_un sunaddr;
	sunaddr.sun_family = AF_UNIX;
	strcpy(sunaddr.sun_path, DMS_UDS_PATH);

	err = bind(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr));
	if (err == -1) {
		fprintf(stderr, "main: bind: %s\n", strerror(errno));
		close(sock);
		exit(1);
	}

	err = listen(sock, MAX_LISTEN_QUEUE);
	if (err == -1) {
		fprintf(stderr, "main: listen: %s\n", strerror(errno));
		close(sock);
		exit(1);
	}
	
	run_event_loop(sock);

	close(sock);

	exit(0);
}
