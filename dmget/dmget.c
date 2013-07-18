#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>


#include "dm.h"
#include "dmget.h"

dm_auth_t	 dmAuthMethod;
stat_display_t	 dmStatDisplayMethod;
int		 dmTimeout;
int		 dmRestartCalls;
int		 dmDebug;
int		 dmLastErrCode;
char		 dmLastErrString[MAXERRSTRING];

static int 	 sigint;
static int 	 siginfo;

static int 	 dmg_error;
static char	*dmg_errstr;

static void *
Malloc(size_t size)
{
	void *ptr = malloc(size);
	if (ptr == NULL) {
		/* Notifiy ENOMEM and exit gracefully */
	}
	return ptr;
}

void dmSigHandler(int signal)
{
	switch(signal) {
	case SIGINT:
		sigint = 1;
		break;
	case SIGINFO:
		siginfo = 1;
		break;
	}
}

static int
sigsafe_write(int sock, char *buf, int bufsize)
{
	int ret;
	sigset_t sm;
	sigemptyset(&sm);
	sigaddset(&sm, SIGINT);
	sigaddset(&sm, SIGINFO);

	sigprocmask(SIG_BLOCK, &sm, NULL);
	ret = Write(sock, buf, bufsize);
	sigprocmask(SIG_UNBLOCK, &sm, NULL);

	return ret;
}

static int
sigsafe_read(int sock, char *buf, int bufsize)
{
	int ret, n = 0;

	/* If the first read was an error return 
	 * because that could be because of a signal
	 * */
	ret = Read(sock, buf, bufsize);
	if (ret == -1 || ret == 0) 
		return ret;
		
	/* But if we've already started reading, we keep reading */
	while ((ret == -1 && errno == EINTR) || n > 0 && n < bufsize) {
		ret = read(sock, buf + n, bufsize - n);	
		if (ret == 0) {
			/* Read ended prematurely
			 * Set dmg_error appropriately and return
			 */

			break;
		}
		
		if (ret != -1)
			n += ret;
	}

	if (ret != -1)
		return(n);
	return(ret);
}

static int
mk_reqbuf(struct dmreq dmreq, char **reqbuf, char op)
{
	int bufsize = 0, i = 0;

	bufsize += sizeof(bufsize); 				// Buffer size
	bufsize += 1; 						// Opcode
	bufsize += sizeof(struct dmreq) - (3 * sizeof(char*)); 	// fix sizeof(dmreq)
	bufsize += strlen(dmreq.i_filename) + 1;		// 
	bufsize += strlen(dmreq.URL) + 1;
	bufsize += strlen(dmreq.path) + 1;

	*reqbuf = (char *) Malloc(bufsize);
	
	memcpy(*reqbuf, &bufsize, sizeof(bufsize));
	i += sizeof(bufsize);
	
	*(*reqbuf+i) = op;
	i++;
	
	memcpy(*reqbuf + i, &(dmreq.v_level), sizeof(sizeof(dmreq.v_level)));
	i += sizeof(dmreq.v_level);
	
	memcpy(*reqbuf + i, &(dmreq.family), sizeof(dmreq.family));
	i += sizeof(dmreq.family);
	
	memcpy(*reqbuf + i, &(dmreq.ftp_timeout), sizeof(dmreq.ftp_timeout));
	i += sizeof(dmreq.ftp_timeout);
	
	memcpy(*reqbuf + i, &(dmreq.http_timeout), sizeof(dmreq.http_timeout));
	i += sizeof(dmreq.http_timeout);
	
	memcpy(*reqbuf + i, &(dmreq.B_size), sizeof(dmreq.B_size));
	i += sizeof(dmreq.B_size);
	
	memcpy(*reqbuf + i, &(dmreq.S_size), sizeof(dmreq.S_size));
	i += sizeof(dmreq.S_size);
	
	memcpy(*reqbuf + i, &(dmreq.T_secs), sizeof(dmreq.T_secs));
	i += sizeof(dmreq.T_secs);
	
	memcpy(*reqbuf + i, &(dmreq.flags), sizeof(dmreq.flags));
	i += sizeof(dmreq.flags);

	strcpy(*reqbuf + i, dmreq.i_filename);
	i += strlen(dmreq.i_filename) + 1;
	
	strcpy(*reqbuf + i, dmreq.URL);
	i += strlen(dmreq.URL) + 1;
	
	strcpy(*reqbuf + i, dmreq.path);
	i += strlen(dmreq.path) + 1;
	
	return(i);
}

static struct dmres *
mk_dmres(char *buf, int buflen)
{
	int i = 0, len;
	struct dmres *dmres;

	dmres = (struct dmres*) Malloc(sizeof(struct dmres));

	memcpy(&(dmres->status), buf + i, sizeof(dmres->status));
	i += sizeof(dmres->status);

	memcpy(&(dmres->errcode), buf + i, sizeof(dmres->errcode));
	i += sizeof(dmres->errcode);

	len = strlen(buf + i);
	dmres->errstr = (char *) Malloc(len);
	strcpy(dmres->errstr, buf + i);

	return dmres;
}

static void
rm_dmres(struct dmres **dmres)
{
	free((*dmres)->errstr);
	free(*dmres);
	*dmres = NULL;
}

static int
send_signal(int sock)
{
	struct dmmsg msg;
	msg.op = DMSIG;
	msg.buf = &signal;
	msg.len = sizeof(signal);
	return (send_msg(sock, msg));
}

static int
write_fd(int sock, int fd)
{
	int ret;
	char c;
	struct msghdr msg;
	struct iovec iov;

	char control[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmptr;

	c = 0;
	iov.iov_base = &c;
	iov.iov_len = sizeof(c);

	msg.msg_control = (caddr_t) control;
	msg.msg_controllen = CMSG_LEN(sizeof(int));
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	cmptr = CMSG_FIRSTHDR(&msg);
	cmptr->cmsg_len = CMSG_LEN(sizeof(int));
	cmptr->cmsg_level = SOL_SOCKET;
	cmptr->cmsg_type = SCM_RIGHTS;
	*((int *) CMSG_DATA(cmptr)) = fd;

	ret = sendmsg(sock, &msg, 0);
	if (ret == -1)
		return (-1);
	else
		return (0);
}

static int
Write_fd(int sock, int fd)
{
	int ret = write_fd(sock, fd);
	if (ret == -1) {
		perror("Write_fd():");
	} else {
		printf("Write_fd(): Success\n");
	}
}

static int
send_request(int sock, struct dmreq dmreq)
{
	char *reqbuf;
	int bufsize, err, fd;

	bufsize = mk_reqbuf(dmreq, &reqbuf, DMREQ);
	err = sigsafe_write(sock, reqbuf, bufsize);

	if (dmreq.flags & O_STDOUT)
		fd = STDOUT_FILENO;
	else
		fd = open(dmreq.path, O_CREAT|O_RDWR|O_TRUNC, S_IRUSR|S_IWUSR);

	Write_fd(sock, fd);
	close(fd);	

	free(reqbuf);
	return(err);
}

struct dmauth *
mk_dmauth(char *buf, int bufsize)
{
	int i = 0, len;
	struct dmauth *dmauth = (struct dmauth *) Malloc(sizeof(struct dmauth));

	len = strlen(buf + i);	
	dmauth->scheme = (char *) Malloc(len + 1);
	strncpy(dmauth->scheme, buf + i, len);
	i += len + 1;

	len = strlen(buf + i);
	dmauth->host = (char *) Malloc(len + 1);
	strncpy(dmauth->host, buf + i, len);
	i += len + 1;

	dmauth->port = *(int *)(buf + i);
	i += sizeof(int);
	
	return dmauth;
}

void
rm_dmauth(struct dmauth **dmauth)
{
	free((*dmauth)->scheme);
	free((*dmauth)->host);
	free(*dmauth);
	*dmauth = NULL;
}

static int
send_dmauth(int sock, struct dmauth *dmauth)
{
	int ulen = strlen(dmauth->user) + 1;
	int bufsize = ulen + strlen(dmauth->pwd) + 1;
	char *buf = (char *) Malloc(bufsize);

	strcpy(buf, dmauth->user);
	strcpy(buf + ulen, dmauth->user);

	struct dmmsg msg;
	msg.op = DMAUTHRESP;
	msg.buf = buf;
	msg.len = bufsize;
	send_msg(sock, msg);
}

int
dmget(struct dmreq dmreq)
{
	int sock, err, ret, force, i;
	struct sockaddr_un dms_addr;
	struct dmres *dmres;
	struct xferstat xs;
	struct dmauth *dmauth;
	sock = Socket(AF_UNIX, SOCK_STREAM, 0);

	dms_addr.sun_family = AF_UNIX;
	strncpy(dms_addr.sun_path, DMS_UDS_PATH, sizeof(dms_addr.sun_path));
	err = Connect(sock, (struct sockaddr *) &dms_addr, sizeof(dms_addr));

	if (siginfo || sigint) 
		goto signal;

	send_request(sock, dmreq);

	while (!sigint) {
		struct dmmsg *msg;
		msg = recv_msg(sock);				
		if (msg == NULL) {
			goto failure;
		}

		if (sigint || siginfo) {
			send_signal(sock);
			goto signal;
		}
		
		switch(msg->op) {
		case DMRESP:
			dmres = mk_dmres(msg->buf, msg->len);
			free_msg(&msg);
			if (dmres->status == 0){
				/* set dmLastErr* */
				rm_dmres(&dmres);
				goto success;
			} else {
				rm_dmres(&dmres);
				goto failure;
			}
		case DMSTAT:
			force = *((int *)(msg->buf));
			memcpy(&xs, (msg->buf) + sizeof(force), sizeof(xs));
			free_msg(&msg);
			dmStatDisplayMethod(&xs, force);
			break;
		case DMAUTHREQ:
			dmauth = mk_dmauth(msg->buf, msg->len);
			if (dmAuthMethod(dmauth) == -1) {
				
			}
			send_dmauth(sock, dmauth);
			rm_dmauth(&dmauth);
			break;
		default:
			break;
		}
	}

signal:
	ret = -1;
	goto done;
failure:
	ret = 1;
	goto done;
success:
	ret = 0;
	goto done;
done:
	/* Set dmLastErrCode dmLastErrString */
	close(sock);
	return (ret);
}
