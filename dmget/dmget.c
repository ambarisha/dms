#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>

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
static char	 dmg_errstr[512];

extern struct dmmsg *recv_dmmsg(int);
extern void free_dmmsg(struct dmmsg **);
extern int send_dmmsg(int, struct dmmsg);

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
	ret = write(sock, buf, bufsize);
	if (ret == -1) {
		fprintf(stderr, "dmget: Write failed (%s)\n", strerror(errno));
		strcpy(dmg_errstr, "Write failed - ");
		strcat(dmg_errstr, strerror(errno));
	}
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
	ret = read(sock, buf, bufsize);
	if (ret == -1 || ret == 0) {
		fprintf(stderr, "dmget: read failed (%s)\n", strerror(errno));
		return ret;
	}

	/* But if we've already started reading, we keep reading */
	while ((ret == -1 && errno == EINTR) || n > 0 && n < bufsize) {
		ret = read(sock, buf + n, bufsize - n);	
		if (ret == 0) {
			fprintf(stderr, "dmget: Remote end closed connection\n");
			strcpy(dmg_errstr, "Remote end closed connection");
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
	int bufsize = 0, i = 0, csumlen = 0;

	switch(dmreq.chksum_type) {
		case SHA1_CHKSUM:
			csumlen = SHA_DIGEST_LENGTH;
			break;
		case MD5_CHKSUM:
			csumlen = MD5_DIGEST_LENGTH;
			break;
		default:
			break;
	}

	bufsize += sizeof(bufsize); 				// Buffer size
	bufsize += 1; 						// Opcode
	bufsize += sizeof(struct dmreq);
	bufsize -= (3 * sizeof(char*)) + sizeof(dmreq.chksum); 	// fix sizeof(dmreq)
	bufsize += csumlen;
	bufsize += strlen(dmreq.i_filename) + 1;		// 
	bufsize += strlen(dmreq.URL) + 1;
	bufsize += strlen(dmreq.path) + 1;

	*reqbuf = (char *) malloc(bufsize);
	if (*reqbuf == NULL) {
		fprintf(stderr, "dmget: Insufficient memory");
		strcpy(dmg_errstr, "Insufficient memory");
		return -1;
	}
	
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

	memcpy(*reqbuf + i, &(dmreq.chksum_type), sizeof(dmreq.chksum_type));
	i += sizeof(dmreq.chksum_type);

	switch(dmreq.chksum_type) {
	case SHA1_CHKSUM:
		memcpy(*reqbuf + i, &(dmreq.chksum.sha1sum), SHA_DIGEST_LENGTH);
		i += SHA_DIGEST_LENGTH;
		break;
	case MD5_CHKSUM:
		memcpy(*reqbuf + i, &(dmreq.chksum.md5sum), MD5_DIGEST_LENGTH);
		i += MD5_DIGEST_LENGTH;
		break;
	default:
		break;
	}
	
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

	dmres = (struct dmres*) malloc(sizeof(struct dmres));
	if (dmres == NULL) {
		fprintf(stderr, "dmget: mk_dmres: Insufficient memory\n");
		return NULL;
	}

	memcpy(&(dmres->status), buf + i, sizeof(dmres->status));
	i += sizeof(dmres->status);

	memcpy(&(dmres->errcode), buf + i, sizeof(dmres->errcode));
	i += sizeof(dmres->errcode);

	len = strlen(buf + i);
	dmres->errstr = (char *) malloc(len);
	if (dmres->errstr == NULL) {
		fprintf(stderr, "dmget: mk_dmres: Insufficient memory\n");
		free(dmres);
		return NULL;
	}
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
send_signal(int sock, int sig)
{
	struct dmmsg msg;
	msg.op = DMSIG;
	msg.buf = (char *)&sig;
	msg.len = sizeof(sig);
	return (send_dmmsg(sock, msg));
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
	if (ret == -1) {
		fprintf(stderr, "dmget: Sending local file fd to daemon failed\n");
		return (-1);
	} 

	return (0);
}

static int
send_request(int sock, struct dmreq dmreq)
{
	char *reqbuf;
	int bufsize, ret, fd;

	bufsize = mk_reqbuf(dmreq, &reqbuf, DMREQ);
	if (bufsize == -1)
		return -1;

	ret = sigsafe_write(sock, reqbuf, bufsize);
	free(reqbuf);

	if (ret == -1)
		return -1;

	if (dmreq.flags & O_STDOUT)
		fd = STDOUT_FILENO;
	else
		fd = open(dmreq.path, O_CREAT|O_RDWR|O_TRUNC, S_IRUSR|S_IWUSR);

	ret = write_fd(sock, fd);

	if (!(dmreq.flags & O_STDOUT))
		close(fd);	

	return(ret);
}

struct dmauth *
mk_dmauth(char *buf, int bufsize)
{
	int i = 0, len;
	struct dmauth *dmauth = (struct dmauth *) malloc(sizeof(struct dmauth));
	if (dmauth == NULL) {
		fprintf(stderr, "dmget: mk_dmauth: Insufficient memory\n");
		return NULL;
	}

	len = strlen(buf + i);	
	dmauth->scheme = (char *) malloc(len + 1);
	if (dmauth->scheme == NULL) {
		fprintf(stderr, "dmget: mk_dmauth: Insufficient memory\n");
		free(dmauth);
		return NULL;
	}

	strncpy(dmauth->scheme, buf + i, len);
	i += len + 1;

	len = strlen(buf + i);
	dmauth->host = (char *) malloc(len + 1);
	if (dmauth->host == NULL) {
		fprintf(stderr, "dmget: mk_dmauth: Insufficient memory\n");
		free(dmauth->scheme);
		free(dmauth);
		return NULL;
	}

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
	int ret, ulen, bufsize;
	char *buf;
	struct dmmsg msg;
	
	ulen = strlen(dmauth->user) + 1;
	bufsize = ulen + strlen(dmauth->pwd) + 1;

	buf = (char *) malloc(bufsize);
	if (buf == NULL) {
		fprintf(stderr, "dmget: send_dmauth: Insufficient memory\n");
		return -1;
	}
	strcpy(buf, dmauth->user);
	strcpy(buf + ulen, dmauth->user);

	msg.op = DMAUTHRESP;
	msg.buf = buf;
	msg.len = bufsize;
	ret = send_dmmsg(sock, msg);
	return (ret);	
}

int
dmget(struct dmreq dmreq)
{
	int sock, err, ret, force, i;
	struct sockaddr_un dms_addr;
	struct dmres *dmres;
	struct xferstat xs;
	struct dmauth *dmauth;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		fprintf(stderr, "dmget: Could not create socket"
				" (%s)\n", strerror(errno));
		return -1;
	}

	dms_addr.sun_family = AF_UNIX;
	strncpy(dms_addr.sun_path, DMS_UDS_PATH, sizeof(dms_addr.sun_path));
	ret = connect(sock, (struct sockaddr *) &dms_addr, sizeof(dms_addr));
	if (ret == -1) {
		fprintf(stderr, "dmget: Could not connect to daemon"
				" (%s)\n", strerror(errno));
		return -1;
	}

	if (siginfo || sigint) 
		goto signal;

	ret = send_request(sock, dmreq);
	if (ret == -1)
		return -1;

	while (!sigint) {
		struct dmmsg *msg;
		msg = recv_dmmsg(sock);				
		if (msg == NULL) {
			goto failure;
		}

		if (sigint) {
			send_signal(sock, SIGINT);
			goto signal;
		}

		if (siginfo) {
			send_signal(sock, SIGINFO);
			goto signal;
		}
		
		switch(msg->op) {
		case DMRESP:
			dmres = mk_dmres(msg->buf, msg->len);
			free_dmmsg(&msg);
			if (dmres->status == 0){
				/* set dmLastErr* */
				rm_dmres(&dmres);
				goto success;
			} else {
				fprintf(stderr, "dmget: download failed: %s\n", dmres->errstr);
				rm_dmres(&dmres);
				goto failure;
			}
		case DMSTAT:
			force = *((int *)(msg->buf));
			memcpy(&xs, (msg->buf) + sizeof(force), sizeof(xs));
			free_dmmsg(&msg);
			dmStatDisplayMethod(&xs, force);
			break;
		case DMAUTHREQ:
			dmauth = mk_dmauth(msg->buf, msg->len);
			ret = dmAuthMethod(dmauth);
			if (ret == -1) {
				fprintf(stderr, "dmget: Authentication failed\n");
				strcpy(dmauth->user, "");
				strcpy(dmauth->pwd, "");
			}

			send_dmauth(sock, dmauth);
			rm_dmauth(&dmauth);

			if (ret == -1)
				goto failure;
			break;
		default:
			break;
		}
	}

signal:
	ret = -1;
	goto done;
failure:
	remove(dmreq.path);
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
