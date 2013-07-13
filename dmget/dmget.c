#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>


#include "dm.h"
#include "dmget.h"

auth_t		 dmAuthMethod;
int		 dmTimeout;
int		 dmRestartCalls;
int		 dmDebug;
int		 dmLastErrCode;
char		 dmLastErrString[MAXERRSTRING];

static int sigint;
static int siginfo;

static void *
Malloc(size_t size)
{
	void *ptr = malloc(size);
	if (ptr == NULL) {
		/* Notifiy ENOMEM and exit gracefully */
	}
	return ptr;
}

void dm_sighandler(int signal)
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
mk_reqbuf(struct dmreq dmreq, char **reqbuf, char op)
{
	int bufsize = 0;

	bufsize += sizeof(bufsize); 				// Buffer size
	bufsize += 1; 						// Opcode
	bufsize += sizeof(struct dmreq) - (3 * sizeof(char*)); 	// fix sizeof(dmreq)
	bufsize += strlen(dmreq.i_filename) + 1;		// 
	bufsize += strlen(dmreq.URL) + 1;
	bufsize += strlen(dmreq.path) + 1;

	*reqbuf = (char *) Malloc(bufsize);
	
	int i = 0;
	
	memcpy(*reqbuf, &(bufsize), sizeof(bufsize));
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
	
	return bufsize;
}

static int
sigsafe_write(int sock, char *buf, int bufsize)
{
	int err;
	sigset_t sm;
	sigemptyset(&sm);
	sigaddset(&sm, SIGINT);
	sigaddset(&sm, SIGINFO);

	sigprocmask(SIG_BLOCK, &sm, NULL);
	err = Write(sock, buf, bufsize);
	sigprocmask(SIG_UNBLOCK, &sm, NULL);

	return err;
}


static int
sigsafe_read(int sock, char *buf, int bufsize)
{
	int ret, n = 0;

	/* If the first read was an error return 
	 * because that could be because of a signal
	 * */
	ret = read(sock, buf, bufsize);
	if (ret == -1) 
		return (-1);

	/* But if we've already started reading, we keep reading */
	while ((ret == -1 && errno == EINTR) || n > 0 && n < bufsize) {
		ret = read(sock, buf + n, bufsize - n);	
		if (ret != -1)
			n += ret;
	}
	
	if (ret == -1)
		return (-1);
	else
		return n;
}

static int
send_request(int sock, struct dmreq dmreq)
{
	char *reqbuf;
	int bufsize = mk_reqbuf(dmreq, &reqbuf, DMREQ);
	int err;

	err = sigsafe_write(sock, reqbuf, bufsize);
	
	free(reqbuf);
	return (err);
}

static int
recv_msg(int sock, struct msg *msg)
{
	int err;
	fd_set fds;
	sigset_t sm;

	FD_ZERO(&fds);
	FD_SET(sock, &fds);
	
	err = Select(sock + 1, &fds, NULL, NULL, NULL);
	if (err == -1)
		return -1;

	sigemptyset(&sm);
	sigaddset(&sm, SIGINT);
	sigaddset(&sm, SIGINFO);

	sigprocmask(SIG_BLOCK, &sm, NULL);
	err = Peel(sock, msg);
	sigprocmask(SIG_UNBLOCK, &sm, NULL);

	return err;
}

static int
send_msg(int socket, struct msg msg)
{
	int bufsize = sizeof(bufsize);	// Buffer size
	bufsize += 1; 			// Op
	bufsize += msg.len;		// Signal number

	char *sndbuf = (char *) Malloc(bufsize);
	
	int i = 0;
	memcpy(sndbuf + i, &bufsize, sizeof(bufsize));	
	i += sizeof(bufsize);

	*(sndbuf + i) = msg.op;
	i++;

	memcpy(sndbuf + i, msg.buf, msg.len);
	i += msg.len;

	int nbytes = Write(socket, sndbuf, bufsize);
	free(sndbuf);

	return (nbytes);
}

static int
send_signal(int sock)
{
	struct msg msg;
	msg.op = DMSIG;
	msg.buf = &signal;
	msg.len = sizeof(signal);
	return (send_msg(sock, msg));
}

static void
mk_dmres(char *buf, int buflen, struct dmres *dmres)
{
	int i = 0, len;
	
	memcpy(dmres->status, buf + i, sizeof(dmres->status));
	i += sizeof(dmres->status);

	memcpy(dmres->errcode, buf + i, sizeof(dmres->errcode));
	i += sizeof(dmres->errcode);
	
	len = strlen(dmres->errstr);
	dmres->errstr = (char *) Malloc(len);
	strcpy(dmres->errstr, buf + i);
}

int
dmget(struct dmreq dmreq)
{
	int sock, err, ret;
	struct sockaddr_un dms_addr;
	struct dmres dmres;

	sock = Socket(AF_UNIX, SOCK_STREAM, 0);

	dms_addr.sun_family = AF_UNIX;
	strncpy(dms_addr.sun_path, DMS_UDS_PATH, sizeof(dms_addr.sun_path));
	err = Connect(sock, (struct sockaddr *) &dms_addr, sizeof(dms_addr));

	if (siginfo || sigint) 
		goto signal;

	send_request(sock, dmreq);

	while (!sigint) {
		struct msg msg;
		err = recv_msg(sock, &msg);				
		if (err == 0)
			goto failure;

		if (sigint || siginfo) {
			send_signal(sock);
			goto signal;
		}
		
		switch(msg.op) {
		case DMRESP:
			mk_dmres(msg.buf, msg.len, &dmres);
			free(msg.buf);
			msg.len = 0;
			if (dmres->status == 0){
				/* set dmLastErr* */
				goto success;
			} else {
				goto failure;
			}
		case DMAUTHREQ:
		case DMSTATRESP:
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
