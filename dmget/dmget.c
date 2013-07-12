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

static int dms;
static int sigint;

static void *
Malloc(size_t size)
{
	void *ptr = malloc(size);
	if (ptr == NULL) {
		/* Notifiy ENOMEM and exit gracefully */
	}
	return ptr;
}

static int
mk_reqbuf(struct dmreq dmreq, char **reqbuf, char op)
{
	int bufsize = 0;
	printf("mk_reqbuf() : Starting\n");

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
send_request(int sock, struct dmreq dmreq)
{
	char *reqbuf;
	int bufsize = mk_reqbuf(dmreq, &reqbuf, DMREQ);
	int err = Write(sock, reqbuf, bufsize);

	free(reqbuf);
	return (err);
}

static int
keep_reading(int sock, char *buf, int size)
{
	int err = read(sock, buf, size);
	while (err == -1 && errno == EINTR && sigint == 0) {
		err = read(sock, buf, size);
	}

	if (err == -1)
		perror("read():");

	return err;
}

static int
recv_response(int sock, struct dmres *dmres)
{
	int bufsize;
	keep_reading(sock, &bufsize, sizeof(bufsize));
	bufsize -= sizeof(bufsize);

	char *buf = (char *) Malloc(bufsize);
	keep_reading(sock, buf, bufsize);

	/* TODO: Check the error code in the response and set the 
		 dmLastErrCode & dmLastErrString values */
}

int
dm_request(struct dmreq dmreq)
{
	dms = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un dms_addr;
	dms_addr.sun_family = AF_UNIX;
	strncpy(dms_addr.sun_path, DMS_UDS_PATH, sizeof(dms_addr.sun_path));
	int err = Connect(dms, (struct sockaddr *) &dms_addr, sizeof(dms_addr));
	
	send_request(dms, dmreq);

	struct dmres dmres;
	recv_response(dms, &dmres);	
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

void
dm_sighandler(int signal)
{
	struct msg msg;
	msg.op = DMSIG;
	msg.buf = &signal;
	msg.len = sizeof(signal);
	send_msg(dms, msg);

	if (signal == SIGINT) {
		close(dms);
		exit(2);
	}
}
