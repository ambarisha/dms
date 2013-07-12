#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>

#include "dm.h"
#include "dms.h"

void *
Malloc(size_t size)
{
	void *ptr = malloc(size);
	if (ptr == NULL) {
		perror("Malloc():");
		/* Notifiy ENOMEM and exit gracefully */
	}
	return ptr;
}

ssize_t
Read(int fd, void *buf, size_t size)
{
	ssize_t err = read(fd, buf, size);
	if (err == -1) {
		perror("Read(): ");
#if DEBUG
	} else if (err != size) {
		printf("Warning: %d bytes received %d expected\n", err, size);
	} else {
		printf("Read() : Success\n");
#endif
	} 
	return err;
}

int
Socket(int domain, int type, int flags)
{
	int err = socket(domain, type, flags);
	if (err == -1) {
		perror("Socket():");
#if DEBUG
	} else {
		printf("Socket(): Success\n");
#endif
	}

	return err;
}

int
Write(int fd, void *buf, size_t size)
{
	int err = write(fd, buf, size);
	if (err == -1) {
		perror("Write():");
#if DEBUG
	} else {
		printf("Write(): Success\n");
#endif
	}
	return err;
}

int 
Socketpair(int domain, int type, int protocol, int socket_vector[2])
{
	int err = socketpair(domain, type, protocol, socket_vector);	
	if (err == -1) {
		perror("Socketpair():");
#if DEBUG
	} else {
		printf("Socketpair() : Success\n");
#endif
	}
	return err;
}

int
Bind(int socket, const struct sockaddr *addr, socklen_t addrlen)
{
	int err = bind(socket, addr, addrlen);
	if (err == -1) {
		perror("Bind():");
#if DEBUG
	} else {
		printf("Bind() : Success\n");
#endif
	}
	return err;
}

int
Accept(int socket, struct sockaddr *addr, socklen_t *addrlen)
{
	int err = accept(socket, addr, addrlen);
	if (err == -1) {
		perror("Accept():");
#if DEBUG
	} else {
		printf("Accept() : Success\n");
#endif
	}
	return err;
}

int
Listen(int socket, int backlog)
{
	int err = listen(socket, backlog);
	if (err == -1) {
		perror("Listen():");
#if DEBUG
	} else {
		printf("Listen() : Success\n");
#endif
	}
	return err;
}

int
Peel(int sock, struct msg *msg)
{
	int bufsize = 0;
	Read(sock, &bufsize, sizeof(bufsize));
	bufsize -= sizeof(bufsize);
	
	Read(sock, &(msg->op), sizeof(msg->op));
	bufsize -= sizeof(msg->op);

	msg->buf = (char *) Malloc(bufsize);
	msg->len = bufsize;

	Read(sock, msg->buf, bufsize);
	return 0;
}

int
Select(int maxfd, fd_set *rset, fd_set *wset, fd_set *xset,
	 const struct timeval *timeout)
{
	int err = select(maxfd, rset, wset, xset, timeout);
	if (err == -1) {
		perror("Select():");
#if DEBUG
	} else {
		printf("Select(): Success\n");
#endif
	}
	return err;
}

int
send_msg(int socket, struct msg msg)
{
	int i = 0, bufsize;
	bufsize = msg.len + sizeof(msg.op) + sizeof(msg.len);
	char *sndbuf = (char *) Malloc(bufsize);
	
	memcpy(sndbuf + i, &bufsize, sizeof(bufsize));
	i += sizeof(bufsize);
	
	memcpy(sndbuf + i, &(msg.op), sizeof(msg.op));
	i += sizeof(msg.op);
	
	memcpy(sndbuf + i, msg.buf, msg.len);
	i += msg.len;

	// Assert i == bufsize;
	
	return Write(socket, sndbuf, bufsize);
}


