#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>

#include "dm.h"

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
	} else if (err != size) {
		printf("Warning: %d bytes received %d expected", err, size);
	} else {
		printf("Read() : Success\n");
	} 

	return err;
}

int
Socket(int domain, int type, int flags)
{
	int err = socket(domain, type, flags);
	if (err == -1) {
		perror("Socket():");
	} else {
		printf("Socket(): Success\n");
	}

	return err;
}

int
Write(int fd, void *buf, size_t size)
{
	int err = write(fd, buf, size);
	if (err == -1) {
		perror("Write():");
	} else {
		printf("Write(): Success\n");
	}
	return err;
}

int 
Socketpair(int domain, int type, int protocol, int socket_vector[2])
{
	int err = socketpair(domain, type, protocol, socket_vector);	
	if (err == -1) {
		perror("Socketpair():");
	} else {
		printf("Socketpair() : Success\n");
	}
	return err;
}

int
Bind(int socket, const struct sockaddr *addr, socklen_t addrlen)
{
	int err = bind(socket, addr, addrlen);
	if (err == -1) {
		perror("Bind():");
	} else {
		printf("Bind() : Success\n");
	}
	return err;
}

int
Accept(int socket, struct sockaddr *addr, socklen_t *addrlen)
{
	int err = accept(socket, addr, addrlen);
	if (err == -1) {
		perror("Accept():");
	} else {
		printf("Accept() : Success\n");
	}
	return err;
}

int
Connect(int socket, struct sockaddr *addr, socklen_t addrlen)
{
	int err = connect(socket, addr, addrlen);
	if (err == -1) {
		perror("Connect():");
	} else {
		printf("Connect() : Success\n");
	}
	return err;
}

int
Listen(int socket, int backlog)
{
	int err = listen(socket, backlog);
	if (err == -1) {
		perror("Listen():");
	} else {
		printf("Listen() : Success\n");
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
	} else {
		printf("Select(): Success\n");
	}
	return err;
}