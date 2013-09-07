#ifndef _DM_H
#define _DM_H

#include <sys/param.h>
#include <sys/time.h>

#include <stdio.h>
#include <fetch.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

/* TODO : Fix the path, make sure the perms on it are good */
#define DMS_UDS_PATH	"/tmp/dms.uds"

#define	NO_CHKSUM	0
#define SHA1_CHKSUM	1
#define	MD5_CHKSUM	2

#define	MAX_CHKSUM_LEN	SHA_DIGEST_LENGTH /* TODO: Any better alternative? */

struct dmres {
	int	 status;
	int	 errcode;
	char	*errstr;
};

struct dmreq {
	int	 v_level;
	int	 family;
	long	 ftp_timeout;
	long	 http_timeout;
	off_t	 B_size;
	off_t	 S_size;
	long	 T_secs;
	int	 sha1;
	char	 sha1sum[SHA_DIGEST_LENGTH];

	int	 chksum_type;
	union {
		char	sha1sum[SHA_DIGEST_LENGTH];
		char	md5sum[MD5_DIGEST_LENGTH];
	} chksum;

	long	 flags;
#define		A_FLAG		(1 << 0)
#define		F_FLAG		(1 << 1)
#define		O_STDOUT	(1 << 2)
#define		R_FLAG		(1 << 3)
#define		U_FLAG		(1 << 4)
#define		d_FLAG		(1 << 5)
#define		i_FLAG		(1 << 6)
#define		l_FLAG		(1 << 7)
#define		m_FLAG		(1 << 8)
#define		n_FLAG		(1 << 9)
#define		p_FLAG		(1 << 10)
#define		r_FLAG		(1 << 11)
#define		s_FLAG		(1 << 12)
#define		V_TTY		(1 << 13)

	char	*i_filename;
	char	*URL;
	char	*path;
};

struct dmmsg {
	char 	 op;
	int 	 len;
	char 	*buf;
};

struct dmsumm {
	char		name[64];
	char		mirror[64];

	enum {
		RUNNING = 0,
		DONE,
		DUPLICATE
	} state;
	
	off_t		size;
	off_t		rcvd;
	long		eta;
};

struct xferstat {
	char		 name[64];
	struct timeval	 start;		/* start of transfer */
	struct timeval	 last;		/* time of last update */
	struct timeval	 last2;		/* time of previous last update */
	off_t		 size;		/* size of file per HTTP hdr */
	off_t		 offset;	/* starting offset in file */
	off_t		 rcvd;		/* bytes already received */
	off_t		 lastrcvd;	/* bytes received since last update */
};

#define		DMREQ			1
#define		DMRESP			2
#define		DMAUTHREQ		3
#define		DMAUTHRESP		4
#define		DMSIG			5
#define		DMSTAT			6
#define		DMDUMPREQ		7
#define		DMDUMPRESP		8

#endif /* _DMCLIENT_H */
