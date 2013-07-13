#ifndef _DM_H
#define _DM_H

#include <sys/param.h>
#include <sys/time.h>

#include <stdio.h>
#include <fetch.h>

/* TODO : Fix the path, make sure the perms on it are good */
#define DMS_UDS_PATH	"/tmp/dms.uds"

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

	char	*i_filename;
	char	*URL;
	char	*path;
};

struct dmmsg {
	char 	 op;
	int 	 len;
	char 	*buf;
};

#define		DMREQ			1
#define		DMRESP			2
#define		DMAUTHREQ		3
#define		DMAUTHRESP		4
#define		DMSIG			5

#endif /* _DMCLIENT_H */
