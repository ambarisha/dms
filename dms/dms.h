#include <sys/types.h>

struct dmjob {
	int	 v_level;
	int	 family;
	long	 ftp_timeout;
	long	 http_timeout;
	off_t	 B_size;
	off_t	 S_size;
	long	 T_secs;
	long	 flags;
	int	 fd;
	int	 csock;

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

struct dmrep {
	int 	 status;
	int 	 errcode;
	char 	*errstr;
};

#define DEBUG			1

#define MAX_LISTEN_QUEUE	5
#define MINBUFSIZE		4096
