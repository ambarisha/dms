/*-
 * Copyright (c) 2000-2011 Dag-Erling Smørgrav
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <fetch.h>

#include "dmget.h"
#include "dm.h"

#define MINBUFSIZE	4096
#define TIMEOUT		120

/* Option flags */
static int	 A_flag;	/*    -A: do not follow 302 redirects */
static int	 a_flag;	/*    -a: auto retry */
static off_t	 B_size;	/*    -B: buffer size */
static int	 b_flag;	/*!   -b: workaround TCP bug */
static char    *c_dirname;	/*    -c: remote directory */
static int	 d_flag;	/*    -d: direct connection */
static int	 F_flag;	/*    -F: restart without checking mtime  */
static char	*f_filename;	/*    -f: file to fetch */
static char	*h_hostname;	/*    -h: host to fetch from */
static int	 i_flag;	/*    -i: specify file for mtime comparison */
static char	*i_filename;	/*        name of input file */
static int	 l_flag;	/*    -l: link rather than copy file: URLs */
static int	 m_flag;	/* -[Mm]: mirror mode */
static char	*N_filename;	/*    -N: netrc file name */
static int	 n_flag;	/*    -n: do not preserve modification time */
static int	 o_flag;	/*    -o: specify output file */
static int	 o_directory;	/*        output file is a directory */
static char	*o_filename;	/*        name of output file */
static int	 o_stdout;	/*        output file is stdout */
static int	 once_flag;	/*    -1: stop at first successful file */
static int	 p_flag;	/* -[Pp]: use passive FTP */
static int	 R_flag;	/*    -R: don't delete partial files */
static int	 r_flag;	/*    -r: restart previous transfer */
static off_t	 S_size;        /*    -S: require size to match */
static int	 s_flag;        /*    -s: show size, don't fetch */
static long	 T_secs;	/*    -T: transfer timeout in seconds */
static int	 t_flag;	/*!   -t: workaround TCP bug */
static int	 U_flag;	/*    -U: do not use high ports */
static int	 v_level = 1;	/*    -v: verbosity level */
static int	 v_tty;		/*        stdout is a tty */
static pid_t	 pgrp;		/*        our process group */
static long	 w_secs;	/*    -w: retry delay */
static int	 family = PF_UNSPEC;	/* -[46]: address family to use */

static int	 sigint;	/* SIGINT received */

static long	 ftp_timeout = TIMEOUT;	/* default timeout for FTP transfers */
static long	 http_timeout = TIMEOUT;/* default timeout for HTTP transfers */
static char	*buf;		/* transfer buffer */

/*
 * Compute and display ETA
 */
static const char *
stat_eta(struct xferstat *xs)
{
	static char str[16];
	long elapsed, eta;
	off_t received, expected;

	elapsed = xs->last.tv_sec - xs->start.tv_sec;
	received = xs->rcvd - xs->offset;
	expected = xs->size - xs->rcvd;
	eta = (long)((double)elapsed * expected / received);
	if (eta > 3600)
		snprintf(str, sizeof str, "%02ldh%02ldm",
		    eta / 3600, (eta % 3600) / 60);
	else if (eta > 0)
		snprintf(str, sizeof str, "%02ldm%02lds",
		    eta / 60, eta % 60);
	else
		snprintf(str, sizeof str, "%02ldm%02lds",
		    elapsed / 60, elapsed % 60);
	return (str);
}

/*
 * Format a number as "xxxx YB" where Y is ' ', 'k', 'M'...
 */
static const char *prefixes = " kMGTP";
static const char *
stat_bytes(off_t bytes)
{
	static char str[16];
	const char *prefix = prefixes;

	while (bytes > 9999 && prefix[1] != '\0') {
		bytes /= 1024;
		prefix++;
	}
	snprintf(str, sizeof str, "%4jd %cB", (intmax_t)bytes, *prefix);
	return (str);
}

/*
 * Compute and display transfer rate
 */
static const char *
stat_bps(struct xferstat *xs)
{
	static char str[16];
	double delta, bps;

	delta = (xs->last.tv_sec + (xs->last.tv_usec / 1.e6))
	    - (xs->last2.tv_sec + (xs->last2.tv_usec / 1.e6));

	if (delta == 0.0) {
		snprintf(str, sizeof str, "?? Bps");
	} else {
		bps = (xs->rcvd - xs->lastrcvd) / delta;
		snprintf(str, sizeof str, "%sps", stat_bytes((off_t)bps));
	}
	return (str);
}

/*
 * Update the stats display
 */
static void
stat_display(struct xferstat *xs, int force)
{
	struct timeval now;
	int ctty_pgrp;

	/* check if we're the foreground process */
	if (ioctl(STDERR_FILENO, TIOCGPGRP, &ctty_pgrp) == -1 ||
	    (pid_t)ctty_pgrp != pgrp)
		return;

	gettimeofday(&now, NULL);
	if (!force && now.tv_sec <= xs->last.tv_sec)
		return;
	xs->last2 = xs->last;
	xs->last = now;

	fprintf(stderr, "\r%-46.46s", xs->name);
	if (xs->size <= 0) {
		setproctitle("%s [%s]", xs->name, stat_bytes(xs->rcvd));
		fprintf(stderr, "        %s", stat_bytes(xs->rcvd));
	} else {
		setproctitle("%s [%d%% of %s]", xs->name,
		    (int)((100.0 * xs->rcvd) / xs->size),
		    stat_bytes(xs->size));
		fprintf(stderr, "%3d%% of %s",
		    (int)((100.0 * xs->rcvd) / xs->size),
		    stat_bytes(xs->size));
	}
	if (force == 2) {
		xs->lastrcvd = xs->offset;
		xs->last2 = xs->start;
	}
	fprintf(stderr, " %s", stat_bps(xs));
	if ((xs->size > 0 && xs->rcvd > 0 &&
	     xs->last.tv_sec >= xs->start.tv_sec + 3) ||
	    force == 2)
		fprintf(stderr, " %s", stat_eta(xs));
	xs->lastrcvd = xs->rcvd;
}

/*
 * Ask the user for authentication details
 */
static int
query_auth(struct url *URL)
{
	struct termios tios;
	tcflag_t saved_flags;
	int i, nopwd;

	fprintf(stderr, "Authentication required for <%s://%s:%d/>!\n",
	    URL->scheme, URL->host, URL->port);

	fprintf(stderr, "Login: ");
	if (fgets(URL->user, sizeof URL->user, stdin) == NULL)
		return (-1);
	for (i = strlen(URL->user); i >= 0; --i)
		if (URL->user[i] == '\r' || URL->user[i] == '\n')
			URL->user[i] = '\0';

	fprintf(stderr, "Password: ");
	if (tcgetattr(STDIN_FILENO, &tios) == 0) {
		saved_flags = tios.c_lflag;
		tios.c_lflag &= ~ECHO;
		tios.c_lflag |= ECHONL|ICANON;
		tcsetattr(STDIN_FILENO, TCSAFLUSH|TCSASOFT, &tios);
		nopwd = (fgets(URL->pwd, sizeof URL->pwd, stdin) == NULL);
		tios.c_lflag = saved_flags;
		tcsetattr(STDIN_FILENO, TCSANOW|TCSASOFT, &tios);
	} else {
		nopwd = (fgets(URL->pwd, sizeof URL->pwd, stdin) == NULL);
	}
	if (nopwd)
		return (-1);
	for (i = strlen(URL->pwd); i >= 0; --i)
		if (URL->pwd[i] == '\r' || URL->pwd[i] == '\n')
			URL->pwd[i] = '\0';

	return (0);
}

/*
 * Fetch a file
 */
static int
fetch(char *URL, const char *path)
{
	struct dmreq dmreq;
	dmreq.v_level = v_level;
	dmreq.family = family;
	dmreq.ftp_timeout = ftp_timeout;
	dmreq.http_timeout = http_timeout;
	dmreq.B_size = B_size;
	dmreq.S_size = S_size;
	dmreq.URL = URL;
	dmreq.path = path;
	dmreq.T_secs = T_secs;

	if (i_flag) dmreq.i_filename = i_filename;
	else dmreq.i_filename = "";

	dmreq.flags = 0;
	if (A_flag) dmreq.flags |= A_FLAG;
	if (F_flag) dmreq.flags |= F_FLAG;
	if (R_flag) dmreq.flags |= R_FLAG;
	if (U_flag) dmreq.flags |= U_FLAG;
	if (d_flag) dmreq.flags |= d_FLAG;
	if (i_flag) dmreq.flags |= i_FLAG;
	if (l_flag) dmreq.flags |= l_FLAG;
	if (m_flag) dmreq.flags |= m_FLAG;
	if (n_flag) dmreq.flags |= n_FLAG;
	if (p_flag) dmreq.flags |= p_FLAG;
	if (r_flag) dmreq.flags |= r_FLAG;
	if (s_flag) dmreq.flags |= s_FLAG;
	if (o_stdout) dmreq.flags |= O_STDOUT;
	if (v_tty) dmreq.flags |= V_TTY;
	
	dmStatDisplayMethod = stat_display;
	return (dmget(dmreq));
}

static void
usage(void)
{
	fprintf(stderr, "%s\n%s\n%s\n%s\n",
"usage: fetch [-146AadFlMmnPpqRrsUv] [-B bytes] [-N file] [-o file] [-S bytes]",
"       [-T seconds] [-w seconds] [-i file] URL ...",
"       fetch [-146AadFlMmnPpqRrsUv] [-B bytes] [-N file] [-o file] [-S bytes]",
"       [-T seconds] [-w seconds] [-i file] -h host -f file [-c dir]");
}


/*
 * Entry point
 */
int
main(int argc, char *argv[])
{
	struct stat sb;
	struct sigaction sa;
	const char *p, *s;
	char *end, *q;
	int c, e, r;

	while ((c = getopt(argc, argv,
	    "146AaB:bc:dFf:Hh:i:lMmN:nPpo:qRrS:sT:tUvw:")) != -1)
		switch (c) {
		case '1':
			once_flag = 1;
			break;
		case '4':
			family = PF_INET;
			break;
		case '6':
			family = PF_INET6;
			break;
		case 'A':
			A_flag = 1;
			break;
		case 'a':
			a_flag = 1;
			break;
		case 'B':
			B_size = (off_t)strtol(optarg, &end, 10);
			if (*optarg == '\0' || *end != '\0')
				errx(1, "invalid buffer size (%s)", optarg);
			break;
		case 'b':
			warnx("warning: the -b option is deprecated");
			b_flag = 1;
			break;
		case 'c':
			c_dirname = optarg;
			break;
		case 'd':
			d_flag = 1;
			break;
		case 'F':
			F_flag = 1;
			break;
		case 'f':
			f_filename = optarg;
			break;
		case 'H':
			warnx("the -H option is now implicit, "
			    "use -U to disable");
			break;
		case 'h':
			h_hostname = optarg;
			break;
		case 'i':
			i_flag = 1;
			i_filename = optarg;
			break;
		case 'l':
			l_flag = 1;
			break;
		case 'o':
			o_flag = 1;
			o_filename = optarg;
			break;
		case 'M':
		case 'm':
			if (r_flag)
				errx(1, "the -m and -r flags "
				    "are mutually exclusive");
			m_flag = 1;
			break;
		case 'N':
			N_filename = optarg;
			break;
		case 'n':
			n_flag = 1;
			break;
		case 'P':
		case 'p':
			p_flag = 1;
			break;
		case 'q':
			v_level = 0;
			break;
		case 'R':
			R_flag = 1;
			break;
		case 'r':
			if (m_flag)
				errx(1, "the -m and -r flags "
				    "are mutually exclusive");
			r_flag = 1;
			break;
		case 'S':
			S_size = (off_t)strtol(optarg, &end, 10);
			if (*optarg == '\0' || *end != '\0')
				errx(1, "invalid size (%s)", optarg);
			break;
		case 's':
			s_flag = 1;
			break;
		case 'T':
			T_secs = strtol(optarg, &end, 10);
			if (*optarg == '\0' || *end != '\0')
				errx(1, "invalid timeout (%s)", optarg);
			break;
		case 't':
			t_flag = 1;
			warnx("warning: the -t option is deprecated");
			break;
		case 'U':
			U_flag = 1;
			break;
		case 'v':
			v_level++;
			break;
		case 'w':
			a_flag = 1;
			w_secs = strtol(optarg, &end, 10);
			if (*optarg == '\0' || *end != '\0')
				errx(1, "invalid delay (%s)", optarg);
			break;
		default:
			usage();
			exit(1);
		}

	argc -= optind;
	argv += optind;

	if (h_hostname || f_filename || c_dirname) {
		if (!h_hostname || !f_filename || argc) {
			usage();
			exit(1);
		}
		/* XXX this is a hack. */
		if (strcspn(h_hostname, "@:/") != strlen(h_hostname))
			errx(1, "invalid hostname");
		if (asprintf(argv, "ftp://%s/%s/%s", h_hostname,
		    c_dirname ? c_dirname : "", f_filename) == -1)
			errx(1, "%s", strerror(ENOMEM));
		argc++;
	}

	if (!argc) {
		usage();
		exit(1);
	}

	/* allocate buffer */
	if (B_size < MINBUFSIZE)
		B_size = MINBUFSIZE;
	if ((buf = malloc(B_size)) == NULL)
		errx(1, "%s", strerror(ENOMEM));

	/* timeouts */
	if ((s = getenv("FTP_TIMEOUT")) != NULL) {
		ftp_timeout = strtol(s, &end, 10);
		if (*s == '\0' || *end != '\0' || ftp_timeout < 0) {
			warnx("FTP_TIMEOUT (%s) is not a positive integer", s);
			ftp_timeout = 0;
		}
	}
	if ((s = getenv("HTTP_TIMEOUT")) != NULL) {
		http_timeout = strtol(s, &end, 10);
		if (*s == '\0' || *end != '\0' || http_timeout < 0) {
			warnx("HTTP_TIMEOUT (%s) is not a positive integer", s);
			http_timeout = 0;
		}
	}

	/* signal handling */
	sa.sa_flags = 0;
	sa.sa_handler = dm_sighandler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGALRM, &sa, NULL);
	sa.sa_flags = SA_RESETHAND;
	sigaction(SIGINT, &sa, NULL);
	dmRestartCalls = 0;

	/* output file */
	if (o_flag) {
		if (strcmp(o_filename, "-") == 0) {
			o_stdout = 1;
		} else if (stat(o_filename, &sb) == -1) {
			if (errno == ENOENT) {
				if (argc > 1)
					errx(1, "%s is not a directory",
					    o_filename);
			} else {
				err(1, "%s", o_filename);
			}
		} else {
			if (sb.st_mode & S_IFDIR)
				o_directory = 1;
		}
	}

	/* check if output is to a tty (for progress report) */
	v_tty = isatty(STDERR_FILENO);
	if (v_tty)
		pgrp = getpgrp();

	r = 0;

	/* authentication */
	if (v_tty)
		dmAuthMethod = query_auth;
	if (N_filename != NULL)
		if (setenv("NETRC", N_filename, 1) == -1)
			err(1, "setenv: cannot set NETRC=%s", N_filename);

	while (argc) {
		if ((p = strrchr(*argv, '/')) == NULL)
			p = *argv;
		else
			p++;

		if (!*p)
			p = "dm.out";

		dmLastErrCode = 0;

		if (o_flag) {
			if (o_stdout) {
				e = fetch(*argv, "-");
			} else if (o_directory) {
				asprintf(&q, "%s/%s", o_filename, p);
				e = fetch(*argv, q);
				free(q);
			} else {
				e = fetch(*argv, o_filename);
			}
		} else {
			e = fetch(*argv, p);
		}

		if (sigint)
			kill(getpid(), SIGINT);

		if (e == 0 && once_flag)
			exit(0);

		if (e) {
			r = 1;
			if ((dmLastErrCode
			    && dmLastErrCode != FETCH_UNAVAIL
			    && dmLastErrCode != FETCH_MOVED
			    && dmLastErrCode != FETCH_URL
			    && dmLastErrCode != FETCH_RESOLV
			    && dmLastErrCode != FETCH_UNKNOWN)) {
				if (w_secs && v_level)
					fprintf(stderr, "Waiting %ld seconds "
					    "before retrying\n", w_secs);
				if (w_secs)
					sleep(w_secs);
				if (a_flag)
					continue;
			}
		}

		argc--, argv++;
	}

	exit(r);
}
