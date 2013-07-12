#include <sys/socket.h>
#include <sys/stat.h>

#include <stdint.h>
#include <err.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include "dms.h"
#include "dm.h"

static int	sigalrm;	/* SIGALRM received by client */
static int 	siginfo;	/* SIGINFO received by client */
static int 	sigint;		/* SIGINT received by client */
static int	handle_siginfo;	/* Yes or No */
static int	parent;

static void
stat_start(struct xferstat *xs, const char *name, off_t size, off_t offset)
{
	/*snprintf(xs->name, sizeof xs->name, "%s", name);
	gettimeofday(&xs->start, NULL);
	xs->last.tv_sec = xs->last.tv_usec = 0;
	xs->size = size;
	xs->offset = offset;
	xs->rcvd = offset;
	xs->lastrcvd = offset;
	if ((dmjob.flags & V_TTY) && dmjob.v_level > 0)
		stat_display(xs, 1);
	else if (v_level > 0)
		fprintf(stderr, "%-46s", xs->name);
	*/
}

static void
stat_end(struct xferstat *xs)
{
	/*
	gettimeofday(&xs->last, NULL);
	if (v_tty && v_level > 0) {
		stat_display(xs, 2);
		putc('\n', stderr);
	} else if (v_level > 0) {
		fprintf(stderr, "        %s %s\n",
		    stat_bytes(xs->size), stat_bps(xs));
	}
	*/
}

static void
stat_update(struct xferstat *xs, off_t rcvd)
{
	/*
	xs->rcvd = rcvd;
	if (v_tty && v_level > 0)
		stat_display(xs, 0);
	*/
}

static void
sig_handler(int sigusr1)
{
	int sig;
	struct msg msg;
	Peel(parent, &msg);

	// Assert msg.op == DMSIG
	
	sig = *(int *) &(msg.buf);
	
	switch(sig) {
	case SIGINFO:
		if (handle_siginfo == 1)
			siginfo = 1;
		break;
	case SIGINT:
		sigint = 1;
		break;
	default:
		/* unregistered signal received */
		break;
	}		

	free(msg.buf);
}

static void
alrm_handler(int sig)
{
	// Assert sig == SIGALRM
	sigalrm = 1;
}

static int
fetch(struct dmjob dmjob, char *buf)
{
	struct url *url;
	struct url_stat us;
	struct stat sb, nsb;
	struct xferstat xs;
	FILE *f, *of;
	size_t size, readcnt, wr;
	off_t count;
	char flags[8];
	const char *slash;
	char *tmppath;
	int r;
	unsigned timeout;
	char *ptr;

	f = of = NULL;
	tmppath = NULL;

	timeout = 0;
	*flags = 0;
	count = 0;

	/* set verbosity level */
	if (dmjob.v_level > 1)
		strcat(flags, "v");
	if (dmjob.v_level > 2)
		fetchDebug = 1;

	/* parse URL */
	url = NULL;
	if (*dmjob.URL == '\0') {
		warnx("empty URL");
		goto failure;
	}
	if ((url = fetchParseURL(dmjob.URL)) == NULL) {
		warnx("%s: parse error", dmjob.URL);
		goto failure;
	}

	/* if no scheme was specified, take a guess */
	if (!*url->scheme) {
		if (!*url->host)
			strcpy(url->scheme, SCHEME_FILE);
		else if (strncasecmp(url->host, "ftp.", 4) == 0)
			strcpy(url->scheme, SCHEME_FTP);
		else if (strncasecmp(url->host, "www.", 4) == 0)
			strcpy(url->scheme, SCHEME_HTTP);
	}

	/* common flags */
	switch (dmjob.family) {
	case PF_INET:
		strcat(flags, "4");
		break;
	case PF_INET6:
		strcat(flags, "6");
		break;
	}

	/* FTP specific flags */
	if (strcmp(url->scheme, SCHEME_FTP) == 0) {
		if (dmjob.flags & p_FLAG)
			strcat(flags, "p");
		if (dmjob.flags & d_FLAG)
			strcat(flags, "d");
		if (dmjob.flags & U_FLAG)
			strcat(flags, "l");
		timeout = dmjob.T_secs ? dmjob.T_secs : dmjob.ftp_timeout;
	}

	/* HTTP specific flags */
	if (strcmp(url->scheme, SCHEME_HTTP) == 0 ||
	    strcmp(url->scheme, SCHEME_HTTPS) == 0) {
		if ((dmjob.flags & d_FLAG))
			strcat(flags, "d");
		if ((dmjob.flags & A_FLAG))
			strcat(flags, "A");
		timeout = dmjob.T_secs ? dmjob.T_secs : dmjob.http_timeout;
		if (dmjob.flags & i_FLAG) {
			if (stat(dmjob.i_filename, &sb)) {
				warn("%s: stat()", dmjob.i_filename);
				goto failure;
			}
			url->ims_time = sb.st_mtime;
			strcat(flags, "i");
		}
	}

	/* set the protocol timeout. */
	fetchTimeout = timeout;

	/* just print size */
	if (dmjob.flags & s_FLAG) {
		if (timeout)
			alarm(timeout);
		r = fetchStat(url, &us, flags);
		if (timeout)
			alarm(0);
		if (sigalrm || sigint)
			goto signal;
		if (r == -1) {
			warnx("%s", fetchLastErrString);
			goto failure;
		}
		if (us.size == -1)
			printf("Unknown\n");
		else
			printf("%jd\n", (intmax_t)us.size);
		goto success;
	}

	/*
	 * If the -r flag was specified, we have to compare the local
	 * and remote files, so we should really do a fetchStat()
	 * first, but I know of at least one HTTP server that only
	 * sends the content size in response to GET requests, and
	 * leaves it out of replies to HEAD requests.  Also, in the
	 * (frequent) case that the local and remote files match but
	 * the local file is truncated, we have sufficient information
	 * before the compare to issue a correct request.  Therefore,
	 * we always issue a GET request as if we were sure the local
	 * file was a truncated copy of the remote file; we can drop
	 * the connection later if we change our minds.
	 */
	sb.st_size = -1;
	if (!(dmjob.flags & O_STDOUT)) {
		r = stat(dmjob.path, &sb);
		if (r == 0 && (dmjob.flags & r_FLAG) && S_ISREG(sb.st_mode)) {
			url->offset = sb.st_size;
		} else if (r == -1 || !S_ISREG(sb.st_mode)) {
			/*
			 * Whatever value sb.st_size has now is either
			 * wrong (if stat(2) failed) or irrelevant (if the
			 * path does not refer to a regular file)
			 */
			sb.st_size = -1;
		}
		if (r == -1 && errno != ENOENT) {
			warnx("%s: stat()", dmjob.path);
			goto failure;
		}
	}

	/* start the transfer */
	if (timeout)
		alarm(timeout);
	f = fetchXGet(url, &us, flags);
	if (timeout)
		alarm(0);
	if (sigalrm || sigint)
		goto signal;
	if (f == NULL) {
		warnx("%s: %s", dmjob.URL, fetchLastErrString);
		if ((dmjob.flags & i_FLAG) && strcmp(url->scheme, SCHEME_HTTP) == 0
		    && fetchLastErrCode == FETCH_OK
		    && strcmp(fetchLastErrString, "Not Modified") == 0) {
			/* HTTP Not Modified Response, return OK. */
			r = 0;
			goto done;
		} else
			goto failure;
	}
	if (sigint)
		goto signal;

	/* check that size is as expected */
	/*if (dmjob.S_size) {
		if (us.size == -1) {
			warnx("%s: size unknown", dmjob.URL);
		} else if (us.size != dmjob.S_size) {
			warnx("%s: size mismatch: expected %jd, actual %jd",
			    dmjob.URL, (intmax_t)dmjob.S_size, (intmax_t)us.size);
			goto failure;
		}
	}
	*/

	/* symlink instead of copy */
	if ((dmjob.flags & l_FLAG) && strcmp(url->scheme, "file") == 0 && !(dmjob.flags & O_STDOUT)) {
		if (symlink(url->doc, dmjob.path) == -1) {
			warn("%s: symlink()", dmjob.path);
			goto failure;
		}
		goto success;
	}

	if (us.size == -1 && !(dmjob.flags & O_STDOUT) && dmjob.v_level > 0)
		warnx("%s: size of remote file is not known", dmjob.URL);
	if (dmjob.v_level > 1) {
		if (sb.st_size != -1)
			fprintf(stderr, "local size / mtime: %jd / %ld\n",
			    (intmax_t)sb.st_size, (long)sb.st_mtime);
		if (us.size != -1)
			fprintf(stderr, "remote size / mtime: %jd / %ld\n",
			    (intmax_t)us.size, (long)us.mtime);
	}

	/* open output file */
	if (dmjob.flags & O_STDOUT) {
		/* output to stdout */
		of = stdout;
	} else if ((dmjob.flags & r_FLAG) && sb.st_size != -1) {
		/* resume mode, local file exists */
		if (!(dmjob.flags & F_FLAG) && us.mtime && sb.st_mtime != us.mtime) {
			/* no match! have to refetch */
			fclose(f);
			/* if precious, warn the user and give up */
			if ((dmjob.flags & R_FLAG)) {
				warnx("%s: local modification time "
				    "does not match remote", dmjob.path);
				goto failure_keep;
			}
		} else if (url->offset > sb.st_size) {
			/* gap between what we asked for and what we got */
			warnx("%s: gap in resume mode", dmjob.URL);
			fclose(of);
			of = NULL;
			/* picked up again later */
		} else if (us.size != -1) {
			if (us.size == sb.st_size)
				/* nothing to do */
				goto success;
			if (sb.st_size > us.size) {
				/* local file too long! */
				warnx("%s: local file (%jd bytes) is longer "
				    "than remote file (%jd bytes)", dmjob.path,
				    (intmax_t)sb.st_size, (intmax_t)us.size);
				goto failure;
			}
			/* we got it, open local file */
			if ((of = fopen(dmjob.path, "r+")) == NULL) {
				warn("%s: fopen()", dmjob.path);
				goto failure;
			}

			/* check that it didn't move under our feet */
			if (fstat(fileno(of), &nsb) == -1) {
				/* can't happen! */
				warn("%s: fstat()", dmjob.path);
				goto failure;
			}
			if (nsb.st_dev != sb.st_dev ||
			    nsb.st_ino != nsb.st_ino ||
			    nsb.st_size != sb.st_size) {
				warnx("%s: file has changed", dmjob.URL);
				fclose(of);
				of = NULL;
				sb = nsb;
				/* picked up again later */
			}
		}
		/* seek to where we left off */
		if (of != NULL && fseeko(of, url->offset, SEEK_SET) != 0) {
			warn("%s: fseeko()", dmjob.path);
			fclose(of);
			of = NULL;
			/* picked up again later */
		}
	} else if ((dmjob.flags & m_FLAG) && sb.st_size != -1) {
		/* mirror mode, local file exists */
		if (sb.st_size == us.size && sb.st_mtime == us.mtime)
			goto success;
	}

	if (of == NULL) {
		/*
		 * We don't yet have an output file; either this is a
		 * vanilla run with no special flags, or the local and
		 * remote files didn't match.
		 */

		if (url->offset > 0) {
			/*
			 * We tried to restart a transfer, but for
			 * some reason gave up - so we have to restart
			 * from scratch if we want the whole file
			 */
			url->offset = 0;
			if ((f = fetchXGet(url, &us, flags)) == NULL) {
				warnx("%s: %s", dmjob.URL, fetchLastErrString);
				goto failure;
			}
			if (sigint)
				goto signal;
		}

		/* construct a temp file name */
		if (sb.st_size != -1 && S_ISREG(sb.st_mode)) {
			if ((slash = strrchr(dmjob.path, '/')) == NULL)
				slash = dmjob.path;
			else
				++slash;
			asprintf(&tmppath, "%.*s.dm.XXXXXX.%s",
			    (int)(slash - dmjob.path), dmjob.path, slash);
			if (tmppath != NULL) {
				if (mkstemps(tmppath, strlen(slash) + 1) == -1) {
					warn("%s: mkstemps()", dmjob.path);
					goto failure;
				}
				of = fopen(tmppath, "w");
				chown(tmppath, sb.st_uid, sb.st_gid);
				chmod(tmppath, sb.st_mode & ALLPERMS);
			}
		}
		if (of == NULL)
			of = fopen(dmjob.path, "w");
		if (of == NULL) {
			warn("%s: open()", dmjob.path);
			goto failure;
		}
	}
	count = url->offset;

	/* start the counter */
	stat_start(&xs, dmjob.path, us.size, count);

	sigalrm = siginfo = sigint = 0;

	/* suck in the data */
	handle_siginfo = 1;
	while (!sigint) {
		if (us.size != -1 && us.size - count < dmjob.B_size &&
		    us.size - count >= 0)
			size = us.size - count;
		else
			size = dmjob.B_size;
		if (siginfo) {
			stat_end(&xs);
			siginfo = 0;
		}

		if (size == 0)
			break;

		if ((readcnt = fread(buf, 1, size, f)) < size) {
			if (ferror(f) && errno == EINTR && !sigint)
				clearerr(f);
			else if (readcnt == 0)
				break;
		}

		stat_update(&xs, count += readcnt);
		for (ptr = buf; readcnt > 0; ptr += wr, readcnt -= wr)
			if ((wr = fwrite(ptr, 1, readcnt, of)) < readcnt) {
				if (ferror(of) && errno == EINTR && !sigint)
					clearerr(of);
				else
					break;
			}
		if (readcnt != 0)
			break;
	}
	if (!sigalrm)
		sigalrm = ferror(f) && errno == ETIMEDOUT;
	handle_siginfo = 0;

	stat_end(&xs);

	/*
	 * If the transfer timed out or was interrupted, we still want to
	 * set the mtime in case the file is not removed (-r or -R) and
	 * the user later restarts the transfer.
	 */
 signal:
	/* set mtime of local file */
	if (!(dmjob.flags & n_FLAG) && us.mtime && !(dmjob.flags & O_STDOUT) && of != NULL &&
	    (stat(dmjob.path, &sb) != -1) && sb.st_mode & S_IFREG) {
		struct timeval tv[2];

		fflush(of);
		tv[0].tv_sec = (long)(us.atime ? us.atime : us.mtime);
		tv[1].tv_sec = (long)us.mtime;
		tv[0].tv_usec = tv[1].tv_usec = 0;
		if (utimes(tmppath ? tmppath : dmjob.path, tv))
			warn("%s: utimes()", tmppath ? tmppath : dmjob.path);
	}

	/* timed out or interrupted? */
	if (sigalrm)
		warnx("transfer timed out");
	if (sigint) {
		warnx("transfer interrupted");
		goto failure;
	}

	/* timeout / interrupt before connection completley established? */
	if (f == NULL)
		goto failure;

	if (!sigalrm) {
		/* check the status of our files */
		if (ferror(f))
			warn("%s", dmjob.URL);
		if (ferror(of))
			warn("%s", dmjob.path);
		if (ferror(f) || ferror(of))
			goto failure;
	}

	/* did the transfer complete normally? */
	if (us.size != -1 && count < us.size) {
		warnx("%s appears to be truncated: %jd/%jd bytes",
		    dmjob.path, (intmax_t)count, (intmax_t)us.size);
		goto failure_keep;
	}

	/*
	 * If the transfer timed out and we didn't know how much to
	 * expect, assume the worst (i.e. we didn't get all of it)
	 */
	if (sigalrm && us.size == -1) {
		warnx("%s may be truncated", dmjob.path);
		goto failure_keep;
	}

 success:

	r = 0;
	if (tmppath != NULL && rename(tmppath, dmjob.path) == -1) {
		warn("%s: rename()", dmjob.path);
		goto failure_keep;
	}
	goto done;
 failure:
	if (of && of != stdout && !(dmjob.flags & R_FLAG) && !(dmjob.flags & r_FLAG))
		if (stat(dmjob.path, &sb) != -1 && (sb.st_mode & S_IFREG))
			unlink(tmppath ? tmppath : dmjob.path);
	if ((dmjob.flags & R_FLAG) && tmppath != NULL && sb.st_size == -1)
		rename(tmppath, dmjob.path); /* ignore errors here */
 failure_keep:
	r = -1;
	goto done;
 done:
	if (f)
		fclose(f);
	if (of && of != stdout)
		fclose(of);
	if (url)
		fetchFreeURL(url);
	if (tmppath != NULL)
		free(tmppath);
	return (r);
}

static void
send_report(int parent, struct dmrep report, char op)
{
	char *buf;
	int bufsize = sizeof(report) - sizeof(report.errstr);
	int errlen = strlen(report.errstr);
	bufsize +=  errlen;	

	buf = (char *) Malloc(bufsize);
	int i = 0;
	
	memcpy(buf + i, &(report.status), sizeof(report.status));
	i += sizeof(report.status);

	memcpy(buf + i, &(report.errcode), sizeof(report.errcode));
	i += sizeof(report.errcode);

	strcpy(buf + i, report.errstr);
	i += errlen;
	
	struct msg msg;
	msg.op = op;
	msg.buf = buf;
	msg.len = bufsize;
	send_msg(parent, msg);
	
	free(buf);
}

void
run_worker(struct dmjob dmjob, int psock)
{
	parent = psock;
	/* allocate buffer */
	char *buf;
	if (dmjob.B_size < MINBUFSIZE)
		dmjob.B_size = MINBUFSIZE;
	buf = (char *) Malloc(dmjob.B_size);

	/* Register sig_handler SIGUSR1 */
	handle_siginfo = 0;
	signal(SIGUSR1, sig_handler);
	signal(SIGALRM, alrm_handler);

	int err = fetch(dmjob, buf);
	struct dmrep report;
	report.status = err;
	report.errcode = fetchLastErrCode;
	report.errstr = fetchLastErrString;	
	send_report(parent, report, DMRESP);
}
