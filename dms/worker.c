#include <sys/socket.h>
#include <sys/stat.h>

#include <stdint.h>
#include <err.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

#include "dms.h"
#include "dm.h"


static const char 	*prefixes = " kMGTP";
extern struct dmjob 	*jobs;
extern pthread_mutex_t	 job_queue_mutex;

#define	TMP_EXT		".tmp"

static int
authenticate(struct url *url)
{
	struct dmmsg msg;
	struct dmjob *cur;
	int bufsize = 0, i = 0, schlen, hlen, ret;

	schlen = strlen(url->scheme) + 1;
	hlen = strlen(url->host) + 1;
	bufsize += schlen + hlen + sizeof(url->port);

	msg.buf = (char *) malloc(bufsize);
	if (msg.buf == NULL) {
		fprintf(stderr, "fetch: authenticate: Insufficient memory\n");
		return -1;
	}

	strcpy(msg.buf, url->scheme);
	i += schlen;

	strcpy(msg.buf + i, url->host);
	i += hlen;

	*(int *) (msg.buf + i) = url->port;

	msg.op = DMAUTHREQ;
	msg.len = bufsize;

	/* Acquire job queue lock */
	ret = pthread_mutex_lock(&job_queue_mutex);
	if (ret == -1) {
		fprintf(stderr, "handle_request: Attempt to acquire"
				" job queue mutex failed\n");
		return -1;
	}

	cur = jobs;
	while (cur != NULL) {
		/* TODO: May be a more thorough comparison? */
		if (cur->url != url) {
			cur = cur->next;
			continue;
		}


		/* TODO: How do we figure out which request's 
		 * authentication credentials to use ???
		 * */

	}

	ret = pthread_mutex_unlock(&job_queue_mutex);
	if (ret == -1) {
		fprintf(stderr, "handle_request: Couldn't release "
				"job queue lock\n");

		return -1;
	}
	/* Job queue lock released */

	return 1;
}

static int
compare_jobs(struct dmjob *j1, struct dmjob *j2)
{
	return strcmp(j1->request->URL, j2->request->URL);
}

static void
stat_send(struct xferstat *xs, int force)
{
	int ret;
	struct dmjob *cur;
	struct dmmsg msg;
	pthread_t  self = pthread_self();

	char *buf = (char *) malloc(sizeof(struct xferstat) + sizeof(force));
	if (buf == NULL) {
		fprintf(stderr,  "stat_send: Insufficient memory\n");
		return;
	}

	*((int *) buf) = force;
	
	memcpy(buf + sizeof(force), xs, sizeof(struct xferstat));

	msg.op = DMSTAT;
	msg.buf = buf; 
	msg.len = sizeof(*xs) + sizeof(force);

	/* Acquire job queue lock */
	ret = pthread_mutex_lock(&job_queue_mutex);
	if (ret == -1) {
		fprintf(stderr, "handle_request: Attempt to acquire"
				" job queue mutex failed\n");
		goto done;
	}

	cur = jobs;
	while (cur != NULL) {
		if (pthread_equal(self, cur->worker) != 0)	
			send_dmmsg(cur->client, msg);
		cur = cur->next;
	}

	ret = pthread_mutex_unlock(&job_queue_mutex);
	if (ret == -1) {
		fprintf(stderr, "handle_request: Couldn't release "
				"job queue lock\n");
	}
	/* Job queue lock released */

done:
	free(buf);
	return;
}

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

static void
stat_start(struct xferstat *xs, const char *name, off_t size,
	off_t offset, struct dmjob *dmjob)
{
	snprintf(xs->name, sizeof xs->name, "%s", name);
	gettimeofday(&xs->start, NULL);
	xs->last.tv_sec = xs->last.tv_usec = 0;
	xs->size = size;
	xs->offset = offset;
	xs->rcvd = offset;
	xs->lastrcvd = offset;
	
	update_mirror(dmjob->mirror , xs);

	if ((dmjob->request->flags & V_TTY) && dmjob->request->v_level > 0)
		stat_send(xs, 1);
	else if (dmjob->request->v_level > 0)
		fprintf(stderr, "%-46s", xs->name);
}

static void
stat_end(struct xferstat *xs, struct dmjob *dmjob)
{
	gettimeofday(&xs->last, NULL);
	update_mirror(dmjob->mirror , xs);
	if ((dmjob->request->flags & V_TTY) && dmjob->request->v_level > 0) {
		stat_send(xs, 2);
		putc('\n', stderr);
	} else if (dmjob->request->v_level > 0) {
		fprintf(stderr, "        %s %s\n",
		    stat_bytes(xs->size), stat_bps(xs));
	}
}

static void
stat_update(struct xferstat *xs, off_t rcvd, struct dmjob *dmjob)
{
	xs->rcvd = rcvd;
	update_mirror(dmjob->mirror , xs);
	if ((dmjob->request->flags & V_TTY) && dmjob->request->v_level > 0)
		stat_send(xs, 0);
}

static void
select_mirror(struct dmjob *dmjob)
{
	dmjob->mirror = get_mirror();
	strcpy(dmjob->url->host, dmjob->mirror->name);
	strcpy(dmjob->request->URL, dmjob->mirror->name);
	strcat(dmjob->request->URL, dmjob->url->doc);
}

static int
mk_url(struct dmjob *dmjob, char *flags)
{
	struct dmreq *dmreq = dmjob->request;
	struct stat sb;
	int r;

	if (dmjob->url != NULL)
		return 0;

	/* set verbosity level */
	if (dmreq->v_level > 1)
		strcat(flags, "v");
	if (dmreq->v_level > 2)
		fetchDebug = 1;

	/* parse URL */
	if (*dmreq->URL == '\0') {
		fprintf(stderr, "warning: mk_url: URL empty\n");
		goto failure;
	}

	if ((dmjob->url = fetchParseURL(dmreq->URL)) == NULL) {
		warnx("%s: parse error", dmreq->URL);
		goto failure;
	}

	/* Replace host name with the mirror name */
	select_mirror(dmjob);

	if (!*(dmjob->url->scheme)) {
		if (!*(dmjob->url->host))
			strcpy(dmjob->url->scheme, SCHEME_FILE);
		else if (strncasecmp(dmjob->url->host, "ftp.", 4) == 0)
			strcpy(dmjob->url->scheme, SCHEME_FTP);
		else if (strncasecmp(dmjob->url->host, "www.", 4) == 0)
			strcpy(dmjob->url->scheme, SCHEME_HTTP);
	}

	/* common flags */
	switch (dmreq->family) {
	case PF_INET:
		strcat(flags, "4");
		break;
	case PF_INET6:
		strcat(flags, "6");
		break;
	}

	/* FTP specific flags */
	if (strcmp(dmjob->url->scheme, SCHEME_FTP) == 0) {
		if (dmreq->flags & p_FLAG)
			strcat(flags, "p");
		if (dmreq->flags & d_FLAG)
			strcat(flags, "d");
		if (dmreq->flags & U_FLAG)
			strcat(flags, "l");
		dmjob->timeout = dmreq->T_secs ? dmreq->T_secs : dmreq->ftp_timeout;
	}

	/* HTTP specific flags */
	if (strcmp(dmjob->url->scheme, SCHEME_HTTP) == 0 ||
	    strcmp(dmjob->url->scheme, SCHEME_HTTPS) == 0) {
		if ((dmreq->flags & d_FLAG))
			strcat(flags, "d");
		if ((dmreq->flags & A_FLAG))
			strcat(flags, "A");
		dmjob->timeout = dmreq->T_secs ? dmreq->T_secs : dmreq->http_timeout;
		if (dmreq->flags & i_FLAG) {
			if (stat(dmreq->i_filename, &sb)) {
				warn("%s: stat()", dmreq->i_filename);
				goto failure;
			}
			dmjob->url->ims_time = sb.st_mtime;
			strcat(flags, "i");
		}
	}

	/* set the protocol timeout. */
	fetchTimeout = dmjob->timeout;
	r = 0;
	goto success;

signal:
	/* report that we were timedout/interrupted */
failure:
	free(dmjob->url->doc);
	free(dmjob->url);
	dmjob->url = NULL;
	r = -1;
success:
	return (r);
}

static int
fetch(struct dmjob *dmjob, FILE *f, struct url_stat us)
{
	struct stat sb, nsb;
	struct xferstat xs;
	FILE *of;
	size_t size, readcnt, wr;
	off_t count;
	char flags[8];
	const char *slash;
	char *tmppath;
	int r;
	char *ptr;
	char *buf;
	struct dmreq *dmreq = dmjob->request;

	of = NULL;
	tmppath = NULL;

	dmjob->timeout = 0;
	*flags = 0;
	count = 0;
	
	r = mk_url(dmjob, flags);
	if (r == -1)
		return -1;

	/* Initialize signal flags */
	dmjob->sigint = 0;
	dmjob->sigalrm = 0;
	dmjob->siginfo = 0;

	/* Set timeout */
	if (strcmp(dmjob->url->scheme, SCHEME_FTP) == 0)
		dmjob->timeout = dmreq->T_secs ? dmreq->T_secs : dmreq->ftp_timeout;
	else if (strcmp(dmjob->url->scheme, SCHEME_HTTP) == 0 ||
	    strcmp(dmjob->url->scheme, SCHEME_HTTPS) == 0) 
		dmjob->timeout = dmreq->T_secs ? dmreq->T_secs : dmreq->http_timeout;

	/* set the protocol timeout. */
	fetchTimeout = dmjob->timeout;

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
	if (!(dmreq->flags & O_STDOUT)) {
		r = stat(dmreq->path, &sb);
		if (r == 0 && (dmreq->flags & r_FLAG) && S_ISREG(sb.st_mode)) {
			dmjob->url->offset = sb.st_size;
		} else if (r == -1 || !S_ISREG(sb.st_mode)) {
			/*
			 * Whatever value sb.st_size has now is either
			 * wrong (if stat(2) failed) or irrelevant (if the
			 * path does not refer to a regular file)
			 */
			sb.st_size = -1;
		}
		if (r == -1 && errno != ENOENT) {
			warnx("%s: stat()", dmreq->path);
			goto failure;
		}
	}

	/* start the transfer */
	if (dmjob->timeout)
		alarm(dmjob->timeout);

	if (dmjob->sigalrm || dmjob->sigint)
		goto signal;
	
	if (dmjob->sigint)
		goto signal;

	/* check that size is as expected */
	/*if (dmreq->S_size) {
		if (us.size == -1) {
			warnx("%s: size unknown", dmreq->URL);
		} else if (us.size != dmreq->S_size) {
			warnx("%s: size mismatch: expected %jd, actual %jd",
			    dmreq->URL, (intmax_t)dmreq->S_size, (intmax_t)us.size);
			goto failure;
		}
	}
	*/

	/* symlink instead of copy */
	if ((dmreq->flags & l_FLAG) && strcmp(dmjob->url->scheme, "file") == 0 && !(dmreq->flags & O_STDOUT)) {
		if (symlink(dmjob->url->doc, dmreq->path) == -1) {
			warn("%s: symlink()", dmreq->path);
			goto failure;
		}
		goto success;
	}

	if (us.size == -1 && !(dmreq->flags & O_STDOUT) && dmreq->v_level > 0)
		warnx("%s: size of remote file is not known", dmreq->URL);
	if (dmreq->v_level > 1) {
		if (sb.st_size != -1)
			fprintf(stderr, "local size / mtime: %jd / %ld\n",
			    (intmax_t)sb.st_size, (long)sb.st_mtime);
		if (us.size != -1)
			fprintf(stderr, "remote size / mtime: %jd / %ld\n",
			    (intmax_t)us.size, (long)us.mtime);
	}

	/* open output file */
	if (dmreq->flags & O_STDOUT) {
		of = fdopen(dmjob->ofd, "a");
	} else if ((dmreq->flags & r_FLAG) && sb.st_size != -1) {
		/* resume mode, local file exists */
		if (!(dmreq->flags & F_FLAG) && us.mtime && sb.st_mtime != us.mtime) {
			/* no match! have to refetch */
			fclose(f);
			/* if precious, warn the user and give up */
			if ((dmreq->flags & R_FLAG)) {
				warnx("%s: local modification time "
				    "does not match remote", dmreq->path);
				goto failure_keep;
			}
		} else if (dmjob->url->offset > sb.st_size) {
			/* gap between what we asked for and what we got */
			warnx("%s: gap in resume mode", dmreq->URL);
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
				    "than remote file (%jd bytes)", dmreq->path,
				    (intmax_t)sb.st_size, (intmax_t)us.size);
				goto failure;
			}
			/* we got it, open local file */
			if ((of = fdopen(dmjob->ofd, "r+")) == NULL) {
				warn("%s: fdopen()", dmreq->path);
				goto failure;
			}

			/* check that it didn't move under our feet */
			if (fstat(fileno(of), &nsb) == -1) {
				/* can't happen! */
				warn("%s: fstat()", dmreq->path);
				goto failure;
			}
			if (nsb.st_dev != sb.st_dev ||
			    nsb.st_ino != nsb.st_ino ||
			    nsb.st_size != sb.st_size) {
				warnx("%s: file has changed", dmreq->URL);
				fclose(of);
				of = NULL;
				sb = nsb;
				/* picked up again later */
			}
		}
		/* seek to where we left off */
		if (of != NULL && fseeko(of, dmjob->url->offset, SEEK_SET) != 0) {
			warn("%s: fseeko()", dmreq->path);
			fclose(of);
			of = NULL;
			/* picked up again later */
		}
	} else if ((dmreq->flags & m_FLAG) && sb.st_size != -1) {
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

		if (dmjob->url->offset > 0) {
			/*
			 * We tried to restart a transfer, but for
			 * some reason gave up - so we have to restart
			 * from scratch if we want the whole file
			 */
			dmjob->url->offset = 0;
			if (dmjob->sigint)
				goto signal;
		}


		/* construct a temp file name */
		if (sb.st_size != -1 && S_ISREG(sb.st_mode)) {
			if ((slash = strrchr(dmreq->path, '/')) == NULL)
				slash = dmreq->path;
			else
				++slash;
			asprintf(&tmppath, "%.*s.dm.XXXXXX.%s",
			    (int)(slash - dmreq->path), dmreq->path, slash);
			if (tmppath != NULL) {
				if (mkstemps(tmppath, strlen(slash) + 1) == -1) {
					warn("%s: mkstemps()", dmreq->path);
					goto failure;
				}
				of = fopen(tmppath, "w");
				chown(tmppath, sb.st_uid, sb.st_gid);
				chmod(tmppath, sb.st_mode & ALLPERMS);
			}
		}

		if (of == NULL)
			of = fdopen(dmjob->ofd, "w");
		if (of == NULL) {
			warn("%s: open()", dmreq->path);
			goto failure;
		}
	}
	count = dmjob->url->offset;

	/* start the counter */
	stat_start(&xs, dmreq->path, us.size, count, dmjob);

	dmjob->sigalrm = dmjob->siginfo = dmjob->sigint = 0;

	if (dmreq->B_size < MINBUFSIZE)
		dmreq->B_size = MINBUFSIZE;
	buf = (char *) malloc(dmreq->B_size);

	/* suck in the data */
	dmjob->siginfo_en = 1;
	while (!dmjob->sigint) {
		if (us.size != -1 && us.size - count < dmreq->B_size &&
		    us.size - count >= 0)
			size = us.size - count;
		else
			size = dmreq->B_size;
		if (dmjob->siginfo) {
			stat_end(&xs, dmjob);
			dmjob->siginfo = 0;
		}

		if (size == 0)
			break;

		if ((readcnt = fread(buf, 1, size, f)) < size) {
			if (ferror(f) && errno == EINTR && !dmjob->sigint)
				clearerr(f);
			else if (readcnt == 0) {
				break;
			}	
		}


		stat_update(&xs, count += readcnt, dmjob);
		for (ptr = buf; readcnt > 0; ptr += wr, readcnt -= wr)
			if ((wr = fwrite(ptr, 1, readcnt, of)) < readcnt) {
				if (ferror(of) && errno == EINTR && !dmjob->sigint)
					clearerr(of);
				else
					break;
			}
		if (readcnt != 0)
			break;
	}

	if (!dmjob->sigalrm)
		dmjob->sigalrm = ferror(f) && errno == ETIMEDOUT;
	dmjob->siginfo_en = 0;

	stat_end(&xs, dmjob);

	/*
	 * If the transfer timed out or was interrupted, we still want to
	 * set the mtime in case the file is not removed (-r or -R) and
	 * the user later restarts the transfer.
	 */
 signal:
	/* set mtime of local file */
	if (!(dmreq->flags & n_FLAG) && us.mtime && !(dmreq->flags & O_STDOUT) && of != NULL &&
	    (stat(dmreq->path, &sb) != -1) && sb.st_mode & S_IFREG) {
		struct timeval tv[2];

		fflush(of);
		tv[0].tv_sec = (long)(us.atime ? us.atime : us.mtime);
		tv[1].tv_sec = (long)us.mtime;
		tv[0].tv_usec = tv[1].tv_usec = 0;
		if (utimes(tmppath ? tmppath : dmreq->path, tv))
			warn("%s: utimes()", tmppath ? tmppath : dmreq->path);
	}

	/* timed out or interrupted? */
	if (dmjob->sigalrm)
		warnx("transfer timed out");
	if (dmjob->sigint) {
		warnx("transfer interrupted");
		goto failure;
	}

	/* timeout / interrupt before connection completley established? */
	if (f == NULL)
		goto failure;

	if (!dmjob->sigalrm) {
		/* check the status of our files */
		if (ferror(f))
			warn("%s", dmreq->URL);
		if (ferror(of))
			warn("%s", dmreq->path);
		if (ferror(f) || ferror(of))
			goto failure;
	}

	/* did the transfer complete normally? */
	if (us.size != -1 && count < us.size) {
		warnx("%s appears to be truncated: %jd/%jd bytes",
		    dmreq->path, (intmax_t)count, (intmax_t)us.size);
		goto failure_keep;
	}

	/*
	 * If the transfer timed out and we didn't know how much to
	 * expect, assume the worst (i.e. we didn't get all of it)
	 */
	if (dmjob->sigalrm && us.size == -1) {
		warnx("%s may be truncated", dmreq->path);
		goto failure_keep;
	}

 success:

	r = 0;
	if (tmppath != NULL && rename(tmppath, dmreq->path) == -1) {
		warn("%s: rename()", dmreq->path);
		goto failure_keep;
	}
	goto done;
 failure:
	if (of && of != stdout && !(dmreq->flags & R_FLAG) && !(dmreq->flags & r_FLAG))
		if (stat(dmreq->path, &sb) != -1 && (sb.st_mode & S_IFREG))
			unlink(tmppath ? tmppath : dmreq->path);
	if ((dmreq->flags & R_FLAG) && tmppath != NULL && sb.st_size == -1)
		rename(tmppath, dmreq->path); /* ignore errors here */
 failure_keep:
	r = -1;
	goto done;
 done:
	if (f)
		fclose(f);
	if (of && of != stdout)
		fclose(of);
	if (dmjob->url)
		fetchFreeURL(dmjob->url);
	if (tmppath != NULL)
		free(tmppath);

	return (r);
}

static FILE *
dmXGet(struct dmjob *dmjob, struct url_stat *us) 
{
	char flags[8];
	int ret;
	struct dmjob tmpjob;
	struct dmreq tmpreq;
	struct dmreq *dmreq = dmjob->request;

	/* populate tmpjob */
	tmpjob.client = STDERR_FILENO;
	tmpjob.request = &tmpreq;
	tmpreq.v_level = dmreq->v_level;
 	tmpreq.ftp_timeout = dmjob->request->ftp_timeout;
	tmpreq.http_timeout = dmjob->request->http_timeout;
	tmpreq.B_size = dmjob->request->B_size;
	tmpreq.S_size = dmjob->request->S_size;
	tmpreq.T_secs = dmjob->request->T_secs;
	tmpreq.flags = dmjob->request->flags;
	tmpreq.family = dmjob->request->family;

	tmpreq.i_filename = (char *) malloc(strlen(dmreq->i_filename));
	if (tmpreq.i_filename == NULL) {
		fprintf(stderr, "dmXGet: Insufficient memory\n");
		return NULL;
	}

	strcpy(tmpreq.i_filename, dmreq->i_filename);

	tmpreq.URL = (char *) malloc(strlen(dmreq->URL));
	if (tmpreq.URL == NULL) {
		fprintf(stderr, "dmXGet: Insufficient memory\n");
		free(tmpreq.i_filename);
		return NULL;
	}

	strcpy(tmpreq.URL, dmreq->URL);
	
	tmpjob.url = NULL;
	ret = mk_url(&tmpjob, flags);
	if (ret == -1) {
		free(tmpreq.i_filename);
		free(tmpreq.URL);
		return NULL;
	}

	/* special case : -s flag
	if (tmpreq.flags & s_FLAG) {
		if (dmjob->timeout)
			alarm(dmjob->timeout); 
		r = fetchStat(dmjob->url, us, flags);
		if (dmjob->timeout)
			alarm(0);
		if (dmjob->sigalrm || dmjob->sigint)
			goto signal;
		if (r == -1) {
			warnx("%s", fetchLastErrString);
			goto failure;
		}
		if (us->size == -1)
			printf("Unknown\n");
		else
			printf("%jd\n", (intmax_t)us->size);
		goto success;
	}
	*/

	tmpreq.path = (char *) malloc(strlen(dmreq->path) + strlen(TMP_EXT));
	if (tmpreq.path == NULL) {
		fprintf(stderr, "dmXGet: Insufficient memory\n");
		goto done;
	}
	strcpy(tmpreq.path, dmreq->path);
	strcat(tmpreq.path, TMP_EXT);

	tmpjob.ofd = open(tmpreq.path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

	FILE *f = fetchXGet(tmpjob.url, us, flags);
	if (f == NULL) {
		close(tmpjob.ofd);
		remove(tmpreq.path);
		fprintf(stderr, "dmXGet: Couldn't fetch remote file\n");//, fetchLastErrStr);
		goto done;
	}

	fetch(&tmpjob, f, *us);
	fclose(f);

	f = fopen(tmpreq.path, "r");

done:
	free(tmpjob.url->doc);
	free(tmpjob.url);
	free(tmpreq.i_filename);
	free(tmpreq.URL);
	free(tmpreq.path);
	
	return f;
}

static int
validate_and_copy(struct dmjob *dmjob, FILE *f, struct url_stat us)
{
	int ret, ret2;
	SHA_CTX sha_ctx;
	MD5_CTX md5_ctx;
	char buf[1024], chksum[SHA_DIGEST_LENGTH]; /* TODO: MAX DIGEST LENGTH */

	switch(dmjob->request->chksum_type) {
	case SHA1_CHKSUM:
		SHA1_Init(&sha_ctx);

		fseek(f, 0, SEEK_SET);
		while ((ret = fread(buf, 1, 1024, f)) != 0)
			SHA1_Update(&sha_ctx, buf, ret);
		SHA1_Final(chksum, &sha_ctx);
		
		if (memcmp(chksum, dmjob->request->chksum.sha1sum,
				SHA_DIGEST_LENGTH) != 0) {
			fprintf(stderr, "dms: checksum missmatch\n");
			/* Notify the client of the same */
			return -1;
		}
		break;
	case MD5_CHKSUM:
		MD5_Init(&md5_ctx);

		fseek(f, 0, SEEK_SET);
		while ((ret = fread(buf, 1, 1024, f)) != 0)
			MD5_Update(&md5_ctx, buf, ret);
		MD5_Final(chksum, &md5_ctx);

		if (memcmp(chksum, dmjob->request->chksum.md5sum,
				MD5_DIGEST_LENGTH) != 0) {
			fprintf(stderr, "dms: checksum mismatch\n");
			return -1;
		}
		break;
	default:
		break;
	}

	fseek(f, 0, SEEK_SET);
	return fetch(dmjob, f, us);	
}

/* TODO: This handler isn't registered as SIGUSR1 interrupts the download
 * 	 Figure out a proper way to handle this
 * */
void
sig_handler(int sig)
{
	struct dmjob *tmp = jobs;
	struct dmmsg *msg;
	int *clisig;
	pthread_t tid = pthread_self();
	if (sig == SIGUSR1) {
		/* TODO: Umm...Locking? */
		while (tmp != NULL) {
			if (pthread_equal(tid, tmp->worker) != 0)
				break;
			tmp = tmp->next;
		}

		msg = recv_dmmsg(tmp->client);
		clisig = msg->buf;	
		if (*clisig == SIGINT)
			tmp->sigint = 1;
		else if (*clisig == SIGINFO)
			tmp->siginfo = 1;
		else if (*clisig == SIGALRM) {
			tmp->sigalrm = 1;
		}
	}
}

int 
send_report(int sock, struct dmrep report)
{
	char *buf;
	int i = 0;
	int bufsize = sizeof(report) - sizeof(report.errstr);
	int errlen = strlen(report.errstr);

	bufsize +=  errlen;	
	buf = (char *) malloc(bufsize);
	if (buf == NULL) {
		fprintf(stderr, "send_report: Insufficient memory\n");
		return -1;
	}
	
	memcpy(buf + i, &(report.status), sizeof(report.status));
	i += sizeof(report.status);

	memcpy(buf + i, &(report.errcode), sizeof(report.errcode));
	i += sizeof(report.errcode);

	strcpy(buf + i, report.errstr);
	i += errlen;
	
	struct dmmsg msg;
	msg.op = DMRESP;
	msg.buf = buf;
	msg.len = bufsize;
	send_dmmsg(sock, msg);
	
	free(buf);
}

void *
run_worker(struct dmjob *dmjob)
{
	struct dmrep report;
	struct dmjob *tmp;
	struct url_stat us;
	int ret;
	FILE *f;
	char *tmppath;
	char flags[8];

	/* Acquire job queue lock */
	ret = pthread_mutex_lock(&job_queue_mutex);
	if (ret == -1) {
		fprintf(stderr, "handle_request: Attempt to acquire"
				" job queue mutex failed\n");
		return -1;
	}

	tmp = jobs;
	while (tmp != NULL) {
		if (tmp != dmjob && compare_jobs(tmp, dmjob) == 0) {
			dmjob->state = DUPLICATE;
			dmjob->worker = tmp->worker;
			return NULL;
		}
		tmp = tmp->next;
	}

	ret = pthread_mutex_unlock(&job_queue_mutex);
	if (ret == -1) {
		fprintf(stderr, "handle_request: Couldn't release "
				"job queue lock\n");

		return -1;
	}
	/* Job queue lock released */

	/* check if this is a duplicate */
	ret = mk_url(dmjob, flags);	
	dmjob->worker = pthread_self();

	/* fetch the remote file into a local tmp file */
	f = dmXGet(dmjob, &us);

	/* Acquire job queue lock */
	ret = pthread_mutex_lock(&job_queue_mutex);
	if (ret == -1) {
		fprintf(stderr, "handle_request: Attempt to acquire"
				" job queue mutex failed\n");
		return -1;
	}

	/* Serve any outstanding requests from the local tmp file */
	tmp = jobs;
	while (tmp != NULL) {
		if (compare_jobs(tmp, dmjob) != 0) {
			tmp = tmp->next;
			continue;
		}

		if (f == NULL) {
			ret = -1;
		} else {
			ret = validate_and_copy(dmjob, f, us);		
		}

		report.status = ret;
		report.errcode = fetchLastErrCode;
		report.errstr = fetchLastErrString;	
		send_report(dmjob->client, report);

		tmp->state = DONE;
		tmp = tmp->next;
	}

	ret = pthread_mutex_unlock(&job_queue_mutex);
	if (ret == -1) {
		fprintf(stderr, "handle_request: Couldn't release "
				"job queue lock\n");

		return -1;
	}
	/* Job queue lock released */

	/* remove the local tmp file */
	if (f != NULL) {
		tmppath = (char *) malloc(strlen(dmjob->request->path) + strlen(TMP_EXT));
		strcpy(tmppath, dmjob->request->path);
		strcat(tmppath, TMP_EXT);

		remove(tmppath);
		free(tmppath);
	}
	
	/* TODO : What is this? Yew!! */
	sleep(10);
}
