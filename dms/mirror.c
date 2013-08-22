#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <errno.h>
#include <sys/time.h>

#include "dm.h"
#include "dms.h"
#include "mirror.h"

#define 	MAX_SAMPLES	256
#define		MAX_CONNS	5
#define		MIRRORS_FILE	"mirrors.list"

static const char *MIRROR_LIST[] = {
	"ftp.freebsd.org"
};

static struct dmmirr *
add_mirror(struct dmmirr *head, struct dmmirr *new)
{ 
	new->prev = NULL;
	new->next = NULL;

	if (head == NULL)
		return new;

	head->prev = new;
	new->next = head;	
}

static struct dmmirr *
rm_mirror(struct dmmirr *head, struct dmmirr *mirror)
{
	if (mirror->next != NULL) 
		mirror->next->prev = mirror->prev;

	if (mirror->prev != NULL)
		mirror->prev->next = mirror->next;
	
	if (mirror == head) 
		return mirror->next;

	return head;
}

static double
get_speed(struct xferstat *xs)
{
	double delta = (xs->last.tv_sec + (xs->last.tv_usec / 1.e6))
			- (xs->last2.tv_sec + (xs->last2.tv_usec / 1.e6));
	if (delta == 0.0) 
		return -1.0;
	return (xs->rcvd - xs->lastrcvd) / delta;
}

static struct dmmirr *
read_mirror(FILE *f)
{
	int i;
	struct dmmirr *mirror;
	char buf[512], rem[64];

	mirror = (struct dmmirr *) malloc(sizeof(struct dmmirr));
	if (mirror == NULL) {
		fprintf(stderr, "read_mirror: Insufficient memory\n");
		return NULL;
	}

	if (fgets(buf, 512, f) == NULL) {
		free(mirror);
		return NULL;
	}
	sscanf(buf, "%s\n", mirror->name);

	if (fgets(buf, 64, f) == NULL) {
		fprintf(stderr, "WARNING: read_mirror: mirrors.list file corrupted\n");
		free(mirror);
		return NULL;
	}
	sscanf(buf, "%s\n", rem);

	if (strcmp(rem, "NOT_TRIED") == 0) {
		mirror->remark = NOT_TRIED;
	} else if (strcmp(rem, "FAILED") == 0) {
		mirror->remark = FAILED;
	} else {
		fprintf(stderr, "WARNING: Unknown mirror state in mirrors.list\n");
	}

	if (fgets(buf, 64, f) == NULL) {
		fprintf(stderr, "WARNING: read_mirror: mirrors.list file corrupted\n");
		free(mirror);
		return NULL;
	}
	sscanf(buf, "%d\n", &mirror->index);

	for(i = 0; i < MAX_SAMPLES; i++) {
		fscanf(f, "%ld\t%f\n", &(mirror->timestamps[i].tv_sec),
					&(mirror->samples[i]));
		/* TODO: What if fscanf fails? */
	}

	mirror->nconns = 0;
	return mirror;
}

static void
write_mirror(struct dmmirr *mirror, FILE *f)
{
	int i;
	
	fputs(mirror->name, f);
	fputc('\n', f);
	
	switch(mirror->remark) {
	case NOT_TRIED:
		fputs("NOT_TRIED\n", f);
		break;
	case FAILED:
		fputs("FAILED\n", f);
		break;
	}

	for(i = 0; i < MAX_SAMPLES; i++) {
		fprintf(f, "%ld\t%f\n", mirror->timestamps[i].tv_sec,
					mirror->samples[i]);
	}
	
	return;
}

static int
init_mirrors_file(void)
{
	int i, j;
	FILE *f = fopen(MIRRORS_FILE, "w");
	if (f == NULL)
		return -1;
	
	for(i = 0; i < sizeof(MIRROR_LIST) / sizeof(MIRROR_LIST[0]); i++) {
		fwrite(MIRROR_LIST[i], strlen(MIRROR_LIST[i]), 1, f);
		fprintf(f, "\nNOT_TRIED\n");
		for (j = 0; j < MAX_SAMPLES; j++)
			fprintf(f, "0\t0\n");
	}

	fclose(f);
}

int
load_mirrors(void)
{
	int ret;
	struct dmmirr *mirror;

	FILE *f = fopen(MIRRORS_FILE, "r");
	if (f == NULL && errno == ENOENT) {
		init_mirrors_file();
		f = fopen(MIRRORS_FILE, "r");
	} else if (f == NULL) {
		fprintf(stderr, "load_mirrors: fopen(%s) failed\n",
				MIRRORS_FILE);
		return -1;
	}

	/* Profile list lock */
	ret = pthread_mutex_lock(&mirror_list_mutex);
	if (ret == -1) {
		fprintf(stderr, "load_mirrors: Attempt to acquire"
				" profile list mutex failed\n");
		return -1;
	}

	mirror = read_mirror(f);
	while(mirror != NULL) {
		mirrors = add_mirror(mirrors, mirror);
		mirror = read_mirror(f);
	}

	ret = pthread_mutex_unlock(&mirror_list_mutex);
	if (ret == -1) {
		fprintf(stderr, "load_mirrors: Couldn't release "
				"profile list lock\n");
		return -1;
	}
	/* Profile list lock released */

	fclose(f);
	return 0;
}

int
save_mirrors(void)
{
	int ret;
	struct dmmirr *mirror = mirrors;

	FILE *f = fopen(MIRRORS_FILE, "w");

	/* Profile list lock */
	ret = pthread_mutex_lock(&mirror_list_mutex);
	if (ret == -1) {
		fprintf(stderr, "save_mirrors: Attempt to acquire"
				" profile list mutex failed\n");
		return -1;
	}

	while(mirrors != NULL) {
		write_mirror(mirror, f);	
		mirrors = rm_mirror(mirrors, mirror);
	}

	ret = pthread_mutex_unlock(&mirror_list_mutex);
	if (ret == -1) {
		fprintf(stderr, "save_mirrors: Couldn't release "
				"profile list lock\n");
		return -1;
	}
	/* Profile list lock released */

	fclose(f);
	return 0;
}

void
update_mirror(struct dmmirr *dmmirr, struct xferstat *xs)
{
	struct timeval tv;
	double speed;
	int ret;

	gettimeofday(&tv, NULL);
	if (tv.tv_sec - dmmirr->timestamps[dmmirr->index].tv_sec < 60)
		return;

	speed = get_speed(xs);

	/* Profile list lock */
	ret = pthread_mutex_lock(&mirror_list_mutex);
	if (ret == -1) {
		fprintf(stderr, "update_mirror: Attempt to acquire"
				" profile list mutex failed\n");
		return;
	}

	/* TODO: This assumes that workers and sites have 1-1 correspondence */
	dmmirr->index = (dmmirr->index + 1) % MAX_SAMPLES;
	dmmirr->timestamps[dmmirr->index] = tv;
	dmmirr->samples[dmmirr->index] = speed;
	dmmirr->remark = ACTIVE;

	ret = pthread_mutex_unlock(&mirror_list_mutex);
	if (ret == -1) {
		fprintf(stderr, "update_mirror: Couldn't release "
				"profile list lock\n");
		return;
	}
	/* Profile list lock released */
}

double
get_average_speed(struct dmmirr *dmmirr)
{
	int i, cnt;
	double average;
	struct timeval now;
	long week_sec;

	week_sec = 7 * 24 * 60 * 60;

	i = dmmirr->index;
	cnt = 0;
	average = 0.0;

	do {
		gettimeofday(&now, NULL);
		if (dmmirr->timestamps[i].tv_sec <  now.tv_sec - week_sec)
			break;
		average = (average * cnt + dmmirr->samples[i]) / (cnt + 1);
		cnt++;

		i = (i - 1) % MAX_SAMPLES;
	} while (i != dmmirr->index);

	return average;
}

struct dmmirr *
get_mirror(void)
{
	struct dmmirr *cur, *tmp;
	double tmpmax = -1.0;
	int cnt, ret, i;
	double average;

	/* Profile list lock */
	ret = pthread_mutex_lock(&mirror_list_mutex);
	if (ret == -1) {
		fprintf(stderr, "get_mirror: Attempt to acquire"
				" profile list mutex failed\n");
		return NULL;
	}

	cur = mirrors;
	tmp = NULL;
	tmpmax = -1.0;
	while (cur != NULL) {
		if (cur->remark == NOT_TRIED) {
			tmp = cur;
			goto success;
		}

		if (cur->remark == FAILED)
			goto next;
		if (cur->nconns > MAX_CONNS)
			goto next;

		average = get_average_speed(cur);

		if (average > tmpmax) {
			tmpmax = average;
			tmp = cur;
		}
next:
		cur = cur->next;
	}
	/* TODO: If we couldn't pick up a mirror? */

success:
	tmp->nconns++;
	ret = pthread_mutex_unlock(&mirror_list_mutex);
	if (ret == -1) {
		fprintf(stderr, "get_mirror: Couldn't release "
				"profile list lock\n");
		return NULL;
	}
	/* Profile list lock released */

	return tmp;
}

int
release_mirror(struct dmmirr *dmmirr)
{
	int ret;

	/* Profile list lock */
	ret = pthread_mutex_lock(&mirror_list_mutex);
	if (ret == -1) {
		fprintf(stderr, "update_mirror: Attempt to acquire"
				" profile list mutex failed\n");
		return -1;
	}

	dmmirr->nconns--;

	ret = pthread_mutex_unlock(&mirror_list_mutex);
	if (ret == -1) {
		fprintf(stderr, "update_mirror: Couldn't release "
				"profile list lock\n");
		return -1;
	}
	/* Profile list lock released */

	return 0;
}
