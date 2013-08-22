#ifndef _MIRROR_H_
#define _MIRROR_H_

struct dmmirr	*mirrors;
pthread_mutex_t	 mirror_list_mutex;

int load_mirrors(void);
int save_mirrors(void);
void update_mirror(struct dmmirr *, struct xferstat *);
struct dmmirr *get_mirror(void);
int release_mirror(struct dmmirr *);
double get_average_speed(struct dmmirr *);

#endif
