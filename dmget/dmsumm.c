
#include <stdio.h>

#include <sys/un.h>
#include <sys/socket.h>

#include "dmsumm.h"
#include "dm.h"
#include "utils.h"

int
receive_summary(int sock, struct dmsumm **summs, int *nsumms)
{
	struct dmmsg *dmmsg;

	dmmsg = recv_dmmsg(sock);
	if (dmmsg == NULL)
		return -1;

	*nsumms = dmmsg->len / sizeof(struct dmsumm);
	*summs = (struct dmsumm *)dmmsg->buf;

	return 0;
}

int
output_summary(FILE *outf, struct dmsumm *summs, int nsumms)
{
	int i;
	double percent;

	for (i = 0; i < nsumms; i++) {
		percent = 100 * summs[i].rcvd / summs[i].size ;
		fprintf(outf, "%64s\t""%f%%\t""%d\t""%64s\t",
				summs[i].name, percent, summs[i].eta,
				summs[i].mirror);
	}
}

int
dump_status_summary(FILE *outf)
{
	int sock, ret, nsumms;
	struct sockaddr_un dms_addr;
	struct dmmsg dmmsg;
	struct dmsumm *summs;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		fprintf(stderr, "dmget: Could not create socket"
				" (%s)\n", strerror(errno));
		return -1;
	}

	dms_addr.sun_family = AF_UNIX;
	strncpy(dms_addr.sun_path, DMS_UDS_PATH, sizeof(dms_addr.sun_path));
	ret = connect(sock, (struct sockaddr *) &dms_addr, sizeof(dms_addr));
	if (ret == -1) {
		fprintf(stderr, "dmget: Could not connect to daemon"
				" (%s)\n", strerror(errno));
		return -1;
	}

	//if (sigint)
	//	goto signal;

	dmmsg.op = DMDUMPREQ;
	dmmsg.len = 0;
	dmmsg.buf = NULL;
	ret = send_dmmsg(sock, dmmsg);
	if (ret == -1) {
		close(sock);
		return -1;
	}
	
	ret = receive_summary(sock, &summs, &nsumms);
	if (ret == -1) {
		close(sock);
		return -1;
	}

	output_summary(outf, summs, nsumms);

	free(summs);
	return nsumms;
}
