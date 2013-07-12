struct conn {
	struct conn *prev;
	struct conn *next;
	int client;
	int worker;
};

struct conn *
add_conn(struct conn *head, int client, int worker);

struct conn *
rm_conn(struct conn *head, struct conn *conn);

