#include <stdlib.h>

#include "list.h"

struct conn *
add_conn(struct conn *head, int client, int worker)
{
	struct conn *new = (struct conn *) Malloc(sizeof(struct conn));
	new->client = client;
	new->worker = worker;		
	new->prev = NULL;
	new->next = NULL;

	if (head == NULL)
		return new;

	head->prev = new;
	new->next = head;	
}

struct conn *
rm_conn(struct conn *head, struct conn *conn)
{
	if (head == NULL)
		return NULL;
	
	if (conn == NULL)
		return head;
		
	if (conn->next != NULL) 
		conn->next->prev = conn->prev;

	if (conn->prev != NULL)
		conn->prev->next = conn->next;
	
	struct conn *tmp = conn->next;
	
	if (conn == head) {
		free(conn);
		return tmp;
	}
	
	free(conn);
	return head;
}

