#include "chat.h"
#include "chat_server.h"
#include "msg_node.h"
#include "array.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#define EPOLL_HANDLING_EVENT_COUNT 99

struct chat_peer {
	/** Client's socket. To read/write messages. */
	int socket;

	/** Output buffer. */
	struct array msgs_to_write;

	/** Input buffer. */
	struct chat_message *reading_msg;

	/** Name of the client. */
	char *name;

	/** List node for storing at server list. */
	struct rlist node;

	/** Event struct for epoll. */
	struct epoll_event ep_ev;
};

struct chat_server {
	/** Listening socket. To accept new clients. */
	int socket;

	/** Array of peers. */
	struct rlist peer_root;

	/** Array of received msgs. */
	struct rlist feed_root;

	int epoll_fd;

	/** Event struct for epoll. */
	struct epoll_event ep_ev;
};

struct chat_server *
chat_server_new(void)
{
	struct chat_server *server = calloc(1, sizeof(*server));
	server->socket = -1;
	server->epoll_fd = -1;

	rlist_create(&server->peer_root);

	return server;
}

void
chat_server_delete(struct chat_server *server)
{
	if (server->socket >= 0) {
		close(server->socket);
	}

	struct chat_peer *iter = rlist_first_entry(&server->peer_root, struct chat_peer, node);
	while (!rlist_empty(&server->peer_root)) {
		struct chat_peer *next = rlist_next_entry(iter, node);
		rlist_del(&iter->node);

		struct chat_message *msg = array_pop(&iter->msgs_to_write, 0);
		while (msg != NULL) {
			free(msg->data);
			free(msg->author);

			free(msg);
			msg = array_pop(&iter->msgs_to_write, 0);
		}

		array_free(&iter->msgs_to_write);

		free(iter->name);
		free(iter->reading_msg);
		free(iter);

		iter = next;
	}

	free(server);
}

int
chat_server_listen(struct chat_server *server, uint16_t port)
{
	if (server->socket >= 0) {
		return CHAT_ERR_ALREADY_STARTED;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	/* Listen on all IPs of this machine. */
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	server->socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (server->socket == -1) {
		return CHAT_ERR_SYS;
	}

	if (bind(server->socket, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		return CHAT_ERR_PORT_BUSY;
	}

	server->epoll_fd = epoll_create1(0);
	if (server->epoll_fd == -1) {
		return CHAT_ERR_SYS;
	}

	server->ep_ev.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->socket, &server->ep_ev) == -1) {
		return CHAT_ERR_SYS;
	}

	return 0;
}

struct chat_message *
chat_server_pop_next(struct chat_server *server)
{
	if (rlist_empty(&server->feed_root)) {
		return NULL;
	}

	struct msg_node *msg_node = rlist_first_entry(&server->feed_root, struct msg_node, node);
	rlist_del(&msg_node->node);

	struct chat_message *msg = msg_node->msg;
	free(msg_node);

	return msg;
}

int
chat_server_update(struct chat_server *server, double timeout)
{
	if (server->socket == -1) {
		return CHAT_ERR_NOT_STARTED;
	}

	struct epoll_event events[EPOLL_HANDLING_EVENT_COUNT];
	int event_count = epoll_wait(server->epoll_fd, events, EPOLL_HANDLING_EVENT_COUNT, (int) (timeout * 1000));
	switch (event_count) {
		case -1: {
			return CHAT_ERR_SYS;
		}

		case 0: {
			return CHAT_ERR_TIMEOUT;
		}

		default: {
			break;
		}
	}

	for (int i = 0; i < event_count; ++i) {
		struct epoll_event *event = &events[i];
		if ((event->events & EPOLLIN) != 0) {
			if (event->data.ptr == NULL) {  // server

				continue;
			}

		}

		if ((event->events & EPOLLOUT) != 0) {

		}

		if ((event->events & EPOLLRDHUP) != 0) {

		}

		if ((event->events & EPOLLERR) != 0) {

		}

		if ((event->events & EPOLLHUP) != 0) {

		}
	}

	return 0;
}

int
chat_server_get_descriptor(const struct chat_server *server)
{
#if NEED_SERVER_FEED

	return server->epoll_fd;

#endif

	(void)server;
	return -1;
}

int
chat_server_get_socket(const struct chat_server *server)
{
	return server->socket;
}

int
chat_server_get_events(const struct chat_server *server)
{
	int result = server->socket == -1 ? 0 : CHAT_EVENT_INPUT;

	struct chat_peer *peer;
	rlist_foreach_entry(peer, &server->peer_root, node) {
		if (peer->msgs_to_write.a_size > 0) {
			result |= CHAT_EVENT_OUTPUT;
			break;
		}
	}

	return result;
}

int
chat_server_feed(struct chat_server *server, const char *msg, uint32_t msg_size)
{
#if NEED_SERVER_FEED
	/* IMPLEMENT THIS FUNCTION if want +5 points. */
#endif
	(void)server;
	(void)msg;
	(void)msg_size;
	return CHAT_ERR_NOT_IMPLEMENTED;
}
