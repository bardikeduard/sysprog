#include "chat.h"
#include "chat_server.h"
#include "msg_node.h"
#include "array.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/fcntl.h>

#define MAX_EPOLL_EVENT_BATCH 99
#define SOCK_READ_BUFF_SIZE 4096

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
	struct array feed_root;

	/** Epoll file descriptor. */
	int epoll_fd;

	/** Event struct for epoll. */
	struct epoll_event ep_ev;

	/** Incomplete message from server feed. */
	char *feed_buffer;

	/** Length of the incomplete message. */
	size_t feed_buffer_len;
};

struct chat_server *
chat_server_new(void)
{
	struct chat_server *server = calloc(1, sizeof(*server));
	server->socket = -1;
	server->epoll_fd = -1;

	rlist_create(&server->peer_root);
	if (array_init(&server->feed_root) != 0) {
		free(server);
		return NULL;
	}

	return server;
}

static void
chat_peer_delete(struct chat_server *server, struct chat_peer *peer)
{
	if (peer->socket >= 0) {
		close(peer->socket);
		epoll_ctl(server->epoll_fd, EPOLL_CTL_DEL, peer->socket, NULL);
	}

	free(peer->name);

	for (size_t i = 0; i < peer->msgs_to_write.a_size; ++i) {
		chat_message_delete(peer->msgs_to_write.a_elems[i]);
	}

	array_free(&peer->msgs_to_write);
	chat_message_delete(peer->reading_msg);

	free(peer);
}

void
chat_server_delete(struct chat_server *server)
{
	if (server->socket >= 0) {
		close(server->socket);
	}

	struct chat_peer *client, *tmp;
	rlist_foreach_entry_safe (client, &server->peer_root, node, tmp) {
		rlist_del_entry(client, node);
		chat_peer_delete(server, client);
	}

	close(server->epoll_fd);
	array_free(&server->feed_root);
	free(server->feed_buffer);

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

	if (listen(server->socket, SOMAXCONN) == -1) {
		return CHAT_ERR_SYS;
	}

	server->epoll_fd = epoll_create1(0);
	if (server->epoll_fd == -1) {
		return CHAT_ERR_SYS;
	}

	server->ep_ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
	if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->socket, &server->ep_ev) != 0) {
		return CHAT_ERR_SYS;
	}

	return 0;
}

struct chat_message *
chat_server_pop_next(struct chat_server *server)
{
	if (server->feed_root.a_size == 0) {
		return NULL;
	}

	return array_pop(&server->feed_root, 0);
}

static int
chat_server_accept_clients(struct chat_server *server)
{
	while (1) {
		int sock = accept(server->socket, NULL, NULL);
		if (sock == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				break;
			}

			return CHAT_ERR_SYS;
		}

		struct chat_peer *client = calloc(1, sizeof(struct chat_peer));
		if (client == NULL) {
			return CHAT_ERR_SYS;
		}

		client->socket = sock;

		if (array_init(&client->msgs_to_write) != 0) {
			close(client->socket);
			free(client);
			return CHAT_ERR_SYS;
		}

		int flags = fcntl(client->socket, F_GETFL, 0);
		fcntl(client->socket, F_SETFL, flags | O_NONBLOCK);

		client->ep_ev.data.ptr = client;
		client->ep_ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLRDHUP | EPOLLHUP | EPOLLET;

		if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, client->socket, &client->ep_ev) != 0) {
			array_free(&client->msgs_to_write);
			close(client->socket);
			free(client);
			return CHAT_ERR_SYS;
		}

		rlist_add_tail(&server->peer_root, &client->node);
	}

	return 0;
}

static struct chat_message *
create_message_from_buff(struct chat_message *src, const char *name)
{
	struct chat_message *msg = calloc(1, sizeof(struct chat_message));
	if (msg == NULL) {
		return NULL;
	}

	msg->data = strdup(src->data);
	if (msg->data == NULL) {
		free(msg);
		return NULL;
	}

	msg->author = strdup(name);
	if (msg->author == NULL) {
		free(msg->data);
		free(msg);
		return NULL;
	}

	msg->current_len = 0;
	return msg;
}

static int
create_message_from_buff_and_push(struct chat_message *src, const char *name, struct array *arr)
{
	struct chat_message *msg = create_message_from_buff(src, name);
	if (msg == NULL) {
		return CHAT_ERR_SYS;
	}

	if (array_push(arr, msg) != 0) {
		chat_message_delete(msg);
		return CHAT_ERR_SYS;
	}

	return 0;
}

static int
chat_server_try_send(struct chat_peer *client)
{
	while (client->msgs_to_write.a_size > 0) {
		struct chat_message *msg = array_at(&client->msgs_to_write, 0);
		if (msg == NULL) {
			array_pop(&client->msgs_to_write, 0);
			continue;
		}

		const char *source = NULL;
		size_t source_len = 0;

		// message body was not sent in full
		if (msg->data != NULL) {
			source = msg->data;
			source_len = strlen(source);

			// if there is no bytes in message body, send \n as delim between text and author
			if (source_len == 0) {
				source = "\n";
				source_len = 1;
			}
		}
		else if (msg->author != NULL) {  // remain to send only author
			source = msg->author;
			source_len = strlen(source) + 1;
		}
		else {  // all is sent, delete the message (unreachable?)
			chat_message_delete(msg);
			array_pop(&client->msgs_to_write, 0);
			continue;
		}

		ssize_t sent = send(client->socket, source, source_len, 0);
		if (sent < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return 0;
			}

			return CHAT_ERR_SYS;
		}

		// was sending message body
		if (msg->data != NULL) {
			// sent fully
			if ((size_t) sent == source_len) {
				// was sending message text
				if (strlen(msg->data) > 0) {
					msg->data[0] = '\0';
					continue;
				}

				// was sending \n, message body ended, delete it
				free(msg->data);
				msg->data = NULL;
				continue;
			}

			memmove(msg->data, msg->data + sent, source_len - sent + 1);
			return 0;
		}

		if ((size_t) sent == source_len) {
			chat_message_delete(msg);
			array_pop(&client->msgs_to_write, 0);
			continue;
		}

		memmove(msg->author, msg->author + sent, source_len - sent + 1);
		return 0;
	}

	return 0;
}

static int
chat_server_broadcast(struct chat_server *server, struct chat_peer *sender, struct chat_message *msg)
{
	struct chat_peer *peer;
	rlist_foreach_entry (peer, &server->peer_root, node) {
		if (peer == sender) {
			continue;
		}

		const char *sender_name;
		if (sender != NULL) {
			sender_name = sender->name;
		}
		else {
			sender_name = "server";
		}

		if (create_message_from_buff_and_push(msg, sender_name, &peer->msgs_to_write) != 0) {
			return CHAT_ERR_SYS;
		}

		chat_server_try_send(peer);
	}

	return 0;
}

static int
append_client_buff(struct chat_peer *client, const char *buff, size_t size)
{
	if (client->reading_msg == NULL) {
		client->reading_msg = calloc(1, sizeof(struct chat_message));
		if (client->reading_msg == NULL) {
			return CHAT_ERR_SYS;
		}
	}

	char *new_buff = NULL;
	if (client->reading_msg->data == NULL) {
		new_buff = calloc(size + 1, sizeof(char));
		if (new_buff == NULL) {
			return CHAT_ERR_SYS;
		}
	}
	else {
		size_t new_size = size + client->reading_msg->current_len + 1;
		new_buff = realloc(client->reading_msg->data, sizeof(char) * new_size);
		if (new_buff == NULL) {
			return CHAT_ERR_SYS;
		}

		new_buff[client->reading_msg->current_len + size] = '\0';
	}

	client->reading_msg->data = new_buff;
	memcpy(client->reading_msg->data + client->reading_msg->current_len, buff, size);
	client->reading_msg->data[client->reading_msg->current_len + size] = '\0';

	client->reading_msg->current_len += size;
	return 0;
}

static int
chat_server_err(struct chat_server *server, struct epoll_event *evt)
{
	struct chat_peer *client = evt->data.ptr;
	if (client == NULL) {  // error on server ?
		return CHAT_ERR_SYS;
	}

	rlist_del_entry(client, node);
	chat_peer_delete(server, client);

	return 0;
}

static int
chat_server_store_message(struct chat_server *server, struct chat_message *msg, const char *client_name)
{
	msg->author = strdup(client_name);
	if (msg->author == NULL) {
		return CHAT_ERR_SYS;
	}

	if (array_push(&server->feed_root, msg) != 0) {
		return CHAT_ERR_SYS;
	}

	return 0;
}

static int
chat_server_input(struct chat_server *server, struct epoll_event *evt)
{
	if (evt->data.ptr == NULL) {
		return chat_server_accept_clients(server);
	}

	struct chat_peer *client = evt->data.ptr;
	char read_buff[SOCK_READ_BUFF_SIZE];  // assume that default size is not so big to cause stack overflow

	while (1) {
		ssize_t recv_bytes = recv(client->socket, read_buff, sizeof(read_buff), 0);
		if (recv_bytes <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				break;
			}

			if (recv_bytes < 0) {
				chat_server_err(server, evt);
			}

			return CHAT_ERR_SYS;
		}

		size_t start_pos = 0;
		size_t i = 0;

		while (i < (size_t) recv_bytes) {
			if (read_buff[i] == '\n') {  // got delim between messages
				if (append_client_buff(client, read_buff + start_pos, i - start_pos) != 0) {
					return CHAT_ERR_SYS;
				}

				start_pos = i + 1;

				if (client->name == NULL) {
					client->name = strdup(client->reading_msg->data);
					if (client->name == NULL) {
						return CHAT_ERR_SYS;
					}

					chat_message_delete(client->reading_msg);
				}
				else {
					if (chat_server_broadcast(server, client, client->reading_msg) != 0) {
						return CHAT_ERR_SYS;
					}

					// msg buff moving to server feed
					if (chat_server_store_message(server, client->reading_msg, client->name) != 0) {
						chat_message_delete(client->reading_msg);
						return CHAT_ERR_SYS;
					}
				}

				client->reading_msg = NULL;
			}

			++i;
		}

		if (append_client_buff(client, read_buff + start_pos, recv_bytes - start_pos) != 0) {
			return CHAT_ERR_SYS;
		}
	}

	return 0;
}

static int
chat_server_output(struct epoll_event *evt)
{
	return chat_server_try_send(evt->data.ptr);
}

int
chat_server_update(struct chat_server *server, double timeout)
{
	if (server->socket == -1) {
		return CHAT_ERR_NOT_STARTED;
	}

	struct epoll_event events[MAX_EPOLL_EVENT_BATCH];
	int event_count = epoll_wait(server->epoll_fd, events, MAX_EPOLL_EVENT_BATCH, (int) (timeout * 1000));
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

		if ((event->events & EPOLLRDHUP) != 0 ||
			(event->events & EPOLLERR) != 0 ||
			(event->events & EPOLLHUP) != 0) {
			chat_server_err(server, event);
			continue;
		}

		int rc = 0;

		if ((event->events & EPOLLIN) != 0) {
			rc = chat_server_input(server, event);
		}

		if (rc == 0 && (event->events & EPOLLOUT) != 0) {
			rc = chat_server_output(event);
		}

		if (rc != 0) {
			return rc;
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
	struct chat_peer *peer;
	rlist_foreach_entry(peer, &server->peer_root, node) {
		if (peer->msgs_to_write.a_size > 0) {
			return CHAT_EVENT_INPUT | CHAT_EVENT_OUTPUT;
		}
	}

	return server->socket >= 0 ? CHAT_EVENT_INPUT : 0;
}

int
chat_server_feed(struct chat_server *server, const char *msg, uint32_t msg_size)
{
#if NEED_SERVER_FEED

	size_t current_start = 0;

	while (current_start < msg_size) {
		char *delim = strchr(msg + current_start, '\n');
		if (delim == NULL) {
			char *new_feed_buff;
			if (server->feed_buffer != NULL) {
				new_feed_buff = realloc(server->feed_buffer, server->feed_buffer_len + msg_size - current_start);
				if (new_feed_buff == NULL) {
					return CHAT_ERR_SYS;
				}
			}
			else {
				new_feed_buff = calloc(msg_size - current_start + 1, sizeof(char));
			}

			memcpy(new_feed_buff, msg + current_start, msg_size - current_start);

			server->feed_buffer = new_feed_buff;
			server->feed_buffer_len += msg_size - current_start;
			return 0;
		}

		size_t buff_size = server->feed_buffer_len + delim - msg - current_start;
		char *buff = malloc(buff_size + 1);

		if (server->feed_buffer != NULL) {
			memcpy(buff, server->feed_buffer, server->feed_buffer_len);

			free(server->feed_buffer);

			server->feed_buffer = NULL;
			server->feed_buffer_len = 0;
		}

		memcpy(buff + server->feed_buffer_len, msg + current_start, delim - msg - current_start);
		buff[buff_size] = '\0';

		struct chat_message result;
		result.data = buff;

		int rc = chat_server_broadcast(server, NULL, &result);
		free(buff);

		if (rc != 0) {
			return rc;
		}

		current_start = delim - msg + 1;
	}

	return 0;

#endif

	(void)server;
	(void)msg;
	(void)msg_size;
	return CHAT_ERR_NOT_IMPLEMENTED;
}
