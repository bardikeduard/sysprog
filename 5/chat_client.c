#include "chat.h"
#include "chat_client.h"
#include "msg_node.h"

#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/fcntl.h>
#include <errno.h>

#define INPUT_BUFFER_INITIAL_SIZE 4096

struct chat_client {
	/** Socket connected to the server. */
	int socket;

	/** Array of received messages. */
	struct msg_node recv_list;

	/** Output buffer. */
	struct msg_node send_list;

	/** Name of the client - deletes after send. */
	char *name;

	/** Unified input buffer for incoming data */
	char *input_buffer;

	/** Current number of bytes in input_buffer */
	size_t input_buffer_len;

	/** Total allocated size of input_buffer */
	size_t input_buffer_capacity;
};


static int
chat_client_parse_input(struct chat_client *client)
{
	char *current_pos = client->input_buffer;
	size_t remaining_len = client->input_buffer_len;

	while (1) {
		char *data_end = memchr(current_pos, '\n', remaining_len);
		if (data_end == NULL) {
			break;
		}

		size_t data_len = data_end - current_pos;
		size_t len_after_data = remaining_len - (data_len + 1);

		if (len_after_data == 0) {
			break;
		}

		char *author_end = memchr(data_end + 1, '\0', len_after_data);
		if (author_end == NULL) {
			break;
		}
		size_t author_len = author_end - (data_end + 1);

		struct msg_node *node = calloc(1, sizeof(struct msg_node));
		if (node == NULL) {
			return CHAT_ERR_SYS;
		}

		node->msg = calloc(1, sizeof(struct chat_message));
		if (node->msg == NULL) {
			free(node);
			return CHAT_ERR_SYS;
		}

		node->msg->data = strndup(current_pos, data_len);
		if (node->msg->data == NULL) {
			free(node->msg);
			free(node);
			return CHAT_ERR_SYS;
		}

		node->msg->author = strndup(data_end + 1, author_len);
		if (node->msg->author == NULL) {
			free(node->msg->data);
			free(node->msg);
			free(node);
			return CHAT_ERR_SYS;
		}

		rlist_add_tail(&client->recv_list.node, &node->node);

		size_t consumed_len = author_end - current_pos + 1;
		current_pos += consumed_len;
		remaining_len -= consumed_len;
	}

	if (current_pos != client->input_buffer) {
		memmove(client->input_buffer, current_pos, remaining_len);
		client->input_buffer_len = remaining_len;
	}

	return 0;
}

static int
chat_client_input(struct chat_client *client)
{
	while (1) {
		if (client->input_buffer_len == client->input_buffer_capacity) {
			size_t new_capacity = client->input_buffer_capacity * 2;
			char *new_buffer = realloc(client->input_buffer, new_capacity);
			if (new_buffer == NULL) {
				return CHAT_ERR_SYS;
			}

			client->input_buffer = new_buffer;
			client->input_buffer_capacity = new_capacity;
		}

		ssize_t recv_bytes = recv(client->socket,
					client->input_buffer + client->input_buffer_len,
					client->input_buffer_capacity - client->input_buffer_len, 0);

		if (recv_bytes > 0) {
			client->input_buffer_len += recv_bytes;
		}
		else if (recv_bytes == 0) {
			return CHAT_ERR_SYS;
		}
		else {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				break;
			}

			return CHAT_ERR_SYS;
		}
	}

	return 0;
}

struct chat_client *
chat_client_new(const char *name)
{
	struct chat_client *client = calloc(1, sizeof(*client));
	if (client == NULL) {
		return NULL;
	}

	if (name != NULL) {
		size_t name_len = strlen(name);

		client->name = malloc((name_len + 2) * sizeof(char));
		if (client->name == NULL) {
			free(client);
			return NULL;
		}

		memcpy(client->name, name, name_len);
		client->name[name_len] = '\n';
		client->name[name_len + 1] = '\0';
	}

	client->socket = -1;

	client->input_buffer = malloc(INPUT_BUFFER_INITIAL_SIZE);
	if (client->input_buffer == NULL) {
		free(client->name);
		free(client);
		return NULL;
	}

	client->input_buffer_len = 0;
	client->input_buffer_capacity = INPUT_BUFFER_INITIAL_SIZE;

	rlist_create(&client->send_list.node);
	rlist_create(&client->recv_list.node);

	return client;
}

void
chat_client_delete(struct chat_client *client)
{
	if (client == NULL) {
		return;
	}

	if (client->socket >= 0) {
		close(client->socket);
	}

	struct msg_node *iter, *tmp;
	rlist_foreach_entry_safe(iter, &client->send_list.node, node, tmp) {
		chat_message_delete(iter->msg);
		free(iter);
	}

	rlist_foreach_entry_safe(iter, &client->recv_list.node, node, tmp) {
		chat_message_delete(iter->msg);
		free(iter);
	}

	free(client->name);
	free(client->input_buffer);
	free(client);
}

int
chat_client_connect(struct chat_client *client, const char *addr)
{
	char *addr_copy = strdup(addr);
	if (addr_copy == NULL) {
		return CHAT_ERR_SYS;
	}

	char *addr_delimeter = strrchr(addr_copy, ':');
	if (addr_delimeter == NULL) {
		free(addr_copy);
		return CHAT_ERR_INVALID_ARGUMENT;
	}

	*addr_delimeter = '\0';

	struct addrinfo hint;
	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;

	struct addrinfo *res;
	if (getaddrinfo(addr_copy, addr_delimeter + 1, &hint, &res) != 0) {
		free(addr_copy);
		return CHAT_ERR_SYS;
	}

	free(addr_copy);

	struct addrinfo *iter = res;
	for (; iter != NULL; iter = iter->ai_next) {
		client->socket = socket(iter->ai_family, iter->ai_socktype, iter->ai_protocol);
		if (client->socket == -1) {
			continue;
		}

		if (connect(client->socket, iter->ai_addr, iter->ai_addrlen) == 0) {
			int flags = fcntl(client->socket, F_GETFL, 0);
			fcntl(client->socket, F_SETFL, flags | O_NONBLOCK);
			freeaddrinfo(res);
			return 0;
		}

		close(client->socket);
		client->socket = -1;
	}

	freeaddrinfo(res);

	return CHAT_ERR_SYS;
}

struct chat_message *
chat_client_pop_next(struct chat_client *client)
{
	if (rlist_empty(&client->recv_list.node)) {
		return NULL;
	}

	struct msg_node *next_recv_msg = rlist_first_entry(&client->recv_list.node, struct msg_node, node);
	rlist_del(&next_recv_msg->node);

	struct chat_message *result = next_recv_msg->msg;
	free(next_recv_msg);

	return result;
}

static int
chat_client_output(struct chat_client *client)
{
	struct msg_node *msg_snd_iter, *tmp;

	rlist_foreach_entry_safe (msg_snd_iter, &client->send_list.node, node, tmp) {
		struct chat_message *msg = msg_snd_iter->msg;
		size_t message_len = strlen(msg->data);
		ssize_t bytes_sent = send(client->socket, msg->data, message_len, 0);

		if (bytes_sent < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				return 0;
			}
			return CHAT_ERR_SYS;
		}

		if (bytes_sent < message_len) {
			memmove(msg->data, msg->data + bytes_sent, message_len - bytes_sent + 1);
			return 0;
		}

		rlist_del(&msg_snd_iter->node);
		chat_message_delete(msg);
		free(msg_snd_iter);
	}

	return 0;
}

int
chat_client_update(struct chat_client *client, double timeout)
{
	if (client->socket < 0) {
		return CHAT_ERR_NOT_STARTED;
	}

	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = client->socket;
	pfd.events = chat_events_to_poll_events(chat_client_get_events(client));

	int poll_rc = poll(&pfd, 1, (int) (timeout * 1000));
	if (poll_rc < 0) {
		return CHAT_ERR_SYS;
	}

	if (poll_rc == 0) {
		return CHAT_ERR_TIMEOUT;
	}

	if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
		return CHAT_ERR_SYS;
	}

	int rc = 0;
	if ((pfd.revents & POLLIN) != 0) {
		rc = chat_client_input(client);
		if (rc == 0) {
			rc = chat_client_parse_input(client);
		}
	}

	if (rc == 0 && (pfd.revents & POLLOUT) != 0) {
		rc = chat_client_output(client);
	}

	return rc;
}

int
chat_client_get_descriptor(const struct chat_client *client)
{
	return client->socket;
}

int
chat_client_get_events(const struct chat_client *client)
{
	if (client->socket == -1) {
		return 0;
	}

	return CHAT_EVENT_INPUT | (!rlist_empty(&client->send_list.node) ? CHAT_EVENT_OUTPUT : 0);
}

static int
chat_client_feed_internal(struct chat_client *client, const char *msg, uint32_t msg_size)
{
	struct msg_node *node = malloc(sizeof(struct msg_node));
	if (node == NULL) {
		return CHAT_ERR_SYS;
	}

	node->msg = calloc(1, sizeof(struct chat_message));
	if (node->msg == NULL) {
		free(node);
		return CHAT_ERR_SYS;
	}

	node->msg->data = strndup(msg, msg_size);
	if (node->msg->data == NULL) {
		free(node->msg);
		free(node);
		return CHAT_ERR_SYS;
	}

	rlist_add_tail(&client->send_list.node, &node->node);
	return 0;
}

int
chat_client_feed(struct chat_client *client, const char *msg, uint32_t msg_size)
{
	if (client->name != NULL) {
		if (chat_client_feed_internal(client, client->name, strlen(client->name)) != 0) {
			return CHAT_ERR_SYS;
		}

		free(client->name);
		client->name = NULL;
	}

	return chat_client_feed_internal(client, msg, msg_size);
}