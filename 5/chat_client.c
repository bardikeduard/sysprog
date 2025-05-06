#include "chat.h"
#include "chat_client.h"
#include "msg_node.h"

#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/ioctl.h>

struct chat_client {
	/** Socket connected to the server. */
	int socket;

	/** Array of received messages. */
	struct msg_node recv_list;

	/** Output buffer. */
	struct msg_node send_list;

	/** Name of the client - deletes after send. */
	char *name;
};

struct chat_client *
chat_client_new(const char *name)
{
	struct chat_client *client = calloc(1, sizeof(*client));
	client->socket = -1;

	client->name = strdup(name);
	if (client->name == NULL) {
		free(client);
		return NULL;
	}

	rlist_create(&client->send_list.node);

	return client;
}

void
chat_client_delete(struct chat_client *client)
{
	if (client->socket >= 0) {
		close(client->socket);
	}

	free(client->name);
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
	int rc = getaddrinfo(addr_copy, addr_delimeter + 1, &hint, &res);
	if (rc != 0) {
		free(addr_copy);
		freeaddrinfo(res);
		return CHAT_ERR_SYS;
	}

	struct addrinfo *iter = res;
	for (; iter != NULL; iter = iter->ai_next) {
		client->socket = socket(iter->ai_family, iter->ai_socktype | SOCK_NONBLOCK, iter->ai_protocol);
		if (client->socket == -1) {
			continue;
		}

		rc = connect(client->socket, iter->ai_addr, iter->ai_addrlen);
		if (rc == 0) {
			break;
		}

		free(addr_copy);
		freeaddrinfo(res);
		return CHAT_ERR_SYS;
	}

	free(addr_copy);
	freeaddrinfo(res);

	return 0;
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

	switch (poll(&pfd, 1, (int) timeout * 1000)) {
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

	if ((pfd.revents & POLLOUT) != 0) {
		if (client->name != NULL) {
			size_t name_full_length = strlen(client->name) + 1;
			ssize_t name_bytes_sent = send(client->socket, client->name, name_full_length, 0);
			if (name_bytes_sent <= 0) {
				return CHAT_ERR_SYS;
			}

			if (name_bytes_sent != name_full_length) {
				memmove(client->name, client->name + name_bytes_sent, sizeof(char) * (name_full_length - name_bytes_sent));
				return 0;
			}

			free(client->name);
			client->name = NULL;
		}

		if (!rlist_empty(&client->send_list.node)) {
			struct msg_node *msg_snd_iter = rlist_first_entry(&client->send_list.node, struct msg_node, node);
			struct msg_node *msg_snd_last = rlist_last_entry(&client->send_list.node, struct msg_node, node);

			while (msg_snd_iter != msg_snd_last) {
				struct msg_node *msg_snd_next = rlist_next_entry(msg_snd_iter, node);

				size_t message_full_length = strlen(msg_snd_iter->msg->data);
				ssize_t bytes_sent = send(client->socket, msg_snd_iter->msg->data, message_full_length, 0);

				if (bytes_sent < 0) {
					return CHAT_ERR_SYS;
				}

				if (bytes_sent != message_full_length) {
					memmove(msg_snd_iter->msg->data, msg_snd_iter->msg->data + bytes_sent, sizeof(char) * (message_full_length - bytes_sent));
					return 0;
				}

				rlist_del(&msg_snd_iter->node);
				free(msg_snd_iter->msg->data);
				free(msg_snd_iter->msg);
				free(msg_snd_iter);

				msg_snd_iter = msg_snd_next;
			}
		}
	}

	if ((pfd.events & POLLIN) != 0) {
		static ssize_t last_recv_data_size = -1;  // counter for already received data
		static ssize_t last_recv_name_size = -1;  // nullifies at each \0 recv

		int bytes_available = 0;
		if (ioctl(client->socket, FIONREAD, &bytes_available) != 0) {
			return CHAT_ERR_SYS;
		}

		char *read_buff = malloc(bytes_available);
		if (read_buff == NULL) {
			return CHAT_ERR_SYS;
		}

		ssize_t recv_bytes = recv(client->socket, read_buff, bytes_available, 0);
		if (recv_bytes < 0) {
			free(read_buff);
			return CHAT_ERR_SYS;
		}

		size_t buff_iter = 0;
		while (buff_iter < recv_bytes) {
			struct msg_node *node_to_recv;

			if (last_recv_data_size == -1 && last_recv_name_size == -1) {
				node_to_recv = calloc(1, sizeof(struct msg_node));

				if (node_to_recv == NULL) {
					free(read_buff);
					return CHAT_ERR_SYS;
				}

				node_to_recv->msg = calloc(1, sizeof(struct msg_node));
				if (node_to_recv->msg == NULL) {
					free(node_to_recv);
					free(read_buff);
					return CHAT_ERR_SYS;
				}

				rlist_add_tail(&client->recv_list.node, &node_to_recv->node);
			}
			else {
				node_to_recv = rlist_last_entry(&client->recv_list.node, struct msg_node, node);
			}

			if (last_recv_data_size != 0) {
				size_t available_str_size = strnlen(read_buff + buff_iter, recv_bytes - buff_iter);

				if (last_recv_data_size == -1) {
					node_to_recv->msg->data = calloc(available_str_size + 1, sizeof(char));
					if (node_to_recv->msg->data == NULL) {
						free(read_buff);
						return CHAT_ERR_SYS;
					}

					memcpy(node_to_recv->msg->data, read_buff + buff_iter, available_str_size);
				}
				else {
					memcpy(node_to_recv->msg->data + last_recv_data_size, read_buff + buff_iter, available_str_size);
				}

				if (read_buff[buff_iter + available_str_size] == '\0') {
					last_recv_data_size = 0;
				}
				else {
					last_recv_data_size += available_str_size;
				}

				buff_iter += available_str_size;
			}
			else {
				size_t available_str_size = strnlen(read_buff + buff_iter, recv_bytes - buff_iter);

				if (last_recv_name_size == -1) {
					node_to_recv->msg->author = calloc(available_str_size + 1, sizeof(char));
					if (node_to_recv->msg->author == NULL) {
						free(read_buff);
						return CHAT_ERR_SYS;
					}

					memcpy(node_to_recv->msg->author, read_buff + buff_iter, available_str_size);
				}
				else {
					memcpy(node_to_recv->msg->author + last_recv_data_size, read_buff + buff_iter, available_str_size);
				}

				if (read_buff[buff_iter + available_str_size] == '\0') {
					last_recv_data_size = -1;
					last_recv_name_size = -1;
				}
				else {
					last_recv_name_size += available_str_size;
				}

				buff_iter += available_str_size;
			}
		}

		free(read_buff);
	}

	return 0;
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

	return CHAT_EVENT_INPUT | (rlist_empty(&client->send_list.node) ? CHAT_EVENT_OUTPUT : 0);
}

int
chat_client_feed(struct chat_client *client, const char *msg, uint32_t msg_size)
{
	struct msg_node *node = calloc(1, sizeof(struct msg_node));
	if (node == NULL) {
		return CHAT_ERR_SYS;
	}

	node->msg = calloc(1, sizeof(struct chat_message));
	if (node->msg == NULL) {
		free(node);
		return CHAT_ERR_SYS;
	}

	node->msg->data = malloc(sizeof(char) * (msg_size + 1));
	if (node->msg->data == NULL) {
		free(node->msg);
		free(node);
		return CHAT_ERR_SYS;
	}

	strncpy(node->msg->data, msg, msg_size);
	node->msg->data[msg_size] = '\0';

	rlist_add(&client->send_list.node, &node->node);

	return 0;
}
