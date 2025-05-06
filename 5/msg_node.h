#pragma once

#include "rlist.h"

struct msg_node {
	struct rlist node;
	struct chat_message *msg;
};
