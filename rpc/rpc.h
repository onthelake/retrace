#ifndef __RTR_RPC_H__
#define __RTR_RPC_H__

#include <sys/types.h>
#include <sys/socket.h>
#include "shim.h"

#define RPC_MSG_LEN_MAX 256

extern const char *rpc_version;

enum rpc_msg_type {
	RPC_MSG_CALL_INIT,
	RPC_MSG_DONE,
	RPC_MSG_DO_CALL,
	RPC_MSG_CALL_RESULT,
	RPC_MSG_SET_RESULT,
	RPC_MSG_SET_PARAMETERS,
	RPC_MSG_GET_STRING,
	RPC_MSG_MISC
};

struct rpc_control_header {
	pid_t pid;
	pthread_t tid;
};

ssize_t rpc_send(int fd, enum rpc_msg_type msg_type, const void *buf, size_t len);
ssize_t rpc_recv(int fd, enum rpc_msg_type *msg_type, void *buf);

#endif
