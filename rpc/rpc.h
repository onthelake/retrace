#ifndef __RTR_RPC_H__
#define __RTR_RPC_H__

#include <sys/types.h>
#include <sys/socket.h>
#include "shim.h"

#define RPC_MSG_LEN_MAX 256

extern const char *retrace_version;

enum rpc_msg_type {
	RPC_MSG_CALL_INIT,
	RPC_MSG_DONE,
	RPC_MSG_DO_CALL,
	RPC_MSG_CALL_RESULT,
	RPC_MSG_SET_RESULT,
	RPC_MSG_SET_ERRNO,
	RPC_MSG_SET_PARAMETERS,
	RPC_MSG_GET_STRING,
	RPC_MSG_GET_MEMORY,
	RPC_MSG_BACKTRACE
};

struct rpc_control_header {
	pid_t pid;
	pthread_t tid;
};

struct rpc_string_params {
	char *address;
	size_t length;
};

struct rpc_memory_params {
	char *address;
	size_t length;
};

struct rpc_backtrace_params {
	int depth;
};

struct rpc_errno_params {
	int e;
};
#endif
