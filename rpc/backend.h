#ifndef __RTR_BACKEND_H__
#define __RTR_BACKEND_H__

#include <sys/types.h>
#include <sys/socket.h>

int rpc_handle_message(enum rpc_msg_type msg_type, void *buf, int *done);
int rpc_backend_recv(enum rpc_msg_type *msg_type, void *buf);
int rpc_backend_send(enum rpc_msg_type msg_type, const void *buf, size_t len);

#endif

