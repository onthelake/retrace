#ifndef __RTR_BACKEND_H__
#define __RTR_BACKEND_H__

#include <sys/types.h>
#include <sys/socket.h>

int rpc_get_sockfd(void);
void rpc_set_sockfd(long int fd);
int rpc_send_message(int fd, enum rpc_msg_type msg_type, const void *buf, size_t len);
int rpc_recv_message(int fd, enum rpc_msg_type *msg_type, void *buf);
int rpc_handle_message(int fd, enum rpc_msg_type msg_type, void *buf);

#endif

