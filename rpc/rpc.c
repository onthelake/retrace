/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "../config.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include "rpc.h"

ssize_t
rpc_send(int fd, enum rpc_msg_type msg_type, const void *buf, size_t length)
{
	struct iovec iov[] = {
	    {&msg_type, sizeof(msg_type)}, {(void *)buf, length} };
	struct msghdr msg = {NULL, 0, iov, 2, NULL, 0, 0};
	ssize_t result;

	do {
		result = sendmsg(fd, &msg, 0);
	} while (result == -1 && errno == EINTR);

	return result;
}

ssize_t
rpc_recv(int fd, enum rpc_msg_type *msg_type, void *buf)
{
	struct iovec iov[] = {
	    {msg_type, sizeof(*msg_type)}, {(void *)buf, RPC_MSG_LEN_MAX} };
	struct msghdr msg = {NULL, 0, iov, 2, NULL, 0, 0};
	ssize_t result;

	do {
		result = recvmsg(fd, &msg, 0);
	} while (result == -1 && errno == EINTR);

	return result;
}
