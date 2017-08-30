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

#include "frontend.h"

#include <stdlib.h>
#include <string.h>
int
dirfd_precall_handler(struct retrace_rpc_endpoint *ep, void *buf, void **context)
{
	struct rpc_dirfd_params *params;
	char bt[4096];
	ssize_t n;

	params = malloc(sizeof(struct rpc_dirfd_params));
	*params = *(struct rpc_dirfd_params *)buf;
	*context = params;

	n = rpc_backtrace(ep->fd, bt, sizeof(bt));
	if (n > 0)
		printf(bt);

	return 1;
}

int main(int argc, char **argv)
{
	struct retrace_handle *trace_handle;

	trace_handle = retrace_start(&argv[1]);

	retrace_set_precall_handler(RPC_dirfd, dirfd_precall_handler);
	retrace_trace(trace_handle);

	retrace_close(trace_handle);
}
