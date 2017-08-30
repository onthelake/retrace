#ifndef __RETRACE_FRONTEND_H__
#define __RETRACE_FRONTEND_H__

#include <sys/types.h>
#include <sys/queue.h>

#include "rpc.h"
#include "shim.h"

#define TRACE_char(ep, c)	printf("'%c'", (c))
#define TRACE_cstring(ep, p)	trace_string(ep->fd, p)
#define TRACE_dir(ep, p)	TRACE_pvoid(ep, p)
#define TRACE_dirent(ep, p)	TRACE_pvoid(ep, p)
#define TRACE_file(ep, p)	TRACE_pvoid(ep, p)
#define TRACE_fd(ep, i)	TRACE_int(ep, i)
#define TRACE_int(ep, i)	printf("%d", (i))
#define TRACE_long(ep, i)	printf("%ld", (i))
#define TRACE_pid_t(ep, i)	TRACE_int(ep, i)
#define TRACE_pcvoid(ep, p)	printf("%p", (p))
#define TRACE_pdirent(ep, p)	TRACE_pvoid(ep, p)
#define TRACE_psize_t(ep, p)	TRACE_pvoid(ep, p)
#define TRACE_pstring(ep, p)	TRACE_pvoid(ep, p)
#define TRACE_pvoid(ep, p)	printf("%p", (p))
#define TRACE_size_t(ep, i)	TRACE_ulong(ep, i)
#define TRACE_ssize_t(ep, i)	TRACE_long(ep, i)
#define TRACE_string(ep, p)	trace_string(ep->fd, p)
#define TRACE_ulong(ep, i)	printf("%lu", (i))
#define TRACE_va_list(ep, ap)	printf("ap")

struct rpc_call_context {
	SLIST_ENTRY(rpc_call_context) next;
	enum rpc_function_id function_id;
	void *context;
};

SLIST_HEAD(rpc_call_stack, rpc_call_context);

struct retrace_rpc_endpoint {
	SLIST_ENTRY(retrace_rpc_endpoint) next;
	int fd;
	pid_t pid;
	int thread_num;
	unsigned int call_num;
	unsigned int call_depth;
	struct rpc_call_stack call_stack;
};

SLIST_HEAD(retrace_endpoints, retrace_rpc_endpoint);

struct retrace_process_info {
	SLIST_ENTRY(retrace_process_info) next;
	pid_t pid;
	int next_thread_num;
};

SLIST_HEAD(process_list, retrace_process_info);

struct retrace_handle {
	struct retrace_endpoints endpoints;
	struct process_list processes;
	int control_fd;
};

typedef int (*retrace_precall_handler_t)(struct retrace_rpc_endpoint *ep, void *buf, void **context);
typedef int (*retrace_postcall_handler_t)(struct retrace_rpc_endpoint *ep, void *buf, void *context);

extern retrace_precall_handler_t g_precall_handlers[];
extern retrace_postcall_handler_t g_postcall_handlers[];

struct retrace_handle *retrace_start(char *const argv[]);
void retrace_close(struct retrace_handle *handle);
void retrace_trace(struct retrace_handle *handle);
void retrace_handle_call(const struct retrace_rpc_endpoint *ep);
void retrace_set_postcall_handler(enum rpc_function_id,
	retrace_postcall_handler_t handler);
void retrace_set_precall_handler(enum rpc_function_id,
	retrace_precall_handler_t handler);

void *trace_buffer(void *buffer, size_t length);
void trace_string(int fd, const char *s);

int rpc_backtrace(int fd, char *buf, size_t len);
#endif
