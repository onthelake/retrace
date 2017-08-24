#ifndef __RETRACE_FRONTEND_H__
#define __RETRACE_FRONTEND_H__

#include <sys/types.h>
#include <sys/queue.h>

#include "rpc.h"
#include "shim.h"

#define TRACE_char(c)	printf("'%c'", (c))
#define TRACE_cstring(p)	TRACE_pvoid(p)
#define TRACE_dir(p)	TRACE_pvoid(p)
#define TRACE_dirent(p)	TRACE_pvoid(p)
#define TRACE_file(p)	TRACE_pvoid(p)
#define TRACE_fd(i)	TRACE_int(i)
#define TRACE_int(i)	printf("%d", (i))
#define TRACE_long(i)	printf("%ld", (i))
#define TRACE_pid_t(i)	TRACE_int(i)
#define TRACE_pchar(p)	TRACE_pvoid(p)
#define TRACE_pcvoid(p)	printf("%p", (p))
#define TRACE_pdirent(p)	TRACE_pvoid(p)
#define TRACE_psize_t(p)	TRACE_pvoid(p)
#define TRACE_pstring(p)	TRACE_pvoid(p)
#define TRACE_pvoid(p)	printf("%p", (p))
#define TRACE_size_t(i)	TRACE_ulong(i)
#define TRACE_ssize_t(i)	TRACE_long(i)
#define TRACE_string(p)	TRACE_pvoid(p)
#define TRACE_ulong(i)	printf("%lu", (i))
#define TRACE_va_list(ap)	printf("ap")

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
#endif
