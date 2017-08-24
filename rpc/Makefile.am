AM_CFLAGS = -Wall -Wno-sizeof-array-argument
noinst_PROGRAMS = functions2yaml
functions2yaml_SOURCES = functions2yaml.c

lib_LTLIBRARIES = libretracerpc.la
libretracerpc_la_LDFLAGS = -no-undefined -avoid-version
libretracerpc_la_CFLAGS = $(AM_CFLAGS) $(LIBSSL_FLAGS)
noinst_HEADERS = rpc.h shim.h frontend.h backend.h
libretracerpc_la_SOURCES = rpc.c shim.c version.c backend.c
bin_PROGRAMS = retrace
retrace_SOURCES = retrace.c version.c handlers.c frontend.c rpc.c

FUNCTIONS_DEPS= shim.c shim.h handlers.c

BUILT_SOURCES= $(FUNCTIONS_DEPS) version.c
CLEANFILES= $(BUILT_SOURCES) functions.yaml

shim.h: shim_h.template
shim.c: shim_c.template
handlers.c : handlers_c.template

$(FUNCTIONS_DEPS): functions.yaml

$(FUNCTIONS_DEPS):
	mustache - $< <functions.yaml >$@

version.c : $(FUNCTION_DEPS)
	echo const char *rpc_version = \"$$(cat $(FUNCTIONS_DEPS) | md5sum | cut -c1-32)\"\; >$@

functions.yaml : functions functions2yaml
	./functions2yaml <$< >$@
