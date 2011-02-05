#ifndef DREW_INTERNAL_H
#define DREW_INTERNAL_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#define _BSD_SOURCE 1
#define DREW_IN_BUILD 1

#if defined(DREW_AS_PLUGIN)
#define DREW_PLUGIN_NAME(x) drew_plugin_info
#elif defined(DREW_AS_MODULE)
#define DREW_PLUGIN_NAME(x) drew_plugin_info_ ## x
#endif

typedef int (*drew_plugin_api_t)(void *, int, int, void *);

#endif
