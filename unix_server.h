#ifndef __UNIX_SERVER_H__
#define __UNIX_SERVER_H__
#include "socket_op.h"

static const char* g_unix_server_name = "/dev/shm/wificam-srever-un";

typedef void (scanEpollCtlFn)(int, uint32_t, wificam_spider_s*);

void init_unix_server(scanEpollCtlFn *fn);

#endif
