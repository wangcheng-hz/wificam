#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/syslog.h>
#include <sys/epoll.h>
#include "wificam_utility.h"
#include "unix_server.h"

static pthread_t g_unix_server_tid = 0;

static void* start_uinx_server_routine(void* fn)
{
    int sockfd = WIFICAM_INVALID_FD;
    int ret = -1;
    int server_len = -1;
    wificam_spider_s* listentsk = NULL;
    struct sockaddr_un ser_addr;
    
    unlink(g_unix_server_name);
    pthread_detach(g_unix_server_tid);

    ser_addr.sun_family = AF_UNIX;  
    strcpy(ser_addr.sun_path, g_unix_server_name);  
    server_len = sizeof(ser_addr);  
    
    sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (sockfd < 0) {
        syslog(LOG_ERR, "Create unix socket failed: %s", strerror(errno));
        return NULL;
    }

    ret = bind(sockfd, (struct sockaddr *)&ser_addr, server_len); 
    if (ret < 0) {
        syslog(LOG_ERR, "Bind unix socket failed: %s", strerror(errno));
        return NULL;
    }

    ret = listen(sockfd, 5); 
    if (ret < 0) {
        syslog(LOG_ERR, "Listen unix socket failed: %s", strerror(errno));
        return NULL;
    }

    listentsk = malloc_spider_task(SPIDER_CLIENT_REQ, sockfd, NULL, NULL, NULL);
    if (NULL == listentsk) {
        syslog(LOG_ERR, "Malloc for unix REQ tsk failed: %s", strerror(errno));
        return NULL;
    }
    ((scanEpollCtlFn*)fn) (EPOLL_CTL_ADD, EPOLLIN, listentsk);
}


void init_unix_server(scanEpollCtlFn *fn)
{
    int ret = -1;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    ret = pthread_create(&g_unix_server_tid, &attr, start_uinx_server_routine, fn);
    if (ret < 0) {
        syslog(LOG_ERR, "Create unix thread failed: %s", strerror(errno));
    }

}





