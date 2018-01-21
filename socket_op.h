/**
This header file include socket APIs, like connecting host/HTTP GET/POST operation

date: 03/10/2016

mail: alexwanghangzhou@gmail.com

**/
#ifndef __SOCKET_OP_H
#define __SOCKET_OP_H

#define WIFICAM_REDIS_PORT 6379
#define WIFICAM_INVALIED_IP -1
#define WIFICAM_SUCCESS     0
#define WIFICAM_FAILED      -1
#define WIFICAM_SCAN_FINISH 1


#define WIFICAM_INVALID_FD -1

typedef enum spider_task {
    SPIDER_UNKOWN = 0,
    SPIDER_INIT,
    SPIDER_WANSVIEW,
    SPIDER_CLIENT_REQ,
    SPIDER_SERVER_ACK,
} spider_task_e;

typedef struct wificam_ip_s {
    int i_index;  /* the index in redis sort set */
    unsigned int i_ipaddr; /* store the int32 ip address, host mode, need to be convert with htonl */
    unsigned short us_port;
} wificam_ip_s;


typedef struct wificam_spider {
    spider_task_e tsk_type;
    int sockfd;
    wificam_ip_s ipaddr;
    char* ipstr;
    char* location;
    void* data;
} wificam_spider_s;



#endif


