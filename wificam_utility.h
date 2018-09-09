#ifndef __WIFICAM_UTILITY_H__
#define __WIFICAM_UTILITY_H__
#include "socket_op.h"

extern char *g_city_list[];

typedef enum CLIENT_REQ_TYPE {
    UNKOWN_REQ = 0,
    SET_WINDOW_REQ,
    GET_WINDOW_REQ,
} client_req_e;

typedef struct CLIENT_REQ_DATA {
    client_req_e type;
    char data[128];
} client_req_data;

typedef struct CLIENT_ACK_DATA {
    int err;
    char data[128];
} client_ack_data;

size_t strlcpy(char *dst, const char *src, size_t dsize);
void split_host_as_ip_port(const char* host, char*ip, unsigned int* port);
int get_city_index(const char* city);
char* get_next_city(const char* city);
void setSockNonBlock(int fd);
int send_get_request(int sockfd, const char *host);
wificam_spider_s* malloc_spider_task( spider_task_e tsk_type,
                                      int sock,
                                      const char* p_key,
                                      const wificam_ip_s* ipaddr, 
                                      const void* data );
void free_spider_task(wificam_spider_s* tsk);

#endif

