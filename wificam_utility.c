#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/syslog.h>
#include "wificam_utility.h"


void setSockNonBlock(int fd)
{
   int flags = 0;

   flags = fcntl(fd, F_GETFL, 0);
   if (flags < 0) {
      syslog(LOG_ERR, "fcntl(F_GETFL) failed, err_string:%s.\n", strerror(errno));
   }

   flags = flags | O_NONBLOCK;
   if (fcntl(fd, F_SETFL, flags) < 0)  {
      syslog(LOG_ERR, "fcntl(F_SETFL) failed, err_string:%s.\n", strerror(errno));
   }

}

int send_get_request(int sockfd, const char *ip, int port)
{
   char buff[2048];
   char *get_string = "GET / HTTP/1.1 \r\n\
Host: %s:%d \r\n\
Connection: keep-alive \r\n\
Upgrade-Insecure-Requests: 1 \r\n\
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36 \r\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8 \r\n\
Accept-Encoding: gzip, deflate, sdch \r\n\
Accept-Language: zh-CN,zh;q=0.8 \r\n\
\r\n";

   if (sockfd < 0) {
      return -1;
   }

   memset(buff, 0, sizeof(buff));
   (void)snprintf(buff, sizeof(buff), get_string, ip, port);
   return send(sockfd, buff, strlen(buff), 0);
}

wificam_spider_s* malloc_spider_task( spider_task_e tsk_type,
                                      int sock,
                                      const char* p_key,
                                      const wificam_ip_s* ipaddr, 
                                      const void* data )
{
    char ip[128] = {0};
    char* tmp_ip = NULL;
    char* tmp_location = NULL;

    wificam_spider_s* tmp = (wificam_spider_s*)malloc(sizeof(wificam_spider_s));
    if (NULL == tmp) {
        syslog(LOG_ERR, "malloc spider task failed.\n");
        return NULL;
    }
    memset(tmp, 0x0, sizeof(*tmp));

    if (SPIDER_CLIENT_REQ != tsk_type && SPIDER_SERVER_ACK != tsk_type) {
        tmp_location = strdup((NULL == p_key) ? "unkown": p_key);
        if (NULL == tmp_location) {
            syslog(LOG_ERR, "strdup spider task key:%s failed.\n", p_key);
            free(tmp);
            return NULL;
        }
        
        int intip = htonl(ipaddr->i_ipaddr);
        tmp_ip = strdup(inet_ntop(AF_INET, &intip, ip, sizeof(ip)));
        if (NULL == tmp_ip) {
            syslog(LOG_ERR, "strdup spider task ip:%s failed.\n", p_key);
            free(tmp);
            free(tmp_location);
            return NULL;
        }

        tmp->ipaddr   = *ipaddr;
    }

    tmp->tsk_type = tsk_type;
    tmp->sockfd   = sock;
    tmp->location = tmp_location;
    tmp->ipstr    = tmp_ip;
    tmp->data     = data;
    return tmp;
}

void free_spider_task(wificam_spider_s* tsk)
{
    if (NULL == tsk) {
        return;
    }
    if (WIFICAM_INVALID_FD != tsk->sockfd) {
        close(tsk->sockfd);
    }
    free(tsk->ipstr);
    free(tsk->location);
    free(tsk->data);
    free(tsk);
}



