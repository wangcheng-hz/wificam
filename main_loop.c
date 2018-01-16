/**
main file for wificam project

date: 03/10/2016

mail: alexwanghangzhou@gmail.com

**/
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/syslog.h>
#include <hiredis.h>
#include "socket_op.h"
#include "redis_thread.h"

#define EPOLL_MAXEVENTS 256
#define EPOLL_TIMEOUT   7000

static int g_wificam_scan_slid_win = 1000;
static int g_total_spider_tsks = 0;
static long g_total_spider_ipaddr_tsks = 0;
static wificam_ip_s g_last_spider_addr;
int g_scan_epfd = WIFICAM_INVALID_FD;
char *g_rev_buff = NULL;
static char *g_city_list[] = {"SC", "HB", "GD", "SD", "ZJ", "JS", "SH", "LN",
                              "BJ", "CQ", "FJ", "HN", "HE", "HA", "SX", "JX",
                              "SN", "AH", "HL", "GX", "JL", "YN", "TJ", "NM",
                              "XJ", "GS", "GZ", "HI", "NX", "QH", "XZ", "HK"};
static char *g_scaning_city = NULL;
static int g_revbuf_len = 8 * 1024 * 1024;

void init()
{
    g_scaning_city = g_city_list[7];

    g_scan_epfd = epoll_create(1);
    if (g_scan_epfd < 0) {
      syslog(LOG_ERR, "init epoll fd failed, exit!\n");
      exit(-1);
    }
    g_rev_buff = (char *)malloc(g_revbuf_len);
    if (NULL == g_rev_buff) {
      syslog(LOG_ERR, "init global buff failed, exit!\n");
      exit(-1);
    }
    memset(g_rev_buff, 0, sizeof(g_revbuf_len));
}

void finish()
{
   if (NULL != g_rev_buff) {
      free(g_rev_buff);
      g_rev_buff = NULL;
   }
   exit(-1);
}

static char* get_next_city(const char* city)
{
    char* tmp = NULL;
    int len = sizeof(g_city_list) / sizeof(char*);

    for (int i = 0; i < len; i++) {
        if (0 == strcmp(city, g_city_list[i]) && i < len - 1) {
            tmp = g_city_list[i + 1];
            return tmp;
        }
    }
    return tmp;
}

int main_loop_rev_data(int fd)
{
   socklen_t len;
   int error = 0;

   if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
      printf("Async socket error, errno[%d], errstring [%s].\n", errno, strerror(errno));
      close(fd);
      return error;
   }

   memset( g_rev_buff, 0, g_revbuf_len );
   return recv(fd, g_rev_buff, g_revbuf_len, 0);
}



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
                                      const wificam_ip_s* ipaddr )
{
    char ip[128] = {0};

    wificam_spider_s* tmp = (wificam_spider_s*)malloc(sizeof(wificam_spider_s));
    if (NULL == tmp) {
        syslog(LOG_ERR, "malloc spider task failed.\n");
        return NULL;
    }
    memset(tmp, 0x0, sizeof(*tmp));
    char* tmp_location = strdup((NULL == p_key) ? "unkown": p_key);
    if (NULL == tmp_location) {
        syslog(LOG_ERR, "strdup spider task key:%s failed.\n", p_key);
        free(tmp);
        return NULL;
    }
    int intip = htonl(ipaddr->i_ipaddr);
    char* tmp_ip = strdup(inet_ntop(AF_INET, &intip, ip, sizeof(ip)));
    if (NULL == tmp_ip) {
        syslog(LOG_ERR, "strdup spider task ip:%s failed.\n", p_key);
        free(tmp);
        free(tmp_location);
        return NULL;
    }

    tmp->tsk_type = tsk_type;
    tmp->sockfd   = sock;
    tmp->location = tmp_location;
    tmp->ipstr    = tmp_ip;
    tmp->ipaddr   = *ipaddr;
    return tmp;
}

extern
void main_loop_epoll_ctl(int op, uint32_t events, wificam_spider_s* spider_tsk);

void free_spider_task(wificam_spider_s* tsk)
{
    if (NULL == tsk) {
        return;
    }
    if (WIFICAM_INVALID_FD != tsk->sockfd) {
        //main_loop_epoll_ctl(EPOLL_CTL_DEL, EPOLLIN, tsk);
        close(tsk->sockfd);
    }
    free(tsk->ipstr);
    free(tsk->location);
    free(tsk->data);
    free(tsk);
}

void main_loop_epoll_ctl(int op, uint32_t events, wificam_spider_s* spider_tsk)
{
    struct epoll_event event;
    event.events = events;
    event.data.ptr = (void *)spider_tsk;

    if ( epoll_ctl(g_scan_epfd, op, spider_tsk->sockfd, &event) < 0 ) {
        syslog(LOG_ERR, "Operate epoll failed, event:%d, fd:%d err:%s.\n",
                        events, spider_tsk->sockfd, strerror(errno));
        free_spider_task(spider_tsk);
        return;
    }

    if (EPOLL_CTL_ADD == op) {
        g_last_spider_addr = (spider_tsk->ipaddr);
        g_total_spider_tsks++;
        g_total_spider_ipaddr_tsks++;
    } else if (EPOLL_CTL_DEL == op) {
        g_total_spider_tsks--;
        free_spider_task(spider_tsk);
    }
}


int init_spider_connection(const char* p_key, const wificam_ip_s* ipaddr)
{
    int ret    = -1;
    int sockfd = WIFICAM_INVALID_FD;
    wificam_spider_s* tsk = NULL;
    struct sockaddr_in servaddr;

    if (NULL == p_key || NULL == ipaddr) {
        syslog(LOG_ERR, "Invalid args.\n");
        return -1;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        syslog(LOG_ERR, "in init_spider, create socket failed:%s.\n", strerror(errno));
        return -1;
    }
    setSockNonBlock(sockfd);

    tsk = malloc_spider_task(SPIDER_INIT, sockfd, p_key, ipaddr);
    if (NULL == tsk) {
        return -1;
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port   = htons(ipaddr->us_port);
    (void)inet_pton(AF_INET, tsk->ipstr, &servaddr.sin_addr);
    ret = connect(sockfd, &servaddr, sizeof(servaddr));
    if (ret < 0 && errno != EINPROGRESS) {
        syslog(LOG_ERR, "Try to connect [%s:%d] failed, errstring [%s].\n",
               tsk->ipstr, ipaddr->us_port, strerror(errno));
        close(sockfd);
        free_spider_task(tsk);
        return -1;
    }
    main_loop_epoll_ctl(EPOLL_CTL_ADD, EPOLLIN | EPOLLOUT, tsk);

    if (!(g_total_spider_ipaddr_tsks % 1000)) {
        syslog(LOG_INFO, "add epoll, connect [%s:%d], total spider tasks:%lu\n", tsk->ipstr,
        ipaddr->us_port, g_total_spider_ipaddr_tsks);
    }

    return ret;
}



void main_loop_handle_slid_window(char* p_key, wificam_ip_s* p_addr)
{
    int ret = WIFICAM_FAILED;
    int hostip = 0;
    char ip[128] = {0};
    char* nextcity = NULL;

    if (NULL == p_key || NULL == p_addr) {
        syslog(LOG_ERR, "Absolutely something is wrong, input NULL pointers.\n");
        return;
    }

    if (g_total_spider_tsks >= g_wificam_scan_slid_win) {
        return;
    }

    hostip = htonl(p_addr->i_ipaddr);
    inet_ntop(AF_INET, &hostip, ip, sizeof(ip));

    while (g_total_spider_tsks < g_wificam_scan_slid_win) {

NEXTCITY:  ret = redis_get_next_ip_with_key(p_key, p_addr);
        if (WIFICAM_SUCCESS != ret)  {
            if (WIFICAM_SCAN_FINISH == ret) {
                nextcity = get_next_city(p_key);
                if (NULL != nextcity) {
                    /* p_key is a tmp stack var. */
                    p_key = nextcity;
                    g_scaning_city = nextcity;
                    memset(p_addr, 0x0, sizeof(wificam_ip_s));
                    redis_get_first_ip_with_key(p_key, p_addr);
                    goto NEXTCITY;
                }
                syslog(LOG_ERR, "Scan finished:%s, %s.\n", p_key, ip);
            } else {
                syslog(LOG_ERR, "Get next ip failed from:%s, %s.\n", p_key, ip);
            }
            return;
        }
        init_spider_connection(p_key, p_addr);
    }
}

void main_loop_handle_in_event(wificam_spider_s* tsk)
{
    int ret = 0;
    char cmd[256] = {0};
    redisReply* reply = NULL;
    static char* key[] = {"Server: GoAhead-Webs", "realm=\"WIFICAM\"", "Server: Hikvision-Webs",
                           "Server: iDVRhttpSvr", "Server: H3C", "Server: Quidway",
                           "Server: cisco-IOS", "DVRDVS-Webs", "NVR",
                           "IPCamera", "ipcamera", "IP CAMERA", "IP Camera", 
                           "NETSuveillance", "glin=false", "360wzws",
                           "Sangfor", "Server: Switch", "Server: Lanswitch",
                           "Server: router"};
    static char* brand[] = {"GoAhead", "WIFICAM", "Hikvision",
                            "iDVRhttpSvr", "H3C", "Quidway",
                            "cisco-IOS", "DVRDVS", "NVR",
                            "ipcam", "ipcam", "ipcam", "ipcam",
                            "netsuveillance", "dahua", "360wzws",
                            "sangfor", "switch", "switch",
                            "router"};

    ret = main_loop_rev_data(tsk->sockfd);
    if (ret < 0) {
        main_loop_epoll_ctl(EPOLL_CTL_DEL, EPOLLIN, tsk);
        syslog(LOG_ERR, "Receive data failed.\n");
        return;
    }
    syslog(LOG_INFO, "contens:%s", g_rev_buff);

    for (int i = 0; i < sizeof(key) / sizeof(char*); ++i) {
        if (NULL != strstr(g_rev_buff, key[i]))
        {
            snprintf(cmd, sizeof(cmd), "RPUSH %s %s:%d-%s", brand[i],
                     tsk->ipstr, tsk->ipaddr.us_port, tsk->location);
             reply = redis_execute_cmd(cmd);
             if (NULL == reply) {
                 syslog(LOG_ERR, "Push data to redis failed, cmd:%s\n", cmd);
             }
             freeReplyObject(reply);
             break;
        }
    }

    main_loop_epoll_ctl(EPOLL_CTL_DEL, EPOLLIN, tsk);
}

void main_loop_handle_out_event(wificam_spider_s* tsk)
{
    int ret = 0;

    ret = send_get_request(tsk->sockfd,
                           tsk->ipstr,
                           tsk->ipaddr.us_port);

    if (ret < 0) {
        syslog(LOG_ERR, "Send out request failed to %s:%d\n",
               tsk->ipstr, tsk->ipaddr.us_port);
        return;
    }
    main_loop_epoll_ctl(EPOLL_CTL_MOD, EPOLLIN, tsk);
}


/*
 enum EPOLL_EVENTS
   {
     EPOLLIN = 0x001,
     EPOLLPRI = 0x002,
     EPOLLOUT = 0x004,
     EPOLLRDNORM = 0x040,
     EPOLLRDBAND = 0x080,
     EPOLLWRNORM = 0x100,
     EPOLLWRBAND = 0x200,
     EPOLLMSG = 0x400,
     EPOLLERR = 0x008,
     EPOLLHUP = 0x010,
     EPOLLRDHUP = 0x2000,
     EPOLLWAKEUP = 1u << 29,
     EPOLLONESHOT = 1u << 30,
     EPOLLET = 1u << 31
   };
 */

void print_event_types(uint32_t event, wificam_spider_s* tsk)
{
    int len = 0;
    char buf[256] = {0};

    len = snprintf(buf, sizeof(buf), "socket:%d %s:%d, events:",
                   tsk->sockfd, tsk->ipstr, tsk->ipaddr.us_port);
    if (event & EPOLLIN) {
        len += snprintf(buf+len, sizeof(buf), "%s ", "EPOLLIN");
    }
    if (event & EPOLLPRI) {
        len += snprintf(buf+len, sizeof(buf), "%s ", "EPOLLPRI");
    }
    if (event & EPOLLOUT) {
        len += snprintf(buf+len, sizeof(buf), "%s ", "EPOLLOUT");
    }
    if (event & EPOLLRDNORM) {
        len += snprintf(buf+len, sizeof(buf), "%s ", "EPOLLRDNORM");
    }
    if (event & EPOLLWRBAND) {
        len += snprintf(buf+len, sizeof(buf), "%s ", "EPOLLWRBAND");
    }
    if (event & EPOLLMSG) {
        len += snprintf(buf+len, sizeof(buf), "%s ", "EPOLLMSG");
    }
    if (event & EPOLLERR) {
        len += snprintf(buf+len, sizeof(buf), "%s ", "EPOLLERR");
    }
    if (event & EPOLLHUP) {
        len += snprintf(buf+len, sizeof(buf), "%s ", "EPOLLHUP");
    }
    if (event & EPOLLRDHUP) {
        len += snprintf(buf+len, sizeof(buf), "%s ", "EPOLLRDHUP");
    }
    if (event & EPOLLWAKEUP) {
        len += snprintf(buf+len, sizeof(buf), "%s ", "EPOLLWAKEUP");
    }
    if (event & EPOLLONESHOT) {
        len += snprintf(buf+len, sizeof(buf), "%s ", "EPOLLONESHOT");
    }
    syslog(LOG_INFO, "%s", buf);
}

void main_loop_handle(uint32_t event, void* ptr)
{
    wificam_spider_s* tsk = NULL;
    if (NULL == ptr) {
        syslog(LOG_ERR, "In main loop handle ptr is NULL, event:%d.\n", event);
        return;
    }
    tsk = (wificam_spider_s*)ptr;
    //print_event_types(event, tsk);

    if (event & EPOLLERR) {
        main_loop_epoll_ctl(EPOLL_CTL_DEL, EPOLLIN, tsk);
        //free_spider_task(tsk);
    } else if (event & EPOLLHUP) {
        main_loop_epoll_ctl(EPOLL_CTL_DEL, EPOLLIN, tsk);
        //free_spider_task(tsk);
    } else if (event & EPOLLIN) {
        main_loop_handle_in_event(tsk);
    } else if (event & EPOLLOUT) {
        main_loop_handle_out_event(tsk);
    } else {
        print_event_types(event, tsk);
        main_loop_epoll_ctl(EPOLL_CTL_DEL, EPOLLIN, tsk);
    }
}

int main(int argc, char **argv)
{
   int ret = -1;
   wificam_ip_s ipaddr;
   struct epoll_event events[EPOLL_MAXEVENTS];
   memset(events, 0, sizeof(events));

   init();
   redis_init_conn_ctx();

   ret = redis_get_first_ip_with_key(g_scaning_city, &ipaddr);
   
   ipaddr.i_index = 0;
   int net_addr;
   inet_pton(AF_INET, "219.217.4.141", &net_addr);
   ipaddr.i_ipaddr = ntohl(net_addr);
   ipaddr.us_port = 81;
   
   main_loop_handle_slid_window(g_scaning_city, &ipaddr);
   while (1) {
      errno = 0;
      ret = epoll_wait(g_scan_epfd, events, EPOLL_MAXEVENTS, -1);
      if (ret < 0 && errno != EINTR) {
          finish();
      } else if (ret == 0 || errno == EINTR) {
          continue;
      }

      for (int i=0; i < ret; i++) {
          main_loop_handle(events[i].events, events[i].data.ptr);
      }
      main_loop_handle_slid_window(g_scaning_city, &g_last_spider_addr);
   }
}


