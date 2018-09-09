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
#include <sys/epoll.h>
#include <sys/syslog.h>
#include <hiredis.h>
#include "socket_op.h"
#include "unix_server.h"
#include "wificam_utility.h"
#include "redis_thread.h"

#define EPOLL_MAXEVENTS 256
#define EPOLL_TIMEOUT   7000

static int g_wificam_scan_slid_win = 8000;
static int g_total_spider_tsks = 0;
static long g_total_spider_ipaddr_tsks = 0;
static wificam_ip_s g_last_spider_addr;
int g_scan_epfd = WIFICAM_INVALID_FD;
char *g_rev_buff = NULL;
static char *g_scaning_city = NULL;
static int g_revbuf_len = 8 * 1024 * 1024;

void init()
{
    g_scaning_city = g_city_list[0];

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

static void main_loop_execute_cmd(const char* cmd)
{
    redisReply* reply = NULL;
    
    reply = redis_execute_cmd(cmd);
    if (NULL == reply || REDIS_REPLY_ERROR == reply->type) {
        syslog(LOG_ERR, "cmd:%s executes failed.\n", cmd);
    }
    freeReplyObject(reply);
}

static void get_start_scanning_addr( wificam_ip_s* p_addr ) 
{
    redisReply* reply = NULL;

    memset(p_addr, 0x0, sizeof(wificam_ip_s));
    
    reply = redis_execute_cmd("GET scanninginfo");
    if (NULL == reply || REDIS_REPLY_ERROR == reply->type || REDIS_REPLY_NIL == reply->type) {
        syslog(LOG_INFO, "execute GET scanninginfo failed\n");
    } else {
        syslog(LOG_INFO, "Get scanning information:%s", reply->str);
        int index = get_city_index(reply->str);
        if (index >= 0) {
            g_scaning_city = g_city_list[index];
        }
    }
    
    (void)redis_get_first_ip_with_key(g_scaning_city, p_addr);

    freeReplyObject(reply);
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

    tsk = malloc_spider_task(SPIDER_INIT, sockfd, p_key, ipaddr, NULL);
    if (NULL == tsk) {
        return -1;
    }
    unsigned int port = 0;
    char ip[16] = {'\0'};
    split_host_as_ip_port(ipaddr->str, ip, &port);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port   = htons(port);
    (void)inet_pton(AF_INET, ip, &servaddr.sin_addr);
    ret = connect(sockfd, &servaddr, sizeof(servaddr));
    if (ret < 0 && errno != EINPROGRESS) {
        syslog(LOG_ERR, "Try to connect [%s] failed, errstring [%s].\n",
               ipaddr->str, strerror(errno));
        close(sockfd);
        free_spider_task(tsk);
        return -1;
    }
    main_loop_epoll_ctl(EPOLL_CTL_ADD, EPOLLIN | EPOLLOUT, tsk);

    //if (!(g_total_spider_ipaddr_tsks % 1000)) 
    {
        syslog(LOG_INFO, "add epoll, connect [%s], total spider tasks:%lu\n", ipaddr->str,
        g_total_spider_ipaddr_tsks);
    }

    /* EINPROGRESS, connect return value is -1, but now need regard as success. */
    return 0;
}



void main_loop_handle_slid_window(char* p_key, wificam_ip_s* p_addr)
{
    int ret = WIFICAM_FAILED;
    char* nextcity = NULL;
    char cmd[256] = {0};

    if (NULL == p_key || NULL == p_addr) {
        syslog(LOG_ERR, "Absolutely something is wrong, input NULL pointers.\n");
        return;
    }

    if (g_total_spider_tsks >= g_wificam_scan_slid_win) {
        return;
    }

    //hostip = htonl(p_addr->i_ipaddr);
    //inet_ntop(AF_INET, &hostip, ip, sizeof(ip));

    while (g_total_spider_tsks < g_wificam_scan_slid_win) {

NEXTCITY:  ret = redis_get_next_ip_with_key(p_key, p_addr);
        if (WIFICAM_SUCCESS != ret)  {
            if (WIFICAM_SCAN_FINISH == ret) {
                nextcity = get_next_city(p_key);
                if (NULL != nextcity) {
                    /* update the scanning info for next start/restarting to continue */
                    snprintf(cmd, sizeof(cmd), "SET scanninginfo %s", nextcity);
                    main_loop_execute_cmd(cmd);
                
                    /* p_key is a tmp stack var. */
                    p_key = nextcity;
                    g_scaning_city = nextcity;
                    memset(p_addr, 0x0, sizeof(wificam_ip_s));
                    redis_get_first_ip_with_key(p_key, p_addr);
                    goto NEXTCITY;
                }
                syslog(LOG_ERR, "Scan finished:%s, %s.\n", p_key, p_addr->str);
            } else {
                syslog(LOG_ERR, "Get next ip failed from:%s, %s.\n", p_key, p_addr->str);
            }
            return;
        }
        ret = init_spider_connection(p_key, p_addr);
        if (WIFICAM_SUCCESS != ret) { 
            break; /* in case of goes into dead loop */
        }
    }
}

void main_loop_handle_scan_in_event(wificam_spider_s* tsk)
{
    int ret = 0;
    char cmd[256] = {0};
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
    } else if( 0 == ret) {
        main_loop_epoll_ctl(EPOLL_CTL_DEL, EPOLLIN, tsk);
        return; /* connection closed. */
    }
    syslog(LOG_INFO, "%s contens:%s", tsk->ipaddr.str, g_rev_buff);

    for (int i = 0; i < sizeof(key) / sizeof(char*); ++i) {
        if (NULL != strstr(g_rev_buff, key[i]))
        {
            snprintf(cmd, sizeof(cmd), "RPUSH %s %s-%s", brand[i],
                 tsk->ipaddr.str, tsk->location);
            main_loop_execute_cmd(cmd);
            break;
        }
    }

    main_loop_epoll_ctl(EPOLL_CTL_DEL, EPOLLIN, tsk);
}


void main_loop_handle_client_in_event(wificam_spider_s* tsk)
{
    int acceptfd = WIFICAM_INVALID_FD;
    wificam_spider_s* cli_tsk = NULL;

    acceptfd = accept(tsk->sockfd, NULL, NULL);
    if (acceptfd < 0) {
        syslog(LOG_ERR, "Accept client connection failed, errstring:%s\n", strerror(errno));
        return;
    }

    cli_tsk = malloc_spider_task(SPIDER_SERVER_ACK, acceptfd, NULL, NULL, NULL);
    if (NULL == cli_tsk) {
        return;
    }

    main_loop_epoll_ctl(EPOLL_CTL_ADD, EPOLLIN, cli_tsk);
}

void main_loop_handle_ack_client_event(wificam_spider_s* tsk)
{
    int ret = -1;
    client_ack_data ack;

    memset(&ack, 0x0, sizeof(ack));
    ret = main_loop_rev_data(tsk->sockfd);
    if (ret < 0) {
        return;
    }
    
    switch(((client_req_data*)g_rev_buff)->type) {
        case SET_WINDOW_REQ:
            g_wificam_scan_slid_win = *((int *)((client_req_data*)g_rev_buff)->data);
            ret = WIFICAM_SUCCESS;
            break;

        case GET_WINDOW_REQ:
            *(int*)ack.data = g_wificam_scan_slid_win;
            ret = WIFICAM_SUCCESS;
            break;
        default:
            ret = WIFICAM_FAILED;
            syslog(LOG_ERR, "received invalid req type:%d\n", ((client_req_data*)g_rev_buff)->type);
    }

    ack.err = ret;
    send(tsk->sockfd, &ack, sizeof(ack), 0);
    main_loop_epoll_ctl(EPOLL_CTL_DEL, EPOLLIN, tsk);
}


void main_loop_handle_in_event(wificam_spider_s* tsk)
{
    if (SPIDER_CLIENT_REQ == tsk->tsk_type) {
        main_loop_handle_client_in_event(tsk);
    } else if (SPIDER_SERVER_ACK == tsk->tsk_type) {
        main_loop_handle_ack_client_event(tsk);
    } else {
        main_loop_handle_scan_in_event(tsk);
    }
}

void main_loop_handle_scan_out_event(wificam_spider_s* tsk)
{
    int ret = 0;

    ret = send_get_request(tsk->sockfd, tsk->ipaddr.str);

    if (ret < 0) {
        syslog(LOG_ERR, "Send out request failed to %s\n", tsk->ipaddr.str);
        return;
    }
    main_loop_epoll_ctl(EPOLL_CTL_MOD, EPOLLIN, tsk);
}


void main_loop_handle_out_event(wificam_spider_s* tsk)
{
    if (SPIDER_SERVER_ACK == tsk->tsk_type) {
        
    } else {
        main_loop_handle_scan_out_event(tsk);
    }
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

    len = snprintf(buf, sizeof(buf), "socket:%d %s, events:",
                   tsk->sockfd, tsk->ipaddr.str);
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
    } else if (event & EPOLLHUP) {
        main_loop_epoll_ctl(EPOLL_CTL_DEL, EPOLLIN, tsk);
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
   init_unix_server(main_loop_epoll_ctl);

   /* continue scanning process and get last scanning ip from redis */
   get_start_scanning_addr(&ipaddr);
   
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


