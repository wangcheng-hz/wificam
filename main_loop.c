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
#include "socket_op.h"

#define EPOLL_MAXEVENTS 1
#define EPOLL_TIMEOUT   7000


void (*fn_callback)(int fd, int mask);
int g_epfd = INVALID_FD;
char *g_rev_buff = NULL;
static int g_revbuf_len = 8 * 1024 * 1024;

void init()
{
   g_epfd = epoll_create(1);
   if (g_epfd < 0) {
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

void rev_and_deal(int fd, int mask)
{
   int recv_size = -1;
   socklen_t len;
   int error = 0;

   printf("Enter into the callback function, mask [%d].\n", mask);

   if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
      printf("Async socket error, errno[%d], errstring [%s].\n", errno, strerror(errno));
      close(fd);
      return;
   }

   printf("The connect errno[%d], errstring [%s].\n", error, strerror(error));

   memset( g_rev_buff, 0, sizeof(g_revbuf_len) );
   recv_size = recv(fd, g_rev_buff, sizeof(g_rev_buff), 0);
   if (recv_size < 0){
      syslog(LOG_ERR, "init global buff failed, exit!\n");
   }

   printf("The outputs is:\r\n%s.", g_rev_buff);
}

void add_into_epoll(int sockfd, int op, void *callback)
{
   struct epoll_event event;
   event.events = EPOLLIN;
   event.data.fd = sockfd;
   event.data.ptr = (void *)callback;

   if ( epoll_ctl(g_epfd, op, sockfd, &event) == -1 ) {
      syslog(LOG_ERR, "Try to add event into epoll failed, %s.\n", strerror(errno));
   }
}

void setSockNonBlock(int fd)
{
   int flags = 0;

   flags = fcntl(fd, F_GETFL, 0);
   if (flags < 0) {
      syslog(LOG_ERR, "fcntl(F_GETFL) failed, err_string:%s.\n", strerror(errno));
   }
   if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
      syslog(LOG_ERR, "fcntl(F_SETFL) failed, err_string:%s.\n", strerror(errno));
   }
}

int send_get_request(int sockfd, const char *ip, int port)
{
   char buff[2048];
   char *get_string = "GET / HTTP/1.1 \r\n\
Host: 58.42.13.243:80 \r\n\
Connection: keep-alive \r\n\
Upgrade-Insecure-Requests: 1 \r\n\
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36 \r\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8 \r\n\
Accept-Encoding: gzip, deflate, sdch \r\n\
Accept-Language: zh-CN,zh;q=0.8";

   if (sockfd < 0) {
      return -1;
   }

   memset(buff, 0, sizeof(buff));
   (void)snprintf(buff, sizeof(buff), get_string, ip, port);
   return send(sockfd, buff, strlen(buff), 0);
}

int try_connect_cam(const char *ip, int port)
{
   int ret    = -1;
   int sockfd = INVALID_FD;
   struct sockaddr_in servaddr;

   if (NULL == ip || port < 0 || port > 65535) {
      syslog(LOG_ERR, "Invalid args [%s:%d].\n", ip, port);
      return -1;
   }

   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sockfd < 0) {
      syslog(LOG_ERR, "create socket failed.\n");
      return -1;
   }
   setSockNonBlock(sockfd);

   bzero(&servaddr, sizeof(servaddr));
   servaddr.sin_family = AF_INET;
   servaddr.sin_port   = htons(port);
   (void)inet_pton(AF_INET, ip, &servaddr.sin_addr);

   ret = connect(sockfd, &servaddr, sizeof(servaddr));
   if (ret < 0 && errno != EINPROGRESS) {
      syslog(LOG_ERR, "Try to connect [%s:%d] failed, errstring [%s].\n", ip, port, strerror(errno));
      return -1;
   }

   add_into_epoll(sockfd, EPOLL_CTL_ADD);
   ret = send_get_request(sockfd, ip, port);
   if (ret < 0) {
      syslog(LOG_ERR, "Try to send [%s:%d] failed, errstring [%s].\n", ip, port, strerror(errno));
   }

   return ret;
}


int main(int argc, char **argv)
{
   int ret = -1;
   struct epoll_event events[EPOLL_MAXEVENTS];
   memset(events, 0, sizeof(events));

   init();

   ret = try_connect_cam("58.42.13.243", 80);

   while (1) {
      ret = epoll_wait(g_epfd, events, EPOLL_MAXEVENTS, EPOLL_TIMEOUT);
      if (ret < 0) {
          finish();
      } else if (ret == 0) {
          continue;
      }

      for (int i=0; i < EPOLL_MAXEVENTS; i++) {
         ((void (*)(int, int))events[i].data.ptr)(events[i].data.fd, events[i].events);
      }
   }
}


