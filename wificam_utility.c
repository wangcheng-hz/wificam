/*	$OpenBSD: strlcpy.c,v 1.12 2015/01/15 03:54:12 millert Exp $	*/

/*
 * Copyright (c) 1998, 2015 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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


//////////////////////////////////////BSD/////////////////////////////////////////////
#include <sys/types.h>
#include <string.h>

/*
 * Copy string src to buffer dst of size dsize.  At most dsize-1
 * chars will be copied.  Always NUL terminates (unless dsize == 0).
 * Returns strlen(src); if retval >= dsize, truncation occurred.
 */
size_t
strlcpy(char *dst, const char *src, size_t dsize)
{
	const char *osrc = src;
	size_t nleft = dsize;

	/* Copy as many bytes as will fit. */
	if (nleft != 0) {
		while (--nleft != 0) {
			if ((*dst++ = *src++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src. */
	if (nleft == 0) {
		if (dsize != 0)
			*dst = '\0';		/* NUL-terminate dst */
		while (*src++)
			;
	}

	return(src - osrc - 1);	/* count does not include NUL */
}
//////////////////////////////////BSD//////////////////////////////////////////////////

char *g_city_list[] = {"SC", "HB", "GD", "SD", "ZJ", "JS", "SH", "LN",
                       "BJ", "CQ", "FJ", "HN", "HE", "HA", "SX", "JX",
                       "SN", "AH", "HL", "GX", "JL", "YN", "TJ", "NM",
                       "XJ", "GS", "GZ", "HI", "NX", "QH", "XZ", "HK"};



void split_host_as_ip_port(const char* host, char*ip, unsigned int* port)
{
    if (NULL == host) { return ;}
    char* tmp = strchr(host, ':');
    strlcpy(ip, host, tmp - host + 1);
    *port = strtol(tmp +1, NULL, 0);
}

int get_city_index(const char* city)
{
    int index = -1;
    int len = sizeof(g_city_list) / sizeof(char*);

    for (int i = 0; i < len; i++) {
        if (0 == strcmp(city, g_city_list[i]) && i < len - 1) {
            index = i;
            break;
        }
    }
    return index;
}


char* get_next_city(const char* city)
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

int is_valid_ip_addr(char* ipaddr)
{
    if (NULL == ipaddr) {return -1;}
    if (NULL == strchr(ipaddr, '.')) {return -1;}
    return 0;
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

int send_get_request(int sockfd, const char *host)
{
   char buff[2048];
   char *get_string = "GET / HTTP/1.1 \r\n\
Host: %s \r\n\
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
   (void)snprintf(buff, sizeof(buff), get_string, host);
   return send(sockfd, buff, strlen(buff), 0);
}

wificam_spider_s* malloc_spider_task( spider_task_e tsk_type,
                                      int sock,
                                      const char* p_key,
                                      const wificam_ip_s* ipaddr, 
                                      const void* data )
{
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

        tmp->ipaddr   = *ipaddr;
    }

    tmp->tsk_type = tsk_type;
    tmp->sockfd   = sock;
    tmp->location = tmp_location;
    //tmp->ipstr    = tmp_ip;
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
    free(tsk->location);
    free(tsk->data);
    free(tsk);
}



