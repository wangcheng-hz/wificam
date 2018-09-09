#include <pthread.h>
#include <syslog.h>
#include <string.h>
#include <hiredis.h>
#include <arpa/inet.h>
#include "wificam_utility.h"
#include "redis_thread.h"


//static int g_redis_epfd = -1;
/////////////////////////////////////////////////////////
static pthread_mutex_t g_conn_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;
static redisContext *g_redis_conn_ctx = NULL; /* connection used for all threads */
/////////////////////////////////////////////////////////
//static redisContext *g_redis_ep_ctx = NULL;
//static int g_scan_ports[] = {81};
static char* _redis_raw_ip_prefix = "raw-ip-for-city";


///////////////////////////////////////////////////////////////////////////////
////////////////////////         INTERNAL API          ////////////////////////
///////////////////////////////////////////////////////////////////////////////

static void convert_set2ipaddrs(char* s, int* start, int* finish)
{
    int i = 0;
    char* token = NULL;

    for(token = strsep(&s, " "); token != NULL; token = strsep(&s, " ")) {
        inet_pton(AF_INET, token, (0 == i) ? start : finish);
        i++;
    }
    *start = ntohl(*start);
    *finish = ntohl(*finish);
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////          PUBLIC API            ////////////////////////
///////////////////////////////////////////////////////////////////////////////

void redis_init_conn_ctx()
{
    const char *hostname = "127.0.0.1";
    int port = WIFICAM_REDIS_PORT;
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds

    while (g_redis_conn_ctx == NULL || g_redis_conn_ctx->err) {
        g_redis_conn_ctx = redisConnectWithTimeout(hostname, port, timeout);
        if (g_redis_conn_ctx == NULL || g_redis_conn_ctx->err) {
            if (g_redis_conn_ctx) {
                syslog(LOG_ERR, "Connection error: %s\n", g_redis_conn_ctx->errstr);
                redisFree(g_redis_conn_ctx);
            } else {
                syslog(LOG_ERR, "Connection error: can't allocate redis context\n");
            }
        }
    }
}


/*
  the replied pointer redisReply* need to be freed by caller through freeReplyObject()
*/
redisReply* redis_execute_cmd(const char* cmd)
{
    redisReply* p_reply = NULL;

    if (NULL == g_redis_conn_ctx) {
        syslog(LOG_ERR, "redis context is NULL\n");
        return NULL;
    }

    pthread_mutex_lock(&g_conn_ctx_mutex);
    p_reply = redisCommand(g_redis_conn_ctx, cmd);
    if (NULL == p_reply) {
        syslog(LOG_ERR, "redisCommand returns NULL, refresh ctx\n");
        redisFree(g_redis_conn_ctx);
        redis_init_conn_ctx();
    }
    pthread_mutex_unlock(&g_conn_ctx_mutex);

    if (NULL != p_reply && REDIS_REPLY_ERROR == p_reply->type) {
        syslog(LOG_ERR, "execute cmd:%s failed, err string:%s\n", cmd, p_reply->str);
        freeReplyObject(p_reply);
        return NULL;
    }

    return p_reply;
}

int redis_get_first_ip_with_key(const char* p_key, wificam_ip_s* p_addr)
{
    redisReply* reply = NULL;
    char buff[256] = {0};
    int ret = WIFICAM_FAILED;

    if (NULL == p_key || NULL == p_addr) {
        syslog(LOG_ERR, "the input key/addr is NULL\n");
        return WIFICAM_FAILED;
    }

    while (WIFICAM_SUCCESS != ret) {
        snprintf(buff, sizeof(buff), "ZRANGE %s-%s 0 0", _redis_raw_ip_prefix, p_key);
        reply = redis_execute_cmd(buff);
        if (NULL == reply) {
            syslog(LOG_ERR, "execute cmd:%s failed\n", buff);
            return WIFICAM_FAILED;
        }
        
        if (REDIS_REPLY_ARRAY != reply->type) {
            syslog(LOG_ERR, "execute cmd:%s return wrong type:%d\n", buff, reply->type);
            freeReplyObject(reply);
            return WIFICAM_FAILED;
        }
        if (0 == reply->elements) {
            p_key = get_next_city(p_key);
            if (NULL == p_key)
            {
                freeReplyObject(reply);
                return WIFICAM_SCAN_FINISH;
            }
        }
        ret = WIFICAM_SUCCESS;
    }

    memset(p_addr, 0x0, sizeof(wificam_ip_s));
    p_addr->i_index = 0;
    strlcpy(p_addr->str, reply->element[0]->str, WIFICAM_IPADDR_LEN);

    freeReplyObject(reply);
    return WIFICAM_SUCCESS;
}


int redis_get_next_ip_with_key(const char* p_key, wificam_ip_s* p_addr)
{
    char buff[256] = {0};
    redisReply* reply = NULL;

    if (NULL == p_key || NULL == p_addr) {
        syslog(LOG_ERR, "the input key/addr is NULL\n");
        return WIFICAM_FAILED;
    }

    //////////scan for next ip address//////////////////////////////////////
    int index = p_addr->i_index + 1;
    snprintf(buff, sizeof(buff), "ZRANGE %s-%s %d %d", _redis_raw_ip_prefix, p_key, index, index);
    reply = redis_execute_cmd(buff);
    if (NULL == reply) {
        syslog(LOG_ERR, "execute cmd:%s failed\n", buff);
        return WIFICAM_FAILED;
    }
    if (0 == reply->elements) {
        freeReplyObject(reply);
        return WIFICAM_SCAN_FINISH;
    }
    //convert_set2ipaddrs(reply->element[0]->str, &start, &finish);
    freeReplyObject(reply);
    p_addr->i_index = index;
    strlcpy(p_addr->str, reply->element[0]->str, WIFICAM_IPADDR_LEN);

    return WIFICAM_SUCCESS;
}



