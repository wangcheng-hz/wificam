#include "socket_op.h"



redisReply* redis_execute_cmd(const char* cmd);
void redis_init_conn_ctx();
int redis_get_first_ip_with_key(const char* p_key, wificam_ip_s* p_addr);
int redis_get_next_ip_with_key(const char* p_key, wificam_ip_s* p_addr);

