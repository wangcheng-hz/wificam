#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include "unix_server.h"
#include "wificam_utility.h"

void print_help()
{
    char* helpinfo = 
"Usage of wificamcli:\n \
        Mandatary:\n \
        -s Set parameter\n \
        -g Get infomation\n \
        Options: \
        -w <value> slid window number\n \
 Examples:\
        wificamcli -s -w 10\n\n";
    printf("%s", helpinfo);
}

int connect_to_ser(client_req_data* req)
{
    int fd = -1;
    struct sockaddr_un address;  
    
    if (NULL == req) {
        return -1;
    }

    address.sun_family = AF_UNIX;  
    strcpy(address.sun_path, g_unix_server_name);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("create socket failed, err:%s\n", strerror(errno));
        return -1;
    }

    int ret = connect(fd, (struct sockaddr *)&address, sizeof(address));  
    if(ret < 0)  
    {  
      perror("connect failed: ");  
      return -1;
    } 

    write(fd, req, sizeof(client_req_data));

    client_ack_data ack;
    read(fd, &ack, sizeof(client_ack_data));  
    printf("operation result:%s\n", ack.err ? "failed":"success");  
      
    close(fd);  
      
    return 0;  
    
}


int main (int argc, char** argv)
{
    char opt;
    int tmp = 0;
    client_req_data req;
    char* optargs = "sgw:h?";

    if (argc < 2) {
        print_help();
        exit(1);
    }

    opt = getopt( argc, argv, optargs );
    while( opt != -1 ) {
        switch( opt ) {
            case 's':
                req.type = SET_WINDOW_REQ;
                break;
            case 'g':
                req.type = GET_WINDOW_REQ;
                break;
            case 'w':
                tmp = atoi(optarg);
                *(int*)req.data = tmp;
                break;
            case 'h':
            case '?':
                print_help();
                exit(1);
                break;
            default:
                print_help();
                exit(1);
                break;
        }
         opt = getopt( argc, argv, optargs );
    }

    connect_to_ser(&req);
    return 0;
}


