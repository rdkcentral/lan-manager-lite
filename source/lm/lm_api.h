/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

#ifndef _LM_API_H_
#define _LM_API_H_

#include <sys/un.h>
#include <time.h>

#define LM_MAX_IP_AMOUNT 24 
#define LM_GEN_STR_SIZE    64 
#define LM_MAX_COMMENT_SIZE 64
#define LM_MAX_HOSTS_NUM 256
#define LM_SERVER_FILE_NAME "/tmp/lm.sock"

#define LM_COMMENTS_LEN 64
#define LM_NETWORK_NAME_SIZE LM_GEN_STR_SIZE

#define LM_RET_SUCCESS 0
#define LM_RET_ERR     -1


#define LM_API_GET_CMD(x) *(unsigned int *)(x)

enum {
    LM_API_CMD_GET_HOSTS = 0,
    LM_API_CMD_GET_HOST_BY_MAC,
    LM_API_CMD_SET_COMMENT,
    LM_API_CMD_GET_ONLINE_DEVICE,
    LM_API_CMD_ADD_NETWORK,
    LM_API_CMD_DELETE_NETWORK,
    LM_API_CMD_GET_NETWORK,
    LM_API_CMD_MAX
};

enum {
    LM_CMD_RESULT_OK = 0,
    LM_CMD_RESULT_INTERNAL_ERR = -1,
    LM_CMD_RESULT_NOT_FOUND = -2
};
enum LM_ADDR_SOURCE{
	LM_ADDRESS_SOURCE_STATIC =0,
	LM_ADDRESS_SOURCE_DHCP,
	LM_ADDRESS_SOURCE_RESERVED,
	LM_ADDRESS_SOURCE_NONE
};

enum LM_MEDIA_TYPE{
	LM_MEDIA_TYPE_UNKNOWN=0,
	LM_MEDIA_TYPE_ETHERNET,
	LM_MEDIA_TYPE_WIFI,
	LM_MEDIA_TYPE_MOCA
};

typedef struct{
	unsigned char	addr[16];
    int active;
    int LeaseTime;
	enum LM_ADDR_SOURCE	addrSource;
    unsigned int priFlg; 
}LM_ip_addr_t;

typedef struct{
	unsigned char	phyAddr[6];
	unsigned char	online;
	unsigned char	ipv4AddrAmount;
	unsigned char	ipv6AddrAmount;
//	LM_ip_addr_t	priAddr;
	enum LM_MEDIA_TYPE mediaType;
	char	hostName[LM_GEN_STR_SIZE];
	char	l1IfName[LM_GEN_STR_SIZE];
	char	l3IfName[LM_GEN_STR_SIZE];
    char    AssociatedDevice[LM_GEN_STR_SIZE];//Only works if this is a wifi host. 
    time_t  activityChangeTime;
	LM_ip_addr_t	ipv4AddrList[LM_MAX_IP_AMOUNT];	
	LM_ip_addr_t	ipv6AddrList[LM_MAX_IP_AMOUNT];
    unsigned char   comments[LM_MAX_COMMENT_SIZE];
    int             RSSI;
}LM_host_t, *LM_host_ptr_t;

typedef struct{
    int count;
    LM_host_t   hosts[LM_MAX_HOSTS_NUM];
}LM_hosts_t;


/***********************************************/
/* API cmd & result struct 
 *
 * ********************************************/
typedef struct{
    int cmd;
}LM_cmd_common_t;

typedef struct{
    int result;
    union{
        LM_host_t host;
        int online_num; 
    }data;
}LM_cmd_common_result_t;

typedef struct{
    int cmd;
    char mac[6];
}LM_cmd_get_host_by_mac_t;

typedef struct{
    int cmd;
    unsigned char mac[6];
    char comment[LM_COMMENTS_LEN];
}LM_cmd_comment_t;


/***********************************************/
/* API Interface 
 *
 * ********************************************/

int lm_get_all_hosts (LM_hosts_t *pHosts);
int lm_get_host_by_mac(char *mac, LM_cmd_common_result_t *pHost);
int lm_set_host_comments (char mac[6], char comments[64]);
int lm_add_network(char netName[LM_NETWORK_NAME_SIZE]);
int lm_delete_network(char netName[LM_NETWORK_NAME_SIZE]);
int lm_get_network(char netName[LM_NETWORK_NAME_SIZE]);
int lm_get_online_device(int *num);
#ifdef __cplusplus
extern "C" {
#endif

int init_client_socket(int* fd);
int lm_send_rev(void *cmd, int size, void *buff, int buff_size);

#ifdef __cplusplus
}
#endif
#endif
