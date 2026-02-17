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

#include <stdio.h>  
#include <stdlib.h>
#include <sys/types.h>  
#include <sys/socket.h>
#include <sys/un.h>  
#include <unistd.h>
#include "lm_api.h"
#include "ansc_wrapper_base.h"
#include "safec_lib_common.h"

#define LM_LOG(x) printf x 

/* internal define */
#define CHK_GOTO_TAG(cond, ret_tag) if((cond)) goto ret_tag


int init_client_socket(int *client_fd){
    struct sockaddr_un srv_addr; 
    int fd;
    int ret;
    errno_t rc = -1;
    fd = socket(PF_UNIX,SOCK_STREAM,0);
    if(fd < 0 )
        return LM_RET_ERR;
    srv_addr.sun_family=AF_UNIX;  
    rc = strcpy_s(srv_addr.sun_path, sizeof(srv_addr.sun_path),LM_SERVER_FILE_NAME);
    ERR_CHK(rc);

    ret=connect(fd,(struct sockaddr*)&srv_addr,sizeof(srv_addr));  
    if(ret==-1)  
    {  
        close(fd);  
        return LM_RET_ERR;  
    }
    *client_fd = fd;
    return LM_RET_SUCCESS;
}

int lm_send_rev(void *cmd, int size, void *buff, int buff_size)
{
    int ret;
    int fd;
    int r_val = LM_RET_ERR;

    ret = init_client_socket(&fd);
    if(ret != LM_RET_SUCCESS){
        LM_LOG(("init_client_socket error\n"));
        return LM_RET_ERR;
    }

    // COVERITY ISSUE: Resource leak - fd not closed on null pointer check failure
    if(cmd == NULL || buff == NULL){
        LM_LOG(("Null pointer passed\n"));
        return LM_RET_ERR;  // fd is not closed here - RESOURCE LEAK
    }

    ret = write(fd, cmd, size);
    CHK_GOTO_TAG((ret <= 0), RET);
    
    ret = recv(fd, buff, buff_size, MSG_WAITALL);
    CHK_GOTO_TAG((ret <= 0), RET);
    r_val = LM_RET_SUCCESS ;

RET:
    close(fd);
    return r_val;
}

int lm_get_all_hosts (LM_hosts_t *pHosts)
{
    LM_cmd_common_t cmd;   

    cmd.cmd = LM_API_CMD_GET_HOSTS;
    
    return (lm_send_rev(&cmd, sizeof(cmd), pHosts, sizeof(LM_hosts_t)));
}

int lm_get_host_by_mac(char *mac, LM_cmd_common_result_t *pHost)
{
    LM_cmd_get_host_by_mac_t cmd;

    cmd.cmd = LM_API_CMD_GET_HOST_BY_MAC;
    memcpy(cmd.mac, mac, 6);
    
    return (lm_send_rev(&cmd, sizeof(cmd), pHost, sizeof(LM_cmd_common_result_t))); 
}

int lm_set_host_comments (char mac[6], char comments[64])
{
    LM_cmd_comment_t cmd;
    LM_cmd_common_result_t result;
    int ret;

    cmd.cmd = LM_API_CMD_SET_COMMENT;
    memcpy(cmd.mac, mac, 6);
    if(comments == NULL){
        cmd.comment[0] = '\0';
    }else{
        strncpy(cmd.comment, comments, LM_COMMENTS_LEN -1);
        cmd.comment[LM_COMMENTS_LEN -1] = '\0';
    }
    
    ret = lm_send_rev(&cmd, sizeof(cmd), &result, sizeof(LM_cmd_common_result_t));
    if(ret != LM_RET_SUCCESS || result.result != LM_RET_SUCCESS)
        return LM_RET_ERR; 
    else
        return LM_RET_SUCCESS;
}

int lm_get_online_device(int *num)
{
    LM_cmd_common_result_t result;
    LM_cmd_common_t  cmd;
    int ret;
    
    cmd.cmd = LM_API_CMD_GET_ONLINE_DEVICE;
    ret = lm_send_rev(&cmd, sizeof(cmd), &result, sizeof(LM_cmd_common_result_t));
    if(ret != LM_RET_SUCCESS || result.result != LM_RET_SUCCESS)
        return LM_RET_ERR;
    else{
        *num = result.data.online_num;
        return LM_RET_SUCCESS;
    }
}

int lm_add_network(char netName[LM_NETWORK_NAME_SIZE])
{
    UNREFERENCED_PARAMETER(netName);
    return -1;
}

int lm_delete_network(char netName[LM_NETWORK_NAME_SIZE])
{
    UNREFERENCED_PARAMETER(netName);
    return -1;
}

int lm_get_network(char netName[LM_NETWORK_NAME_SIZE])
{
    UNREFERENCED_PARAMETER(netName);
    return -1;
}



