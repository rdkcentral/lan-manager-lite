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

#include <arpa/inet.h>

#include <stdio.h>
#include "lm_api.h"


#ifdef SERVER
int main(){
    lm_cmd_thread_func();
}
#elif CLIENT
int mac_string_to_array(char *pStr, unsigned char array[6])
{
    int tmp[6],n,i;
	if(pStr == NULL)
		return -1;
		
    memset(array,0,6);
    n = sscanf(pStr,"%02x:%02x:%02x:%02x:%02x:%02x",&tmp[0],&tmp[1],&tmp[2],&tmp[3],&tmp[4],&tmp[5]);
    if(n==6){
        for(i=0;i<n;i++)
            array[i] = (unsigned char)tmp[i];
        return 0;
    }

    return -1;
}


void printf_host(LM_host_t *pHost){
    int i;   
    LM_ip_addr_t *pIp;
    char str[100];

    printf("Device %s Mac %02x:%02x:%02x:%02x:%02x:%02x -> \n\t%s meidaType:%d \n", pHost->hostName, pHost->phyAddr[0], pHost->phyAddr[1], pHost->phyAddr[2], pHost->phyAddr[3], pHost->phyAddr[4], pHost->phyAddr[5],(pHost->online == 1 ? "Online" : "offline"), pHost->mediaType);
    printf("\tL1interface %s, L3interface %s comments %s RSSI %d \n", pHost->l1IfName, pHost->l3IfName, pHost->comments, pHost->RSSI);
    printf("\tActive change time %s %d\n", ctime(&(pHost->activityChangeTime)), pHost->activityChangeTime);
    if(strstr(pHost->l1IfName, "WiFi"))
        printf("\tAssociatedDevice %s\n", pHost->AssociatedDevice);
    printf("\tIPv4 address list:\n");
    for(i = 0; i < pHost->ipv4AddrAmount ;i++){
        pIp = &(pHost->ipv4AddrList[i]);
        inet_ntop(AF_INET, pIp->addr, str, 100);
        printf("\t\t%d. %s %d pri %d leaseTime %s %d\n", i+1, str, pIp->addrSource, pIp->priFlg,ctime(&(pIp->LeaseTime)), pIp->LeaseTime);
    }
    printf("\tIPv6 address list:\n");
    for(i = 0; i < pHost->ipv6AddrAmount ;i++){
        pIp = &(pHost->ipv6AddrList[i]);
        inet_ntop(AF_INET6, pIp->addr, str, 100);
        printf("\t\t%d. %s %d pri %d leaseTime %s %d\n", i+1, str, pIp->addrSource, pIp->priFlg,ctime(&(pIp->LeaseTime)), pIp->LeaseTime);
    }
}

void printf_hosts(LM_hosts_t *pHosts){
    int i;
    printf(">>>>\nTotal: %d\n",pHosts->count);
    for(i = 0; i < pHosts->count; i++){
        printf("%d. ", i);
        printf_host(&(pHosts->hosts[i]));
    }
    printf("<<<<\n");    
}

int input_mac(char mac[6])
{
    char str[256];
    
    printf("get Mac address format as XX:XX:XX:XX:XX:XX\n");
    gets(str);
    if( -1 == mac_string_to_array(str, mac)){
        printf("Mac address format error\n");
        return -1;
    }else
        return 0;
}

int input_str(char *str)
{
    gets(str);
    return 0;
}
int main(){
    LM_hosts_t Hosts;
    int ret;
    char c[256];
    char mac[6];
    char str[256];
    LM_cmd_common_result_t result;

    memset(&result, 0, sizeof(result));
    memset(&Hosts, 0 , sizeof(Hosts));

    printf(" 1. print all hosts information\n");
    printf(" 2. print host information by mac\n");
    printf(" 3. set comment\n");
    printf(" 4. get online device\n");
    gets(c);
    
    if(c[0] == '1'){

        ret = lm_get_all_hosts(&Hosts);
        if(ret == -1){
           printf("error\n");
           return 0;
        } 
        printf_hosts(&Hosts);
    }

    if(c[0] == '2'){
        if( -1 != input_mac(mac) &&
            -1 != lm_get_host_by_mac(mac, &result)){
            printf("%s \n", result.result == 0 ? "SUCESS": "ERROR");
            if(result.result == 0){
                printf_host(&(result.data.host));
            }else
                printf("Error NUM %d\n", result.result);
        } 
    }   

    if(c[0] == '3'){
         if( -1 != input_mac(mac) &&
             -1 != input_str(str) &&
             -1 != lm_set_host_comments(mac, str)){
                printf("%s \n", result.result == 0 ? "SUCESS": "ERROR");
            }
    }

    if(c[0] == '4'){
        int num;
        if( -1 != lm_get_online_device(&num)){
            printf("%d \n", num);
        }
    } 
}
#endif
