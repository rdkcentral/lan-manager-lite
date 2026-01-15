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
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <sys/un.h>
#include "secure_wrapper.h"
#include <stddef.h>
#include <string.h>
/*usage of printf -CID:55379, 59688, 61675, 65508*/ 
#include <stdio.h>
#include <sys/stat.h>
#include "ansc_platform.h"
#include "ccsp_base_api.h"
#include "ccsp_psm_helper.h"
#include "lm_wrapper.h"
#include "syscfg/syscfg.h"
#include "lm_util.h"
#include "ccsp_lmliteLog_wrapper.h"
#include "lm_main.h"
#include "safec_lib_common.h"

// TELEMETRY 2.0 //RDKB-25996
#include <telemetry_busmessage_sender.h>

/* Fix RDKB-499 */
#define DHCPV4_RESERVED_FORMAT  "%17[^,],%63[^,],%63[^,]"
#define LM_DHCP_CLIENT_FORMAT   "%63d %17s %63s %63s"   
#define LM_ARP_ENTRY_FORMAT  "%63s %63s %63s %63s %17s %31s"   

extern ANSC_HANDLE bus_handle;
extern char g_Subsystem[32];
static char *pERTPAMComponentName = NULL;
static char *pERTPAMComponentPath = NULL;
extern pthread_mutex_t LmHostObjectMutex;
#if !defined (RESOURCE_OPTIMIZATION)
extern pthread_mutex_t XLmHostObjectMutex;
#endif
extern pthread_mutex_t HostNameMutex;

extern LmObjectHosts lmHosts;

#define WIFI_DM_CHANNEL      "Device.WiFi.Radio.%d.Channel"
#define WIFI_DM_AUTOCHAN     "Device.WiFi.Radio.%d.AutoChannelEnable"
#define WIFI_DM_BSS_SECURITY_MODE "Device.WiFi.AccessPoint.%d.Security.ModeEnabled"
#define WIFI_DM_BSS_SECURITY_ENCRYMODE "Device.WiFi.AccessPoint.%d.Security.X_CISCO_COM_EncryptionMethod"
#define WIFI_DM_SSID         "Device.WiFi.SSID.%d.SSID"
static char pAtomBRMac[32] = {0};
#define WIFI_DM_BSSID         "Device.WiFi.SSID.1.BSSID"

extern int consoleDebugEnable;
extern FILE* debugLogFile;

int bWifiHost = FALSE;
static int fd;
static pthread_mutex_t GetARPEntryMutex;

#ifdef USE_NOTIFY_COMPONENT
static LM_wifi_hosts_t hosts;
#if !defined (RESOURCE_OPTIMIZATION)
static LM_wifi_hosts_t Xhosts;
#endif
static pthread_mutex_t Wifi_Hosts_mutex;
#else

#define HASHSIZE 512

typedef struct mac_band_record {
    int band;
    BOOL active;
    char macAddress[18];
    struct mac_band_record *next;
} mac_band_record;

static mac_band_record *Mac_to_band_mapping[HASHSIZE] = { NULL };
#endif

#ifdef CORE_NET_LIB

static libnet_status file_append(const char *file_name ,const char *buf, size_t count)
{
    FILE *fp = NULL;
    if (!file_name || !buf || count == 0) {
        CcspTraceError(("%s Invalid input to file_append %s\n", __FUNCTION__, file_name));
        return CNL_STATUS_FAILURE;
    }

    fp = fopen(file_name, "a");
    if (NULL == fp) {
        perror("fopen failed");
        CcspTraceError(("%s Failed to open file %s\n", __FUNCTION__, file_name));
        return CNL_STATUS_FAILURE;
    }
    if (count != fwrite(buf, sizeof(char), count, fp)) {
        CcspTraceError(("%s Failed to write to file %s\n", __FUNCTION__, file_name));
        fclose(fp);
        return CNL_STATUS_FAILURE;
    }
    fclose(fp);
    return CNL_STATUS_SUCCESS;
}

// Define the enum for IP type
typedef enum {
    NEI_INVALID = 0,   // Invalid address or error
    NEI_IPV6 = 1,      // Valid IPv6 address
    NEI_IPV4 = 2       // Valid IPv4 address
} NEI_IPType;

static NEI_IPType check_nei_ip_type(const char *address) {
    struct in6_addr ipv6;
    struct in_addr ipv4;

    if (inet_pton(AF_INET6, address, &ipv6) == 1) {
        // Address is a valid IPv6 address
        return NEI_IPV6;
    } else if (inet_pton(AF_INET, address, &ipv4) == 1) {
        // Address is a valid IPv4 address
        return NEI_IPV4;
    } else {
        // Invalid input or error
        return NEI_INVALID;
    }
}
#endif

static int AreIPv4AddressesInSameSubnet(char* ipaddress, char* ipaddres2, char* subnetmask)
{
    struct in_addr addr, addr2, mask;
    int ret = 0;

    if (inet_pton(AF_INET, ipaddress, &addr) == 0) {
        fprintf(stderr, "%s Invalid IPAddress1\n", __FUNCTION__);
        return 0;
    }

   if (inet_pton(AF_INET, ipaddres2, &addr2) == 0) {
        fprintf(stderr, "%s Invalid IPAddress2\n", __FUNCTION__);
        return 0;
    }

   if (inet_pton(AF_INET, subnetmask, &mask) == 0) {
        fprintf(stderr, "%s Invalid SubnetMask\n", __FUNCTION__);
        return 0;
    }
   
   if((addr.s_addr & mask.s_addr) == (addr2.s_addr & mask.s_addr))
        ret = 1;

    return ret;
}

#ifndef USE_NOTIFY_COMPONENT
static unsigned long hash (char *s)
{
	unsigned long hashval=0;
	if(s)
	{
        	while(*s)
		{
			if (!(*s==':'))
			{
				hashval^=*s;
                		s++;
			}	
                	else s++;
		}
	}
        return (hashval%HASHSIZE); 
}

static mac_band_record *lookup_Mac_to_band_mapping (char *macstring)
{	
	mac_band_record * curr=NULL, *wp=NULL;
        unsigned long hashindex;
        hashindex=hash(macstring);
	wp=Mac_to_band_mapping[hashindex];
        for(curr=wp;curr!=NULL;curr=curr->next)
	{
		if(!strcmp(curr->macAddress,macstring)) return curr;
	}
       return curr;
}

static void insert_Mac_to_band_mapping (char *macstring, int band)
{
	unsigned long hashindex;
        hashindex=hash(macstring);
        mac_band_record *curr=NULL, *wp=NULL,*np=NULL;
        errno_t rc = -1;

	wp=lookup_Mac_to_band_mapping(macstring);
        if(!wp)
	{
		wp=malloc(sizeof(mac_band_record));
		if(wp)
		{
			hashindex=hash(macstring);
                        np=Mac_to_band_mapping[hashindex];
			if(np)
			{
                                curr=np;
				for(curr=np;curr->next!=NULL;curr=curr->next);
                        	curr->next=wp;
				curr=curr->next;
                        	curr->next=NULL;
			}
			else 
			{
				curr=wp;
				curr->next=NULL;
                                Mac_to_band_mapping[hashindex]=curr;
			}
			rc = strcpy_s(curr->macAddress, sizeof(curr->macAddress),macstring);
			ERR_CHK(rc);
			curr->band=band;
		}
	}
	else
	{
		wp->band=band;
		
	}
}

void remove_Mac_to_band_mapping(char *macstring)
{
	//CcspTraceWarning(("Wifi inside remove_Mac  \n"));
	mac_band_record *prev=NULL,*curr=NULL,*next=NULL,*tmp=NULL;
        unsigned long hashindex;
        hashindex=hash(macstring);
	curr=Mac_to_band_mapping[hashindex];
	prev=curr;
        
	if(curr && !strcmp(curr->macAddress,macstring))
	{       tmp=curr;
                curr=curr->next;
		free(tmp);
		tmp=NULL;
		//CcspTraceWarning(("Wifi band %d \n",curr->band));
	}
 
	else
        {
		//cspWifiTrace(("RDK_LOG_WARN,Wifiinside else 2.10  \n"));
       	  	if(curr) curr=curr->next;
		if (curr) next=curr->next;
		if(curr) 
		{
			//CcspTraceWarning(("Wifi kb   %d \n",curr->band));
			for (;curr!=NULL&&prev!=NULL;curr=curr->next,prev=prev->next,next=next->next)
			{
				if(curr && !strcmp(curr->macAddress,macstring)) 
		
				{
					//CcspTraceWarning(("Wifi kb -mac %s  band %d \n",curr->macAddress,curr->band));
					prev->next=next;
					free(curr);
					curr=NULL;
                                        break;
				}
                                if(!next) break;

			}
		}
	}
}
#endif

#ifdef CORE_NET_LIB
void format_neighbour_entry(const struct neighbour_info *neighbours, int nei_index, char* neighbour_table_entry, size_t nei_size){
    // neighbour_info *neighbours passed by reference for better efficiency
    const char *state_str = "";
    switch (neighbours->neigh_arr[nei_index].state) {
        case NEIGH_STATE_INCOMPLETE:
            state_str = "INCOMPLETE";
            break;
        case NEIGH_STATE_REACHABLE:
            state_str = "REACHABLE";
            break;
        case NEIGH_STATE_STALE:
            state_str = "STALE";
            break;
        case NEIGH_STATE_DELAY:
            state_str = "DELAY";
            break;
        case NEIGH_STATE_PROBE:
            state_str = "PROBE";
            break;
        case NEIGH_STATE_FAILED:
            state_str = "FAILED";
            break;
        default:
            state_str = "UNKNOWN";
            break;
    }

    snprintf(neighbour_table_entry, nei_size, "%s dev %s lladdr %s %s\n",
        neighbours->neigh_arr[nei_index].local,
        neighbours->neigh_arr[nei_index].ifname,
        neighbours->neigh_arr[nei_index].mac,
        state_str);
    return;
}
#endif

static int LanManager_DiscoverComponent (void)
{
    char CrName[256] = {0};
    int ret = 0;
    errno_t rc = -1;

    rc = sprintf_s(CrName,sizeof(CrName), "eRT.%s", CCSP_DBUS_INTERFACE_CR);
    if(rc < EOK)
    {
        ERR_CHK(rc);
    }

    componentStruct_t **components = NULL;
    int compNum = 0;
    int res = CcspBaseIf_discComponentSupportingNamespace (
            bus_handle,
            CrName,
            "Device.WiFi.AccessPoint.",
            "",
            &components,
            &compNum);
    if(res != CCSP_SUCCESS || compNum < 1){
        CcspTraceError(("LanManager_DiscoverComponent find eRT PAM component error %d\n", res));
        ret = -1;
    }
    else{
        pERTPAMComponentName = AnscCloneString(components[0]->componentName);
        pERTPAMComponentPath = AnscCloneString(components[0]->dbusPath);
        CcspTraceInfo(("LanManager_DiscoverComponent find eRT PAM component %s--%s\n", pERTPAMComponentName, pERTPAMComponentPath));
    }
    free_componentStruct_t(bus_handle, compNum, components);
    return ret;
}

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

int ip_string_to_arrary(char* pStr, unsigned char array[4])
{
    int tmp[4],n,i;

    memset(array,0,4);
    n = sscanf(pStr, "%d.%d.%d.%d", &tmp[0],&tmp[1],&tmp[2],&tmp[3]);
    if (n==4)
    {
        for (i=0;i<n;i++)
        {
            array[i] = (unsigned char)tmp[i];
        }
        return 0;
    }

    return -1;
}

int lm_arping_v4_send(char netName[64], char strMac[17], unsigned char ip[]){
    struct ifreq ifr;
    char m_mac[6], m_ip[4];
    //struct sockaddr_in saddr;
    struct arp_pkt arp_req;
    struct sockaddr_ll reqsa;
    struct sockaddr_in *ip_sockaddr;
    unsigned char phyAddr[6];
    unsigned char t_ip[4];

    memset(&ifr, 0, sizeof(ifr));
    memset(&arp_req, 0, sizeof(arp_req));
    memset(&reqsa, 0, sizeof(reqsa));
    mac_string_to_array(strMac,phyAddr);
    ip_string_to_arrary((char*)ip, t_ip);

    reqsa.sll_ifindex = if_nametoindex(netName);
    reqsa.sll_ifindex = if_nametoindex(netName);
    if(fd < 0){
        fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (fd < 0)
        {
            printf("LM %s create socket error\n", __FUNCTION__);
            return -1;
        }
    }
    /*CID: 135499 Buffer overflow and not null terminated*/
    strncpy(ifr.ifr_name, netName, IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';

    /* get interface mac address */
    if(-1 == ioctl(fd, SIOCGIFHWADDR, &ifr)){
        printf("LM %s ioctl get %s HW addr error\n", __FUNCTION__, netName);
        return -1;
    }
    memcpy(m_mac, ifr.ifr_hwaddr.sa_data, 6);
    if(-1 == ioctl(fd, SIOCGIFADDR, &ifr)){
        printf("LM %s ioctl get %s IP addr error\n", __FUNCTION__, netName);
        return -1;
    }
    ip_sockaddr = (struct sockaddr_in *)&(ifr.ifr_addr);
    memcpy(m_ip, (void *)&(ip_sockaddr->sin_addr), 4);

    /* set ethernet header */
    memcpy(arp_req.ether_dhost, phyAddr, 6);
    memcpy(arp_req.ether_shost, m_mac , 6);

    /* set arp requrest */
    arp_req.ether_type = htons(0x0806);
    arp_req.hw_type = htons(1);
    arp_req.pro_type = htons(0x0800);
    arp_req.hw_size = 6;
    arp_req.pro_size = 4;
    arp_req.opcode = htons(1);
    memcpy(arp_req.sMac, m_mac, 6);
    memcpy(arp_req.sIP, m_ip, 4);
    memcpy(arp_req.tIP, t_ip, 4);

    /* send packet */
    if( 0 >= sendto(fd, &arp_req, sizeof(arp_req), 0, (struct sockaddr *)&reqsa, sizeof(reqsa))){
        printf("LM %s send packet error, errno = %d\n", __FUNCTION__, errno);
        return -1;
    }

    return 0;
}

int lm_wrapper_init(){
    pthread_mutex_init(&GetARPEntryMutex, 0);
/*
    ret = CCSP_Message_Bus_Init(
                "ccsp.lmbusclient",
                CCSP_MSG_BUS_CFG,
                &bus_handle,
                AnscAllocateMemory,
                AnscFreeMemory
            );

    if ( ret != ANSC_STATUS_SUCCESS )
    {
        CcspTraceError((" !!! SSD Message Bus Init ERROR !!!\n"));
        return -1;
    }
*/
    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(fd < 0){
        printf("LM %s create socket error\n", __FUNCTION__);
        return -1;
    }

    LanManager_DiscoverComponent();
#ifdef USE_NOTIFY_COMPONENT
    pthread_mutex_init(&Wifi_Hosts_mutex,0);
#endif
    return 0;
}

void SyncWiFi()
{

	parameterValStruct_t    value = { "Device.WiFi.X_RDKCENTRAL-COM_WiFiHost_Sync", "true", ccsp_boolean};
	char compo[256] = "eRT.com.cisco.spvtg.ccsp.wifi";
	char bus[256] = "/com/cisco/spvtg/ccsp/wifi";
	char* faultParam = NULL;
	int ret = 0;	
	CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;

    CcspTraceWarning(("WIFI %s : Get WiFi Clients \n",__FUNCTION__));

	ret = CcspBaseIf_setParameterValues(
		  bus_handle,
		  compo,
		  bus,
		  0,
		  0,
		  &value,
		  1,
		  TRUE,
		  &faultParam
		  );

	if(ret != CCSP_SUCCESS)
	{
		CcspTraceWarning(("WIFI %s : Failed ret %d\n",__FUNCTION__,ret));
		if(faultParam)
		{
			bus_info->freefunc(faultParam);
		}
	}	
}

#ifdef USE_NOTIFY_COMPONENT
#if 0
void Wifi_Server_Thread_func()
{

	int sockfd, newsockfd;
	socklen_t clilen;
	int i;
	char *pos2=NULL;
	char *pos5=NULL;
	char *Xpos2=NULL;
	char *Xpos5=NULL;
	errno_t rc = -1;
#ifdef DUAL_CORE_XB3
	struct sockaddr_in serv_addr, cli_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) 
	{		
		CcspTraceWarning(("WIFI-CLIENT <%s> <%d> : ERROR opening socket\n",__FUNCTION__, __LINE__));
		return;
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(5001);
#else
	#define WIFI_SERVER_FILE_NAME  "/tmp/wifi.sock"
    	struct sockaddr_un serv_addr, cli_addr;
	sockfd=socket(PF_UNIX,SOCK_STREAM,0);
	if(sockfd<0)
		return;

	serv_addr.sun_family=AF_UNIX;
	unlink(WIFI_SERVER_FILE_NAME);
	rc = strcpy_s(serv_addr.sun_path, sizeof(serv_addr.sun_path),WIFI_SERVER_FILE_NAME);
	ERR_CHK(rc);

#endif
	if (bind(sockfd, (struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
	{		
		CcspTraceWarning(("WIFI-CLIENT <%s> <%d> : ERROR on binding  \n",__FUNCTION__, __LINE__));
                return;
	}

	/*CID:64728 Unchecked return value*/
	if(listen(sockfd,10) < 0)
	{
		CcspTraceWarning(("WIFI-CLIENT <%s> <%d> : ERROR on listen  \n",__FUNCTION__, __LINE__));
                return;
	}
	clilen = sizeof(cli_addr);

	SyncWiFi();
	
    while(1){
        newsockfd = accept(sockfd,(struct sockaddr *) &cli_addr,&clilen);
        if(newsockfd < 0 )
           continue;
       	
		
		pthread_mutex_lock(&Wifi_Hosts_mutex);

		if ( recv(newsockfd, &hosts, sizeof(LM_wifi_hosts_t), MSG_WAITALL) <= 0)
		{
			CcspTraceWarning(("WIFI-CLIENT <%s> <%d> : Data recv failed from WiFi-Agent \n",__FUNCTION__, __LINE__));
		}
		else
		{
			hosts.count = ntohl(hosts.count);
			
			
			for(i = 0; i < hosts.count ; i++)
			{
				Xpos2=strstr((const char *)hosts.host[i].ssid,".3");
				Xpos5=strstr((const char *)hosts.host[i].ssid,".4");
				if(Xpos2!=NULL || Xpos5!=NULL)
				{
#if !defined (RESOURCE_OPTIMIZATION)
					CcspTraceWarning(("%s, %d\n",__FUNCTION__, __LINE__));
					Xhosts.host[i].RSSI = ntohl(hosts.host[i].RSSI);
     				Xhosts.host[i].Status = ntohl(hosts.host[i].Status);
					rc = STRCPY_S_NOCLOBBER((char *)Xhosts.host[i].phyAddr, sizeof(Xhosts.host[i].phyAddr), (char *)hosts.host[i].phyAddr );
					ERR_CHK(rc);

					if(Xhosts.host[i].Status) {
						rc = STRCPY_S_NOCLOBBER((char *)Xhosts.host[i].AssociatedDevice, sizeof(Xhosts.host[i].AssociatedDevice), (char *)hosts.host[i].AssociatedDevice);
						ERR_CHK(rc);
					}

					Xhosts.count++;
#endif
				}
				else
				{
				    hosts.host[i].RSSI = ntohl(hosts.host[i].RSSI);
     				hosts.host[i].Status = ntohl(hosts.host[i].Status);
				pos2=strstr((char *)hosts.host[i].ssid,".1");
				pos5=strstr((char *)hosts.host[i].ssid,".2");
			    	hosts.host[i].phyAddr[17] = '\0';
                    if(hosts.host[i].Status)
				    {
					    if(pos2!=NULL)
					    {
						    CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is WiFi, MacAddress %s connected(2.4 GHz)\n",hosts.host[i].phyAddr));
    					}
	    				else if(pos5!=NULL)
		    			{	
			    			CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is WiFi, MacAddress is %s connected(5 GHz)\n",hosts.host[i].phyAddr));
				    	}
				    }
				}
				
			}
			bWifiHost = TRUE;

		}
		pthread_mutex_unlock(&Wifi_Hosts_mutex);
        close(newsockfd);
#if !defined (RESOURCE_OPTIMIZATION)
		XHosts_SyncWifi();
#endif
		sleep(1);
    }

}
BOOL SearchWiFiClients(char *phyAddr, char *ssid)
{
	int i = 0;
	for(i = 0; i < hosts.count ; i++)
	{
		if(!strcasecmp((const char *)hosts.host[i].phyAddr, (const char *)phyAddr))
		{
			strcpy((char*)ssid, (char*)hosts.host[i].ssid);
			return TRUE;
		}
	}
	return FALSE;
}
#endif

#if !defined (RESOURCE_OPTIMIZATION)
int Xlm_wrapper_get_wifi_wsta_list(int *pCount, LM_wifi_wsta_t **ppWstaArray)
{
	LM_wifi_wsta_t *pwifi_wsta = NULL;
	int i;
	errno_t rc = -1;
        
	
	/*TODO : Receive Data from WIFI Agent via Socket*/
	pthread_mutex_lock(&Wifi_Hosts_mutex);

	*pCount = Xhosts.count;
		
	pwifi_wsta = (LM_wifi_wsta_t *) malloc(sizeof(LM_wifi_wsta_t) * (*pCount));
    if(pwifi_wsta == NULL )
    {
		pthread_mutex_unlock(&Wifi_Hosts_mutex);
        return -1;
    }	

    *ppWstaArray = pwifi_wsta;

	for(i=0 ; i < *pCount ; i++)
	{
		rc = STRCPY_S_NOCLOBBER((char *)pwifi_wsta[i].AssociatedDevice, sizeof(pwifi_wsta[i].AssociatedDevice) ,(const char *)Xhosts.host[i].AssociatedDevice);
		ERR_CHK(rc);
		strncpy((char *)pwifi_wsta[i].phyAddr, (const char *)Xhosts.host[i].phyAddr,17);
		pwifi_wsta[i].phyAddr[17] = '\0';
		rc = STRCPY_S_NOCLOBBER((char *)pwifi_wsta[i].ssid, sizeof(pwifi_wsta[i].ssid),(const char *)Xhosts.host[i].ssid);
		ERR_CHK(rc);
		pwifi_wsta[i].RSSI = Xhosts.host[i].RSSI;
		pwifi_wsta[i].Status = Xhosts.host[i].Status;
                
	}	
	pthread_mutex_unlock(&Wifi_Hosts_mutex);

	return 0;
}
#endif

int lm_wrapper_get_wifi_wsta_list(char netName[LM_NETWORK_NAME_SIZE], int *pCount, LM_wifi_wsta_t **ppWstaArray)
{
        UNREFERENCED_PARAMETER(netName);
	LM_wifi_wsta_t *pwifi_wsta = NULL;
	int i;
	errno_t rc = -1;
	
	/*TODO : Receive Data from WIFI Agent via Socket*/
	pthread_mutex_lock(&Wifi_Hosts_mutex);

	*pCount = hosts.count;
	
	
	pwifi_wsta = (LM_wifi_wsta_t *) malloc(sizeof(LM_wifi_wsta_t) * (*pCount));
    if(pwifi_wsta == NULL )
    {
		pthread_mutex_unlock(&Wifi_Hosts_mutex);
        return -1;
    }	

    *ppWstaArray = pwifi_wsta;

	for(i=0 ; i < *pCount ; i++)
	{
		rc = strcpy_s((char *)pwifi_wsta[i].AssociatedDevice, sizeof(pwifi_wsta[i].AssociatedDevice),(const char *)hosts.host[i].AssociatedDevice);
		ERR_CHK(rc);
		strncpy((char *)pwifi_wsta[i].phyAddr, (const char *)hosts.host[i].phyAddr,17);
		pwifi_wsta[i].phyAddr[17] = '\0';
		rc = strcpy_s((char *)pwifi_wsta[i].ssid, sizeof(pwifi_wsta[i].ssid),(const char *)hosts.host[i].ssid);
		ERR_CHK(rc);
		pwifi_wsta[i].RSSI = hosts.host[i].RSSI;
		pwifi_wsta[i].Status = hosts.host[i].Status;
		
	}
	pthread_mutex_unlock(&Wifi_Hosts_mutex);

	return 0;
}

#else
static int _get_field_pos( char *field[], int field_num, int *pos, parameterValStruct_t **val, int val_num){
    int i, j;
    for(j = 0; j < field_num; j++){
        pos[j] = -1;
    }
    for(i = 0; i < val_num; i++){
        for(j = 0; j < field_num; j++){
            if( NULL != strstr(val[i]->parameterName, field[j])){
               if(pos[j] != -1){
                  i -= pos[j];
                  goto OUT;
               }else
                  pos[j] = i;
            }
        }
    }
OUT:
    for(j = 0; j < field_num; j++){
        if(pos[j] == -1)
            return 0;
    }
    return (i);
}

int lm_wrapper_get_wifi_wsta_list(char netName[LM_NETWORK_NAME_SIZE], int *pCount, LM_wifi_wsta_t **ppWstaArray)
{
    UNREFERENCED_PARAMETER(netName);
    char *tblName = DEVICE_WIFI_ACCESS_POINT;
    char *pWiFiComponentName = pERTPAMComponentName;
    char *pComponentPath = pERTPAMComponentPath;
    int interface_number = 0;
    int bkup_ifaceNumber = 0;
    int AssociatedDevice_number[LM_MAX_INTERFACE_NUMBER];
    parameterInfoStruct_t **interfaceInfo = NULL;
    int i, j, itmp;
    int ret;
    LM_wifi_wsta_t *pwifi_wsta = NULL;
    char *field[2] = {"MACAddress", "SignalStrength"};
    int field_num = 0;
    int pos[2];
    int rVal = -1;
    errno_t rc = -1;

    *pCount = 0;
    PRINTD("ENT %s\n", __FUNCTION__);

     char  *paramAtomMacName[1] ;
     parameterValStruct_t    **valStructs = NULL;
     int valNum = 0;
     char br0Mac[128]  = {'\0'};

    if(pComponentPath == NULL || pWiFiComponentName == NULL)
    {
        if(-1 == LanManager_DiscoverComponent()){
            CcspTraceError(("%s ComponentPath or pWiFiComponentName is NULL\n", __FUNCTION__));
            return rVal;
        }
    }

    /* Get parameter name of Device.WiFi.AccessPoint. */
    ret = CcspBaseIf_getParameterNames(
        bus_handle,
        pWiFiComponentName,
        pComponentPath,
        tblName,
        1,
        &bkup_ifaceNumber,
        &interfaceInfo);
    if(ret != CCSP_Message_Bus_OK) {
        CcspTraceError(("%s CcspBaseIf_getParameterNames %s error %d!\n", __FUNCTION__, tblName, ret));
        return -1;
    }

    /* if netName is "brlan0",  need to update only private network.*/
        interface_number = 2 ;

    char *(*pReferenceParaNameArray)[] = calloc(1,sizeof(char*) * interface_number); /*RDKB-7349,CID-33112, initialize before use*/
    if(pReferenceParaNameArray == NULL)
        goto RET1;

    char *(*pAssociatedDeviceNameArray)[] = calloc(1,sizeof(char*) * interface_number * 2); /*RDKB-7349,CID-33017, initialize before use*/
    if(pAssociatedDeviceNameArray == NULL)
        goto RET2;

    char* pReferenceParaNameBuf = malloc( interface_number * 100 );
    if(pReferenceParaNameBuf == NULL)
        goto RET3;

    char* pAssociatedDeviceNameBuf = malloc( interface_number * 100 * 2);
    if(pAssociatedDeviceNameBuf == NULL)
        goto RET4;

    char (* pReferenceParaName)[100] =  (char (*)[100])pReferenceParaNameBuf;
    char (* pAssociatedDeviceName)[100] = (char (*)[100])pAssociatedDeviceNameBuf;

    for(i=0; i < interface_number; i++){
        rc = sprintf_s(pReferenceParaName[i], 100, "%s%s", interfaceInfo[i]->parameterName,"SSIDReference");
        if(rc < EOK){
           ERR_CHK(rc);
        }
        rc = sprintf_s(pAssociatedDeviceName[i], 100, "%s%s", interfaceInfo[i]->parameterName,"AssociatedDevice.");
        if(rc < EOK){
           ERR_CHK(rc);
        }
        rc = sprintf_s(pAssociatedDeviceName[i + interface_number], 100, "%s%s", interfaceInfo[i]->parameterName,"AssociatedDeviceNumberOfEntries");
        if(rc < EOK){
           ERR_CHK(rc);
        }
        (*pReferenceParaNameArray)[i] = pReferenceParaName[i];
        (*pAssociatedDeviceNameArray)[i] = pAssociatedDeviceName[i];
        (*pAssociatedDeviceNameArray)[i + interface_number] = pAssociatedDeviceName[i + interface_number];
    }

    /* get SSID reference
     * like Device.WiFi.SSID.1. */
    parameterValStruct_t **parametervalSSIDRef = NULL;
    int ref_size = 0 ;
    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            pWiFiComponentName,
            pComponentPath,
            *pReferenceParaNameArray,
            interface_number,
            &ref_size,
            &parametervalSSIDRef);
    if(ret != CCSP_Message_Bus_OK) {
            CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d!\n", __FUNCTION__, pReferenceParaName, ret));
            printf("%s CcspBaseIf_getParameterValues %s error %d!\n", __FUNCTION__, pReferenceParaName, ret);
            goto RET5;
    }

    /* get Associated Device Number
     * Device.WiFi.AccessPoint.1.AssociatedDevice. */
    parameterValStruct_t **parametervalAssociatedDeviceNum = NULL;
    int num_size = 0;
    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            pWiFiComponentName,
            pComponentPath,
            *pAssociatedDeviceNameArray,
            interface_number * 2,
            &num_size,
            &parametervalAssociatedDeviceNum);
    if(ret != CCSP_Message_Bus_OK){
        CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d!\n", __FUNCTION__, pAssociatedDeviceName[0], ret));
        printf("%s CcspBaseIf_getParameterValues %s error %d!\n", __FUNCTION__, pAssociatedDeviceName[0], ret);
        goto RET6;
    }
    //for(i = 0; i < num_size; i++){
    //    PRINTD("%s %s \n",parametervalAssociatedDeviceNum[i]->parameterName, parametervalAssociatedDeviceNum[i]->parameterValue);
    //}


    field_num = _get_field_pos(field, 2, pos, parametervalAssociatedDeviceNum, num_size - interface_number);
    if(field_num == 0)
        goto RET7;
    for(*pCount = 0, i = 0, j = num_size - interface_number; i < interface_number; i++, j++){
        AssociatedDevice_number[i] = atoi(parametervalAssociatedDeviceNum[j]->parameterValue);
        PRINTD("AssociatedDevice_number %d \n", AssociatedDevice_number[i]);
        (*pCount) += AssociatedDevice_number[i];
    }
    if(*pCount != (num_size - interface_number)/field_num)
        goto RET7;

    pwifi_wsta = malloc(sizeof(LM_wifi_wsta_t) * (*pCount));
    if(pwifi_wsta == NULL )
        goto RET7;

    *ppWstaArray = pwifi_wsta;


	/*Below lines are commented out and rewritten as with this logic  XHS and xfinity wifi devices are not copied with correct WIFI SSID ref and these  gets logged with wrong interface .
		This is observed when there are no devices connected over private wifi and devices are connected over other interfaces */

/*
    for(i = 0, j = 0; i < *pCount; i++)
    {
        strncpy(pwifi_wsta->phyAddr, parametervalAssociatedDeviceNum[i * field_num + pos[0]]->parameterValue, 18);
        itmp = strlen(parametervalAssociatedDeviceNum[i * field_num + pos[0]]->parameterName) - strlen(".MACAddress");
        itmp = (itmp > LM_GEN_STR_SIZE - 1) ? LM_GEN_STR_SIZE-1 : itmp;
        memcpy(pwifi_wsta->AssociatedDevice, parametervalAssociatedDeviceNum[i * field_num + pos[0]]->parameterName, itmp);
        pwifi_wsta->AssociatedDevice[itmp] = '\0';
        pwifi_wsta->RSSI = atoi(parametervalAssociatedDeviceNum[i * field_num + pos[1]]->parameterValue);
        if((AssociatedDevice_number[j]--) == 0){
            j++;
        }
        strncpy(pwifi_wsta->ssid, parametervalSSIDRef[j]->parameterValue, LM_GEN_STR_SIZE-1);
        pwifi_wsta->ssid[strlen(pwifi_wsta->ssid) - 1] = '\0';
        pwifi_wsta++;
    }
	*/
	int k = 0;
	int device_no= 0;
	int device_count= 0;
	for(k = 0; k < interface_number ; k++)
	{
		device_no = AssociatedDevice_number[k];
	    if(device_no > 0)
		{
			for(i = device_count, j = 1; i < *pCount && j <=device_no ; i++,device_count++,j++)
			{
				strncpy(pwifi_wsta->phyAddr, parametervalAssociatedDeviceNum[i * field_num + pos[0]]->parameterValue, 18);
				itmp = strlen(parametervalAssociatedDeviceNum[i * field_num + pos[0]]->parameterName) - strlen(".MACAddress");
				itmp = (itmp > LM_GEN_STR_SIZE - 1) ? LM_GEN_STR_SIZE-1 : itmp;
				memcpy(pwifi_wsta->AssociatedDevice, parametervalAssociatedDeviceNum[i * field_num + pos[0]]->parameterName, itmp);
				pwifi_wsta->AssociatedDevice[itmp] = '\0';
				pwifi_wsta->RSSI = atoi(parametervalAssociatedDeviceNum[i * field_num + pos[1]]->parameterValue);
				strncpy(pwifi_wsta->ssid, parametervalSSIDRef[k]->parameterValue, LM_GEN_STR_SIZE-1);
				pwifi_wsta->ssid[strlen(pwifi_wsta->ssid) - 1] = '\0';
				pwifi_wsta++;
			}
		}
	}

    rVal = 0;

    parameterValStruct_t **valStrchannel = NULL;
	parameterValStruct_t **valStrsecmode = NULL;
	parameterValStruct_t **valStrsecencrymode = NULL;
	parameterValStruct_t **valStrssid = NULL;
    int nval = 0, retval = -1, retband = 0;
	char str[2][80];
	char * name[2] = {(char*) str[0], (char*) str[1]};  
	int interface ;
	char secMode[128]  = {'\0'};
	char secEncMode[128] = {'\0'};
	char ssid[128] = {'\0'};
    char  *paramNames[1]  = {NULL};
	int radioInt = 0;
	int currentChannel = 0;
        LM_wifi_wsta_t *hosts = *ppWstaArray;
	time_t     now;
	int activityTimeChangeDiff = 0;
        int band=0;
        char macstring[18]={0};
        mac_band_record *hash_record=NULL; 
	for (i = 0; i < *pCount ; i++)
        {
		PLmObjectHost pHost;
		char index;
  		index = hosts[i].ssid[strlen(hosts[i].ssid)-1];
		interface = index - '0';
                if (interface==2) band=5;
                if (interface==1) band=2;
		/* SSID index check. Disabling logging for xfinity wifi devices and XHS clients. As these devices are not getting saved, whenever this loop runs , everytime these devices are getting logged as New Client.
			TODO: Need to figure out the way to idenify new client. 
		1 and 2 private wifi - Log is enabled
	    3 - Home-security, 5 & 6 - hotspot index - Log is disabled.*/
		if(interface > 2) {
			//printf(" It is not private wifi Device. \n");
			continue;
		}
		/* disable logic ends */
		pHost = Hosts_FindHostByPhysAddress(hosts[i].phyAddr);
		if(pHost) 
		{
			if(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId]) 
			{
			 	if((strstr(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],"WiFi"))) 
				{
					rc = strcpy_s(macstring, sizeof(macstring),hosts[i].phyAddr);
					ERR_CHK(rc);
                                        if(!strlen(hosts[i].phyAddr) >=17) continue;
                        		hash_record = lookup_Mac_to_band_mapping(macstring);
                			if(hash_record) 
					{  
						retband= hash_record->band;
						if(retband == band) continue;
					}
                			else
					{
               					insert_Mac_to_band_mapping(macstring,band);
						CcspTraceWarning(("Wifi Client %s connected to  band %d GHz RSSI %d \n",hosts[i].phyAddr,band,pwifi_wsta[i].RSSI));
					}
			     	} else continue;
		    	}  
			else continue;
		} 
		else 
		{
                        if(!strlen(hosts[i].phyAddr) >=17) continue;
                        rc = strcpy_s(macstring, sizeof(macstring),hosts[i].phyAddr);
                        ERR_CHK(rc);
                        hash_record = lookup_Mac_to_band_mapping(macstring);
                	if(hash_record) 
			{  
				retband = hash_record->band;
				if(retband == band) 
				{
					continue;
				}
				else
				{
					hash_record->band=band;
				        CcspTraceWarning(("Wifi Client %s connected to  band %d GHz RSSI %d \n",hosts[i].phyAddr,band,hosts[i].RSSI));               }
			}
                	else
			{
               			insert_Mac_to_band_mapping(macstring,band);
                                CcspTraceWarning(("New Wifi Client %s connected to  band %d GHz RSSI %d \n",hosts[i].phyAddr,band,hosts[i].RSSI));
			}
		}
		if(interface%2 == 0)
			radioInt = 1;
		else
			radioInt = 0;

		snprintf(str[0], sizeof(str[0]),WIFI_DM_AUTOCHAN,radioInt+1);
		snprintf(str[1], sizeof(str[1]),WIFI_DM_CHANNEL,radioInt+1);
		ret = CcspBaseIf_getParameterValues(
		    bus_handle,
		    pWiFiComponentName,
		    pComponentPath,
		    &name,
		    2,
		    &nval,
		    &valStrchannel);

		if(ret != CCSP_Message_Bus_OK){
			CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d!\n", __FUNCTION__, name, ret));
			printf("%s CcspBaseIf_getParameterValues %s error %d!\n", __FUNCTION__, name, ret);
			goto RET7;
		}

		if(strncmp("true", valStrchannel[0]->parameterValue, 5)==0)
			retval = 0;

		currentChannel = atoi(valStrchannel[1]->parameterValue);
        if (valStrchannel)
        {
            CcspTraceWarning(("%s Freeing valStrchannel after use!\n", __FUNCTION__));
            free_parameterValStruct_t(bus_handle, nval, valStrchannel);
            valStrchannel = NULL;
        }
		
		snprintf(secMode, sizeof(secMode), WIFI_DM_BSS_SECURITY_MODE,interface);
		paramNames[0] = AnscCloneString(secMode);;
		ret = CcspBaseIf_getParameterValues(
		    bus_handle,
		    pWiFiComponentName,
		    pComponentPath,
		    paramNames,
		    1,
		    &nval,
		    &valStrsecmode);
		if(ret != CCSP_Message_Bus_OK){
			CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d!\n", __FUNCTION__, secMode, ret));
			printf("%s CcspBaseIf_getParameterValues %s error %d!\n", __FUNCTION__, secMode, ret);
		        goto RET7;
		} 

		snprintf(secEncMode, sizeof(secEncMode),WIFI_DM_BSS_SECURITY_ENCRYMODE,interface);
        if(paramNames[0])
        {
            CcspTraceWarning(("%s Freeing paramNames after use!\n", __FUNCTION__));
            free(paramNames[0]);
            paramNames[0] = NULL;
        }
            paramNames[0] = AnscCloneString(secEncMode);
		ret = CcspBaseIf_getParameterValues(
		    bus_handle,
		    pWiFiComponentName,
		    pComponentPath,
		    paramNames,
		    1,
		    &nval,
		    &valStrsecencrymode);
		if(ret != CCSP_Message_Bus_OK){
			CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d!\n", __FUNCTION__, secEncMode, ret));
			printf("%s CcspBaseIf_getParameterValues %s error %d!\n", __FUNCTION__, secEncMode, ret);
            if (valStrsecencrymode)
            {
                CcspTraceWarning(("%s Freeing valStrsecencrymode!\n", __FUNCTION__));
                free_parameterValStruct_t(bus_handle, nval, valStrsecencrymode);
                valStrsecencrymode = NULL;
            }
            if (valStrsecmode)
            {
                CcspTraceWarning(("%s Freeing valStrsecmode!\n", __FUNCTION__));
                free_parameterValStruct_t(bus_handle, nval, valStrsecmode);
                valStrsecmode = NULL;
            }
			goto RET7;
		} 

		snprintf(ssid, sizeof(ssid),WIFI_DM_SSID,interface);
        if(paramNames[0])
        {
            CcspTraceWarning(("%s Freeing paramNames after use!!\n", __FUNCTION__));
            free(paramNames[0]);
            paramNames[0] = NULL;
        }
	        paramNames[0] = AnscCloneString(ssid);
		ret = CcspBaseIf_getParameterValues(
		    bus_handle,
		    pWiFiComponentName,
		    pComponentPath,
		    paramNames,
		    1,
		    &nval,
		    &valStrssid);
		if(ret != CCSP_Message_Bus_OK){
			CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d!\n", __FUNCTION__, ssid, ret));
			printf("%s CcspBaseIf_getParameterValues %s error %d!\n", __FUNCTION__, ssid, ret);
            if (valStrssid)
            {
                CcspTraceWarning(("%s Freeing valStrssid on error case!\n", __FUNCTION__));
                free_parameterValStruct_t(bus_handle, nval, valStrssid);
                valStrssid = NULL;
            }
            if (valStrsecencrymode)
            {
                CcspTraceWarning(("%s Freeing valStrsecencrymode on error case!\n", __FUNCTION__));
                free_parameterValStruct_t(bus_handle, nval, valStrsecencrymode);
                valStrsecencrymode = NULL;
            }
            if (valStrsecmode)
            {
                CcspTraceWarning(("%s Freeing valStrsecmode on error case!\n", __FUNCTION__));
                free_parameterValStruct_t(bus_handle, nval, valStrsecmode);
                valStrsecmode = NULL;
            }
            if(paramNames[0])
            {
                CcspTraceWarning(("%s Freeing paramNames after use !!!\n", __FUNCTION__));
                free(paramNames[0]);
                paramNames[0] = NULL;
            }
			goto RET7;
		}
		CcspTraceWarning(("No of Wifi clients connected : %d \n",*pCount));
		CcspTraceWarning(("Device No : %d MAC - %s interface: ath%d band %dGHz RSSI %d \n",i+1,hosts[i].phyAddr,interface-1,band,hosts[i].RSSI));
		if(!retval){	
		  CcspTraceWarning(("ssid : %s Auto channel enabled, channel : %d \n",valStrssid[0]->parameterValue,currentChannel));
		}else {
		 CcspTraceWarning(("ssid : %s  channel : %d \n",valStrssid[0]->parameterValue,currentChannel));
		}	
		CcspTraceWarning(("Security Mode : %s , Security Encryptionmode : %s \n",valStrsecmode[0]->parameterValue,valStrsecencrymode[0]->parameterValue));

	}


RET7:
    free_parameterValStruct_t(bus_handle, num_size, parametervalAssociatedDeviceNum);
RET6:
    free_parameterValStruct_t (bus_handle, ref_size, parametervalSSIDRef);
RET5:
    free(pAssociatedDeviceNameBuf);
    pAssociatedDeviceNameBuf=NULL;
RET4:
    free(pReferenceParaNameBuf);
    pReferenceParaNameBuf = NULL;
RET3:
    free(pAssociatedDeviceNameArray);
    pAssociatedDeviceNameArray = NULL;
RET2:
    free(pReferenceParaNameArray);
    pReferenceParaNameArray = NULL;
RET1:
    free_parameterInfoStruct_t (bus_handle, bkup_ifaceNumber, interfaceInfo);

    PRINTD("EXT %s\n", __FUNCTION__);
    return rVal;
}
#endif

#if !defined(INTEL_PUMA7) && !defined(_COSA_BCM_MIPS_) && !defined(_COSA_BCM_ARM_) && !defined(_PLATFORM_TURRIS_) && !defined(_COSA_QCA_ARM_)
/*
   Note that there are two versions of _get_shell_output() used with RDKB.
   This version, which accepts a char * command as the first argument, is
   the older version. The newer version accepts a FILE pointer as created
   by a call to v_secure_popen().
*/
static void _get_shell_output (FILE *fp, char *buf, size_t len)
{
    if (len > 0)
        buf[0] = 0;
    if (fp == NULL)
        return;
    buf = fgets (buf, len, fp);
    if ((len > 0) && (buf != NULL)) {
        len = strlen (buf);
        if ((len > 0) && (buf[len - 1] == '\n'))
            buf[len - 1] = 0;
    }
}
#endif

int lm_wrapper_get_arp_entries (char netName[LM_NETWORK_NAME_SIZE], int *pCount, LM_host_entry_t **ppArray)
{
    FILE *fp = NULL;
    char buf[200] = {0};
    int index = 0;
    char stub[64], status[32];;
    int ret;
    LM_host_entry_t *hosts = NULL;

    pthread_mutex_lock(&GetARPEntryMutex);

    unlink(ARP_CACHE_FILE);
   // snprintf(buf, sizeof(buf), "ip nei show | grep %s | grep -v 192.168.10 > %s", netName, ARP_CACHE_FILE);

    // XB6/XF3 Do not have this interface. Remove constant warnings.
#if !defined(INTEL_PUMA7) && !defined(_COSA_BCM_MIPS_) && !defined(_COSA_BCM_ARM_) && !defined(_PLATFORM_TURRIS_) && !defined(_COSA_QCA_ARM_)
    // This is added to remove atom mac from the connected device list.
    if (pAtomBRMac[0] == '\0' || pAtomBRMac[0] == ' ') {
        fp = v_secure_popen("r","ifconfig l2sd0 | grep HWaddr | awk '{print $5}' | cut -c 1-14");
        _get_shell_output(fp, pAtomBRMac, sizeof(pAtomBRMac));
        ret = v_secure_pclose(fp);
	if(ret !=0)
	{
	    CcspTraceWarning(("Error in closing pipe ret val  [%d] \n",ret));
	}
        CcspTraceWarning(("Atom mac is %s\n",pAtomBRMac));
    }
#endif

    if(pAtomBRMac[0] != '\0'  &&  pAtomBRMac[0] != ' ') {
    	v_secure_system("ip -4 nei show | grep %s | grep -v 192.168.10  | grep -i -v %s > "ARP_CACHE_FILE, netName,pAtomBRMac);
        v_secure_system("ip -6 nei show | grep %s | grep -i -v %s >> "ARP_CACHE_FILE, netName, pAtomBRMac);
    } else {
#ifdef CORE_NET_LIB
        char *mac_filter = NULL;
        char *if_filter = NULL;
        int af_filter = 0;

        if (netName == NULL || netName[0] == '\0') {
            CcspTraceError(("%s: Input interface name is NULL or empty\n", __FUNCTION__));
            pthread_mutex_unlock(&GetARPEntryMutex);
            return -1;
        }

        if_filter = strdup(netName);
        if (!if_filter) {
            CcspTraceError(("%s: Failed to copy interface name string\n", __FUNCTION__));
            pthread_mutex_unlock(&GetARPEntryMutex);
            return -1;
        }

        struct neighbour_info *neighbours =  init_neighbour_info();
        if (!neighbours) {
            CcspTraceError(("%s: Failed to initialize neighbor information structure\n", __FUNCTION__));
            free(if_filter);
            pthread_mutex_unlock(&GetARPEntryMutex);
            return -1;
        }
        libnet_status st = neighbour_get_list(neighbours, mac_filter, if_filter, af_filter);
        free(if_filter);
        if (st == CNL_STATUS_SUCCESS) {
            CcspTraceDebug(("%s: Successfully retrieved neighbor list based on interface:%s, and Neighbour count: %d\n", __FUNCTION__, netName, neighbours->neigh_count));
            if (neighbours->neigh_count <= 0 || neighbours->neigh_arr == NULL) {
                CcspTraceError(("%s: Neighbour list is empty\n", __FUNCTION__));
                neighbour_free_neigh(neighbours);
                pthread_mutex_unlock(&GetARPEntryMutex);
                return -1;
            }
            for (int i = 0; i < neighbours->neigh_count; ++i) {
                CcspTraceDebug(("Neighbor %d: local=%s, mac=%s, ifname=%s,state=%d\n",
                    i,
                    neighbours->neigh_arr[i].local ? neighbours->neigh_arr[i].local : "NULL",
                    neighbours->neigh_arr[i].mac ? neighbours->neigh_arr[i].mac : "NULL",
                    neighbours->neigh_arr[i].ifname ? neighbours->neigh_arr[i].ifname : "NULL",
                    neighbours->neigh_arr[i].state));

                char arp_entry[128] = {0};
                // Handle IPv4 address
                if (neighbours->neigh_arr[i].local == NULL || strlen(neighbours->neigh_arr[i].local) == 0 || strcmp(neighbours->neigh_arr[i].local, "none") == 0) {
                    CcspTraceError(("%s %d: Invalid local value for neighbor %d\n", __FUNCTION__, __LINE__, i));
                    continue;
                }
                if (strstr(neighbours->neigh_arr[i].local, "192.168.10") == NULL) {
                    if (check_nei_ip_type(neighbours->neigh_arr[i].local) == NEI_IPV4) {
                        format_neighbour_entry(neighbours, i, arp_entry, sizeof(arp_entry));
                    }
                }
                if (arp_entry[0] != '\0') {
                    libnet_status fw_st = file_write(ARP_CACHE_FILE, arp_entry, strlen(arp_entry));
                    if (fw_st != CNL_STATUS_SUCCESS){
                        CcspTraceError(("%s %d: File write failed for neighbor list!\n", __FUNCTION__, __LINE__));
                    }
                }
            }
        }
        else{
            CcspTraceError(("%s: Failed to execute neighbour_get_list!\n", __FUNCTION__));
            neighbour_free_neigh(neighbours);
            pthread_mutex_unlock(&GetARPEntryMutex);
            return -1;
        }

#else
	v_secure_system("ip -4 nei show | grep %s | grep -v 192.168.10 > "ARP_CACHE_FILE, netName);
#endif /* CORE_NET_LIB */

#ifdef CORE_NET_LIB
        if (st == CNL_STATUS_SUCCESS) {
            for (int i = 0; i < neighbours->neigh_count; ++i) {
                char arp_entry[128] = {0};
                // Handle IPv6 address
#if defined(_HUB4_PRODUCT_REQ_) || defined(_RDKB_GLOBAL_PRODUCT_REQ_)
                if (neighbours->neigh_arr[i].local == NULL || strlen(neighbours->neigh_arr[i].local) == 0 || strcmp(neighbours->neigh_arr[i].local, "none") == 0) {
                    CcspTraceError(("%s %d: Invalid local value for neighbor %d\n", __FUNCTION__, __LINE__, i));
                    continue;
                }
#endif /*_HUB4_PRODUCT_REQ_ || _RDKB_GLOBAL_PRODUCT_REQ_*/
                if (check_nei_ip_type(neighbours->neigh_arr[i].local) == NEI_IPV6) {
#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
                    if (strncmp(neighbours->neigh_arr[i].local, "fd", 2) != 0 && strncmp(neighbours->neigh_arr[i].local, "fc", 2) != 0)
#elif defined(_HUB4_PRODUCT_REQ_)
                    if (strstr(neighbours->neigh_arr[i].local, "fd") == NULL && strstr(neighbours->neigh_arr[i].local, "fc") == NULL)
#endif /*_HUB4_PRODUCT_REQ_*/
                            format_neighbour_entry(neighbours, i, arp_entry, sizeof(arp_entry));
                }
                if (arp_entry[0] != '\0') {
                    libnet_status fw_st = file_append(ARP_CACHE_FILE, arp_entry, strlen(arp_entry));
                    if (fw_st != CNL_STATUS_SUCCESS){
                        CcspTraceError(("%s %d: File write failed for neighbor list!\n", __FUNCTION__, __LINE__));
                    }
                }
            }
        }
        neighbour_free_neigh(neighbours);
#else
#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
        v_secure_system("ip -6 nei show | grep %s | egrep -v \'^(fc|fd)\' >> "ARP_CACHE_FILE, netName);
#elif defined(_HUB4_PRODUCT_REQ_)
	v_secure_system("ip -6 nei show | grep %s | grep -v fd | grep -v fc >> "ARP_CACHE_FILE, netName);
#else
        v_secure_system("ip -6 nei show | grep %s  >> "ARP_CACHE_FILE, netName);
#endif
#endif /* CORE_NET_LIB */

    }

    if ( (fp=fopen(ARP_CACHE_FILE, "r")) == NULL )
    {
        *pCount = 0;
        CcspTraceError(("Error reading ARP cache file at %s -  %d\n", __FILE__,__LINE__));
        pthread_mutex_unlock(&GetARPEntryMutex);
        return -1;
    }

    while ( fgets(buf, sizeof(buf), fp)!= NULL )
    {
        if ( strstr(buf, "FAILED") != 0 || strstr(buf, "router") != 0)
        {
            continue;
        }

        hosts = (LM_host_entry_t *) realloc(hosts, sizeof(LM_host_entry_t) * (index+1));

        if ( hosts == NULL )
        {
            fclose(fp);
            unlink(ARP_CACHE_FILE);
            *pCount = 0;
            CcspTraceError(("unlinking ARP cache file at %s -  %d\n", __FILE__,__LINE__));
            pthread_mutex_unlock(&GetARPEntryMutex);
            return -1;
        }

        /*
        Sample:
        fe80::f07f:ef54:f9b3:69f4 dev brlan0 lladdr f0:de:f1:0b:39:65 STALE
        192.168.1.200 dev brlan0 lladdr f0:de:f1:0b:39:65 STALE
        192.168.1.206 dev brlan0 lladdr f0:de:f1:0b:39:65 REACHABLE
        192.168.100.3 dev lan0 lladdr 00:13:20:fa:72:25 STALE
        */
        ret = sscanf(buf, LM_ARP_ENTRY_FORMAT,
                 hosts[index].ipAddr,
                 stub,
                 hosts[index].ifName,
                 stub,
                 hosts[index].phyAddr,
                 status);  //todo: should IPv6 router be cared about?
        if(ret != 6)
            continue;

        if ( 0 == strcmp(status, "REACHABLE") )
        {
            hosts[index].status = LM_NEIGHBOR_STATE_REACHABLE;
        }
        else
        {
            hosts[index].status = LM_NEIGHBOR_STATE_STALE;
        }
        PRINTD("%s:%s %s %s %d\n", __FUNCTION__,
                hosts[index].phyAddr,
                hosts[index].ipAddr,
                hosts[index].ifName,
                hosts[index].status);

        index++;
    }

    (*pCount) = index;

    (*ppArray) = hosts;

    fclose(fp);

    unlink(ARP_CACHE_FILE);

    pthread_mutex_unlock(&GetARPEntryMutex);

    return 0;
}


void getAddressSource(char *physAddress, char *pAddressSource)
{

    FILE *fp = NULL;
    char buf[200] = {0};
    int ret;
    LM_host_entry_t dhcpHost;
    errno_t rc = -1;
    char ipAddress[50] = {0};
    getIPAddress(physAddress , ipAddress);

    if ( (fp=fopen(DNSMASQ_LEASES_FILE, "r")) == NULL )
    {
        return;
    }

    while ( fgets(buf, sizeof(buf), fp)!= NULL )
    {
        memset(&dhcpHost,0,sizeof(LM_host_entry_t));
        /*
        Sample:
        6885 f0:de:f1:0b:39:65 10.0.0.96 shiywang-WS 01:f0:de:f1:0b:39:65 6765 MSFT 5.0
        6487 02:10:18:01:00:02 10.0.0.91 * * 6367 *
        */
        ret = sscanf(buf, LM_DHCP_CLIENT_FORMAT,
                 &(dhcpHost.LeaseTime),
                 dhcpHost.phyAddr,
                 dhcpHost.ipAddr,
                 dhcpHost.hostName
              );


        if(ret != 4)
            continue;

    if (!strcasecmp(ipAddress,(const char *)dhcpHost.ipAddr))
	{
		rc = STRCPY_S_NOCLOBBER(pAddressSource, 20,"DHCP");
		ERR_CHK(rc);
		break;
	}

   }

    fclose(fp);
    fp=NULL;
memset(buf,0,sizeof(buf));
   if ( (fp=fopen(DNSMASQ_RESERVED_FILE, "r")) == NULL )
    {
        return;
    }

    while ( fgets(buf, sizeof(buf), fp)!= NULL )
    {
        memset(&dhcpHost,0,sizeof(LM_host_entry_t));
        /*
        Sample:
        02:10:18:01:00:02,10.0.0.91,*
        */
        ret = sscanf(buf, DHCPV4_RESERVED_FORMAT,
                 dhcpHost.phyAddr,
                 dhcpHost.ipAddr,
                 dhcpHost.hostName
              );
        if(ret != 3)
            continue;

	if (!strcasecmp(physAddress, (const char *)dhcpHost.phyAddr))
	{
		rc = STRCPY_S_NOCLOBBER(pAddressSource, 20,"Static");
		ERR_CHK(rc);
		break;
	}

   }
    fclose(fp);
   if(rc == -1)
   {
     rc = STRCPY_S_NOCLOBBER(pAddressSource, 20,"Static");
     ERR_CHK(rc);

   }
   return;
}

int get_HostName(char *physAddress, char *HostName, size_t HostNameLen)
{
    int count = 0;

    CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Wait for dnsmasq to update hostname\n"));

    while (1)
    {
        struct stat st;
        FILE *fp = NULL;
        size_t len;

        sleep(HOST_NAME_RETRY_INTERVAL);

        *HostName = 0;

        pthread_mutex_lock(&HostNameMutex);

        if ((stat(DNSMASQ_LEASES_FILE, &st) == 0) &&
            (st.st_size != 0) &&
            ((fp = v_secure_popen("r", "grep -i %s " DNSMASQ_LEASES_FILE " | awk '{print $4}'", physAddress)) != NULL))
        {
            while (fgets(HostName, HostNameLen, fp) != NULL)
            {
                /* Read all lines */
            }

            v_secure_pclose(fp);
        }

        pthread_mutex_unlock(&HostNameMutex);

        len = strlen(HostName);

        if ((len > 0) && (HostName[len - 1] == '\n'))
        {
            HostName[len - 1] = 0;  /* Remove trailing newline */
            len--;
        }

        if ((len == 0) || ((len == 1) && (HostName[0] == '*')))
        {
            if (++count > HOST_NAME_RETRY)
            {
                CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Retry-%d Hostname not available\n", count));
                return 0;
            }
            CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Retry-%d for HostName\n", count));
            continue;
        }

        return 1;
    }
}

#ifdef CORE_NET_LIB
static int neigh_state_score(int state)
{
    switch (state) {
        case NEIGH_STATE_REACHABLE:
            return 300;
        case NEIGH_STATE_DELAY:
            return 200;
        case NEIGH_STATE_STALE:
            return 100;
        default:
            return 0;
    }
}
#endif

int getIPAddress(char *physAddress,char *IPAddress)
{

    FILE *fp = NULL;
    char output[50] = {0};
    char buf[200] = {0};
#if 0
    v_secure_system("ip -4 nei show | grep brlan0 | grep -v 192.168.10 | grep -i %s | awk '{print $1}' | tail -1 > /tmp/LMgetIP.txt ", physAddress);

    fp = fopen ("/tmp/LMgetIP.txt", "r");

    if (fp != NULL) 
    {
        while(fgets(output, sizeof(output), fp)!=NULL);
        fclose (fp);
        fp=NULL
    }

    rc = STRCPY_S_NOCLOBBER(IPAddress, 50,output);
    ERR_CHK(rc);
    return 0;
#endif

//FIX START
/* With previous fix provided few corner cases was not not getting handled.
   This was seen when connected clients moved from DHCP to Static
   1) Not transitioning states when changed from DHCP to Static while client was connected.

   This led to improper values in Host Table or not getting updated at all resulting wrong values in UI.

   This fix handles the above case by dividing the updation of neighbour table into 2 parts :
   CASE 1 : handles the updation of host table from neighbour table when clients are connected and mode is changed to STATIC on the fly.
   CASE 2 : handles the updation of host table from neighbour table when clients are disconnected/change mode to DHCP
   CASE 3 : handles the updation of host table from dnsmasq.leases when connected clients are set to receive ip from DHCP.
*/

#ifdef CORE_NET_LIB
    char *mac_filter = NULL;
    char *if_filter = NULL;
    int af_filter = AF_INET;
    int last_state = -1;
    libnet_status st = CNL_STATUS_FAILURE;

    if (physAddress != NULL) {
        mac_filter = strdup(physAddress);
        if (!mac_filter) {
            CcspTraceError(("%s: Failed to copy MAC string\n", __FUNCTION__));
            return -1;
        }
    }
    else{
        CcspTraceError(("%s: Input MAC address is NULL\n", __FUNCTION__));
        return -1;
    }

    struct neighbour_info *neighbours =  init_neighbour_info();
    if (!neighbours) {
        CcspTraceError(("%s: Failed to initialize neighbor information structure\n", __FUNCTION__));
        free(mac_filter);
        goto CASE_DNSMASQ;
    }

    st = neighbour_get_list(neighbours, mac_filter, if_filter, af_filter);
    free(mac_filter);
    if (st != CNL_STATUS_SUCCESS) {
        CcspTraceError(("%s: Failed to execute neighbour_get_list!\n", __FUNCTION__));
        neighbour_free_neigh(neighbours);
        goto CASE_DNSMASQ;
    }

    CcspTraceDebug(("%s: Successfully retrieved neighbor list based on MAC:%s, and Neighbour count: %d\n", __FUNCTION__, physAddress, neighbours->neigh_count));
    if (neighbours->neigh_count <= 0 || neighbours->neigh_arr == NULL) {
        CcspTraceError(("%s: Neighbour list is empty\n", __FUNCTION__));
        neighbour_free_neigh(neighbours);
        goto CASE_DNSMASQ;
    }

    /* FIX:
     * Choose the best neighbour instead of the last one.
     * Priority is based on neighbour state while still allowing
     * STALE to win if it is the only valid entry.
     */
    int best_score = -1;
    int best_state = -1;
    char best_ip[50] = {0};

    for (int i = 0; i < neighbours->neigh_count; ++i) {
        CcspTraceDebug(("Neighbor %d: local=%s, mac=%s, ifname=%s, state=%d\n",
            i,
            neighbours->neigh_arr[i].local ? neighbours->neigh_arr[i].local : "NULL",
            neighbours->neigh_arr[i].mac ? neighbours->neigh_arr[i].mac : "NULL",
            neighbours->neigh_arr[i].ifname ? neighbours->neigh_arr[i].ifname : "NULL",
            neighbours->neigh_arr[i].state));

        if (neighbours->neigh_arr[i].local == NULL ||
            strlen(neighbours->neigh_arr[i].local) == 0 ||
            strcmp(neighbours->neigh_arr[i].local, "none") == 0) {
            continue;
        }

        if (strstr(neighbours->neigh_arr[i].local, "169.254.") != NULL) {
            continue;
        }

        int score = neigh_state_score(neighbours->neigh_arr[i].state);
        if (score <= 0) {
            continue;
        }

        if (score > best_score) {
            best_score = score;
            best_state = neighbours->neigh_arr[i].state;
            strncpy(best_ip, neighbours->neigh_arr[i].local, sizeof(best_ip) - 1);
        }
    }

    if (best_ip[0] != '\0') {

        strncpy(IPAddress, best_ip, 50 - 1);
        IPAddress[50 - 1] = '\0';

        if (best_state == NEIGH_STATE_STALE) {
            //CASE 1 : To update neighbour table when Static clients are transistioning between REACHABLE and DELAY
            AnscTraceWarning(("client is in stale state: MAC %s IP %s\n", physAddress, IPAddress));  //Case 1
        } else {
            //CASE 2 : To update neighbour table when Static clients are disconnected or mode changes to DHCP due to which it receives new IP...existing IP is obsolete
            AnscTraceWarning(("client is either reachable or delay: MAC %s IP %s\n", physAddress, IPAddress)); //Case 2
        }
        neighbour_free_neigh(neighbours);
        return 0;
    }
    neighbour_free_neigh(neighbours);
#else /* CORE_NET_LIB */
//CASE 1 : To update neighbour table when Static clients are transistioning between REACHABLE and DELAY
    memset(buf, 0, sizeof(buf));
    memset(output, 0, sizeof(output));
    snprintf(buf, sizeof(buf), "ip -4 nei show | grep -i %s | grep -e REACHABLE -e DELAY | awk '{print $1}' | grep -v 169.254. | tail -1", physAddress); //Link local IP is filtered.
    if((fp = popen(buf, "r")))
    {
        while(fgets(output, sizeof(output), fp)!=NULL)
        {
                output[strlen(output) - 1] = '\0';
        }
        if (output[0] != '\0')
        {
            memcpy(IPAddress,output,sizeof(output));
            AnscTraceWarning(("client is either reachable or delay: MAC %s IP %s\n", physAddress, IPAddress));
            pclose(fp);
            fp = NULL;
            return 0;
         }
         else
         {
             pclose(fp);
             fp = NULL;
         }
    }

//CASE 2 : To update neighbour table when Static clients are disconnected or mode changes to DHCP due to which it receives new IP...existing IP is obsolete
    memset(buf, 0, sizeof(buf));
    memset(output, 0, sizeof(output));
    snprintf(buf, sizeof(buf), "ip -4 nei show | grep -i %s | grep -e STALE | awk '{print $1}' | grep -v 169.254. | tail -1", physAddress); //Link local IP is filtered.
    if((fp = popen(buf, "r")))
    {
        while(fgets(output, sizeof(output), fp)!=NULL)
        {
                output[strlen(output) - 1] = '\0';
        }
        if (output[0] != '\0')
        {
             memcpy(IPAddress,output,sizeof(output));
             AnscTraceWarning(("client is in stale state: MAC %s IP %s\n", physAddress, IPAddress));
             pclose(fp);
             fp = NULL;
             return 0;
         }
         else
         {
             pclose(fp);
             fp = NULL;
         }
    }
#endif /* CORE_NET_LIB */

#ifdef CORE_NET_LIB
CASE_DNSMASQ:
#endif /* CORE_NET_LIB */

//CASE 3 : Handles details of clients that are set to receive automatic IP via DHCP
    memset(buf, 0, sizeof(buf));
    memset(output, 0, sizeof(output));
    snprintf(buf, sizeof(buf), "cat /nvram/dnsmasq.leases | grep -i %s | cut -d ' ' -f3", physAddress);

   if( ( (access( "/nvram/dnsmasq.leases", F_OK ) != -1)) && (fp = popen(buf, "r")))
    {
         while(fgets(output, sizeof(output), fp)!=NULL)
         {
             output[strlen(output) - 1] = '\0';
         }

         if (output[0] != '\0')
         {
             memcpy(IPAddress,output,sizeof(output));
             AnscTraceWarning(("client mac present in dnsmasq: MAC %s IP %s\n", physAddress, IPAddress));
             pclose(fp);
             fp = NULL;
             return 0;
         }
         else
         {
             pclose(fp);
             fp = NULL;
         }
    }
//FIX END
//Return empty and update primray IP in caller
   memcpy(IPAddress,output,sizeof(output));
   return 0;

}

#if !defined (RESOURCE_OPTIMIZATION)
void Xlm_wrapper_get_info(PLmObjectHost pHost)
{
    FILE *fp = NULL;
    char buf[200] = {0};
    int ret;
    LM_host_entry_t dhcpHost;
    char *strValue = NULL;
    int retPsmGet = CCSP_SUCCESS;
    char ip[13] = {0};

    if ( (fp=fopen(DNSMASQ_LEASES_FILE, "r")) == NULL )
    {
        return;
    }

    while ( fgets(buf, sizeof(buf), fp)!= NULL )
    {
        memset(&dhcpHost,0,sizeof(LM_host_entry_t));
        /*
        Sample:sss
        6885 f0:de:f1:0b:39:65 10.0.0.96 shiywang-WS 01:f0:de:f1:0b:39:65 6765 MSFT 5.0
        6487 02:10:18:01:00:02 10.0.0.91 * * 6367 *
        */
        ret = sscanf(buf, LM_DHCP_CLIENT_FORMAT,
                 &(dhcpHost.LeaseTime),
                 dhcpHost.phyAddr,
                 dhcpHost.ipAddr,
                 dhcpHost.hostName
              );
        if(ret != 4)
            continue;

        retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, "dmsb.l3net.5.V4Addr", NULL, &strValue);
        if(retPsmGet == CCSP_SUCCESS)
        {
            sprintf(ip, "%.12s", strValue);
           ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
        }

        if (strstr((const char *)dhcpHost.ipAddr, ip) && (strcasecmp((char *)dhcpHost.phyAddr, pHost->pStringParaValue[LM_HOST_PhysAddressId]) == 0))
        {
            pthread_mutex_lock(&XLmHostObjectMutex);

            if (strcmp((char *) dhcpHost.hostName, "*") == 0)
			LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_HostNameId]), pHost->pStringParaValue[LM_HOST_PhysAddressId]);
            else
			LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_HostNameId]), (const char *)dhcpHost.hostName);

            Host_AddIPv4Address ( pHost, (char *)dhcpHost.ipAddr);
            pHost->LeaseTime  = (dhcpHost.LeaseTime == 0 ? 0xFFFFFFFF: (unsigned int)dhcpHost.LeaseTime);

            pthread_mutex_unlock(&XLmHostObjectMutex);
            break;
        }
    }

    fclose(fp);

    return;
}
#endif


void lm_wrapper_get_dhcpv4_client()
{
    FILE *fp = NULL;
    char buf[200] = {0};
    char lan_ip_address[32] = {0};
    char lan_net_mask[32] = {0};
    int ret;
    PLmObjectHostIPAddress pIP;

    LM_host_entry_t dhcpHost;
    PLmObjectHost pHost;
    errno_t rc = -1;

    if ( (fp = fopen(DNSMASQ_LEASES_FILE, "r")) == NULL )
    {
        return;
    }

    while ( fgets(buf, sizeof(buf), fp)!= NULL )
    {
        memset(&dhcpHost,0,sizeof(LM_host_entry_t));
        /*
        Sample:sss
        6885 f0:de:f1:0b:39:65 10.0.0.96 shiywang-WS 01:f0:de:f1:0b:39:65 6765 MSFT 5.0
        6487 02:10:18:01:00:02 10.0.0.91 * * 6367 *
        */
        syscfg_get( NULL, "lan_ipaddr", lan_ip_address, sizeof(lan_ip_address));

        syscfg_get( NULL, "lan_netmask", lan_net_mask, sizeof(lan_net_mask));


        ret = sscanf(buf, LM_DHCP_CLIENT_FORMAT,
                 &(dhcpHost.LeaseTime),
                 dhcpHost.phyAddr,
                 dhcpHost.ipAddr,
                 dhcpHost.hostName
              );
        if(ret != 4)
            continue;


        if(!AreIPv4AddressesInSameSubnet(lan_ip_address, (char *)dhcpHost.ipAddr, lan_net_mask))
        {
            continue;
        }

        CcspTraceDebug(("%s:%d, Acquiring presence locks \n",__FUNCTION__,__LINE__));
        acquirePresencelocks ();
        CcspTraceDebug(("%s:%d, Acquired presence locks \n",__FUNCTION__,__LINE__));
        pHost = Hosts_FindHostByPhysAddress((char *)dhcpHost.phyAddr);

        if ( !pHost )
        {
            if(! (pAtomBRMac[0] != '\0'  &&  pAtomBRMac[0] != ' ' && strcasestr((const char *)dhcpHost.phyAddr,pAtomBRMac) != NULL ))
            {
                pHost = Hosts_AddHostByPhysAddress((char *)dhcpHost.phyAddr);

                if ( pHost )
                {
                    if ( pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] )
                    {
                        AnscFreeMemory(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId]);
                        pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] = NULL;
                    }
                }
            }
        }

        if ( pHost )
        {
            PRINTD("%s: %s %s\n", __FUNCTION__, dhcpHost.phyAddr, dhcpHost.hostName);
	if (strcmp(pHost->pStringParaValue[LM_HOST_AddressSource], "Static") != 0)
	{
            if (strcasecmp(pHost->pStringParaValue[LM_HOST_PhysAddressId], pHost->pStringParaValue[LM_HOST_HostNameId]) != 0){
                rc = strcpy_s(pHost->backupHostname, sizeof(pHost->backupHostname),pHost->pStringParaValue[LM_HOST_HostNameId]); // hostanme change id.
                ERR_CHK(rc);
            }
            if (strcmp((char *) dhcpHost.hostName, "*") == 0)
            {
                LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_HostNameId]), pHost->pStringParaValue[LM_HOST_PhysAddressId]);
            }else
                LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_HostNameId]), (char *)dhcpHost.hostName);

            
            if((pHost->backupHostname[0]!='\0') && (strcmp(pHost->backupHostname, pHost->pStringParaValue[LM_HOST_HostNameId]) != 0))
                {
                    rc = strcpy_s(pHost->backupHostname, sizeof(pHost->backupHostname),pHost->pStringParaValue[LM_HOST_HostNameId]);
                    ERR_CHK(rc);
                    lmHosts.lastActivity++;
                    CcspTraceWarning(("Hostname Changed <%s> <%d> : Hostname = %s HostVersionID %lu\n",__FUNCTION__, __LINE__,pHost->pStringParaValue[LM_HOST_HostNameId],lmHosts.lastActivity));
		    t2_event_d("SYS_INFO_Hostname_changed", 1);
                    if (syscfg_set_u_commit(NULL, "X_RDKCENTRAL-COM_HostVersionId", lmHosts.lastActivity) != 0)
                    {
                        AnscTraceWarning(("syscfg_set failed\n"));
                    }
                }
	}
            LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_AddressSource]), "DHCP");
            char ipAddress[50] = {0};
            getIPAddress((char *)dhcpHost.phyAddr, ipAddress);

            pIP = Host_AddIPv4Address
            (
                pHost,
                (char *)ipAddress
            );
            if(pIP != NULL)
            {
                LanManager_CheckCloneCopy(&(pIP->pStringParaValue[LM_HOST_IPAddress_IPAddressSourceId]), "DHCP");
                pIP->LeaseTime = (dhcpHost.LeaseTime == 0 ? 0xFFFFFFFF: (unsigned int)dhcpHost.LeaseTime);
                pHost->LeaseTime = pIP->LeaseTime;
                
            }
        }
        releasePresenceLocks();
        CcspTraceDebug(("%s:%d, released presence locks \n",__FUNCTION__,__LINE__));
    }

    fclose(fp);

    return;
}

void lm_wrapper_get_dhcpv4_reserved()
{

    FILE *fp = NULL;
    char buf[200] = {0};
    int ret;

    PLmObjectHostIPAddress pIP;
    LM_host_entry_t dhcpHost;
    PLmObjectHost pHost;
    errno_t rc = -1;

    if ( (fp=fopen(DNSMASQ_RESERVED_FILE, "r")) == NULL )
    {
        return;
    }
  
    while ( fgets(buf, sizeof(buf), fp)!= NULL )
    {
       memset(&dhcpHost,0,sizeof(LM_host_entry_t));
       /*
        Sample:
        02:10:18:01:00:02,10.0.0.91,*
        */
        ret = sscanf(buf, DHCPV4_RESERVED_FORMAT,
                 dhcpHost.phyAddr,
                 dhcpHost.ipAddr,
                 dhcpHost.hostName
              );

        if((ret < 2) || (ret > 3))
            continue;

        CcspTraceDebug(("%s:%d, Acquiring presence locks \n",__FUNCTION__,__LINE__));
        acquirePresencelocks();
        CcspTraceDebug(("%s:%d, Acquired presence locks \n",__FUNCTION__,__LINE__));
        pHost = Hosts_FindHostByPhysAddress((char *)dhcpHost.phyAddr);

        if ( !pHost )
        {
            pHost = Hosts_AddHostByPhysAddress((char *)dhcpHost.phyAddr);

            if ( pHost )
            {
                if ( pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] )
                {
                    AnscFreeMemory(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId]);
                    pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] = NULL;
                }


            }
        }

        if ( pHost )
        {
            PRINTD("%s: %s %s %s\n", __FUNCTION__, dhcpHost.phyAddr, dhcpHost.ipAddr, dhcpHost.hostName);
			if (strcasecmp(pHost->pStringParaValue[LM_HOST_PhysAddressId], pHost->pStringParaValue[LM_HOST_HostNameId]) != 0){
				rc = strcpy_s(pHost->backupHostname, sizeof(pHost->backupHostname),pHost->pStringParaValue[LM_HOST_HostNameId]); // hostanme change id.
				ERR_CHK(rc);
            }

            if (strcmp((char *) dhcpHost.hostName, "*") == 0)
            {
                LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_HostNameId]), pHost->pStringParaValue[LM_HOST_PhysAddressId]);
            }
            else
            {
                // copy only if not empty.
                if (dhcpHost.hostName[0] != '\0')
                {
                    LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_HostNameId]), (char *)dhcpHost.hostName);
                }
                else
                {
                    // Copy Mac address if there is no host name exist already.
                    if (pHost->pStringParaValue[LM_HOST_HostNameId] == NULL)
                    {
                        LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_HostNameId]), pHost->pStringParaValue[LM_HOST_PhysAddressId]);
                    }
                }
            }

			if((pHost->backupHostname[0]!='\0') && (strcmp(pHost->backupHostname, pHost->pStringParaValue[LM_HOST_HostNameId]) != 0))
                {
					rc = strcpy_s(pHost->backupHostname, sizeof(pHost->backupHostname),pHost->pStringParaValue[LM_HOST_HostNameId]);
					ERR_CHK(rc);
					lmHosts.lastActivity++;
					CcspTraceWarning(("Hostname Changed <%s> <%d> : Hostname = %s HostVersionID %lu\n",__FUNCTION__, __LINE__,pHost->pStringParaValue[LM_HOST_HostNameId],lmHosts.lastActivity));
					t2_event_d("SYS_INFO_Hostname_changed", 1);
					if (syscfg_set_u_commit(NULL, "X_RDKCENTRAL-COM_HostVersionId", lmHosts.lastActivity) != 0)
					{
						AnscTraceWarning(("syscfg_set failed\n"));
					}
				}
            LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_AddressSource]), "Static");
            pIP = Host_AddIPv4Address
                (
                    pHost,
                    (char *)dhcpHost.ipAddr
                );
            if(pIP != NULL)
            {
                LanManager_CheckCloneCopy(&(pIP->pStringParaValue[LM_HOST_IPAddress_IPAddressSourceId]), "Static");
                pIP->LeaseTime = 0;
            }
        }
        releasePresenceLocks();
        CcspTraceDebug(("%s:%d, released presence locks \n",__FUNCTION__,__LINE__));
    }

    fclose(fp);

    return;
}

int lm_wrap_checkIPv4AddressInRange(char* ipaddress, char* ipaddres2, char* subnetmask) {
	return AreIPv4AddressesInSameSubnet(ipaddress, ipaddres2, subnetmask);
}

