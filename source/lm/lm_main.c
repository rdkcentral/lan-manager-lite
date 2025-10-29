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


/**************************************************************************

    module: cosa_apis_hosts.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file implementes back-end apis for the COSA Data Model Library

    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        09/16/2011    initial revision.

**************************************************************************/
#define _GNU_SOURCE
#include <time.h>
#include <sys/sysinfo.h>
#include <string.h>

#include "ansc_platform.h"
#include "ccsp_base_api.h"
#include "lm_main.h"
#include "lm_util.h"
#ifdef WAN_TRAFFIC_COUNT_SUPPORT
#include "cosa_wantraffic_api.h"
#endif
#include "webpa_interface.h"
#include "lm_wrapper.h"
#include "lm_api.h"
#include "lm_wrapper_priv.h"
#include "ccsp_lmliteLog_wrapper.h"
#include "network_devices_interface.h"
#include "syscfg/syscfg.h"
#include "ccsp_memory.h"
#include "cosa_plugin_api.h"
#include "safec_lib_common.h"
#include "secure_wrapper.h"
#ifdef FEATURE_SUPPORT_ONBOARD_LOGGING
#define OnboardLog(...)                     rdk_log_onboard("LM", __VA_ARGS__)
#else
#define OnboardLog(...)
#endif

#include <telemetry_busmessage_sender.h>
#define TELEMETRY_MAX_BUFFER 256

#define LM_IPC_SUPPORT
#include "ccsp_dm_api.h"

#define NAME_DM_LEN  257

#define STRNCPY_NULL_CHK1(dest, src) { if((dest) != NULL ) AnscFreeMemory((dest));\
                                           (dest) = _CloneString((src));}


#define DNS_LEASE "/nvram/dnsmasq.leases"
#define DEBUG_INI_NAME  "/etc/debug.ini"
#define HOST_ENTRY_LIMIT 175
#define HOST_OBJECT_SIZE	200
#define ARP_IPv6 0
#define DIBBLER_IPv6 1

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <mqueue.h>

#define EVENT_QUEUE_NAME  "/Event_queue"
#define DNSMASQ_NOTIFY_QUEUE_NAME  "/dnsmasq_eventqueue"

#define MAX_SIZE    2048
#define MAX_SIZE_DNSMASQ_Q    512
#define MAX_SIZE_EVT    1024

#define CHECK(x) \
    do { \
        if (!(x)) { \
            fprintf(stderr, "%s:%d: ", __func__, __LINE__); \
            perror(#x); \
            return; \
        } \
    } while (0) \

#define MSG_TYPE_EMPTY  0
#define MSG_TYPE_ETH    1
#define MSG_TYPE_WIFI   2
#if !defined (NO_MOCA_FEATURE_SUPPORT)
#define MSG_TYPE_MOCA   3
#endif
#define MSG_TYPE_RFC  5
#define MSG_TYPE_DNSMASQ  6

#define VALIDATE_QUEUE_NAME             "/Validate_host_queue"
#define MAX_SIZE_VALIDATE_QUEUE         sizeof(ValidateHostQData)
#define MAX_COUNT_VALIDATE_RETRY        (3)
#define MAX_WAIT_VALIDATE_RETRY         (15)
#define ARP_CACHE                       "/tmp/arp.txt"
#define DNSMASQ_CACHE                   "/tmp/dns.txt"
#define DNSMASQ_FILE                    "/nvram/dnsmasq.leases"
#define ACTION_FLAG_ADD                 (1)
#define ACTION_FLAG_DEL                 (2)

typedef enum {
    CLIENT_STATE_OFFLINE,
    CLIENT_STATE_DISCONNECT,
    CLIENT_STATE_ONLINE,
    CLIENT_STATE_CONNECT
} ClientConnectState;

typedef struct _EventQData 
{
    char Msg[MAX_SIZE_EVT];
    int MsgType; // Ethernet = 1, WiFi = 2, MoCA = 3
}EventQData;

typedef struct _Eth_data
{
    char MacAddr[18];
    int Active; // Online = 1, offline = 0
}Eth_data;

typedef struct _Name_DM 
{
    char name[NAME_DM_LEN];
    char dm[NAME_DM_LEN];
}Name_DM_t;

typedef struct _ValidateHostQData
{
    char phyAddr[18];
    char AssociatedDevice[LM_GEN_STR_SIZE];
    char ssid[LM_GEN_STR_SIZE];
    int RSSI;
    int Status;
} ValidateHostQData;

typedef struct _RetryHostList
{
    ValidateHostQData host;
    int retryCount;
    struct _RetryHostList *next;
} RetryHostList;

RetryHostList *pListHead = NULL;

int g_IPIfNameDMListNum = 0;
Name_DM_t *g_pIPIfNameDMList = NULL;

#if !defined (NO_MOCA_FEATURE_SUPPORT)
int g_MoCAADListNum = 0;
Name_DM_t *g_pMoCAADList = NULL;
#endif

int g_DHCPv4ListNum = 0;
Name_DM_t *g_pDHCPv4List = NULL;

static int firstFlg = 0;
#if !defined (RESOURCE_OPTIMIZATION)
static int xfirstFlg = 0;
#endif

extern int bWifiHost;

extern char*                                pComponentName;

#if defined (RDKB_EXTENDER_ENABLED)
extern char dev_Mode[20] ;
#endif

int g_Client_Poll_interval;

/* Presence Notification - Payload */
typedef struct {
    PLmObjectHost pHost;
    char interface[32];
    ClientConnectState status;
    char *ipv4;
    char *hostName;
    char *physAddr;
} LMPresenceNotifyAddressInfo;

typedef struct RetryNotifyHostList {
    struct RetryNotifyHostList *next;
    LMPresenceNotifyAddressInfo *ctx;
    int retry_count;
} RetryNotifyHostList;

static RetryNotifyHostList *pNotifyListHead = NULL;
static pthread_mutex_t LmRetryNotifyHostListMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t LmNotifyCond = PTHREAD_COND_INITIALIZER;
static pthread_t NotifyIPMonitorThread;
static bool worker_thread_running = false;


#define IP_RETRY_INTERVAL              10
#define IP_MAX_RETRIES             6
/***********************************************************************
 IMPORTANT NOTE:

 According to TR69 spec:
 On successful receipt of a SetParameterValues RPC, the CPE MUST apply
 the changes to all of the specified Parameters atomically. That is, either
 all of the value changes are applied together, or none of the changes are
 applied at all. In the latter case, the CPE MUST return a fault response
 indicating the reason for the failure to apply the changes.

 The CPE MUST NOT apply any of the specified changes without applying all
 of them.

 In order to set parameter values correctly, the back-end is required to
 hold the updated values until "Validate" and "Commit" are called. Only after
 all the "Validate" passed in different objects, the "Commit" will be called.
 Otherwise, "Rollback" will be called instead.

 The sequence in COSA Data Model will be:

 SetParamBoolValue/SetParamIntValue/SetParamUlongValue/SetParamStringValue
 -- Backup the updated values;

 if( Validate_XXX())
 {
     Commit_XXX();    -- Commit the update all together in the same object
 }
 else
 {
     Rollback_XXX();  -- Remove the update at backup;
 }

***********************************************************************/
pthread_mutex_t LmRetryHostListMutex;
#define LM_HOST_OBJECT_NAME_HEADER  "Device.Hosts.Host."
#define LM_HOST_RETRY_LIMIT         30

//#define TIME_NO_NEGATIVE(x) ((long)(x) < 0 ? 0 : (x))

#define STRNCPY_NULL_CHK(x, y, z) if((y) != NULL) strncpy((x),(y),(z)); else  *(unsigned char*)(x) = 0;

LmObjectHosts lmHosts = {
    .pHostBoolParaName = {"Active","X_RDKCENTRAL-COM_PresenceNotificationEnabled","RDK_PresenceActive"},
    .pHostIntParaName = {"X_CISCO_COM_ActiveTime", "X_CISCO_COM_InactiveTime", "X_CISCO_COM_RSSI"},
    .pHostUlongParaName = {"X_CISCO_COM_DeviceType", "X_CISCO_COM_NetworkInterface", "X_CISCO_COM_ConnectionStatus", "X_CISCO_COM_OSType","X_COMCAST-COM_LastChange","RDK_PresenceActiveLastChange"},
    .pHostStringParaName = {"Alias", "PhysAddress", "IPAddress", "DHCPClient", "AssociatedDevice", "Layer1Interface", "Layer3Interface", "HostName",
                                        "X_CISCO_COM_UPnPDevice", "X_CISCO_COM_HNAPDevice", "X_CISCO_COM_DNSRecords", "X_CISCO_COM_HardwareVendor",
                                        "X_CISCO_COM_SoftwareVendor", "X_CISCO_COM_SerialNumbre", "X_CISCO_COM_DefinedDeviceType",
                                        "X_CISCO_COM_DefinedHWVendor", "X_CISCO_COM_DefinedSWVendor", "AddressSource", "Comments",
                                        "X_RDKCENTRAL-COM_Parent", "X_RDKCENTRAL-COM_DeviceType", "X_RDKCENTRAL-COM_Layer1Interface"
#ifdef VENDOR_CLASS_ID
, "VendorClassID"
#endif
 },
    .pIPv4AddressStringParaName = {"IPAddress"},
    .pIPv6AddressStringParaName = {"IPAddress"}
};

#if !defined (RESOURCE_OPTIMIZATION)
LmObjectHosts XlmHosts = {
    .pHostBoolParaName = {"Active","X_RDKCENTRAL-COM_PresenceNotificationEnabled","RDK_PresenceActive"},
    .pHostIntParaName = {"X_CISCO_COM_ActiveTime", "X_CISCO_COM_InactiveTime", "X_CISCO_COM_RSSI"},
    .pHostUlongParaName = {"X_CISCO_COM_DeviceType", "X_CISCO_COM_NetworkInterface", "X_CISCO_COM_ConnectionStatus", "X_CISCO_COM_OSType","X_COMCAST-COM_LastChange","RDK_PresenceActiveLastChange"},
    .pHostStringParaName = {"Alias", "PhysAddress", "IPAddress", "DHCPClient", "AssociatedDevice", "Layer1Interface", "Layer3Interface", "HostName",
                                        "X_CISCO_COM_UPnPDevice", "X_CISCO_COM_HNAPDevice", "X_CISCO_COM_DNSRecords", "X_CISCO_COM_HardwareVendor",
                                        "X_CISCO_COM_SoftwareVendor", "X_CISCO_COM_SerialNumbre", "X_CISCO_COM_DefinedDeviceType",
                                        "X_CISCO_COM_DefinedHWVendor", "X_CISCO_COM_DefinedSWVendor", "AddressSource", "Comments",
                                        "X_RDKCENTRAL-COM_Parent", "X_RDKCENTRAL-COM_DeviceType", "X_RDKCENTRAL-COM_Layer1Interface"
#ifdef VENDOR_CLASS_ID
, "VendorClassID"
#endif
 },
    .pIPv4AddressStringParaName = {"IPAddress"},
    .pIPv6AddressStringParaName = {"IPAddress"}
};
#endif

ANSC_STATUS COSAGetParamValueByPathName(void* bus_handle, parameterValStruct_t *val, ULONG *parameterValueLength);

/* It may be updated by different threads at the same time? */
ULONG HostsUpdateTime = 0;
#if !defined (RESOURCE_OPTIMIZATION)
ULONG XHostsUpdateTime = 0;
#endif

pthread_mutex_t HostNameMutex;
pthread_mutex_t PollHostMutex;
pthread_mutex_t LmHostObjectMutex;
extern pthread_mutex_t PresenceDetectionMutex;
#if !defined (RESOURCE_OPTIMIZATION)
pthread_mutex_t XLmHostObjectMutex;
#endif

static void Wifi_ServerSyncHost(char *phyAddr, char *AssociatedDevice, char *ssid, int RSSI, int Status);
static void Host_FreeIPAddress(PLmObjectHost pHost, int version);
static void Hosts_SyncDHCP(void);
static void Sendmsg_dnsmasq(BOOL enablePresenceFeature);
static void Send_Eth_Host_Sync_Req(void);

#if defined (CONFIG_SYSTEM_MOCA)
static void Send_MoCA_Host_Sync_Req(void);
#endif

static char *_CloneString (const char *src);

#ifdef USE_NOTIFY_COMPONENT

extern ANSC_HANDLE bus_handle;
static void DelAndShuffleAssoDevIndx (PLmObjectHost pHost);

static void Send_PresenceNotification (char *interface, char *mac, ClientConnectState status, char *hostname,
		                       char *ipv4)
{
    char str[500];
    parameterValStruct_t notif_val[1];
    char *param_name = "Device.NotifyComponent.SetNotifi_ParamName";
    char *compo = "eRT.com.cisco.spvtg.ccsp.notifycomponent";
    char *bus = "/com/cisco/spvtg/ccsp/notifycomponent";
    char *faultParam = NULL;
    char *status_str;
    int ret;

    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *) bus_handle;


    if (mac && strlen(mac))
    {
        switch (status) {
            case CLIENT_STATE_OFFLINE:
                status_str = "Presence Leave Detected";
                break;
            case CLIENT_STATE_ONLINE:
                status_str = "Presence Join Detected";
                break;
            default:
                status_str = "NULL";
                break;
        }

        snprintf (str, sizeof(str), "PresenceNotification,%s,%s,%s,%s,%s",
                                    interface != NULL ? (strlen(interface) > 0 ? interface : "NULL") : "NULL",
                                    mac,
                                    status_str,
                                    hostname != NULL ? (strlen(hostname) > 0 ? hostname : "NULL") : "NULL",
                                    ipv4 != NULL ? (strlen(ipv4) > 0 ? ipv4 : "NULL") : "NULL");

        CcspTraceWarning(("\n%s\n",str));
        notif_val[0].parameterName = param_name;
        notif_val[0].parameterValue = str;
        notif_val[0].type = ccsp_string;
        ret = CcspBaseIf_setParameterValues (
                bus_handle,
                compo,
                bus,
                0,
                0,
                notif_val,
                1,
                TRUE,
                &faultParam);

        if (ret != CCSP_SUCCESS)
        {
            CcspTraceWarning(("\n LMLite <%s> <%d >  Notification Failure %d \n",__FUNCTION__,__LINE__, ret));
            if (faultParam)
            {
                bus_info->freefunc(faultParam);
            }
        }
        else
        {
            CcspTraceWarning(("RDKB_PRESENCE: Mac %s status %s Notification sent successfully\n",mac,status_str));
        }
    }
    else
    {
        CcspTraceWarning(("RDKB_PRESENCE: MacAddress is NULL, hence Presence notifications are not sent\n"));
        //printf("RDKB_CONNECTED_CLIENTS: MacAddress is NULL, hence Connected-Client notifications are not sent\n");
    }
}

static void Send_Notification (char *interface, char *mac, ClientConnectState status, char *hostname)
{
    char str[500];
    parameterValStruct_t notif_val[1];
    char *param_name = "Device.NotifyComponent.SetNotifi_ParamName";
    char *compo = "eRT.com.cisco.spvtg.ccsp.notifycomponent";
    char *bus = "/com/cisco/spvtg/ccsp/notifycomponent";
    char *faultParam = NULL;
    char *status_str;
    int ret;

    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *) bus_handle;

    if (mac && strlen(mac))
    {

        switch (status) {
            case CLIENT_STATE_OFFLINE:
                status_str = "Offline";
                break;
            case CLIENT_STATE_DISCONNECT:
                status_str = "Disconnected";
                break;
            case CLIENT_STATE_ONLINE:
                status_str = "Online";
                break;
            case CLIENT_STATE_CONNECT:
                status_str = "Connected";
                break;
            default:
                status_str = "NULL";
                break;
        }

        snprintf (str, sizeof(str), "Connected-Client,%s,%s,%s,%s",
                                    interface != NULL ? (strlen(interface) > 0 ? interface : "NULL") : "NULL",
                                    mac,
                                    status_str,
                                    hostname != NULL ? (strlen(hostname) > 0 ? hostname : "NULL") : "NULL");

        CcspTraceWarning (("\n%s\n",str));
        notif_val[0].parameterName = param_name;
        notif_val[0].parameterValue = str;
        notif_val[0].type = ccsp_string;

        ret = CcspBaseIf_setParameterValues (
                bus_handle,
                compo,
                bus,
                0,
                0,
                notif_val,
                1,
                TRUE,
                &faultParam);

        if (ret != CCSP_SUCCESS)
        {
            CcspTraceWarning(("\n LMLite <%s> <%d >  Notification Failure %d \n",__FUNCTION__,__LINE__, ret));
            if (faultParam)
            {
                bus_info->freefunc(faultParam);
            }
        }
    }
    else
    {
        CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: MacAddress is NULL, hence Connected-Client notifications are not sent\n"));
        //printf("RDKB_CONNECTED_CLIENTS: MacAddress is NULL, hence Connected-Client notifications are not sent\n");
    }
}

#endif

static int FindHostInLeases (char *Temp, char *FileName)
{
    char buf[200];
    FILE *fp;
    int ret = 1;

    if ((fp = fopen (FileName, "r")) == NULL)
    {
        return 1;
    }

    while (fgets (buf, sizeof(buf), fp) != NULL)
    {
        if (strstr (buf, Temp))
        {
            ret = 0;
            break;
        }
    }

    fclose (fp);

    return ret;
}

static void LanManager_StringToLower (char *pstring)
{
    int i;

    for (i = 0; pstring[i] != '\0'; i++)
    {
        if ((pstring[i] >= 'A') && (pstring[i] <= 'Z'))
        {
            pstring[i] += ('a' - 'A');
        }
    }
}

static int logOnlineDevicesCount (void)
{
    PLmObjectHost pHost;
    int NumOfOnlineDevices = 0;
    int i;

    for (i = 0; i < lmHosts.numHost; i++)
    {
        pHost = lmHosts.hostArray[i];

        if (pHost->bBoolParaValue[LM_HOST_ActiveId])
        {
            NumOfOnlineDevices++;
        }
    }

    CcspTraceWarning(("CONNECTED_CLIENTS_COUNT : %d \n",NumOfOnlineDevices));

    return NumOfOnlineDevices;
}

static void get_uptime (int *uptime)
{
    struct sysinfo info;
    sysinfo( &info );
    *uptime = info.uptime;
}

#ifdef VENDOR_CLASS_ID
static void get_vendor_class_id (char* physAddress, char* vendor_class)
{
    char buffer[512] ={0}, *tmp_vendor=NULL;
    char client_mac[32] = {0};
    FILE* fpv = fopen(DNSMASQ_VENDORCLASS_FILE, "r");
    if(fpv != NULL)
    {
        while((fgets(buffer, sizeof(buffer), fpv)) != NULL)
        {
            memset(client_mac, 0, sizeof(client_mac));
            sscanf(buffer, "%s", client_mac);
            if (strcasecmp(physAddress, client_mac) == 0)
            {
                tmp_vendor = strstr(buffer, " ");
                if(tmp_vendor)
                {
                    strtok(tmp_vendor, "\n");
                    tmp_vendor++;
                    strncpy(vendor_class, tmp_vendor, 256);
                    break;
                }
            }
        }
        fclose(fpv);
    }
}
#endif

#define LM_SET_ACTIVE_STATE_TIME(x, y) LM_SET_ACTIVE_STATE_TIME_(__LINE__, x, y)
static void LM_SET_ACTIVE_STATE_TIME_(int line, LmObjectHost *pHost,BOOL state){
        UNREFERENCED_PARAMETER(line);
	char interface[32] = {0};
	int uptime = 0;
	errno_t rc = -1;
    if(pHost->bBoolParaValue[LM_HOST_ActiveId] != state){

        char addressSource[20] = {0};
	char IPAddress[50] = {0};
	memset(addressSource,0,sizeof(addressSource));
	memset(IPAddress,0,sizeof(IPAddress));
	memset(interface,0,sizeof(interface));
    if ( ! pHost->pStringParaValue[LM_HOST_IPAddressId] )
    {
        getIPAddress(pHost->pStringParaValue[LM_HOST_PhysAddressId], IPAddress);
        LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_IPAddressId]) , IPAddress);
    }
/*
		getAddressSource(pHost->pStringParaValue[LM_HOST_PhysAddressId], addressSource);
		if ( (pHost->pStringParaValue[LM_HOST_AddressSource]) && (strlen(addressSource)))	
		{
   		       LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_AddressSource]) , addressSource);
		}
*/
	if(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] != NULL)
	{
		if((strstr(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],"WiFi"))) 
		{
			if(state) 
			{
				if(pHost->ipv4Active == TRUE)
				{
				CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is WiFi, MacAddress is %s and HostName is %s appeared online\n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]));
				OnboardLog("RDKB_CONNECTED_CLIENTS: Client type is WiFi, MacAddress is %s and HostName is %s appeared online\n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]);

				CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: IP Address : %s , address source : %s, HostName : %s \n",pHost->pStringParaValue[LM_HOST_IPAddressId],pHost->pStringParaValue[LM_HOST_AddressSource],pHost->pStringParaValue[LM_HOST_HostNameId]));
				}
			}  
			else 
			{
				if(pHost->ipv4Active == TRUE)
				{
				CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Wifi client with %s MacAddress and %s HostName gone offline\n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]));
				OnboardLog("RDKB_CONNECTED_CLIENTS: Wifi client with %s MacAddress and %s HostName gone offline\n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]);
				t2_event_d("WIFI_INFO_clientdisconnect", 1);
				}
#ifndef USE_NOTIFY_COMPONENT
				remove_Mac_to_band_mapping(pHost->pStringParaValue[LM_HOST_PhysAddressId]);
#endif
			}
			rc = strcpy_s(interface, sizeof(interface),"WiFi");
			ERR_CHK(rc);
		}
#if !defined (NO_MOCA_FEATURE_SUPPORT)
		else if ((strstr(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],"MoCA")))
		{
			if(pHost->ipv4Active == TRUE)
			{
				  if(state) {
					CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is MoCA, MacAddress is %s and HostName is %s appeared online \n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]));
					OnboardLog("RDKB_CONNECTED_CLIENTS: Client type is MoCA, MacAddress is %s and HostName is %s appeared online \n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]);
					CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: IP Address : %s , address source : %s, HostName : %s \n",pHost->pStringParaValue[LM_HOST_IPAddressId],pHost->pStringParaValue[LM_HOST_AddressSource],pHost->pStringParaValue[LM_HOST_HostNameId]));
				}  else {
					CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: MoCA client with %s MacAddress and HostName is %s gone offline \n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]));
					OnboardLog("RDKB_CONNECTED_CLIENTS: MoCA client with %s MacAddress and HostName is %s gone offline \n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]);

				}
			}
			rc = strcpy_s(interface, sizeof(interface),"MoCA");
			ERR_CHK(rc);
		}
#endif
		else if ((strstr(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],"Ethernet")))
		{
			if(pHost->ipv4Active == TRUE)
			{
				  if(state) {
					CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is Ethernet, MacAddress is %s and HostName is %s appeared online \n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]));
					OnboardLog("RDKB_CONNECTED_CLIENTS: Client type is Ethernet, MacAddress is %s and HostName is %s appeared online \n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]);
					CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: IP Address : %s , address source : %s, HostName : %s \n",pHost->pStringParaValue[LM_HOST_IPAddressId],pHost->pStringParaValue[LM_HOST_AddressSource],pHost->pStringParaValue[LM_HOST_HostNameId]));
				}  else {
					CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Ethernet client with %s MacAddress and %s HostName gone offline \n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]));
					OnboardLog("RDKB_CONNECTED_CLIENTS: Ethernet client with %s MacAddress and %s HostName gone offline \n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]);
				}
			}
			rc = strcpy_s(interface, sizeof(interface),"Ethernet");
			ERR_CHK(rc);
		}

		else 
		{
		      if(state) {
				CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is %s , MacAddress is %s and HostName is %s appeared online \n",pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]));
				OnboardLog("RDKB_CONNECTED_CLIENTS: Client type is %s , MacAddress is %s and HostName is %s appeared online \n",pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]);
				CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: IP Address : %s , address source : %s, HostName : %s \n",pHost->pStringParaValue[LM_HOST_IPAddressId],pHost->pStringParaValue[LM_HOST_AddressSource],pHost->pStringParaValue[LM_HOST_HostNameId]));
			}  else {
				CcspTraceWarning(("RDKB_CONNECTED_CLIENTS:  client with %s MacAddress and %s HostName gone offline \n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]));
				OnboardLog("RDKB_CONNECTED_CLIENTS:  client with %s MacAddress and %s HostName gone offline \n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]);
			}
			rc = strcpy_s(interface, sizeof(interface),"Other");
			ERR_CHK(rc);
		}

        if(pHost->ipv4Active == TRUE) {
            if (state) {
                if(0 == FindHostInLeases(pHost->pStringParaValue[LM_HOST_IPAddressId], DNS_LEASE)){
                    char lan_ip_address[32] = {0};
                    char lan_net_mask[32] = {0};

                    syscfg_get( NULL, "lan_ipaddr", lan_ip_address, sizeof(lan_ip_address));
                    syscfg_get( NULL, "lan_netmask", lan_net_mask, sizeof(lan_net_mask));
                    
                    if(!lm_wrap_checkIPv4AddressInRange(lan_ip_address, pHost->pStringParaValue[LM_HOST_IPAddressId], lan_net_mask))
                    {
                        CcspTraceWarning(("<%s> IPAddress out of range : IPAddress = %s, MAC Addr = %s \n",__FUNCTION__, pHost->pStringParaValue[LM_HOST_IPAddressId], pHost->pStringParaValue[LM_HOST_PhysAddressId]));
                        t2_event_d("SYS_ERROR_IPAOR", 1);
                    }
                }
                else {
                    CcspTraceWarning(("<%s> IPAddress not found in lease file : IPAddress = %s, MAC Addr = %s \n",__FUNCTION__, pHost->pStringParaValue[LM_HOST_IPAddressId], pHost->pStringParaValue[LM_HOST_PhysAddressId]));
                }
            }
        }
        pHost->bBoolParaValue[LM_HOST_ActiveId] = state;
        pHost->activityChangeTime = time((time_t*)NULL);
		logOnlineDevicesCount();

	}
	PRINTD("%d: mac %s, state %d time %d\n",line ,pHost->pStringParaValue[LM_HOST_PhysAddressId], state, pHost->activityChangeTime);
    }
	#ifdef USE_NOTIFY_COMPONENT
	if(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] != NULL)
	{
		if((strstr(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],"WiFi"))) {
			rc = strcpy_s(interface, sizeof(interface),"WiFi");
			ERR_CHK(rc);
		}
#if !defined (NO_MOCA_FEATURE_SUPPORT)
		else if ((strstr(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],"MoCA")))
		{
			rc = strcpy_s(interface, sizeof(interface),"MoCA");
			ERR_CHK(rc);
		}
#endif
		else if ((strstr(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],"Ethernet")))
		{
			rc = strcpy_s(interface, sizeof(interface),"Ethernet");
			ERR_CHK(rc);
		}
		else
		{
			rc = strcpy_s(interface, sizeof(interface),"Other");
			ERR_CHK(rc);
		}
	
		if(state == FALSE)
		{
			
            #if 0
            if(FindHostInLeases(pHost->pStringParaValue[LM_HOST_PhysAddressId], DNS_LEASE))
            {

                if(pHost->ipv4Active == TRUE)
                {
                    if(pHost->bNotify == TRUE)
                    {
                        CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is %s, MacAddress is %s Disconnected \n",interface,pHost->pStringParaValue[LM_HOST_PhysAddressId]));
                        lmHosts.lastActivity++;
                        Send_Notification(interface, pHost->pStringParaValue[LM_HOST_PhysAddressId], CLINET_STATE_DISCONNECT, pHost->pStringParaValue[LM_HOST_HostNameId]);
                        char buf[12] = {0};
                        snprintf(buf,sizeof(buf)-1,"%lu",lmHosts.lastActivity);
                        pHost->ipv4Active = FALSE;
                        if (syscfg_set(NULL, "X_RDKCENTRAL-COM_HostVersionId", buf) != 0)
                        {
                            AnscTraceWarning(("syscfg_set failed\n"));
                        }
                        else
                        {
                            if (syscfg_commit() != 0)
                            {
                                AnscTraceWarning(("syscfg_commit failed\n"));
                            }

                        }
                        pHost->bNotify = FALSE;

                    }
                }

            }
            #endif

			#if defined(FEATURE_SUPPORT_MESH)
            // We are going to send offline notifications to mesh when clients go offline.
            if(pHost->bNotify == TRUE)
            {
                //CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is %s, MacAddress is %s Offline \n",interface,pHost->pStringParaValue[LM_HOST_PhysAddressId]));
                Send_Notification(interface, pHost->pStringParaValue[LM_HOST_PhysAddressId], CLIENT_STATE_OFFLINE, pHost->pStringParaValue[LM_HOST_HostNameId]);
            }
			#endif
		}
		else
		{
			
			{
				if(pHost->bNotify == FALSE)
				{
				   if(access("/tmp/.conn_cli_flag", F_OK) != 0)
				   {
					/* CID :257716 Resource leak */
					int fd;
					/* CID 257720 Time of check time of use */
					if ((fd = open("/tmp/.conn_cli_flag", O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH | O_CLOEXEC)) >= 0)
                                        {
                                            close(fd);
                                        }
					get_uptime(&uptime);
                  			CcspTraceWarning(("Client_Connect_complete:%d\n",uptime));	
					OnboardLog("Client_Connect_complete:%d\n",uptime);
					t2_event_d("btime_clientconn_split", uptime);
				   }
					CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is %s, MacAddress is %s and HostName is %s Connected  \n",interface,pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]));
					lmHosts.lastActivity++;
					pHost->bClientReady = TRUE;
                    if(pHost->pStringParaValue[LM_HOST_HostNameId])
					{

						if(0 == strcmp(pHost->pStringParaValue[LM_HOST_HostNameId],pHost->pStringParaValue[LM_HOST_PhysAddressId]))
						{
							char HostName[50];
							if (get_HostName(pHost->pStringParaValue[LM_HOST_PhysAddressId],HostName,sizeof(HostName)) == 1)
								LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_HostNameId]), HostName);

							CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is %s, MacAddress is %s and HostName is %s Connected \n",interface,pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]));
						}
					}
					//CcspTraceWarning(("RDKB_CONNECTED_CLIENTS:  %s pHost->bClientReady = %d \n",interface,pHost->bClientReady));
					Send_Notification(interface, pHost->pStringParaValue[LM_HOST_PhysAddressId], CLIENT_STATE_CONNECT, pHost->pStringParaValue[LM_HOST_HostNameId]);
					if (syscfg_set_u_commit(NULL, "X_RDKCENTRAL-COM_HostVersionId", lmHosts.lastActivity) != 0)
					{
						AnscTraceWarning(("syscfg_set failed\n"));
					}
					pHost->bNotify = TRUE;
				}
				else
				{
				    // This case is for "Online" events after we have send a connection message. WebPA apparently only wants a
				    // single connect request and no online/offline events.
                    //CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is %s, MacAddress is %s and HostName is %s Online  \n",interface,pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_HostNameId]));
                    Send_Notification(interface, pHost->pStringParaValue[LM_HOST_PhysAddressId], CLIENT_STATE_ONLINE, pHost->pStringParaValue[LM_HOST_HostNameId]);
                }
			}
			
		}
	}
#endif
} 

#define LM_SET_PSTRINGPARAVALUE(var, val) if((var)) AnscFreeMemory(var);var = AnscCloneString(val);

/***********************************************************************

 APIs for Object:

    Hosts.

    *  Hosts_Init
    *  Hosts_SavePsmValueRecord

***********************************************************************/
static void _getLanHostComments(char *physAddress, char *pComments)
{
    lm_wrapper_priv_getLanHostComments(physAddress, pComments);
}

static inline BOOL _isIPv6Addr(const char* ipAddr)
{
    if(strchr(ipAddr, ':') != NULL)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

#if 0
static void Hosts_FindHostByIPv4Address
(
    const char *ipv4Addr,
    char hostList[],
    int *hostListSize,
    void * userData,
    enum DeviceType userDataType
)
{
    if(!ipv4Addr) return;
    int i, j, firstOne = 1;
    for(i=0; i<lmHosts.numHost; i++)
    {
        for(j=0; j<lmHosts.hostArray[i]->numIPv4Addr; j++)
        {
            if (strcasecmp(ipv4Addr, lmHosts.hostArray[i]->ipv4AddrArray[j]->pStringParaValue[LM_HOST_IPAddress_IPAddressId]) == 0)
            {
                if(!firstOne){
                    strcat(hostList, ",");
                    *hostListSize--;
                }
                else firstOne = 0;
                size_t len = strlen(lmHosts.hostArray[i]->objectName);
                if(*hostListSize < len) return;
                strcat(hostList, lmHosts.hostArray[i]->objectName);
                *hostListSize -= len;
                Host_SetExtensionParameters(lmHosts.hostArray[i], userData, userDataType);
                break;
            }
        }
    }
}
#endif

static void Hosts_FreeHost (PLmObjectHost pHost)
{
    int i;
    if(pHost == NULL)
        return;
    pHost->bBoolParaValue[LM_HOST_PresenceActiveId] = FALSE;
    if (pHost->bBoolParaValue[LM_HOST_PresenceNotificationEnabledId])
    {
        pHost->bBoolParaValue[LM_HOST_PresenceNotificationEnabledId] = FALSE;
        Hosts_UpdateDeviceIntoPresenceDetection(pHost,FALSE, FALSE);
    }
    for(i=0; i<LM_HOST_NumStringPara; i++)
    {
        if(NULL != pHost->pStringParaValue[i])
            AnscFreeMemory(pHost->pStringParaValue[i]);
        pHost->pStringParaValue[i] = NULL;
    }
    if(pHost->objectName != NULL)
        AnscFreeMemory(pHost->objectName);
    if(pHost->Layer3Interface != NULL)
        AnscFreeMemory(pHost->Layer3Interface);

    pHost->objectName = NULL;
    pHost->Layer3Interface = NULL;
    Host_FreeIPAddress(pHost, 4);
    Host_FreeIPAddress(pHost, 6);

    AnscFreeMemory(pHost);
    pHost = NULL;

    lmHosts.numHost--;
    lmHosts.availableInstanceNum--;
}

static void Hosts_RmHosts (void)
{
    int i;

    if(lmHosts.numHost == 0)
        return;

    for(i = 0; i < lmHosts.numHost; i++){
        Hosts_FreeHost(lmHosts.hostArray[i]);
        lmHosts.hostArray[i] = NULL;
    }
    AnscFreeMemory(lmHosts.hostArray);
    lmHosts.availableInstanceNum = 1;
    lmHosts.hostArray = NULL;
    lmHosts.numHost = 0;
    lmHosts.sizeHost = 0;
    lmHosts.lastActivity++;

	if (syscfg_set_u_commit(NULL, "X_RDKCENTRAL-COM_HostVersionId", lmHosts.lastActivity) != 0)
		{
			AnscTraceWarning(("syscfg_set failed\n"));
		}

    return;
}

#if !defined (RESOURCE_OPTIMIZATION)
static PLmObjectHost XHosts_AddHost (int instanceNum)
{
    //printf("in XHosts_AddHost %d \n", instanceNum);
    PLmObjectHost pHost = AnscAllocateMemory(sizeof(LmObjectHost));
    if(pHost == NULL)
    {
        return NULL;
    }
    pHost->instanceNum = instanceNum;
    /* Compose Host object name. */
    char objectName[100] = LM_HOST_OBJECT_NAME_HEADER;
    char instanceNumStr[50] = {0};
    errno_t rc              = -1;
    _ansc_itoa(pHost->instanceNum, instanceNumStr, 10);
    rc = strcat_s(instanceNumStr, sizeof(instanceNumStr),".");
    if(rc != EOK)
    {
       ERR_CHK(rc);
       AnscFreeMemory(pHost);
       return NULL;
    }
    rc = strcat_s(objectName, sizeof(objectName),instanceNumStr);
    if(rc != EOK)
    {
        ERR_CHK(rc);
        AnscFreeMemory(pHost);
        return NULL;
    }
    pHost->objectName = AnscCloneString(objectName);

    pHost->ipv4AddrArray = NULL;
    pHost->numIPv4Addr = 0;
    pHost->ipv6AddrArray = NULL;
    pHost->numIPv6Addr = 0;
	pHost->pStringParaValue[LM_HOST_IPAddressId] = NULL;
    /* Default it is inactive. */
    pHost->bBoolParaValue[LM_HOST_ActiveId] = FALSE;
    pHost->ipv4Active = FALSE;
    pHost->ipv6Active = FALSE;
    pHost->activityChangeTime  = time(NULL);
    pHost->iIntParaValue[LM_HOST_X_CISCO_COM_ActiveTimeId] = -1;
    pHost->iIntParaValue[LM_HOST_X_CISCO_COM_RSSIId] = -200;

	pHost->Layer3Interface = NULL;

	memset(pHost->backupHostname,0,64);
    int i;
    for(i=0; i<LM_HOST_NumStringPara; i++) pHost->pStringParaValue[i] = NULL;

    if(XlmHosts.numHost >= XlmHosts.sizeHost){
        XlmHosts.sizeHost += LM_HOST_ARRAY_STEP;
        PLmObjectHost *newArray = AnscAllocateMemory(XlmHosts.sizeHost * sizeof(PLmObjectHost));
        for(i=0; i<XlmHosts.numHost; i++){
            newArray[i] = XlmHosts.hostArray[i];
        }
        PLmObjectHost *backupArray = XlmHosts.hostArray;
        XlmHosts.hostArray = newArray;
        if(backupArray) AnscFreeMemory(backupArray);
    }
    pHost->id = XlmHosts.numHost;
    XlmHosts.hostArray[pHost->id] = pHost;
    XlmHosts.numHost++;
    return pHost;
}
#endif

static void Clean_Host_Table (void)
{

    if(lmHosts.numHost < HOST_ENTRY_LIMIT)
        return;

    time_t currentTime = time(NULL);
    int count,count1,total_count = lmHosts.numHost;
    for(count=0 ; count < total_count; count++)
    {
        PLmObjectHost pHost = lmHosts.hostArray[count];

        if((pHost->bBoolParaValue[LM_HOST_ActiveId] == FALSE) &&
            (strcmp(pHost->pStringParaValue[LM_HOST_AddressSource], "DHCP") == 0) &&
            ((pHost->LeaseTime == 0xFFFFFFFF) || (currentTime >= (time_t)pHost->LeaseTime)))
        {
            CcspTraceWarning((" Freeing Host %s \n",pHost->pStringParaValue[LM_HOST_PhysAddressId]));
            Hosts_FreeHost(pHost);
            lmHosts.hostArray[count] = NULL;
        }
    }

    for(count=0 ; count < total_count; count++)
    {
        if(lmHosts.hostArray[count]) continue;
        for(count1=count+1; count1 < total_count; count1++)
        {
            if(lmHosts.hostArray[count1]) break;
        }
        if(count1 >= total_count) break;
        lmHosts.hostArray[count] = lmHosts.hostArray[count1];
        lmHosts.hostArray[count]->instanceNum = count+1;
        lmHosts.hostArray[count1] = NULL;
    }
}

static PLmObjectHost Hosts_AddHost (int instanceNum)
{
        UNREFERENCED_PARAMETER(instanceNum);
	Clean_Host_Table();

	if(lmHosts.numHost < HOST_OBJECT_SIZE)/* RDKB-23038, max client support to 200 */
	{	
	    //printf("in Hosts_AddHost %d \n", instanceNum);
	    PLmObjectHost pHost = AnscAllocateMemory(sizeof(LmObjectHost));
	    if(pHost == NULL)
	    {
	        return NULL;
	    }
	    pHost->instanceNum = lmHosts.availableInstanceNum;
	    //pHost->instanceNum = instanceNum;
	    /* Compose Host object name. */
	    char objectName[100] = LM_HOST_OBJECT_NAME_HEADER;
	    char instanceNumStr[50] = {0};
	    errno_t rc = -1;
	    _ansc_itoa(pHost->instanceNum, instanceNumStr, 10);
	    rc = strcat_s(instanceNumStr, sizeof(instanceNumStr),".");
	    if(rc != EOK)
	    {
	       ERR_CHK(rc);
	       AnscFreeMemory(pHost);
	       return NULL;
	    }
	    rc = strcat_s(objectName, sizeof(objectName),instanceNumStr);
	    if(rc != EOK)
	    {
	       ERR_CHK(rc);
	       AnscFreeMemory(pHost);
	       return NULL;
	    }

	    pHost->objectName = AnscCloneString(objectName);

	    pHost->l3unReachableCnt = 0;
	    pHost->l1unReachableCnt = 0;
	    pHost->ipv4AddrArray = NULL;
	    pHost->numIPv4Addr = 0;
	    pHost->ipv6AddrArray = NULL;
	    pHost->numIPv6Addr = 0;
		pHost->pStringParaValue[LM_HOST_IPAddressId] = NULL;
	    /* Default it is inactive. */
	    pHost->bBoolParaValue[LM_HOST_ActiveId] = FALSE;
	    pHost->ipv4Active = FALSE;
	    pHost->ipv6Active = FALSE;
	    pHost->activityChangeTime  = time(NULL);
	    pHost->iIntParaValue[LM_HOST_X_CISCO_COM_ActiveTimeId] = -1;
	    pHost->iIntParaValue[LM_HOST_X_CISCO_COM_RSSIId] = -200;

		pHost->Layer3Interface = NULL;
    pHost->bBoolParaValue[LM_HOST_PresenceActiveId] = FALSE;

		memset(pHost->backupHostname,0,64);
	    int i;
	    for(i=0; i<LM_HOST_NumStringPara; i++) pHost->pStringParaValue[i] = NULL;
	    if(lmHosts.numHost >= lmHosts.sizeHost){
	        lmHosts.sizeHost += LM_HOST_ARRAY_STEP;
	        PLmObjectHost *newArray = AnscAllocateMemory(lmHosts.sizeHost * sizeof(PLmObjectHost));
	        for(i=0; i<lmHosts.numHost; i++){
	            newArray[i] = lmHosts.hostArray[i];
	        }
	        PLmObjectHost *backupArray = lmHosts.hostArray;
	        lmHosts.hostArray = newArray;
	        if(backupArray) AnscFreeMemory(backupArray);
	    }
	    pHost->id = lmHosts.numHost;
	    lmHosts.hostArray[pHost->id] = pHost;
	    lmHosts.numHost++;
	    return pHost;
	}
	else
	{
		CcspTraceWarning((" [%s][%d] MAX Host reach to %d \n",__FUNCTION__,__LINE__,lmHosts.numHost));
	}
	return NULL;
}

static void Host_SetIPAddress (PLmObjectHostIPAddress pIP, int l3unReachableCnt, char *source)
{
    pIP->l3unReachableCnt = l3unReachableCnt;
    LM_SET_PSTRINGPARAVALUE(pIP->pStringParaValue[LM_HOST_IPAddress_IPAddressSourceId], source);
}

void addHostsToPresenceTable(void)
{
    for (int iVar = 0; iVar < lmHosts.numHost; iVar++)
    {
        if (lmHosts.hostArray[iVar] && lmHosts.hostArray[iVar]->pStringParaValue[LM_HOST_PhysAddressId])
        {
            lmHosts.hostArray[iVar]->bBoolParaValue[LM_HOST_PresenceActiveId] = FALSE;
            lmHosts.hostArray[iVar]->bBoolParaValue[LM_HOST_PresenceNotificationEnabledId] = TRUE;
            Hosts_UpdateDeviceIntoPresenceDetection(lmHosts.hostArray[iVar], FALSE, FALSE);
        }
    }
}

/* Acuquire the both LmHostObjectMutex and PresenceDetectionMutex locks */
void acquirePresencelocks(void)
{
    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock (&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock (&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
}

/* unlock the both LmHostObjectMutex and PresenceDetectionMutex locks */
void releasePresenceLocks(void)
{
    pthread_mutex_unlock (&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_unlock (&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
}

PLmObjectHost Hosts_FindHostByPhysAddress (char * physAddress)
{
    int i;

    for (i = 0; i < lmHosts.numHost; i++) {
        if (lmHosts.hostArray[i] && lmHosts.hostArray[i]->pStringParaValue[LM_HOST_PhysAddressId]) {
            if (strcasecmp(lmHosts.hostArray[i]->pStringParaValue[LM_HOST_PhysAddressId], physAddress) == 0) {
                return lmHosts.hostArray[i];
            }
        }
    }

    return NULL;
}

#if !defined (RESOURCE_OPTIMIZATION)
PLmObjectHost XHosts_FindHostByPhysAddress (char * physAddress)
{
    int i;

    for (i = 0; i < XlmHosts.numHost; i++) {
        if (XlmHosts.hostArray[i] && XlmHosts.hostArray[i]->pStringParaValue[LM_HOST_PhysAddressId]) {
            if (strcasecmp(XlmHosts.hostArray[i]->pStringParaValue[LM_HOST_PhysAddressId], physAddress) == 0) {
                return XlmHosts.hostArray[i];
            }
        }
    }

    return NULL;
}
#endif

#define MACADDR_SZ      18
#define ATOM_MAC        "00:00:ca:01:02:03"
#define ATOM_MAC_CSC    "00:05:04:03:02:01"

static int validate_mac (char *physAddress)
{
    int i;

    for (i = 0; i < 6; i++)
    {
        if ((isxdigit(physAddress[0])) &&
            (isxdigit(physAddress[1])) &&
            (physAddress[2] == ((i == 5) ? 0 : ':')))
        {
            physAddress += 3;
        }
        else
        {
            return -1;
        }
    }

    return 0;
}

#if !defined (RESOURCE_OPTIMIZATION)
static PLmObjectHost XHosts_AddHostByPhysAddress (char *physAddress)
{
    char comments[256];

    if (!physAddress || (validate_mac(physAddress) != 0))
    {
        CcspTraceWarning(("RDKB_CONNECTED_CLIENT: Invalid MacAddress ignored\n"));
        return NULL;
    }

    if ((strlen(physAddress) != (MACADDR_SZ - 1)) ||
        (memcmp(physAddress, "00:00:00:00:00:00", MACADDR_SZ) == 0))
    {
        return NULL;
    }

    PLmObjectHost pHost = XHosts_FindHostByPhysAddress(physAddress);
    if (pHost)
        return pHost;

    pHost = XHosts_AddHost(XlmHosts.availableInstanceNum);

    if (pHost)
    {
        pHost->pStringParaValue[LM_HOST_PhysAddressId] = AnscCloneString(physAddress);
        pHost->pStringParaValue[LM_HOST_HostNameId] = AnscCloneString(physAddress);

        comments[0] = 0;
        _getLanHostComments(physAddress, comments);
        if ( comments[0] != 0 )
        {
            pHost->pStringParaValue[LM_HOST_Comments] = AnscCloneString(comments);
        }

        pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] = AnscCloneString("Device.WiFi.SSID.3");
        pHost->pStringParaValue[LM_HOST_AddressSource] = AnscCloneString("DHCP");
        pHost->bClientReady = FALSE;
        //CcspTraceWarning(("RDKB_CONNECTED_CLIENT: pHost->bClientReady = %d \n",pHost->bClientReady));
        XlmHosts.availableInstanceNum++;
    }

    CcspTraceWarning(("New XHS host added sucessfully\n"));

    return pHost;
}
#endif

PLmObjectHost Hosts_AddHostByPhysAddress(char *physAddress)
{
    char comments[256];
    static BOOL bPresenceDetectEnable = FALSE;
    static BOOL bReadFromSyscfg = FALSE;
#ifdef VENDOR_CLASS_ID
    char vendor_class[256] = {0};
    char vendor_retry_count = 0;
#endif
    if (!physAddress || (validate_mac(physAddress) != 0))
    {
        CcspTraceWarning(("RDKB_CONNECTED_CLIENT: Invalid MacAddress ignored\n"));
        return NULL;
    }

    if ((strlen(physAddress) != (MACADDR_SZ - 1)) ||
        (memcmp(physAddress, "00:00:00:00:00:00", MACADDR_SZ) == 0))
    {
        return NULL;
    }

    PLmObjectHost pHost = Hosts_FindHostByPhysAddress(physAddress);
    if (pHost)
        return pHost;

    if ((strcasecmp(physAddress, ATOM_MAC) == 0) ||
        (strcasecmp(physAddress, ATOM_MAC_CSC) == 0))
    {
        //CcspTraceWarning(("RDKB_CONNECTED_CLIENT: ATOM_MAC = %s ignored\n",physAddress));
        return NULL;
    }

    pHost = Hosts_AddHost(lmHosts.availableInstanceNum);

    if (pHost)
    {
        pHost->pStringParaValue[LM_HOST_PhysAddressId] = AnscCloneString(physAddress);
        pHost->pStringParaValue[LM_HOST_HostNameId] = AnscCloneString(physAddress);

        comments[0] = 0;
        _getLanHostComments(physAddress, comments);
        if ( comments[0] != 0 )
        {
            pHost->pStringParaValue[LM_HOST_Comments] = AnscCloneString(comments);
        }
        pHost->bBoolParaValue[LM_HOST_PresenceNotificationEnabledId] = FALSE;
        if (FALSE == bReadFromSyscfg)
        {
            readPresenceFromSyscfg (&bPresenceDetectEnable);
            bReadFromSyscfg = TRUE;
        }
        if (TRUE == lmHosts.enablePresence)
        {
            bPresenceDetectEnable = TRUE;
        }
        if (TRUE == bPresenceDetectEnable)
        {
            BOOL bConfiguredMacListIsSet = FALSE;
            getConfiguredMaclistStatus (&bConfiguredMacListIsSet);
            if (TRUE == bConfiguredMacListIsSet)
            {
                pHost->bBoolParaValue[LM_HOST_PresenceNotificationEnabledId] = Hosts_GetPresenceNotificationEnableStatus(physAddress);
            }
            else
            {
                pHost->bBoolParaValue[LM_HOST_PresenceNotificationEnabledId] = TRUE;
            }
            CcspTraceWarning (("[%s][%d] PresenceNotificationEnabledId = %s \n",__FUNCTION__,__LINE__,pHost->bBoolParaValue[LM_HOST_PresenceNotificationEnabledId] ? "TRUE" : "FALSE"));
        }
/* #ifdef USE_NOTIFY_COMPONENT
        if(bWifiHost)
        {
            char ssid[LM_GEN_STR_SIZE] = {0};

            if(SearchWiFiClients(physAddress,ssid))
            {
                pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] = AnscCloneString(ssid);
                bWifiHost = FALSE;
            }
            else
            {
                pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] = AnscCloneString("Ethernet");
            }

        }
        else
#endif
*/
        if ((strncasecmp (physAddress, "60:b4:f7:", 9) == 0) ||
            (strncasecmp (physAddress, "58:90:43:", 9) == 0) ||
            (strncasecmp (physAddress, "b8:ee:0e:", 9) == 0) ||
            (strncasecmp (physAddress, "b8:d9:4d:", 9) == 0))
        {
            pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] = AnscCloneString("Mesh");
        }
        else
        {
            pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] = AnscCloneString("Ethernet");
        }

        pHost->pStringParaValue[LM_HOST_AddressSource] = AnscCloneString("DHCP");
        pHost->bClientReady = FALSE;
#ifdef VENDOR_CLASS_ID
        while (vendor_retry_count < 5 )
        {
            get_vendor_class_id(physAddress, vendor_class);
            if(strlen(vendor_class) != 0)
               break;
            vendor_retry_count++;
            CcspTraceWarning(("Retry(%d) to fetch VendorClass ID with MAC = %s\n", vendor_retry_count, pHost->pStringParaValue[LM_HOST_PhysAddressId]));
            sleep(1);
        }
// for clients not advertising valid vendor class, we will have space character in the vendor class buffer from dnsmasq side
// so check if its valid vendor class then only write into param
        if(strncmp(vendor_class," ",sizeof(vendor_class)) != 0)
        {
            LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_VendorClassID]), vendor_class);
            CcspTraceInfo(("Connected Mac = %s with vendor class id = %s\n", pHost->pStringParaValue[LM_HOST_PhysAddressId], pHost->pStringParaValue[LM_HOST_VendorClassID]));
		}
        if(vendor_class[0] != '\0')
        {
            CcspTraceWarning(("RDKB_CONNECTED_CLIENT: Connected Mac = %s, vendor class id = %s\n", pHost->pStringParaValue[LM_HOST_PhysAddressId], pHost->pStringParaValue[LM_HOST_VendorClassID]));
        }
        else
        {
            CcspTraceWarning(("RDKB_CONNECTED_CLIENT: Connected Mac = %s, has no vendor class id\n", pHost->pStringParaValue[LM_HOST_PhysAddressId]));
        }
#endif
        //CcspTraceWarning(("RDKB_CONNECTED_CLIENT: pHost->bClientReady = %d \n",pHost->bClientReady));
        lmHosts.availableInstanceNum++;

#ifdef USE_NOTIFY_COMPONENT
        CcspTraceWarning(("LMlite-CLIENT <%s> <%d> : Connected Mac = %s \n",__FUNCTION__,__LINE__ ,pHost->pStringParaValue[LM_HOST_PhysAddressId]));
        pHost->bNotify = FALSE;
#endif
    }

    return pHost;
}

static void Host_FreeIPAddress(PLmObjectHost pHost, int version)
{
    int *num;
    PLmObjectHostIPAddress pIpAddrList, pCur, *ppHeader;

    if(version == 4){
        num = &(pHost->numIPv4Addr);
        pIpAddrList = pHost->ipv4AddrArray;
        ppHeader = &(pHost->ipv4AddrArray);
    }else{
        num = &(pHost->numIPv6Addr);
        pIpAddrList = pHost->ipv6AddrArray;
        ppHeader = &(pHost->ipv6AddrArray);
    }

    *num = 0;
    while(pIpAddrList != NULL)
    {
        AnscFreeMemory(pIpAddrList->pStringParaValue[LM_HOST_IPAddress_IPAddressId]);
        pCur = pIpAddrList;
        pIpAddrList = pIpAddrList->pNext;
        AnscFreeMemory(pCur); /*RDKB-7348, CID-33198, free current list*/
        pCur = NULL;
        *ppHeader = NULL;
    }
}

static PLmObjectHostIPAddress Add_Update_IPv4Address (PLmObjectHost pHost, char *ipAddress)
{
	int *num;
	PLmObjectHostIPAddress pIpAddrList, pCur, pPre, *ppHeader;

	num = &(pHost->numIPv4Addr);
	pIpAddrList = pHost->ipv4AddrArray;
	ppHeader = &(pHost->ipv4AddrArray);
	pHost->ipv4Active = TRUE;
	pPre = NULL;

   for(pCur = pIpAddrList; pCur != NULL; pPre = pCur, pCur = pCur->pNext){
        if (strcasecmp(pCur->pStringParaValue[LM_HOST_IPAddress_IPAddressId], ipAddress) == 0){
			break;
        }
    }
	if (pCur == NULL){
		pCur = AnscAllocateMemory(sizeof(LmObjectHostIPAddress));
		if(pCur == NULL){
			return NULL;
	}
	pCur->pStringParaValue[LM_HOST_IPAddress_IPAddressId] = AnscCloneString(ipAddress);
        pCur->pNext = *ppHeader;
        *ppHeader = pCur;
        (*num)++;
	pCur->instanceNum = *num;
   }
   else{
     	if(pCur != pIpAddrList)
	{
          pPre->pNext=pCur->pNext;
          pCur->pNext = pIpAddrList;
          *ppHeader = pCur;
        }
    }
    return pCur;
}

static PLmObjectHostIPAddress Add_Update_IPv6Address (PLmObjectHost pHost, char * ipAddress, int dibbler_flag)
{
	int i, *num;
	PLmObjectHostIPAddress pIpAddrList, pCur, *ppHeader, prev, temp;
	num = &(pHost->numIPv6Addr);
	pIpAddrList = pHost->ipv6AddrArray;
	ppHeader = &(pHost->ipv6AddrArray);
	pHost->ipv6Active = TRUE;

	if(*ppHeader==NULL)
	{
		prev=NULL;
		/*List is Empty, Allocate Memory*/

		for(i=0;i<3;i++)
		{
			temp=AnscAllocateMemory(sizeof(LmObjectHostIPAddress));
			if(temp == NULL)
			{
				return NULL;
			}
			else
			{
				//temp->pStringParaValue[LM_HOST_IPAddress_IPAddressId] = AnscCloneString("EMPTY");
				temp->pStringParaValue[LM_HOST_IPAddress_IPAddressId] = AnscCloneString(" "); // fix for RDKB-19836
				(*num)++;
				temp->instanceNum = *num;
				temp->pNext=prev;
				pIpAddrList=temp;
				*ppHeader=temp;
				prev=temp;
			}
		}
	}
	if(dibbler_flag==0)
	{
		if(strncmp(ipAddress,"fe80:",5)==0)
		{
			pCur=pIpAddrList->pNext;
		}
		else
		{
			pCur=pIpAddrList->pNext->pNext;
		}
	}
	else
	{
		pCur=pIpAddrList;
	}
	LanManager_CheckCloneCopy(&(pCur->pStringParaValue[LM_HOST_IPAddress_IPAddressId]), ipAddress);
	return pCur;
}

static int extract (char *line, char *mac, char *ip)
{
	int pivot=0,mac_start=0,flag=-1;
        unsigned int i;
	mac[0] = 0;
	if((strstr(line,"<entry") == NULL) || (strstr(line,"</entry>") == NULL))
	{
		//CcspTraceWarning(("Invalid dibbler entry : %s\n",line));
		return 1;
	}

	for (i=0;i<(strlen(line));i++)
	{
		if(line[i]=='>')
		{
			pivot=i+1;
			mac_start=pivot-19;
			if (0 <= mac_start)
			{
				flag = 0;
				break;
			}
			return 1;
		}
	}

	if (-1 == flag) {
		return 1;
	}

	for(i=0;((flag==0)||(i<=17));i++)
	{
		if((line[pivot+i]!='<')&&(flag==0))
		{
			ip[i]=line[pivot+i];
		}
		if(line[pivot+i]=='<')
		{
			ip[i]='\0';
			flag=1;
		}
		if(i<17)
		{
			mac[i]=line[mac_start+i];
		}
		if(i==17)
		{
			mac[i]='\0';
		}
	}
	return 0;
}

static void Add_IPv6_from_Dibbler (void)
{
	FILE *fptr = NULL;
	char line[256]={0},ip[64]={0},mac[18]={0};
	PLmObjectHost	pHost	= NULL;

	if ((fptr=fopen("/etc/dibbler/server-cache.xml","r")) != NULL )
	{
		while ( fgets(line, sizeof(line), fptr) != NULL )
		{
			if(strstr(line,"addr") != NULL)
			{
				if(1 == extract(line,mac,ip))
					continue;
                CcspTraceDebug(("%s:%d, Acquiring presence locks \n",__FUNCTION__,__LINE__));
                acquirePresencelocks();
                CcspTraceDebug(("%s:%d, Acquired presence locks \n",__FUNCTION__,__LINE__));
				/* TCCBR-4621:
				 * - Dont add host from dibbler and
				 *   update only ipv6 address from dibbler cache for the client.
				 */
				pHost = Hosts_FindHostByPhysAddress(mac);
				if(pHost)
				{
					Add_Update_IPv6Address(pHost,ip,DIBBLER_IPv6);
                    Hosts_UpdateDeviceIntoPresenceDetection(pHost, TRUE, FALSE);
				}
                releasePresenceLocks();
                CcspTraceDebug(("%s:%d, released presence locks \n",__FUNCTION__,__LINE__));
			}
		}
		fclose(fptr);
	}
}

PLmObjectHostIPAddress Host_AddIPAddress (PLmObjectHost pHost, char *ipAddress, int version)
{
    PLmObjectHostIPAddress pCur;

	if(!ipAddress)
		return NULL;

    if(version == 4)
	{
		pCur = Add_Update_IPv4Address(pHost,ipAddress);
		LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_IPAddressId]) , ipAddress);
    }
	else
	{
		pCur = Add_Update_IPv6Address(pHost,ipAddress,ARP_IPv6);
    }
    Hosts_UpdateDeviceIntoPresenceDetection(pHost,TRUE, FALSE);
	return pCur;
}

static void _set_comment_ (LM_cmd_comment_t *cmd)
{
    PLmObjectHost pHost;
    char mac[18];
	
    snprintf (mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", cmd->mac[0], cmd->mac[1], cmd->mac[2], cmd->mac[3], cmd->mac[4], cmd->mac[5]);

    /* set comment value into syscfg */
    /* we don't check whether this device is in our LmObject list */

    if (lm_wrapper_priv_set_lan_host_comments(cmd))
		return;

    /* But if this device is in LmObject list, update the comments value */
    
    pHost = Hosts_FindHostByPhysAddress(mac);
    if(pHost){
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
		pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_Comments]), cmd->comment);
		pthread_mutex_unlock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    }
    

}

char *FindMACByIPAddress (char *ip_address)
{
	if (ip_address)
	{
	    int i = 0;
	    for(; i<lmHosts.numHost; i++){
	        if (strcmp(lmHosts.hostArray[i]->pStringParaValue[LM_HOST_IPAddressId], ip_address) == 0){
	            return lmHosts.hostArray[i]->pStringParaValue[LM_HOST_PhysAddressId];
	        }
	    }		
	}

    return NULL;
}

static inline int _mac_string_to_array(char *pStr, unsigned char array[6])
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

PLmObjectHostIPAddress LM_GetIPArr_FromIndex(PLmObjectHost pHost, ULONG nIndex, int version)
{

	PLmObjectHostIPAddress pIpAddrList, pCur = NULL;
	UINT i;

	if(version == IP_V4){
		pIpAddrList = pHost->ipv4AddrArray;
	}else{
		pIpAddrList = pHost->ipv6AddrArray;
	}

	for(pCur = pIpAddrList, i=0; (pCur != NULL) && (i < nIndex); pCur =	pCur->pNext,i++);

	return pCur;
}

int LM_get_online_device (void)
{
    int i;
    int num = 0;
    PLmObjectHostIPAddress pIP4;
#if defined(_HUB4_PRODUCT_REQ_) || defined(_RDKB_GLOBAL_PRODUCT_REQ_)
    PLmObjectHostIPAddress pIP6;
    bool isDeviceHasIPv4;
#endif /*_HUB4_PRODUCT_REQ_ || _RDKB_GLOBAL_PRODUCT_REQ_ */

	if(0 != Hosts_stop_scan()){
        PRINTD("bridge mode\n");
		return num;
    }
	
   // pthread_mutex_lock(&LmHostObjectMutex);
    for(i = 0; i < lmHosts.numHost; i++){
        if(TRUE == lmHosts.hostArray[i]->bBoolParaValue[LM_HOST_ActiveId]){
#if defined(_HUB4_PRODUCT_REQ_) || defined(_RDKB_GLOBAL_PRODUCT_REQ_)
            isDeviceHasIPv4 = FALSE;
#endif /*_HUB4_PRODUCT_REQ_ || _RDKB_GLOBAL_PRODUCT_REQ_ */
            /* Do NOT count TrueStaticIP client */
            for(pIP4 = lmHosts.hostArray[i]->ipv4AddrArray; pIP4 != NULL; pIP4 = pIP4->pNext){
                if ( 0 == strncmp(pIP4->pStringParaValue[LM_HOST_IPAddress_IPAddressId], "192.168", 7) ||
                     0 == strncmp(pIP4->pStringParaValue[LM_HOST_IPAddress_IPAddressId], "10.", 3) ||
                     (	(0 == strncmp(pIP4->pStringParaValue[LM_HOST_IPAddress_IPAddressId], "172.", 4)) && \
                     	(0 != strncmp(pIP4->pStringParaValue[LM_HOST_IPAddress_IPAddressId], "172.16.12", 9) ) ) 
                   )
                {
#if defined(_HUB4_PRODUCT_REQ_) || defined(_RDKB_GLOBAL_PRODUCT_REQ_)
                    isDeviceHasIPv4 = TRUE;
#endif /*_HUB4_PRODUCT_REQ_ || _RDKB_GLOBAL_PRODUCT_REQ_ */
                    num++;
                    break;
                }
            }
/* Device Count is not updated for IPv6 only configured clients.
 * Added code to count IPv6 only configured clients
 * by checking the condition whether device is counted for IPv4 or not.*/
#if defined(_HUB4_PRODUCT_REQ_) || defined(_RDKB_GLOBAL_PRODUCT_REQ_)
            if ( FALSE == isDeviceHasIPv4 ){
                for(pIP6 = lmHosts.hostArray[i]->ipv6AddrArray; pIP6 != NULL; pIP6 = pIP6->pNext){
                    num++;
                    break;
                }
            }
#endif /*_HUB4_PRODUCT_REQ_ || _RDKB_GLOBAL_PRODUCT_REQ_ */
        }
    }
    //pthread_mutex_unlock(&LmHostObjectMutex);
	return num;
}

#if !defined (RESOURCE_OPTIMIZATION)
int XLM_get_online_device (void)
{
	int i;
    int num = 0;
    PLmObjectHostIPAddress pIP4;

	CcspTraceWarning(("Inside %s XlmHosts.numHost = %d\n",__FUNCTION__,XlmHosts.numHost));


	for(i = 0; i < XlmHosts.numHost; i++){
        if(TRUE == XlmHosts.hostArray[i]->bBoolParaValue[LM_HOST_ActiveId]){
            /* Do NOT count TrueStaticIP client */
            /*TODO CID: 70272 Structurally dead code - logic error due to loop in break*/
            for(pIP4 = XlmHosts.hostArray[i]->ipv4AddrArray; pIP4 != NULL; pIP4 = pIP4->pNext){
                if (0 == strncmp(pIP4->pStringParaValue[LM_HOST_IPAddress_IPAddressId], "172.", 4))
                {
                  num++;
                  break;
                }
           }
        }
    }
	return num;
}
#endif

int LMDmlHostsSetHostComment (char *pMac, char *pComment)
{
    int ret;
    unsigned char mac[6];
	LM_cmd_comment_t cmd;
    
    ret = _mac_string_to_array(pMac, mac);
	
    if(ret == 0){
		cmd.cmd = LM_API_CMD_SET_COMMENT;
	    memcpy(cmd.mac, mac, 6);
	    if(pComment == NULL){
	        cmd.comment[0] = '\0';
	    }else{
	        strncpy(cmd.comment, pComment, LM_COMMENTS_LEN -1);
	        cmd.comment[LM_COMMENTS_LEN -1] = '\0';
	    }
        _set_comment_(&cmd);   
    }
    
    return 0;
}

#if 0
PLmObjectHostIPv6Address
Host_AddIPv6Address
    (
        PLmObjectHost pHost,
        int instanceNum,
        char * ipv6Address
    )
{
    /* check if the address has already exist. */
    int i = 0;
    for(i=0; i<pHost->numIPv6Addr; i++){
        /* If IP address already exists, return. */
        if (strcasecmp(pHost->ipv6AddrArray[i]->pStringParaValue[LM_HOST_IPv6Address_IPAddressId], ipv6Address) == 0)
            return pHost->ipv6AddrArray[i];
    }

    for(i=0; i<pHost->numIPv6Addr; i++){
        /* If instance number is occuppied, assign a new instance number. It may not happen in DHCP mode. */
        if(pHost->ipv6AddrArray[i]->instanceNum == instanceNum){
            instanceNum = pHost->availableInstanceNumIPv6Address;
            pHost->availableInstanceNumIPv6Address++;
        }
    }

    PLmObjectHostIPv6Address pIPv6Address = AnscAllocateMemory(sizeof(LmObjectHostIPv6Address));
    pIPv6Address->instanceNum = instanceNum;
    pIPv6Address->pStringParaValue[LM_HOST_IPv6Address_IPAddressId] = AnscCloneString(ipv6Address);
    if(pHost->availableInstanceNumIPv6Address <= pIPv6Address->instanceNum)
        pHost->availableInstanceNumIPv6Address = pIPv6Address->instanceNum + 1;

    if(pHost->numIPv6Addr >= pHost->sizeIPv6Addr){
        pHost->sizeIPv6Addr += LM_HOST_ARRAY_STEP;
        PLmObjectHostIPv6Address *newArray = AnscAllocateMemory(pHost->sizeIPv6Addr * sizeof(PLmObjectHostIPv6Address));
        for(i=0; i<pHost->numIPv6Addr; i++){
            newArray[i] = pHost->ipv6AddrArray[i];
        }
        PLmObjectHostIPv6Address *backupArray = pHost->ipv6AddrArray;
        pHost->ipv6AddrArray = newArray;
        if(backupArray) AnscFreeMemory(backupArray);
    }
    pIPv6Address->id = pHost->numIPv6Addr;
    pHost->ipv6AddrArray[pIPv6Address->id] = pIPv6Address;
    pHost->numIPv6Addr++;
    return pIPv6Address;
}
#endif

#ifdef LM_IPC_SUPPORT

static void _get_host_mediaType(enum LM_MEDIA_TYPE * m_type, char * l1Interfce)
{
    if(l1Interfce == NULL){
        *m_type = LM_MEDIA_TYPE_UNKNOWN;
#if !defined (NO_MOCA_FEATURE_SUPPORT)
    }else if(strstr(l1Interfce, "MoCA")){
        *m_type = LM_MEDIA_TYPE_MOCA;
#endif
    }else if(strstr(l1Interfce, "WiFi")){
        *m_type = LM_MEDIA_TYPE_WIFI;
    }else
        *m_type = LM_MEDIA_TYPE_ETHERNET;
}

static enum LM_ADDR_SOURCE _get_addr_source(char *source)
{
    if(source == NULL)
        return LM_ADDRESS_SOURCE_NONE;

    if(strstr(source,LM_ADDRESS_SOURCE_DHCP_STR)){
        return LM_ADDRESS_SOURCE_DHCP;
    }else if(strstr(source, LM_ADDRESS_SOURCE_STATIC_STR)){
        return LM_ADDRESS_SOURCE_STATIC;
    }else if(strstr(source, LM_ADDRESS_SOURCE_RESERVED_STR)){
        return LM_ADDRESS_SOURCE_RESERVED;
    }else
        return LM_ADDRESS_SOURCE_NONE;
}

static void _get_host_ipaddress(LM_host_t *pDestHost, PLmObjectHost pHost)
{
    int i;   
    PLmObjectHostIPAddress pIpSrc; 
    pDestHost->ipv4AddrAmount = pHost->numIPv4Addr;
    pDestHost->ipv6AddrAmount = pHost->numIPv6Addr;
    LM_ip_addr_t *pIp;
    for(i=0, pIpSrc = pHost->ipv4AddrArray; pIpSrc != NULL && i < LM_MAX_IP_AMOUNT;i++, pIpSrc = pIpSrc->pNext){
        pIp = &(pDestHost->ipv4AddrList[i]);
        if(inet_pton(AF_INET, pIpSrc->pStringParaValue[LM_HOST_IPAddress_IPAddressId],pIp->addr) != 1)
        {
         CcspTraceWarning(("Invalid IP Address %s\n",pIpSrc->pStringParaValue[LM_HOST_IPAddress_IPAddressId]));
         continue;
        }
        pIp->addrSource = _get_addr_source(pIpSrc->pStringParaValue[LM_HOST_IPAddress_IPAddressSourceId]);
        pIp->priFlg = pIpSrc->l3unReachableCnt;
        if(pIp->addrSource == LM_ADDRESS_SOURCE_DHCP)
            pIp->LeaseTime = pIpSrc->LeaseTime;
        else
            pIp->LeaseTime = 0;
   }
    
    
    for(i = 0, pIpSrc = pHost->ipv6AddrArray;pIpSrc != NULL && i < LM_MAX_IP_AMOUNT;i++, pIpSrc = pIpSrc->pNext){
        pIp = &(pDestHost->ipv6AddrList[i]);
        inet_pton(AF_INET6, pIpSrc->pStringParaValue[LM_HOST_IPAddress_IPAddressId],pIp->addr);
        pIp->addrSource = _get_addr_source(pIpSrc->pStringParaValue[LM_HOST_IPAddress_IPAddressSourceId]); 
        //Not support yet
        pIp->LeaseTime = 0;
    }
}

static void _get_host_info(LM_host_t *pDestHost, PLmObjectHost pHost)
{
        mac_string_to_array(pHost->pStringParaValue[LM_HOST_PhysAddressId], pDestHost->phyAddr);
        pDestHost->online = (unsigned char)pHost->bBoolParaValue[LM_HOST_ActiveId];
        pDestHost->activityChangeTime = pHost->activityChangeTime;
        _get_host_mediaType(&(pDestHost->mediaType), pHost->pStringParaValue[LM_HOST_Layer1InterfaceId]); 
        STRNCPY_NULL_CHK(pDestHost->hostName, pHost->pStringParaValue[LM_HOST_HostNameId], sizeof(pDestHost->hostName)-1);
        STRNCPY_NULL_CHK(pDestHost->l3IfName, pHost->pStringParaValue[LM_HOST_Layer3InterfaceId], sizeof(pDestHost->l3IfName)-1);
        STRNCPY_NULL_CHK(pDestHost->l1IfName, pHost->pStringParaValue[LM_HOST_Layer1InterfaceId], sizeof(pDestHost->l1IfName)-1);
        STRNCPY_NULL_CHK((char *)pDestHost->comments, pHost->pStringParaValue[LM_HOST_Comments], sizeof(pDestHost->comments)-1);
        STRNCPY_NULL_CHK(pDestHost->AssociatedDevice, pHost->pStringParaValue[LM_HOST_AssociatedDeviceId], sizeof(pDestHost->AssociatedDevice)-1);
        pDestHost->RSSI = pHost->iIntParaValue[LM_HOST_X_CISCO_COM_RSSIId];
        _get_host_ipaddress(pDestHost, pHost); 
}

static void _get_hosts_info_cfunc(int fd, void* recv_buf, int buf_size)
{
    UNREFERENCED_PARAMETER(recv_buf);
    UNREFERENCED_PARAMETER(buf_size);
    int i, len = 0;
    PLmObjectHost pHost = NULL;
    LM_host_t *pDestHost = NULL;
    /*CID: 135585, 135577 Large stack use*/
    LM_hosts_t *hosts = NULL;

    hosts = (LM_hosts_t *) malloc(sizeof(LM_hosts_t));
    if (!hosts)
        return;
/*
    if(0 == Hosts_stop_scan()){
        PRINTD("bridge mode return 0\n");
        Hosts_PollHost();
    }
*/

    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    hosts->count = lmHosts.numHost;

    for(i = 0; i < hosts->count; i++){
        pHost = lmHosts.hostArray[i];
        pDestHost = &(hosts->hosts[i]);
        _get_host_info(pDestHost, pHost);
    }
    pthread_mutex_unlock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));

    len = (hosts->count)*sizeof(LM_host_t) + sizeof(int);
    write(fd, hosts, len);
    free(hosts);
}

static void _get_host_by_mac_cfunc(int fd, void* recv_buf, int buf_size)
{
    LM_cmd_get_host_by_mac_t *cmd = recv_buf;
    LM_cmd_common_result_t result;
    PLmObjectHost pHost;
    char mac[18];

    if(buf_size < (int)sizeof(LM_cmd_get_host_by_mac_t))
        return;
    memset(&result, 0, sizeof(result));
    snprintf(mac,sizeof(mac)/sizeof(mac[0]), "%02x:%02x:%02x:%02x:%02x:%02x", cmd->mac[0], cmd->mac[1], cmd->mac[2], cmd->mac[3], cmd->mac[4], cmd->mac[5]);
    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    pHost = Hosts_FindHostByPhysAddress(mac);
    if(pHost){
        result.result = LM_CMD_RESULT_OK;
        _get_host_info(&(result.data.host), pHost);
    }else{
        result.result = LM_CMD_RESULT_NOT_FOUND;
    }
    pthread_mutex_unlock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    write(fd, &result, sizeof(result));
}

static void _set_comment_cfunc(int fd, void* recv_buf, int buf_size)
{

    LM_cmd_comment_t *cmd = recv_buf;
    LM_cmd_common_result_t result;
    PLmObjectHost pHost;
    char mac[18];

    if(buf_size < (int)sizeof(LM_cmd_comment_t))
        return;

    memset(&result, 0, sizeof(result));
    snprintf(mac,sizeof(mac)/sizeof(mac[0]), "%02x:%02x:%02x:%02x:%02x:%02x", cmd->mac[0], cmd->mac[1], cmd->mac[2], cmd->mac[3], cmd->mac[4], cmd->mac[5]);

    /* set comment value into syscfg */
    /* we don't check whether this device is in our LmObject list */
    result.result = LM_CMD_RESULT_INTERNAL_ERR;

    if (lm_wrapper_priv_set_lan_host_comments(cmd))
	goto END;

    /* But if this device is in LmObject list, update the comments value */
    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    pHost = Hosts_FindHostByPhysAddress(mac);
    if(pHost){
        LanManager_CheckCloneCopy( &(pHost->pStringParaValue[LM_HOST_Comments]) , cmd->comment);
    }
    pthread_mutex_unlock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    result.result = LM_CMD_RESULT_OK;

END:
    write(fd, &result, sizeof(result));
}

static inline void _get_online_device_cfunc(int fd, void* recv_buf, int buf_size)
{
    UNREFERENCED_PARAMETER(recv_buf);
    UNREFERENCED_PARAMETER(buf_size);
    int i;
    int num = 0;
    LM_cmd_common_result_t result;
    PLmObjectHostIPAddress pIP4;
    memset(&result, 0, sizeof(result));
    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    for(i = 0; i < lmHosts.numHost; i++){
        if(TRUE == lmHosts.hostArray[i]->bBoolParaValue[LM_HOST_ActiveId]){
            /* Do NOT count TrueStaticIP client */
            /* TODO CID: 74169 Structurally dead code - logic error*/
            for(pIP4 = lmHosts.hostArray[i]->ipv4AddrArray; pIP4 != NULL; pIP4 = pIP4->pNext){
                if ( 0 == strncmp(pIP4->pStringParaValue[LM_HOST_IPAddress_IPAddressId], "192.168", 7) ||
                     0 == strncmp(pIP4->pStringParaValue[LM_HOST_IPAddress_IPAddressId], "10.", 3) ||
                     0 == strncmp(pIP4->pStringParaValue[LM_HOST_IPAddress_IPAddressId], "172.", 4)
                   )
                {
                num++;
                break;
                }
            }
        }
    }
    pthread_mutex_unlock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    result.result = LM_CMD_RESULT_OK;
    result.data.online_num = num;
    write(fd, &result, sizeof(result));
}

static inline void _not_support_cfunc(int fd, void* recv_buf, int buf_size)
{
    UNREFERENCED_PARAMETER(fd);
    UNREFERENCED_PARAMETER(recv_buf);
    UNREFERENCED_PARAMETER(buf_size);
}

typedef void (*LM_cfunc_t)(int, void*, int);

static const LM_cfunc_t cfunc[LM_API_CMD_MAX] =
{
    _get_hosts_info_cfunc,              // LM_API_CMD_GET_HOSTS = 0,
    _get_host_by_mac_cfunc,             //LM_API_CMD_GET_HOST_BY_MAC,
    _set_comment_cfunc,                 //LM_API_CMD_SET_COMMENT,
    _get_online_device_cfunc,           //LM_API_CMD_GET_ONLINE_DEVICE,
    _not_support_cfunc,                 //LM_API_CMD_ADD_NETWORK,
    _not_support_cfunc,                 //LM_API_CMD_DELETE_NETWORK,
    _not_support_cfunc,                 //LM_API_CMD_GET_NETWORK,
};

void *lm_cmd_thread_func(void *args)
{
	UNREFERENCED_PARAMETER(args);
    int listen_fd;
    int cmd_fd;
    int ret;
    static char recv_buf[1024];
    int len;
    struct sockaddr_un clt_addr;
    struct sockaddr_un srv_addr;
    errno_t rc = -1;

    listen_fd=socket(PF_UNIX,SOCK_STREAM,0);
    if(listen_fd<0)
        return NULL;

    srv_addr.sun_family=AF_UNIX;
    unlink(LM_SERVER_FILE_NAME);
    rc = strcpy_s(srv_addr.sun_path, sizeof(srv_addr.sun_path),LM_SERVER_FILE_NAME);
    ERR_CHK(rc);

    /*CID: 53112 Unchecked return value from library*/
    if(bind(listen_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0)
    {
	    perror("bind failed");
            close(listen_fd);
            return NULL;
    }
    /*CID: 55938 Unchecked return value*/
    if(listen(listen_fd, 10) < 0)
    {
	    perror("listen");
            close(listen_fd);
            return NULL;
    }

    PRINTD("start listen\n");
    while(1){
	len = sizeof(clt_addr);
        cmd_fd = accept(listen_fd,(struct sockaddr *)&clt_addr,(socklen_t *)&len);
        if(cmd_fd < 0 )
           continue;
        PRINTD("accept \n");
        ret = read(cmd_fd, recv_buf, sizeof(recv_buf));
        if(ret > 0){
            PRINTD("get command %d \n", LM_API_GET_CMD(recv_buf));
            if((unsigned int)LM_API_CMD_MAX > LM_API_GET_CMD(recv_buf)){
                cfunc[LM_API_GET_CMD(recv_buf)](cmd_fd, recv_buf, ret);
            }
        }
        close(cmd_fd);
    }
	return NULL;
}
#endif

int Hosts_stop_scan()
{
    return lm_wrapper_priv_stop_scan();
}

#if !defined (RESOURCE_OPTIMIZATION)
void XHosts_SyncWifi()
{
	int count = 0;
    int i;
	CcspTraceWarning(("Inside %s \n",__FUNCTION__));
    PLmObjectHost pHost;
    LM_wifi_wsta_t *hosts = NULL;

	Xlm_wrapper_get_wifi_wsta_list(&count, &hosts);
	
	if (count > 0)
    {
        for (i = 0; i < count; i++)
        {
            PRINTD("%s: Process No.%d mac %s\n", __FUNCTION__, i+1, hosts[i].phyAddr);

            pHost = XHosts_FindHostByPhysAddress((char*)hosts[i].phyAddr);

	    if ( !pHost )
	    {

		    pHost = XHosts_AddHostByPhysAddress((char*)hosts[i].phyAddr);
		    if ( pHost )
		    {      
			    CcspTraceWarning(("%s, %d New XHS host added sucessfully\n",__FUNCTION__, __LINE__));
		    } else {
			    CcspTraceError(("%s, %d New XHS host *NOT* added\n",__FUNCTION__, __LINE__));
                            if (hosts)
                               free(hosts);
			    /*CID: 60384 Dereference after null check*/
			    return;
		    }
	    }
			Xlm_wrapper_get_info(pHost);
			Host_AddIPv4Address ( pHost, pHost->pStringParaValue[LM_HOST_IPAddressId]);
			LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId]), (const char *)hosts[i].ssid);
			LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_AssociatedDeviceId]), (const char *)hosts[i].AssociatedDevice);
			pHost->iIntParaValue[LM_HOST_X_CISCO_COM_RSSIId] = hosts[i].RSSI;
			pHost->l1unReachableCnt = 1;
			pHost->bBoolParaValue[LM_HOST_ActiveId] = hosts[i].Status;
			pHost->activityChangeTime = time((time_t*)NULL);
			LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Parent]), getFullDeviceMac());
			LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_DeviceType]), " ");
			
        }
 	}

    if ( hosts )
    {
        free(hosts);
    }
	//Get the lease time as well as update host name.
	
}
#endif

static void *Event_HandlerThread(void *threadid)
{
    UNREFERENCED_PARAMETER(threadid);
    LM_wifi_wsta_t hosts;
#if !defined (NO_MOCA_FEATURE_SUPPORT)
    LM_moca_cpe_t mhosts;
#endif
    PLmObjectHost pHost;
    //printf("Hello World! It's me, thread #%ld!\n", tid);
    mqd_t mq;
    struct mq_attr attr;
    char buffer[MAX_SIZE + 1];
	char radio[32];
    BOOL do_dhcpsync = FALSE;

    /* initialize the queue attributes */
    attr.mq_flags = 0;
    attr.mq_maxmsg = 100;
    attr.mq_msgsize = MAX_SIZE;
    attr.mq_curmsgs = 0;

    /* create the message queue */
    mq = mq_open(EVENT_QUEUE_NAME, O_CREAT | O_RDONLY, 0644, &attr);

    if (mq == (mqd_t)-1) {
        CcspTraceError(("%s:%d: ", __FUNCTION__, __LINE__));
        perror("mq == (mqd_t)-1");
        return NULL;
    }

    do
    {
        ssize_t bytes_read;
        EventQData EventMsg;
        Eth_data EthHost;

        /* receive the message */
        bytes_read = mq_receive(mq, buffer, MAX_SIZE, NULL);

        if (bytes_read < 0) {
            CcspTraceError(("%s:%d: ", __FUNCTION__, __LINE__));
            perror("bytes_read < 0");
            return NULL;
        }

        buffer[bytes_read] = '\0';

        memcpy(&EventMsg,buffer,sizeof(EventMsg));
        /* CID 339816 String not null terminated */
        EventMsg.Msg[MAX_SIZE_EVT-1] = '\0';
        do_dhcpsync = FALSE;
        if(Hosts_stop_scan())
        {
            continue;
        }

        if(EventMsg.MsgType == MSG_TYPE_ETH)
        {
            memcpy(&EthHost,EventMsg.Msg,sizeof(EthHost));
            /* CID 339816 String not null terminated */
            EthHost.MacAddr[sizeof(EthHost.MacAddr) - 1] = '\0';

            CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            pthread_mutex_lock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            pHost = Hosts_FindHostByPhysAddress(EthHost.MacAddr);
            if ( !pHost )
            {
                 CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
                 pthread_mutex_lock(&PresenceDetectionMutex);
                 CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
                 pHost = Hosts_AddHostByPhysAddress(EthHost.MacAddr);
                 pthread_mutex_unlock(&PresenceDetectionMutex);
                 CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));

                if ( pHost )
                {
                    if ( pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] )
                    {
                         AnscFreeMemory(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId]);
                         pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] = NULL;
                    }
                }
                else
                {
                    pthread_mutex_unlock(&LmHostObjectMutex);
                    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
                    continue;
                }      
            }

            if(EthHost.Active)
            {
                CcspTraceDebug(("%s-%d LM Ethernet client is active \n",__FUNCTION__,__LINE__));
                LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId]), "Ethernet");
                if ( ! pHost->pStringParaValue[LM_HOST_IPAddressId] )
                {
                    CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is Ethernet, MacAddress is %s IPAddr is not updated in ARP\n",pHost->pStringParaValue[LM_HOST_PhysAddressId]));
                    do_dhcpsync = TRUE;
                }
 
                LM_SET_ACTIVE_STATE_TIME(pHost, TRUE);
            }
            else
            {
                CcspTraceDebug(("%s-%d LM Ethernet client is NOT active \n",__FUNCTION__,__LINE__));
                LM_SET_ACTIVE_STATE_TIME(pHost, FALSE);
            }
           
            LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Layer1Interface]), ""); 
            LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Parent]), getFullDeviceMac());
            LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_DeviceType]), "empty");
            pthread_mutex_unlock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));

            if(EthHost.Active && do_dhcpsync)
            {
                Hosts_SyncDHCP();
                CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
                pthread_mutex_lock(&LmHostObjectMutex);
                CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
                pHost = Hosts_FindHostByPhysAddress(EthHost.MacAddr);
                if (pHost && pHost->pStringParaValue[LM_HOST_PhysAddressId] && pHost->pStringParaValue[LM_HOST_IPAddressId])
                {
                    CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is Ethernet, MacAddress is %s IP from DNSMASQ is %s \n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_IPAddressId]));
                }
                pthread_mutex_unlock(&LmHostObjectMutex);
                CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            }

        }
        else if(EventMsg.MsgType == MSG_TYPE_WIFI)
        {
            memcpy(&hosts,EventMsg.Msg,sizeof(hosts));
            CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            pthread_mutex_lock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            pHost = Hosts_FindHostByPhysAddress((char*)hosts.phyAddr);
            if ( !pHost )
            {
                CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
                pthread_mutex_lock(&PresenceDetectionMutex);
                CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
                pHost = Hosts_AddHostByPhysAddress((char*)hosts.phyAddr);
                pthread_mutex_unlock(&PresenceDetectionMutex);
                CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
                if ( pHost )
                {
                    if ( pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] )
                    {
                        AnscFreeMemory(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId]);
                        pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] = NULL;
                    }
                }
                else
                {
                    pthread_mutex_unlock(&LmHostObjectMutex);
                    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
                    continue;
                }   
                
            }

            if(hosts.Status)
            {
				memset(radio,0,sizeof(radio));	
                convert_ssid_to_radio((char *)hosts.ssid, radio);
				LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Layer1Interface]), radio);
                LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId]), (const char *)hosts.ssid);
                LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_AssociatedDeviceId]), (const char *)hosts.AssociatedDevice);
                pHost->iIntParaValue[LM_HOST_X_CISCO_COM_RSSIId] = hosts.RSSI;
                pHost->l1unReachableCnt = 1;
                if ( ! pHost->pStringParaValue[LM_HOST_IPAddressId] )
                {
                    CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is WiFi, MacAddress is %s IPAddr is not updated in ARP\n",pHost->pStringParaValue[LM_HOST_PhysAddressId]));
                    do_dhcpsync = TRUE;
               }

                LM_SET_ACTIVE_STATE_TIME(pHost, TRUE);
            }
            else
            {
                /*CID:63986 Array compared against 0*/
                if( (pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] != NULL) )
                {
                    if(!strcmp(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId], (const char *)hosts.ssid))
                    {
                        memset(radio,0,sizeof(radio));
                        convert_ssid_to_radio((char *)hosts.ssid, radio);
                        DelAndShuffleAssoDevIndx(pHost);
                        LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Layer1Interface]), radio);
                        LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId]), (const char *)hosts.ssid);
                        //LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_AssociatedDeviceId]), hosts.AssociatedDevice);
                        LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_AssociatedDeviceId]), " "); // fix for RDKB-19836
                        LM_SET_ACTIVE_STATE_TIME(pHost, FALSE);
                    }
                }
            }
            
            LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Parent]), getFullDeviceMac());
            LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_DeviceType]), " ");
            pthread_mutex_unlock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));

            if(hosts.Status && do_dhcpsync) 
            {
                Hosts_SyncDHCP();
                CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
                pthread_mutex_lock(&LmHostObjectMutex);
                CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
                pHost = Hosts_FindHostByPhysAddress((char *)hosts.phyAddr);
                if (pHost && pHost->pStringParaValue[LM_HOST_PhysAddressId] && pHost->pStringParaValue[LM_HOST_IPAddressId])
                {
                    CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is WiFi, MacAddress is %s IP from DNSMASQ is %s \n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_IPAddressId])); 
                }
                pthread_mutex_unlock(&LmHostObjectMutex);
                CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            }

        }
#if !defined (NO_MOCA_FEATURE_SUPPORT)
        else if(EventMsg.MsgType == MSG_TYPE_MOCA)
        {
            memcpy(&mhosts,EventMsg.Msg,sizeof(mhosts));
            CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            pthread_mutex_lock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            pHost = Hosts_FindHostByPhysAddress((char *)mhosts.phyAddr);
            if ( !pHost )
            {
                pHost = Hosts_AddHostByPhysAddress((char *)mhosts.phyAddr);

                if ( pHost )
                {
                    if ( pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] )
                    {
                        AnscFreeMemory(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId]);
                        pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] = NULL;
                    }
                }
                else
                {
                    pthread_mutex_unlock(&LmHostObjectMutex);
                    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
                    continue;
                }   
            }

            if(mhosts.Status)
            {
                LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId]), (const char *)mhosts.ssid);
                LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Layer1Interface]), "");
                LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_AssociatedDeviceId]), (const char *)mhosts.AssociatedDevice);
                LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Parent]), (const char *)mhosts.parentMac);
                LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_DeviceType]), (const char *)mhosts.deviceType);
                pHost->iIntParaValue[LM_HOST_X_CISCO_COM_RSSIId] = mhosts.RSSI;
                pHost->l1unReachableCnt = 1;

                if ( ! pHost->pStringParaValue[LM_HOST_IPAddressId] )
                {
                    do_dhcpsync = TRUE;
                    CcspTraceWarning(("<<< %s client type is MoCA, IPAddr is not updated in ARP %d >>\n>",__FUNCTION__,__LINE__));
                    CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is MoCA, MacAddress is %s IPAddr is not updated in ARP\n",pHost->pStringParaValue[LM_HOST_PhysAddressId]));
                }
                
                LM_SET_ACTIVE_STATE_TIME(pHost, TRUE);
            }
            else
            {
                LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId]), (const char *)mhosts.ssid);
                LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Layer1Interface]), "");
                LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_AssociatedDeviceId]), (const char *)mhosts.AssociatedDevice);

                LM_SET_ACTIVE_STATE_TIME(pHost, FALSE);
            }       
            pthread_mutex_unlock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));

           if(mhosts.Status && do_dhcpsync)
            {
                Hosts_SyncDHCP();
                CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
                pthread_mutex_lock(&LmHostObjectMutex);
                CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
                pHost = Hosts_FindHostByPhysAddress((char *)mhosts.phyAddr);
                if (pHost && pHost->pStringParaValue[LM_HOST_PhysAddressId] && pHost->pStringParaValue[LM_HOST_IPAddressId])
                {
                    CcspTraceWarning(("RDKB_CONNECTED_CLIENTS: Client type is MoCA, MacAddress is %s IP from DNSMASQ is %s \n",pHost->pStringParaValue[LM_HOST_PhysAddressId],pHost->pStringParaValue[LM_HOST_IPAddressId]));
                }

                pthread_mutex_unlock(&LmHostObjectMutex);
                CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            }
            
        }
#endif
        else if (MSG_TYPE_RFC == EventMsg.MsgType)
        {
#if defined (RDKB_EXTENDER_ENABLED)
        if (atoi(dev_Mode) == 1)
        {
            CcspTraceInfo(("Skipping Presence Detect and posting functionality for Extender mode \n"));
        }
        else
        {
#endif
            if (!strcmp(EventMsg.Msg,"true"))
            {
                if (0 == Hosts_EnablePresenceDetectionTask())
                {
                    CcspTraceDebug(("%s:%d, Acquiring presence locks \n",__FUNCTION__,__LINE__));
                    acquirePresencelocks();
                    CcspTraceDebug(("%s:%d, Acquired presence locks \n",__FUNCTION__,__LINE__));
                    addHostsToPresenceTable();
                    releasePresenceLocks();
                    CcspTraceDebug(("%s:%d, released presence locks \n",__FUNCTION__,__LINE__));
                }
            }
            else
            {
                Hosts_DisablePresenceDetectionTask();
            }
#if defined (RDKB_EXTENDER_ENABLED)
        }
#endif
        }
    } while(1);
   pthread_exit(NULL);
}

static void Hosts_SyncArp (void)
{
    char comments[256] = {0};
    int count = 0;
    int i;

    PLmObjectHost pHost = NULL;
    LM_host_entry_t *hosts = NULL;
    PLmObjectHostIPAddress pIP;

    lm_wrapper_get_arp_entries("brlan0", &count, &hosts);
    if (count > 0)
    {
        CcspTraceDebug(("%s:%d, Acquiring presence locks \n",__FUNCTION__,__LINE__));
        acquirePresencelocks ();
        CcspTraceDebug(("%s:%d, Acquired presence locks \n",__FUNCTION__,__LINE__));

        for (i = 0; i < count; i++)
        {
            PRINTD("%s: Process No.%d mac %s\n", __FUNCTION__, i+1, hosts[i].phyAddr);

            pHost = Hosts_FindHostByPhysAddress((char *)hosts[i].phyAddr);

            if ( pHost )
            {
                if ( _isIPv6Addr((char *)hosts[i].ipAddr) )
                {
                    pIP = Host_AddIPv6Address(pHost, (char *)hosts[i].ipAddr);
                    if ( hosts[i].status == LM_NEIGHBOR_STATE_REACHABLE)
                    {
                        Host_SetIPAddress(pIP, 0, "NONE"); 
                    }
                    else
                    {
                        Host_SetIPAddress(pIP, LM_HOST_RETRY_LIMIT, "NONE"); 
                    }
                }
                else
                {
                    if ( hosts[i].status == LM_NEIGHBOR_STATE_REACHABLE)
                    {
						/*
						  * We need to maintain recent reachable IP in "Device.Hosts.Host.1.IPAddress" host. so 
						  * that we are doing swap here.
						  */
						pIP = Host_AddIPv4Address(pHost, (char *)hosts[i].ipAddr);

                        Host_SetIPAddress(pIP, 0, "NONE");

                        _getLanHostComments((char *)hosts[i].phyAddr, comments);
                        if ( comments[0] != 0 )
                        {
                            LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_Comments]), comments);
                        }
                    }
                    else
                    {
						/*
						  * We need to update non-reachable IP in host details. No need to swap.
						  */
						pIP = LM_FindIPv4BaseFromLink( pHost, (char *)hosts[i].ipAddr );

						if( NULL != pIP )
						{
							Host_SetIPAddress(pIP, LM_HOST_RETRY_LIMIT, "NONE"); 
						}
                    }
                }

                LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_Layer3InterfaceId]), (const char *)hosts[i].ifName );
            }
        }

        releasePresenceLocks();
        CcspTraceDebug(("%s:%d, released presence locks \n",__FUNCTION__,__LINE__));
    }

    if ( hosts )
    {
        free(hosts);
        hosts=NULL;
    }

    return;
}

static void Hosts_SyncDHCP(void)
{
    lm_wrapper_get_dhcpv4_client();
    lm_wrapper_get_dhcpv4_reserved();
}

static void *Hosts_LoggingThread(void *args)
{
    UNREFERENCED_PARAMETER(args);
    int i;
    PLmObjectHost pHost;
	int TotalDevCount = 0;
	int TotalOnlineDev = 0;
	int TotalOffLineDev = 0;
	int TotalWiFiDev = 0;
	int Radio_2_Dev = 0;
	int Radio_5_Dev = 0;
        int Radio_6_Dev = 0;
	int TotalEthDev = 0;
#if !defined (NO_MOCA_FEATURE_SUPPORT)
	int TotalMoCADev = 0;
#endif

	sleep(30);

	while(1)
	{
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
		pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
		TotalDevCount = lmHosts.numHost;

		for ( i = 0; i < lmHosts.numHost; i++ )
		{

			pHost = lmHosts.hostArray[i];
			if(pHost)
			{
				if(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId])
				{
					if(pHost->bBoolParaValue[LM_HOST_ActiveId])
					{
						TotalOnlineDev ++;


						if((strstr(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],"WiFi")))
						{
                                                        if((strstr(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],"WiFi.SSID.17")))
                                                        {
                                                            Radio_6_Dev++;
                                                        }
                                                        else if((strstr(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],"WiFi.SSID.1")))
							{
								Radio_2_Dev++;
							}
							else if((strstr(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],"WiFi.SSID.2")))
							{
								Radio_5_Dev++;
							}
							TotalWiFiDev++;
						}
#if !defined (NO_MOCA_FEATURE_SUPPORT)
						else if ((strstr(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],"MoCA")))
						{
							
							TotalMoCADev++;
						}
#endif
						else if ((strstr(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],"Ethernet")))
						{
							
							TotalEthDev++;
						}
					}
				
				}
			}
		}
		pthread_mutex_unlock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
		TotalOffLineDev = TotalDevCount - TotalOnlineDev;
		
		CcspTraceWarning(("------------------------AssociatedClientsInfo-----------------------\n"));
		CcspTraceWarning(("RDKB_CONNECTED_CLIENTS:Total_Clients_Connected=%d\n",TotalDevCount));
		CcspTraceWarning(("RDKB_CONNECTED_CLIENTS:Total_Online_Clients=%d\n",TotalOnlineDev));
		CcspTraceWarning(("RDKB_CONNECTED_CLIENTS:Total_Offline_Clients=%d\n",TotalOffLineDev));
		CcspTraceWarning(("RDKB_CONNECTED_CLIENTS:Total_WiFi_Clients=%d\n",TotalWiFiDev));
		CcspTraceWarning(("RDKB_CONNECTED_CLIENTS:Total_WiFi-2.4G_Clients=%d\n",Radio_2_Dev));
		CcspTraceWarning(("RDKB_CONNECTED_CLIENTS:Total_WiFi-5.0G_Clients=%d\n",Radio_5_Dev));
                CcspTraceWarning(("RDKB_CONNECTED_CLIENTS:Total_WiFi-6.0G_Clients=%d\n",Radio_6_Dev));
		CcspTraceWarning(("RDKB_CONNECTED_CLIENTS:Total_Ethernet_Clients=%d\n",TotalEthDev));
#if !defined (NO_MOCA_FEATURE_SUPPORT)
		CcspTraceWarning(("RDKB_CONNECTED_CLIENTS:Total_MoCA_Clients=%d\n",TotalMoCADev));
#endif
		CcspTraceWarning(("-------------------------------------------------------------------\n"));

		t2_event_d("Total_devices_connected_split", TotalDevCount);
		t2_event_d("Total_online_clients_split", TotalOnlineDev);
		t2_event_d("Total_offline_clients_split", TotalOffLineDev);
		t2_event_d("Total_wifi_clients_split", TotalWiFiDev);
		t2_event_d("Total_Ethernet_Clients_split", TotalEthDev);
#if !defined (NO_MOCA_FEATURE_SUPPORT)
		t2_event_d("Total_MoCA_Clients_split", TotalMoCADev);
#endif
	
		/* CID 340337 Unused value fix */
		TotalOnlineDev = 0;
		TotalOffLineDev = 0;
		TotalWiFiDev = 0;
		Radio_2_Dev = 0;
		Radio_5_Dev = 0;
                Radio_6_Dev = 0;
		TotalEthDev = 0;
#if !defined (NO_MOCA_FEATURE_SUPPORT)
		TotalMoCADev = 0;
#endif

		sleep(g_Client_Poll_interval*60); 
	}
	return NULL;
}

static void *Hosts_StatSyncThreadFunc(void *args)
{
    static BOOL bridgemode = FALSE;

    UNREFERENCED_PARAMETER(args);

    while (1)
    {
        if(Hosts_stop_scan() )
        {
            PRINTD("\n%s bridge mode, remove all host information\n", __FUNCTION__);
            bridgemode = TRUE;
            CcspTraceDebug(("%s:%d, Acquiring presence locks \n",__FUNCTION__,__LINE__));
            acquirePresencelocks();
            CcspTraceDebug(("%s:%d, Acquired presence locks \n",__FUNCTION__,__LINE__));
            Hosts_RmHosts();
            releasePresenceLocks();
            CcspTraceDebug(("%s:%d, released presence locks \n",__FUNCTION__,__LINE__));
            sleep(30);
        }
        else
        {
#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_TURRIS_) && !defined(_PLATFORM_BANANAPI_R4_)
            if(bridgemode)
            {
                Send_Eth_Host_Sync_Req(); 
#if defined (CONFIG_SYSTEM_MOCA)
                Send_MoCA_Host_Sync_Req(); 
#endif
                SyncWiFi();
                bridgemode = FALSE;
            }
#else
             UNREFERENCED_PARAMETER(bridgemode);
#endif
            sleep(30);
            Sendmsg_dnsmasq(lmHosts.enablePresence);
            Hosts_SyncDHCP();
            Hosts_SyncArp();
            Add_IPv6_from_Dibbler();
        }
    }
    return NULL;
}

void Hosts_PollHost (void)
{
    pthread_mutex_lock(&PollHostMutex);
    Hosts_SyncArp();
    Hosts_SyncDHCP();
    pthread_mutex_unlock(&PollHostMutex);
}

static BOOL ValidateHost (char *mac)
{
    char buf[200];
    FILE *fp;
    int ret =0;

#ifdef CORE_NET_LIB
    char *mac_filter = NULL;
    char *if_filter = NULL;
    int af_filter = 0;

    if (mac != NULL) {
        mac_filter = strdup(mac);
        if (!mac_filter) {
            CcspTraceError(("%s: Failed to copy MAC string\n", __FUNCTION__));
            return FALSE;
        }
    }
    else{
        CcspTraceError(("%s: Input MAC address is NULL\n", __FUNCTION__));
        return FALSE;
    }

    struct neighbour_info *neighbours =  init_neighbour_info();
    if (!neighbours) {
        CcspTraceError(("%s: Failed to initialize neighbor information structure\n", __FUNCTION__));
        free(mac_filter);
        return FALSE;
    }
    libnet_status st = neighbour_get_list(neighbours, mac_filter, if_filter, af_filter);
    free(mac_filter);
    if (st == CNL_STATUS_SUCCESS) {
        CcspTraceDebug(("%s: Successfully retrieved neighbor list based on MAC:%s, and Neighbour count: %d\n", __FUNCTION__, mac, neighbours->neigh_count));
        if (neighbours->neigh_count <= 0 || neighbours->neigh_arr == NULL) {
            CcspTraceError(("%s: Neighbour list is empty\n", __FUNCTION__));
            neighbour_free_neigh(neighbours);
            return FALSE;
        }
        for (int i = 0; i < neighbours->neigh_count; ++i) {
            CcspTraceDebug(("Neighbor %d: local=%s, mac=%s, ifname=%s,state=%d\n",
                i,
                neighbours->neigh_arr[i].local ? neighbours->neigh_arr[i].local : "NULL",
                neighbours->neigh_arr[i].mac ? neighbours->neigh_arr[i].mac : "NULL",
                neighbours->neigh_arr[i].ifname ? neighbours->neigh_arr[i].ifname : "NULL",
                neighbours->neigh_arr[i].state));

            char arp_entry[128] = {0};
            format_neighbour_entry(neighbours, i, arp_entry, sizeof(arp_entry));
            if (arp_entry[0] != '\0') {
                libnet_status fw_st = file_write(ARP_CACHE, arp_entry, strlen(arp_entry));
                if (fw_st != CNL_STATUS_SUCCESS){
                    CcspTraceError(("%s %d: File write failed for neighbor list!\n", __FUNCTION__, __LINE__));
                }
            }
        }
    }
    else{
        CcspTraceError(("%s: Failed to execute core net lib neighbour_get_list\n", __FUNCTION__));
        neighbour_free_neigh(neighbours);
        return FALSE;
    }
    neighbour_free_neigh(neighbours);
#else
    ret = v_secure_system("ip nei show | grep -i %s > "ARP_CACHE, mac);
    if(ret < 0)
    {
         CcspTraceError(("Failed in executing the command via v_secure_system ret: %d\n",ret));
    }
#endif /* CORE_NET_LIB */

    if ((fp = fopen(ARP_CACHE, "r")) == NULL)
    {
        return FALSE;
    }

    if (fgets (buf, sizeof(buf), fp) != NULL)
    {
        fclose(fp);
        unlink(ARP_CACHE);
        return TRUE;
    }

    fclose(fp);
    fp = NULL;
    unlink(ARP_CACHE);

    ret = v_secure_system("cat "DNSMASQ_FILE" | grep -i %s > "DNSMASQ_CACHE, mac);
    if(ret < 0)
    {
        CcspTraceError(("Failed in executing the command via v_seure_system ret: %d\n",ret));
    }

    if ((fp = fopen(DNSMASQ_CACHE, "r")) == NULL)
    {
        CcspTraceWarning(("%s not able to open dnsmasq cache file\n", __FUNCTION__));
        return FALSE;
    }

    if (fgets (buf, sizeof(buf), fp) != NULL)
    {
        fclose(fp);
        unlink(DNSMASQ_CACHE);
        return TRUE;
    }

    fclose(fp);
    unlink(DNSMASQ_CACHE);
    return FALSE;
}

static RetryHostList *CreateValidateHostEntry(ValidateHostQData *pValidateHost)
{
    RetryHostList *pHost;
    errno_t rc = -1;

    pHost = (RetryHostList *)malloc(sizeof(RetryHostList));
    if (pHost)
    {
        memset(pHost, 0, sizeof(RetryHostList));
        rc = strcpy_s(pHost->host.phyAddr, sizeof(pHost->host.phyAddr), pValidateHost->phyAddr);
        ERR_CHK(rc);
        rc = strcpy_s(pHost->host.AssociatedDevice, sizeof(pHost->host.AssociatedDevice),pValidateHost->AssociatedDevice);
        ERR_CHK(rc);
        rc = strcpy_s(pHost->host.ssid, sizeof(pHost->host.ssid),pValidateHost->ssid);
        ERR_CHK(rc);
        pHost->host.RSSI = pValidateHost->RSSI;
        pHost->host.Status = pValidateHost->Status;
        pHost->retryCount = 0;
        pHost->next = NULL;
    }

    return pHost;
}

static void UpdateHostRetryValidateList(ValidateHostQData *pValidateHostMsg, int actionFlag)
{
    RetryHostList *pHostNode = NULL;
    RetryHostList *retryList = NULL;
    RetryHostList *prevNode = NULL;
    errno_t rc = -1;

    if (!pValidateHostMsg)
    {
        CcspTraceWarning(("%s Null Param\n",__FUNCTION__));
        return;
    }

    pthread_mutex_lock(&LmRetryHostListMutex);
    retryList = pListHead;
    prevNode = NULL;
    while(retryList)
    {
        if (!strcmp(retryList->host.phyAddr, pValidateHostMsg->phyAddr))
        {
            /* found the mac */
            if (actionFlag == ACTION_FLAG_DEL)
            {
                if (NULL == prevNode)
                {
                    /* First Node */
                    pListHead = retryList->next;
                }
                else
                {
                    prevNode->next = retryList->next;
                }
                free(retryList);
            }
            else if (ACTION_FLAG_ADD == actionFlag)
            {
                /* 
                 * Alreday present in list, if it was off before and now it's on,
                 * update info, and reset the retry count 
                 */
                if (!retryList->host.Status && pValidateHostMsg->Status) {
                    rc = strcpy_s(retryList->host.AssociatedDevice, sizeof(retryList->host.AssociatedDevice),pValidateHostMsg->AssociatedDevice);
                    ERR_CHK(rc);
                    rc = strcpy_s(retryList->host.ssid, sizeof(retryList->host.ssid),pValidateHostMsg->ssid);
                    ERR_CHK(rc);
                    retryList->host.RSSI = pValidateHostMsg->RSSI;
                    retryList->host.Status = pValidateHostMsg->Status;
                }
                retryList->retryCount = 0;
            }
            pthread_mutex_unlock(&LmRetryHostListMutex);
            return;
        }
        prevNode = retryList;
        retryList = retryList->next;
    }

    if (ACTION_FLAG_ADD == actionFlag)
    {
        /* Not found in list. Add it. */
        pHostNode = CreateValidateHostEntry(pValidateHostMsg);
        if (!pHostNode)
        {
            CcspTraceWarning(("%s Malloc failed....\n",__FUNCTION__));
            pthread_mutex_unlock(&LmRetryHostListMutex);
            return;
        }
        if (NULL == prevNode)
        {
            /* empty list */
            pListHead = pHostNode;
        }
        else
        {
            /* add at last */
            prevNode->next = pHostNode;
        }
    }

    pthread_mutex_unlock(&LmRetryHostListMutex);
    return;
}

static void RemoveHostRetryValidateList(RetryHostList *pPrevNode, RetryHostList *pHost)
{
    if (NULL == pPrevNode)
    {
        //First Node
        pListHead = pHost->next;
    }
    else
    {
        pPrevNode->next = pHost->next;
    }
    free(pHost);
    return;
}

static void *ValidateHostRetry_Thread (void *arg)
{
    UNREFERENCED_PARAMETER(arg);
    RetryHostList *retryList;
    RetryHostList *prevNode = NULL;

    CcspTraceWarning(("%s started\n", __FUNCTION__));

    do
    {
        sleep(MAX_WAIT_VALIDATE_RETRY);
        pthread_mutex_lock(&LmRetryHostListMutex);
        if (pListHead)
        {
            retryList = pListHead;
            prevNode = NULL;
            while(retryList)
            {
                retryList->retryCount++;
                if (TRUE == ValidateHost(retryList->host.phyAddr))
                {
                    Wifi_ServerSyncHost(retryList->host.phyAddr,
                                        retryList->host.AssociatedDevice,
                                        retryList->host.ssid,
                                        retryList->host.RSSI,
                                        retryList->host.Status);
                    /* Valide Host. Remove from Retry Validate list */
                    RemoveHostRetryValidateList(prevNode, retryList);
                    retryList = (NULL == prevNode) ? pListHead : prevNode->next;
                    continue;
                }
                else if (retryList->retryCount >= MAX_COUNT_VALIDATE_RETRY)
                {
                    /* Reached maximum retry. Remove from the Retry Validate list */
                    RemoveHostRetryValidateList(prevNode, retryList);
                    retryList = (NULL == prevNode) ? pListHead : prevNode->next;
                    continue;
                }
                prevNode = retryList;
                retryList = retryList->next;
            }
        }
        pthread_mutex_unlock(&LmRetryHostListMutex);
    }
    while (1);

    pthread_exit(NULL);
}

static void *ValidateHost_Thread (void *arg)
{
    UNREFERENCED_PARAMETER(arg);
    mqd_t mq;
    struct mq_attr attr;

    /* initialize the queue attributes */
    attr.mq_flags = 0;
    attr.mq_maxmsg = 100;
    attr.mq_msgsize = MAX_SIZE_VALIDATE_QUEUE;
    attr.mq_curmsgs = 0;

    /* create the message queue */
    mq = mq_open(VALIDATE_QUEUE_NAME, O_CREAT | O_RDONLY, 0644, &attr);
    if (mq == (mqd_t)-1) {
        CcspTraceError(("%s:%d: ", __FUNCTION__, __LINE__));
        perror("mq == (mqd_t)-1");
        return NULL;
    }

    do
    {
        ssize_t bytes_read;
        ValidateHostQData ValidateHostMsg;
        memset(&ValidateHostMsg, 0, sizeof(ValidateHostQData));

        /* receive the message */
        bytes_read = mq_receive(mq, (char *)&ValidateHostMsg, MAX_SIZE_VALIDATE_QUEUE, NULL);
        if (bytes_read < 0) {
            CcspTraceError(("%s:%d: ", __FUNCTION__, __LINE__));
            perror("bytes_read < 0");
            return NULL;
        }

        if (TRUE == ValidateHost(ValidateHostMsg.phyAddr))
        {
            Wifi_ServerSyncHost(ValidateHostMsg.phyAddr,
                                ValidateHostMsg.AssociatedDevice,
                                ValidateHostMsg.ssid,
                                ValidateHostMsg.RSSI,
                                ValidateHostMsg.Status);
            /* Valid Host. Remove from retry list if present */
            UpdateHostRetryValidateList(&ValidateHostMsg, ACTION_FLAG_DEL);
        }
        else
        {
            CcspTraceError(("%s: ValidateHost execution failed\n", __FUNCTION__));
            /* Host is not valide. Add the host details in retry list */
            UpdateHostRetryValidateList(&ValidateHostMsg, ACTION_FLAG_ADD);
        }
    } while(1);
    pthread_exit(NULL);
}

static const char *compName = "LOG.RDK.LM";

void LM_main (void)
{
    int res;
    char buf[12]; // this value is reading a ULONG
    char buf1[12]; // this is reading an int

    pthread_mutex_init(&PollHostMutex, 0);
    pthread_mutex_init(&LmHostObjectMutex,0);
#if !defined (RESOURCE_OPTIMIZATION)
	pthread_mutex_init(&XLmHostObjectMutex,0);
#endif
    pthread_mutex_init(&HostNameMutex,0);
    pthread_mutex_init(&LmRetryHostListMutex, 0);
    pthread_mutex_init(&LmRetryNotifyHostListMutex, 0);
    lm_wrapper_init();
    lmHosts.hostArray = AnscAllocateMemory(LM_HOST_ARRAY_STEP * sizeof(PLmObjectHost));
    lmHosts.sizeHost = LM_HOST_ARRAY_STEP;
    lmHosts.numHost = 0;
    lmHosts.lastActivity = 0;
    lmHosts.availableInstanceNum = 1;
    lmHosts.enablePresence = FALSE;

#if !defined (RESOURCE_OPTIMIZATION)
	XlmHosts.hostArray = AnscAllocateMemory(LM_HOST_ARRAY_STEP * sizeof(PLmObjectHost));
	XlmHosts.sizeHost = LM_HOST_ARRAY_STEP;
	XlmHosts.numHost = 0;
	XlmHosts.lastActivity = 0;
    XlmHosts.availableInstanceNum = 1;
#endif
	
    pComponentName = (char*)compName;
    Hosts_GetPresenceParamFromSysDb(&lmHosts.param_val); // update presence syscfg param into lmhost object.
    /*CID: 59596 Array compared against 0*/
    if(!syscfg_get( NULL, "X_RDKCENTRAL-COM_HostVersionId", buf, sizeof(buf)))
    {
	lmHosts.lastActivity = atol(buf);
    }

    if(syscfg_get( NULL, "X_RDKCENTRAL-COM_HostCountPeriod", buf1, sizeof(buf1)) == 0)
    {
        g_Client_Poll_interval = atoi(buf1);
    }
    else
    {
        g_Client_Poll_interval = 60;
        if (syscfg_set_u_commit(NULL, "X_RDKCENTRAL-COM_HostCountPeriod", g_Client_Poll_interval) != 0) {
            return;
        }
    }

#ifdef FEATURE_SUPPORT_RDKLOG
    RDK_LOGGER_INIT();
#endif
    CcspTraceWarning(("LMLite:rdk initialzed!\n"));

#ifdef WAN_FAILOVER_SUPPORTED
    if(checkRbusEnabled()) {
        CcspTraceDebug(("RBUS mode. lmliteRbusInit\n"));
	lmliteRbusInit(LMLITE_COMPONENT_NAME);  // Initiating the Rbus 
	get_WanManager_ActiveInterface();  
	subscribeTo_InterfaceActiveStatus_Event();  
    }	     
#endif
    initparodusTask();

#ifdef WAN_TRAFFIC_COUNT_SUPPORT
#if defined (RDKB_EXTENDER_ENABLED)
    if (atoi(dev_Mode) == 1)
    {
        CcspTraceInfo(("Skipping WanTraffic count related Thread create for Extender mode \n"));
    }
    else
    {
#endif
    CcspTraceInfo(("%s : WanTraffic Count Support ENABLED\n",__FUNCTION__));
    WTC_Init();
#if defined (RDKB_EXTENDER_ENABLED)
    }
#endif
#endif

    pthread_t ValidateHost_ThreadID;
    res = pthread_create(&ValidateHost_ThreadID, NULL, ValidateHost_Thread, "ValidateHost_Thread");
    if(res != 0) {
        CcspTraceError(("Create Event_HandlerThread error %d\n", res));
    }

    pthread_t ValidateHostRetry_ThreadID;
    res = pthread_create(&ValidateHostRetry_ThreadID, NULL, ValidateHostRetry_Thread, "ValidateHostRetry_Thread");
    if(res != 0) {
        CcspTraceError(("Create ValidateHostRetry_Thread error %d\n", res));
    }

    pthread_t Event_HandlerThreadID;
    res = pthread_create(&Event_HandlerThreadID, NULL, Event_HandlerThread, "Event_HandlerThread");
    if(res != 0) {
        CcspTraceError(("Create Event_HandlerThread error %d\n", res));
    }
    Hosts_PollHost();

    sleep(5);

    pthread_t Hosts_StatSyncThread;
    res = pthread_create(&Hosts_StatSyncThread, NULL, Hosts_StatSyncThreadFunc, "Hosts_StatSyncThreadFunc");
    if(res != 0) {
        CcspTraceError(("Create Hosts_StatSyncThread error %d\n", res));
    }
    pthread_t Hosts_LogThread;
    res = pthread_create(&Hosts_LogThread, NULL, Hosts_LoggingThread, "Hosts_LoggingThread");
    if(res != 0) {
        CcspTraceError(("Create Hosts_LogThread error %d\n", res));
    }
#ifdef LM_IPC_SUPPORT
    pthread_t Hosts_CmdThread;
    res = pthread_create(&Hosts_CmdThread, NULL, lm_cmd_thread_func, "lm_cmd_thread_func");
    if(res != 0){
        CcspTraceError(("Create lm_cmd_thread_func error %d\n", res));
    }
#endif
#ifdef USE_NOTIFY_COMPONENT
/* Use DBUS instead of socket */
#if 0
	printf("\n WIFI-CLIENT : Creating Wifi_Server_Thread \n");

	pthread_t Wifi_Server_Thread;
	res = pthread_create(&Wifi_Server_Thread, NULL, Wifi_Server_Thread_func, "Wifi_Server_Thread_func");
	if(res != 0){
		CcspTraceWarning(("\n WIFI-CLIENT : Create Wifi_Server_Thread error %d \n",res));
	}
	else
	{
		CcspTraceWarning(("\n WIFI-CLIENT : Create Wifi_Server_Thread success %d \n",res));
	}
	///pthread_join(Wifi_Server_Thread, &status);
#else

#endif /* 0 */
#endif
    if(!Hosts_stop_scan()) {
        Send_Eth_Host_Sync_Req();
#if defined (CONFIG_SYSTEM_MOCA)
        Send_MoCA_Host_Sync_Req();
#endif
        SyncWiFi( );
    }

#if defined (RDKB_EXTENDER_ENABLED)
    if (atoi(dev_Mode) == 1)
    {
        CcspTraceInfo(("Skipping Presence Detect and posting functionality for Extender mode \n"));
    }
    else
    {
#endif
     syscfg_get( NULL, "PresenceDetectEnabled", buf, sizeof(buf));
     if (!strcmp(buf,"true"))
     {
        if (0 == Hosts_EnablePresenceDetectionTask())
        {
            BOOL bConfiguredMacListIsSet = FALSE;
            CcspTraceDebug(("%s:%d, Acquiring presence locks \n",__FUNCTION__,__LINE__));
            acquirePresencelocks();
            CcspTraceDebug(("%s:%d, Acquired presence locks \n",__FUNCTION__,__LINE__));
            getConfiguredMaclistStatus(&bConfiguredMacListIsSet);
            if (TRUE == bConfiguredMacListIsSet)
            {
                CcspTraceWarning(("[%s] [%d] Configured Mac List is Set\n", __FUNCTION__, __LINE__));
            }
            else
            {
                CcspTraceWarning(("[%s] [%d] Adding all hosts to presence table\n", __FUNCTION__, __LINE__));
                addHostsToPresenceTable();
            }
            releasePresenceLocks();
            CcspTraceDebug(("%s:%d, released presence locks \n",__FUNCTION__,__LINE__));
        }
      }
#if defined (RDKB_EXTENDER_ENABLED)
     }
#endif
    //pthread_join(Hosts_StatSyncThread, &status);
    //pthread_join(Hosts_CmdThread, &status);
    return;

}

static char *_CloneString (const char *src)
{
	if(src == NULL) return NULL;
	
    size_t len = strlen(src) + 1;
    if(len <= 1) return NULL;
	
    char * dest = AnscAllocateMemory(len);
    if ( dest )
    {
        strncpy(dest, src, len);
        dest[len - 1] = 0;
    }
	
    return dest;
}

static void _init_DM_List(int *num, Name_DM_t **pList, char *path, char *name)
{
    int i;
    char (*dmnames)[CDM_PATH_SZ]=NULL;
    int nname = 0;
    errno_t rc = -1;
    
    if(*pList != NULL){
        AnscFreeMemory(*pList);
        *pList = NULL;
    }
 
    if((CCSP_SUCCESS == Cdm_GetNames(path, 0, &dmnames, &nname)) && \
            (nname > 0))
    {
        *pList = AnscAllocateMemory(sizeof(Name_DM_t) * nname);

        if (*pList != NULL)
        {
            for(i = 0; i < nname; i++){
			ULONG ulEntryNameLen;
			parameterValStruct_t varStruct;
			char ucEntryParamName[NAME_DM_LEN];
			
			rc = sprintf_s((*pList)[i].dm , sizeof((*pList)[i].dm),"%s", dmnames[i]);
			if(rc < EOK)
			{
				ERR_CHK(rc);
			}
			rc = sprintf_s(ucEntryParamName , sizeof(ucEntryParamName),"%s%s", dmnames[i], name);
			if(rc < EOK)
			{
				ERR_CHK(rc);
			}
			varStruct.parameterName = ucEntryParamName;
   			varStruct.parameterValue = (*pList)[i].name;
			/*CID: 73391 Unchecked return value*/
			ulEntryNameLen = NAME_DM_LEN;
			if(COSAGetParamValueByPathName(bus_handle,&varStruct,&ulEntryNameLen))
				CcspTraceError(("%s Failed to get param\n",__FUNCTION__));

            }
        }
    }

	/* 
	 * To avoid the memory leak of dmnames pointer value
	 */
	if( dmnames )
	{
	  Cdm_FreeNames(dmnames); 
	  dmnames = NULL;
	}
	
    *num = nname;
}

static void _get_dmbyname(int num, Name_DM_t *list, char** dm, char* name)
{
    int i;
	
	if(name == NULL)
		return;
	
    for(i = 0; i < num; i++){
        if(strcasestr(list[i].name, name)){
            STRNCPY_NULL_CHK1((*dm), list[i].dm);
            break;
        }
    }
	
}

int LM_get_host_info()
{

	int i = 0;
	

	if(firstFlg == 0){
        firstFlg = 1;
        return 0;
    }
	
/*
	if(0 == Hosts_stop_scan()){
		printf("bridge mode return 0\n");
		Hosts_PollHost();
	}
*/
	_init_DM_List(&g_IPIfNameDMListNum, &g_pIPIfNameDMList, "Device.IP.Interface.", "Name");
#if !defined (NO_MOCA_FEATURE_SUPPORT)
	_init_DM_List(&g_MoCAADListNum, &g_pMoCAADList, "Device.MoCA.Interface.1.AssociatedDevice.", "MACAddress");
#endif
	_init_DM_List(&g_DHCPv4ListNum, &g_pDHCPv4List, "Device.DHCPv4.Server.Pool.1.Client.", "Chaddr");

    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
	pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));

	for(i = 0; i<lmHosts.numHost; i++){

		_get_dmbyname(g_IPIfNameDMListNum, g_pIPIfNameDMList, &(lmHosts.hostArray[i]->Layer3Interface), lmHosts.hostArray[i]->pStringParaValue[LM_HOST_Layer3InterfaceId]);

		if(lmHosts.hostArray[i]->pStringParaValue[LM_HOST_Layer1InterfaceId] != NULL)
		{
#if !defined (NO_MOCA_FEATURE_SUPPORT)
			if(strstr(lmHosts.hostArray[i]->pStringParaValue[LM_HOST_Layer1InterfaceId], "MoCA") != NULL){
	        	_get_dmbyname(g_MoCAADListNum, g_pMoCAADList, &(lmHosts.hostArray[i]->pStringParaValue[LM_HOST_AssociatedDeviceId]), lmHosts.hostArray[i]->pStringParaValue[LM_HOST_PhysAddressId]);
			}
#endif
		}
		

		if((lmHosts.hostArray[i]->numIPv4Addr) && (lmHosts.hostArray[i]->pStringParaValue[LM_HOST_AddressSource] != NULL))
		{
			if(strstr(lmHosts.hostArray[i]->pStringParaValue[LM_HOST_AddressSource],LM_ADDRESS_SOURCE_DHCP_STR)	!= NULL){
                _get_dmbyname(g_DHCPv4ListNum, g_pDHCPv4List, &(lmHosts.hostArray[i]->pStringParaValue[LM_HOST_DHCPClientId]), lmHosts.hostArray[i]->pStringParaValue[LM_HOST_PhysAddressId]);
                lmHosts.hostArray[i]->LeaseTime = lmHosts.hostArray[i]->ipv4AddrArray->LeaseTime;    		
            }
		}
		
		
	}

	pthread_mutex_unlock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
	return 0;
}

#if !defined (RESOURCE_OPTIMIZATION)
int XLM_get_host_info()
{

	int i = 0;
	

	if(xfirstFlg == 0){
        xfirstFlg = 1;
        return 0;
    }
	//XHosts_SyncWifi();
	_init_DM_List(&g_IPIfNameDMListNum, &g_pIPIfNameDMList, "Device.IP.Interface.", "Name");
	_init_DM_List(&g_DHCPv4ListNum, &g_pDHCPv4List, "Device.DHCPv4.Server.Pool.2.Client.", "Chaddr"); 

	for(i = 0; i<XlmHosts.numHost; i++){
		Xlm_wrapper_get_info(XlmHosts.hostArray[i]);
	pthread_mutex_lock(&XLmHostObjectMutex);
		_get_dmbyname(g_IPIfNameDMListNum, g_pIPIfNameDMList, &(XlmHosts.hostArray[i]->Layer3Interface), XlmHosts.hostArray[i]->pStringParaValue[LM_HOST_Layer3InterfaceId]);

		if(XlmHosts.hostArray[i]->numIPv4Addr)
		{
			if(strstr(XlmHosts.hostArray[i]->pStringParaValue[LM_HOST_AddressSource],LM_ADDRESS_SOURCE_DHCP_STR)	!= NULL){
                _get_dmbyname(g_DHCPv4ListNum, g_pDHCPv4List, &(XlmHosts.hostArray[i]->pStringParaValue[LM_HOST_DHCPClientId]), XlmHosts.hostArray[i]->pStringParaValue[LM_HOST_PhysAddressId]);
            }
		}
		
	pthread_mutex_unlock(&XLmHostObjectMutex);
	}

	return 0;

}
#endif

void Wifi_ServerSyncHost (char *phyAddr, char *AssociatedDevice, char *ssid, int RSSI, int Status)
{
	char *Xpos2 = NULL;
	char *Xpos5 = NULL;
#if !defined (RESOURCE_OPTIMIZATION)
	char radio[32] 			= {0};
        char telemetryBuff[TELEMETRY_MAX_BUFFER] = { '\0' };
#endif

	CcspTraceWarning(("%s [%s %s %s %d %d]\n",
									__FUNCTION__,
									(NULL != phyAddr) ? phyAddr : "NULL",
									(NULL != AssociatedDevice) ? AssociatedDevice : "NULL",
									(NULL != ssid) ? ssid : "NULL",
									RSSI,
									Status));
        /*CID: 71084 Dereference before null check*/
        if(!ssid)
           return;

	Xpos2	= strstr( ssid,".3" );
	Xpos5	= strstr( ssid,".4" );


	if( ( NULL != Xpos2 ) || \
		( NULL != Xpos5 ) 
	   )
	{
#if !defined (RESOURCE_OPTIMIZATION)
		PLmObjectHost pHost;

		pHost = XHosts_AddHostByPhysAddress(phyAddr);

		if ( pHost )
		{
			Xlm_wrapper_get_info(pHost);

			pthread_mutex_lock(&XLmHostObjectMutex);
			convert_ssid_to_radio(ssid, radio);
			LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Layer1Interface]), radio);
			LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId]), ssid);
			if(strncmp(AssociatedDevice,"NULL",strlen(AssociatedDevice)) == 0)
				LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_AssociatedDeviceId]), " ");
			else
			LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_AssociatedDeviceId]), AssociatedDevice);
			pHost->iIntParaValue[LM_HOST_X_CISCO_COM_RSSIId] = RSSI;
			pHost->l1unReachableCnt = 1;
			pHost->bBoolParaValue[LM_HOST_ActiveId] = Status;
			pHost->activityChangeTime = time((time_t*)NULL);
			LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Parent]), getFullDeviceMac());
			LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_DeviceType]), " ");

			if( Status ) 
			{
				if( pHost->ipv4Active == TRUE )
				{
					CcspTraceInfo(("XHS_CONNECTED_CLIENTS: WiFi XHS client online:%s,%s\n", ( pHost->pStringParaValue[LM_HOST_HostNameId] ) ? ( pHost->pStringParaValue[LM_HOST_HostNameId] ) : "NULL", pHost->pStringParaValue[LM_HOST_PhysAddressId]));
					CcspTraceInfo(("XHS_CONNECTED_CLIENTS: IP Address is  %s , address source is %s and HostName is %s \n",(pHost->pStringParaValue[LM_HOST_IPAddressId]) ? (pHost->pStringParaValue[LM_HOST_IPAddressId]) : "NULL",
																	       (pHost->pStringParaValue[LM_HOST_AddressSource]) ? (pHost->pStringParaValue[LM_HOST_AddressSource]) : "NULL",
																	       (pHost->pStringParaValue[LM_HOST_HostNameId]) ? (pHost->pStringParaValue[LM_HOST_HostNameId]) : "NULL"));	
					memset(telemetryBuff, 0, TELEMETRY_MAX_BUFFER);
					snprintf(telemetryBuff,16,"%s",pHost->pStringParaValue[LM_HOST_HostNameId]);
					if(strncmp(telemetryBuff,"SC",strlen("SC")) == 0)
					{
						t2_event_d("WIFI_INFO_XHCAM_online", 1);
					}
					else if(strncmp(telemetryBuff,"android",strlen("android")) == 0)
					{
						t2_event_d("WIFI_INFO_XHTS_online", 1);
					}
					else
					{
						t2_event_d("WIFI_INFO_XHclient_online", 1);
					}
				}
			}  
			else 
			{
				if( pHost->ipv4Active == TRUE )
				{
					CcspTraceInfo(("XHS_CONNECTED_CLIENTS: WiFi XHS client offline:%s,%s\n", ( pHost->pStringParaValue[LM_HOST_HostNameId] ) ? ( pHost->pStringParaValue[LM_HOST_HostNameId] ) : "NULL", pHost->pStringParaValue[LM_HOST_PhysAddressId]));

					memset(telemetryBuff, 0, TELEMETRY_MAX_BUFFER);
					snprintf(telemetryBuff,16,"%s",pHost->pStringParaValue[LM_HOST_HostNameId]);
					if(strncmp(telemetryBuff,"SC",strlen("SC")) == 0)
					{
						t2_event_d("WIFI_INFO_XHCAM_offline", 1);
					}
					else if(strncmp(telemetryBuff,"android",strlen("android")) == 0) 
					{
						t2_event_d("WIFI_INFO_XHTS_offline", 1);
					}
					else
					{
						t2_event_d("WIFI_INFO_XHclient_offline", 1);
					}
				}
			}

			pthread_mutex_unlock(&XLmHostObjectMutex);
		}
#endif
	}
	else
	{

		LM_wifi_wsta_t hosts;
		memset(&hosts, 0, sizeof(hosts));
		if (AssociatedDevice) {
                    /*CID:135530 Buffer not null terminated*/
		    strncpy((char *)hosts.AssociatedDevice, AssociatedDevice,
			sizeof(hosts.AssociatedDevice)-1);
                   hosts.AssociatedDevice[sizeof(hosts.AssociatedDevice)-1] = '\0';
		}
		if (phyAddr) {
		    strncpy((char *)hosts.phyAddr, phyAddr, sizeof(hosts.phyAddr));
		}
		hosts.phyAddr[17] = '\0';
		if (ssid) {
		    strncpy((char *)hosts.ssid, ssid, sizeof(hosts.ssid));
		}
		hosts.RSSI = RSSI;
		hosts.Status = Status;
		EventQData EventMsg;
		mqd_t mq;
        char buffer[MAX_SIZE];
		
		mq = mq_open(EVENT_QUEUE_NAME, O_WRONLY);
        CHECK((mqd_t)-1 != mq);
		memset(buffer, 0, MAX_SIZE);
		EventMsg.MsgType = MSG_TYPE_WIFI;

		memcpy(EventMsg.Msg,&hosts,sizeof(hosts));
		memcpy(buffer,&EventMsg,sizeof(EventMsg));
		CHECK(0 <= mq_send(mq, buffer, MAX_SIZE, 0));
		CHECK((mqd_t)-1 != mq_close(mq));
	}
}

void Wifi_Server_Sync_Function( char *phyAddr, char *AssociatedDevice, char *ssid, int RSSI, int Status )
{
	ValidateHostQData ValidateHostMsg;
	memset(&ValidateHostMsg, 0, sizeof(ValidateHostQData));
	mqd_t mq;

	CcspTraceWarning(("%s [%s %s %s %d %d]\n",
						__FUNCTION__,
						(NULL != phyAddr) ? phyAddr : "NULL",
						(NULL != AssociatedDevice) ? AssociatedDevice : "NULL",
						(NULL != ssid) ? ssid : "NULL",
						RSSI,
						Status));
	mq = mq_open(VALIDATE_QUEUE_NAME, O_WRONLY);
    CHECK((mqd_t)-1 != mq);

    if(phyAddr != NULL)
    {
	strncpy(ValidateHostMsg.phyAddr, phyAddr, sizeof(ValidateHostMsg.phyAddr)-1);
	ValidateHostMsg.phyAddr[sizeof(ValidateHostMsg.phyAddr)-1] = '\0';
    }
    if(AssociatedDevice != NULL)
    {
	strncpy(ValidateHostMsg.AssociatedDevice, AssociatedDevice, sizeof(ValidateHostMsg.AssociatedDevice)-1);
	ValidateHostMsg.AssociatedDevice[sizeof(ValidateHostMsg.AssociatedDevice)-1] = '\0';
    }
    if(ssid != NULL)
    {
	strncpy(ValidateHostMsg.ssid, ssid, sizeof(ValidateHostMsg.ssid)-1);
	ValidateHostMsg.ssid[sizeof(ValidateHostMsg.ssid)-1] = '\0';
    }
    ValidateHostMsg.RSSI = RSSI;
    ValidateHostMsg.Status = Status;

	CHECK(0 <= mq_send(mq, (char *)&ValidateHostMsg, MAX_SIZE_VALIDATE_QUEUE, 0));
	CHECK((mqd_t)-1 != mq_close(mq));
}

int Hosts_FindHostIndexByPhysAddress(char * physAddress)
{
    int i = 0;
    for(; i<lmHosts.numHost; i++){
        if (strcasecmp(lmHosts.hostArray[i]->pStringParaValue[LM_HOST_PhysAddressId], physAddress) == 0){
            return i;
        }
    }
    return 0;
}

static void DelAndShuffleAssoDevIndx (PLmObjectHost pHost)
{
	int x = 0,y = 0,tmp =0, tAP = 0;
	int token = 0,AP = 0;
	char str[100];
	errno_t rc = -1;
	
	x = Hosts_FindHostIndexByPhysAddress(pHost->pStringParaValue[LM_HOST_PhysAddressId]);

	if ( pHost->pStringParaValue[LM_HOST_AssociatedDeviceId] != NULL )
		sscanf(pHost->pStringParaValue[LM_HOST_AssociatedDeviceId],"Device.WiFi.AccessPoint.%d.AssociatedDevice.%d",&AP,&token);

	CcspTraceWarning(("AP = %d token = %d\n",AP,token));
	//printf("AP = %d token = %d\n",AP,token);
// modify uper indexes from token index
    for(y = x-1;y >= 0; y--)
	{
		tmp = 0; tAP = 0;
		if(lmHosts.hostArray[y]->pStringParaValue[LM_HOST_AssociatedDeviceId] != NULL)
		{
		    sscanf(lmHosts.hostArray[y]->pStringParaValue[LM_HOST_AssociatedDeviceId],"Device.WiFi.AccessPoint.%d.AssociatedDevice.%d",&tAP,&tmp);
		}
		else
		continue;
	
		if(AP == tAP)
		{
			if((token < tmp))
			{
				if(strcmp(lmHosts.hostArray[y]->pStringParaValue[LM_HOST_AssociatedDeviceId],"empty"))
				{
					tmp = tmp-1;
					rc = sprintf_s(str, sizeof(str),"Device.WiFi.AccessPoint.%d.AssociatedDevice.%d",tAP,tmp);
					if(rc < EOK)
					{
						ERR_CHK(rc);
					}
					LanManager_CheckCloneCopy(&(lmHosts.hostArray[y]->pStringParaValue[LM_HOST_AssociatedDeviceId]), str);
				}
			}
		}
	}
	LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_AssociatedDeviceId]), "empty");
	x++;
// modify lower indexes from token index
	for(;x<lmHosts.numHost;x++)
	{
		tmp = 0; tAP = 0;

		if(lmHosts.hostArray[x]->pStringParaValue[LM_HOST_AssociatedDeviceId] != NULL)
		{
	    		sscanf(lmHosts.hostArray[x]->pStringParaValue[LM_HOST_AssociatedDeviceId],"Device.WiFi.AccessPoint.%d.AssociatedDevice.%d",&tAP,&tmp);
		}
		else
		   continue;
		
		if(AP == tAP)
		{
			if(strcmp(lmHosts.hostArray[x]->pStringParaValue[LM_HOST_AssociatedDeviceId],"empty"))
			{
				if(token < tmp)
				{
					tmp = tmp-1;
					rc = sprintf_s(str, sizeof(str),"Device.WiFi.AccessPoint.%d.AssociatedDevice.%d",tAP,tmp);
					if(rc < EOK)
					{
						ERR_CHK(rc);
					}
					LanManager_CheckCloneCopy(&(lmHosts.hostArray[x]->pStringParaValue[LM_HOST_AssociatedDeviceId]), str);
				}
			}
		}
	}
}

#if !defined (NO_MOCA_FEATURE_SUPPORT)
void MoCA_Server_Sync_Function( char *phyAddr, char *AssociatedDevice, char *ssid, char* parentMac, char* deviceType, int RSSI, int Status )
{
	CcspTraceWarning(("%s [%s %s %s %s %s %d %d]\n",
									__FUNCTION__,
									(NULL != phyAddr) ? phyAddr : "NULL",
									(NULL != AssociatedDevice) ? AssociatedDevice : "NULL",
									(NULL != ssid) ? ssid : "NULL",
									(NULL != parentMac) ? parentMac : "NULL", 
									(NULL != deviceType) ? deviceType : "NULL", 
									RSSI,
									Status));

		LM_moca_cpe_t hosts = {0};
                
                /*CID:62979 Uninitialized scalar variable*/
                memset (&hosts.parentMac, 0, sizeof(hosts.parentMac));
		if(AssociatedDevice)
		{
			strncpy((char *)hosts.AssociatedDevice,AssociatedDevice,sizeof(hosts.AssociatedDevice)-1);
			hosts.AssociatedDevice[sizeof(hosts.AssociatedDevice)-1] = '\0';
		}
		strncpy((char *)hosts.phyAddr,phyAddr,17);
		hosts.phyAddr[17] = '\0';
		if(ssid)
		{
			strncpy((char *)hosts.ssid,ssid,sizeof(hosts.ssid)-1);
			hosts.ssid[sizeof(hosts.ssid)-1] = '\0';
		}
		if(parentMac)
		{
			strncpy((char *)hosts.parentMac,parentMac,sizeof(hosts.parentMac)-1);
			hosts.parentMac[sizeof(hosts.parentMac)-1] = '\0';
		}
		if(deviceType)
		{
			strncpy((char *)hosts.deviceType,deviceType,sizeof(hosts.deviceType)-1);
			hosts.deviceType[sizeof(hosts.deviceType)-1] = '\0';
		}

		hosts.RSSI = RSSI;
		hosts.Status = Status;
		EventQData EventMsg;
		mqd_t mq;
        char buffer[MAX_SIZE];
		

		mq = mq_open(EVENT_QUEUE_NAME, O_WRONLY);
        CHECK((mqd_t)-1 != mq);
		memset(buffer, 0, MAX_SIZE);
		EventMsg.MsgType = MSG_TYPE_MOCA;
                /*CID: 62979 Uninitialized scalar variable for Field hosts.parentMac*/
		memcpy(EventMsg.Msg,&hosts,sizeof(hosts));
		memcpy(buffer,&EventMsg,sizeof(EventMsg));
		CHECK(0 <= mq_send(mq, buffer, MAX_SIZE, 0));
		CHECK((mqd_t)-1 != mq_close(mq));
}


#if defined (CONFIG_SYSTEM_MOCA)
static void Send_MoCA_Host_Sync_Req(void)
{
        parameterValStruct_t value = {"Device.MoCA.X_RDKCENTRAL-COM_MoCAHost_Sync", "true", ccsp_boolean};
        char *compo = "eRT.com.cisco.spvtg.ccsp.moca";
        char *bus = "/com/cisco/spvtg/ccsp/moca";
        char *faultParam = NULL;
        int ret = CCSP_FAILURE;

        CcspTraceWarning(("%s : Get MoCA Clients \n",__FUNCTION__));
        //printf("%s : Get MoCA Clients \n",__FUNCTION__);
		CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;

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
		CcspTraceWarning(("MoCA %s : Failed ret %d\n",__FUNCTION__,ret));
		if(faultParam)
		{
			bus_info->freefunc(faultParam);
		}
	}
}
#endif
#endif
static void Send_Eth_Host_Sync_Req(void)
{
        parameterValStruct_t value = {"Device.Ethernet.X_RDKCENTRAL-COM_EthHost_Sync", "true", ccsp_boolean};
        char *compo = "eRT.com.cisco.spvtg.ccsp.ethagent";
        char *bus = "/com/cisco/spvtg/ccsp/ethagent";
        char *faultParam = NULL;
        int ret = CCSP_FAILURE;

        CcspTraceWarning(("%s : Get Ethernet Clients \n",__FUNCTION__));
        //printf("%s : Get Ethernet Clients \n",__FUNCTION__);
		CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;

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
		CcspTraceWarning(("Ethernet %s : Failed ret %d\n",__FUNCTION__,ret));
		if(faultParam)
		{
			bus_info->freefunc(faultParam);
		}
	}
}

void EthClient_AddtoQueue(char *phyAddr,int Status )
{
		EventQData EventMsg;
		Eth_data EthHost;
		mqd_t mq;
        char buffer[MAX_SIZE];
        errno_t rc = -1;
		
		mq = mq_open(EVENT_QUEUE_NAME, O_WRONLY);
        CHECK((mqd_t)-1 != mq);
		memset(buffer, 0, MAX_SIZE);
		EventMsg.MsgType = MSG_TYPE_ETH;

		rc = strcpy_s(EthHost.MacAddr, sizeof(EthHost.MacAddr),phyAddr);
		ERR_CHK(rc);
		EthHost.Active = Status;
		memcpy(EventMsg.Msg,&EthHost,sizeof(EthHost));
		memcpy(buffer,&EventMsg,sizeof(EventMsg));
		CHECK(0 <= mq_send(mq, buffer, MAX_SIZE, 0));
		CHECK((mqd_t)-1 != mq_close(mq));
}

void convert_ssid_to_radio(char *ssid, char *radio)
{
    if(ssid == NULL){
        CcspTraceWarning(("Empty ssid\n"));
    }
    else{
        if(strstr(ssid,".17")) {
               AnscCopyString(radio,"Device.WiFi.Radio.3");
        }
        else if(strstr(ssid,".1") || strstr(ssid,".3")){
               AnscCopyString(radio,"Device.WiFi.Radio.1");
        }
        else if(strstr(ssid,".2") || strstr(ssid,".4")){
               AnscCopyString(radio,"Device.WiFi.Radio.2");
        }
        else{
	       CcspTraceWarning(("Invalid ssid\n"));
        }
    
    }
}

/* LM_FindIPv4BaseFromLink(  ) */
PLmObjectHostIPAddress LM_FindIPv4BaseFromLink( PLmObjectHost pHost, char * ipAddress )
{
	  PLmObjectHostIPAddress pIpAddrList = NULL, pCur = NULL;

	  pIpAddrList = pHost->ipv4AddrArray;

	  for( pCur = pIpAddrList; pCur != NULL; pCur = pCur->pNext )
	  {
		if (strcasecmp(pCur->pStringParaValue[LM_HOST_IPAddress_IPAddressId], ipAddress) == 0)
		{
			return pCur;
		}
	  }

		return NULL;
}

BOOL Hosts_UpdateSysDb(char *paramName,ULONG uValue)
{
    if (syscfg_set_u_commit(NULL, paramName, uValue) != 0) {
        return FALSE;
    }
    return TRUE;

}

static void Sendmsg_dnsmasq(BOOL enablePresenceFeature)
{
        DnsmasqEventQData EventMsg;
        mqd_t mq;
        char buffer[MAX_SIZE_DNSMASQ_Q];
        char buf_ip[32];
        errno_t rc = -1;

        mq = mq_open(DNSMASQ_NOTIFY_QUEUE_NAME, O_WRONLY | O_NONBLOCK);
        CHECK((mqd_t)-1 != mq);
        memset(buffer, 0, MAX_SIZE_DNSMASQ_Q);
        EventMsg.MsgType = MSG_TYPE_DNSMASQ;

        rc = strcpy_s(EventMsg.enable, sizeof(EventMsg.enable), ((enablePresenceFeature == TRUE) ? "true" : "false"));
        ERR_CHK(rc);
        syscfg_get( NULL, "lan_ipaddr", buf_ip, sizeof(buf_ip)); 
        rc = strcpy_s (EventMsg.ip, sizeof(EventMsg.ip),buf_ip);
        ERR_CHK(rc);
        /*CID: 70724 Uninitialized scalar variable*/
        memset (&EventMsg.mac, 0, sizeof(EventMsg.mac));
        memcpy(buffer,&EventMsg,sizeof(EventMsg));
        CHECK(0 <= mq_send(mq, buffer, MAX_SIZE_DNSMASQ_Q, 0));
        CHECK((mqd_t)-1 != mq_close(mq));
}


int Hosts_EnablePresenceDetectionTask()
{
    int ret_val = 0;
    char buf[12];

    syscfg_get( NULL, "PresenceDetectEnabled", buf, sizeof(buf));
    if ((!strcmp(buf,"true")) && (!lmHosts.enablePresence))
    {
        lmHosts.enablePresence = TRUE;
    }
    else
    {
        CcspTraceWarning(("RDKB_PRESENCE:  ignored! presence detection feature already enabled\n"));
        return ret_val;
    }
    ret_val = Hosts_InitPresenceDetection();
    if (0 == ret_val)
    {
        Hosts_UpdatePresenceDetectionParam(&lmHosts.param_val,HOST_PRESENCE_PARAM_ALL);
        Hosts_StartPresenceDetection();
        Sendmsg_dnsmasq(TRUE);
        CcspTraceWarning(("RDKB_PRESENCE: Presence Detection enabled Successfully\n"));
    }
    return ret_val;
}

int Hosts_DisablePresenceDetectionTask()
{
    PLmObjectHost pHost = NULL;
    LmHostPresenceDetectionParam param = {0};
    char tmpmac[64];
    char dbParam[128];
    int i = 0;
    if (!lmHosts.enablePresence)
    {
        CcspTraceWarning(("RDKB_PRESENCE: Presence Detection already disabled !!!\n"));
        return 0;
    }
    // clear all param related to presence.
    Sendmsg_dnsmasq(FALSE);
    syscfg_set(NULL, "notify_presence_webpa", "false");
    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    lmHosts.enablePresence = FALSE;
    for(i = 0; i < lmHosts.numHost; i++)
    {
        pHost = lmHosts.hostArray[i];
        if (pHost)
        {
            if (pHost->bBoolParaValue[LM_HOST_PresenceNotificationEnabledId])
            {
                pHost->bBoolParaValue[LM_HOST_PresenceNotificationEnabledId] = FALSE;
                pHost->bBoolParaValue[LM_HOST_PresenceActiveId] = FALSE;
                pHost->ulUlongParaValue[LM_HOST_X_RDK_PresenceActiveLastChange] = 0;
                if (pHost->pStringParaValue[LM_HOST_PhysAddressId])
                {
                    snprintf(tmpmac,sizeof(tmpmac),"%s",pHost->pStringParaValue[LM_HOST_PhysAddressId]);
                    LanManager_StringToLower(tmpmac);
                    snprintf(dbParam,sizeof(dbParam), "PDE_%s",tmpmac);
                    syscfg_unset(NULL, dbParam);
                }
                else
                {
                    continue;
                }
            }
        }
    }
    pthread_mutex_unlock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    syscfg_commit();
    memset(&param,0,sizeof(LmHostPresenceDetectionParam));
    Hosts_UpdatePresenceDetectionParam(&param,HOST_PRESENCE_PARAM_ALL);
    Hosts_StopPresenceDetection();
    Hosts_DeInitPresenceDetection();
    CcspTraceWarning(("RDKB_PRESENCE: Presence Detection disabled Successfully\n"));
    return 0;
}


BOOL Hosts_GetPresenceNotificationEnableStatus(char *Mac)
{
    char tmpmac[64];
    char dbParam[128];
    char result[12] = {0};

    if (!Mac)
        return FALSE;
    snprintf(tmpmac,sizeof(tmpmac),"%s",Mac);
    LanManager_StringToLower(tmpmac);
    snprintf(dbParam,sizeof(dbParam), "PDE_%s",tmpmac);
    syscfg_get(NULL, dbParam, result, sizeof(result));
    if (!strcmp(result,"true"))
    {
        return TRUE;
    }
    return FALSE;
}

int Hosts_GetPresenceParamFromSysDb(LmHostPresenceDetectionParam *paramOut)
{
    char result[16];
    //CIDs 330412,330410,330411,330413,330414: Data race condition (MISSING_LOCK)
    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));

    if (!paramOut)
    {
        pthread_mutex_unlock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        return -1;
    }

    syscfg_get(NULL, "X_RDKCENTRAL-COM_PresenceLeaveIPv4CheckInterval", result, sizeof(result));
    paramOut->ipv4CheckInterval = atol(result);

    syscfg_get(NULL, "X_RDKCENTRAL-COM_PresenceLeaveIPv4Retries", result, sizeof(result));
    paramOut->ipv4RetryCount    = atol(result);
    
    syscfg_get(NULL, "X_RDKCENTRAL-COM_PresenceLeaveIPv6CheckInterval", result, sizeof(result)); 
    paramOut->ipv6CheckInterval = atol(result);

    syscfg_get(NULL, "X_RDKCENTRAL-COM_PresenceLeaveIPv6Retries", result, sizeof(result)); 
    paramOut->ipv6RetryCount    = atol(result);

    syscfg_get(NULL, "X_RDKCENTRAL-COM_BackgroundPresenceJoinInterval", result, sizeof(result));
    paramOut->bkgrndjoinInterval = atol(result);

    pthread_mutex_unlock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    return 0;
}

int Hosts_UpdateDeviceIntoPresenceDetection(PLmObjectHost pHost, BOOL isIpAddressUpdate, BOOL bIsMacConfigurationEnabled)
{
    LmPresenceDetectionInfo status;
    memset(&status, 0, sizeof(LmPresenceDetectionInfo));
    PLmObjectHostIPAddress pIpAddrList;
    errno_t rc = -1;

    if (!pHost || !lmHosts.enablePresence) 
        return -1;   
    if (pHost->pStringParaValue[LM_HOST_PhysAddressId])
    {
        snprintf(status.physaddress,sizeof(status.physaddress),"%s",pHost->pStringParaValue[LM_HOST_PhysAddressId]);
    }
    else
    {
        return -1;
    }
    status.enable = pHost->bBoolParaValue[LM_HOST_PresenceNotificationEnabledId];
    if (!status.enable)
    {
        if (isIpAddressUpdate)
            return 0;
        pHost->bBoolParaValue[LM_HOST_PresenceActiveId] = FALSE;
    }
    else
    {
        status.ipv4Active = pHost->ipv4Active;
        status.ipv6Active = pHost->ipv6Active;
        status.currentActive = pHost->bBoolParaValue[LM_HOST_ActiveId];
        if (status.ipv6Active)
        {
            memset(status.ipv6,0,sizeof(status.ipv6));
            if (0 == strlen(status.ipv6))
            {
                pIpAddrList = LM_GetIPArr_FromIndex(pHost,1,IP_V6); // Local link address starts with "fe80"

                if (pIpAddrList)
                {
                    if (pIpAddrList->pStringParaValue[LM_HOST_IPAddress_IPAddressId])
                    {
                        char* ipadd = pIpAddrList->pStringParaValue[LM_HOST_IPAddress_IPAddressId];
                        if (strcmp(ipadd," ") && strcmp(ipadd,"EMPTY"))
                        {
                            rc = strcpy_s (status.ipv6, sizeof(status.ipv6),pIpAddrList->pStringParaValue[LM_HOST_IPAddress_IPAddressId]);
                            ERR_CHK(rc);
                        }
                    }
                }
            }
        }
        if ((status.ipv4Active) && (pHost->pStringParaValue[LM_HOST_IPAddressId]))
        {
            rc = strcpy_s (status.ipv4, sizeof(status.ipv4),pHost->pStringParaValue[LM_HOST_IPAddressId]);
            ERR_CHK(rc);
        }
    }
    Hosts_UpdatePresenceDetectionStatus(&status, bIsMacConfigurationEnabled);
    return 0;
}

BOOL Hosts_CheckAndUpdatePresenceDeviceMac(char *Mac, BOOL val)
{
    if (!Mac || !lmHosts.enablePresence)
        return FALSE;
    CcspTraceDebug(("%s:%d, Acquiring presence locks \n",__FUNCTION__,__LINE__));
    acquirePresencelocks();
    CcspTraceDebug(("%s:%d, Acquired presence locks \n",__FUNCTION__,__LINE__));
    PLmObjectHost pHost = Hosts_FindHostByPhysAddress(Mac);
    if (pHost)
    {
        BOOL bConfiguredMacListIsSet = FALSE;
        char tmpmac[64];
        char dbParam[128];
        int ret = 0;
        snprintf(tmpmac,sizeof(tmpmac),"%s",Mac);
        LanManager_StringToLower(tmpmac);
        snprintf(dbParam,sizeof(dbParam), "PDE_%s",tmpmac);

        CcspTraceWarning(("%s:%d, Mac %s, val %d\n", __FUNCTION__, __LINE__, Mac, val));
        getConfiguredMaclistStatus(&bConfiguredMacListIsSet);
        if (FALSE == bConfiguredMacListIsSet)
        {
            if (TRUE == val)
            {
                CcspTraceWarning(("%s:%d, resetPresenceDetectionList\n", __FUNCTION__, __LINE__));
                resetPresenceDetectionList(tmpmac);
            }
            else if (FALSE == val)
            {
                if (FALSE == Hosts_GetPresenceNotificationEnableStatus(Mac))
                {
                    CcspTraceWarning(("RDKB_PRESENCE:  Mac %s Not exist in detection list \n",Mac));
                    releasePresenceLocks();
                    CcspTraceDebug(("%s:%d, released presence locks \n",__FUNCTION__,__LINE__));
                    return TRUE;
                }
            }
        }
        pHost->bBoolParaValue[LM_HOST_PresenceNotificationEnabledId] = val;
        ret = Hosts_UpdateDeviceIntoPresenceDetection(pHost,FALSE, TRUE);
        if (val)
        {
            ret = syscfg_set(NULL, dbParam , "true");
        }
        else
        {
            ret = syscfg_unset(NULL, dbParam);
        }
        if (0 == ret)
        {
            syscfg_commit();
        }
        else
        {
            releasePresenceLocks();
            CcspTraceDebug(("%s:%d, released presence locks \n",__FUNCTION__,__LINE__));
            return FALSE;
        }
    }
    else
    {
        //Not found in host table
        releasePresenceLocks();
        CcspTraceDebug(("%s:%d, released presence locks \n",__FUNCTION__,__LINE__));
        return FALSE;
    }
    releasePresenceLocks();
    CcspTraceDebug(("%s:%d, released presence locks \n",__FUNCTION__,__LINE__));
    return TRUE;
}

static void *UpdateAndSendHostIPAddress_Thread(void *arg)
{
    UNREFERENCED_PARAMETER(arg);
    CcspTraceWarning((" %s started\n", __FUNCTION__));
    while (1) {
        pthread_mutex_lock(&LmRetryNotifyHostListMutex);
        while (!pNotifyListHead) {
            CcspTraceDebug((" %s line:%d\n", __FUNCTION__, __LINE__));
            pthread_cond_wait(&LmNotifyCond, &LmRetryNotifyHostListMutex);
        }

        RetryNotifyHostList *prev = NULL;
        RetryNotifyHostList *curr = pNotifyListHead;

        while (curr != NULL) {

            bool completed = false;
            LMPresenceNotifyAddressInfo *ctx = curr->ctx;

            // Check IPv4
	    pthread_mutex_lock (&LmHostObjectMutex);
            PLmObjectHost pHost = ctx->pHost;
            if (pHost != NULL) {
                if (pHost->pStringParaValue[LM_HOST_IPAddressId]) {
                    ctx->ipv4 = strdup(pHost->pStringParaValue[LM_HOST_IPAddressId]);
                }
                ctx->physAddr = strdup(pHost->pStringParaValue[LM_HOST_PhysAddressId]);
                ctx->hostName = strdup(pHost->pStringParaValue[LM_HOST_HostNameId]);
            }
	    if ((pHost->pStringParaValue[LM_HOST_PhysAddressId] && ctx->physAddr == NULL) ||
	        (pHost->pStringParaValue[LM_HOST_HostNameId] && ctx->hostName == NULL)) {
	        CcspTraceWarning(("Memory allocation failed for physAddr or hostName in %s at line %d\n", __FUNCTION__, __LINE__));
	        free(ctx->ipv4);
	        free(ctx->physAddr);
	        free(ctx->hostName);
	        pthread_mutex_unlock (&LmHostObjectMutex);
	        // Remove this node from the list and free its memory
	        if (prev) {
	            prev->next = curr->next;
	        } else {
	            pNotifyListHead = curr->next;
	        }
	        RetryNotifyHostList *toDelete = curr;
	        curr = curr->next;
	        if (toDelete->ctx) {
	            free(toDelete->ctx);
	        }
	        free(toDelete);
	        continue;
	    }
	    pthread_mutex_unlock (&LmHostObjectMutex);
            if (ctx->ipv4 ) {
                completed = true;
            } else if (++curr->retry_count > IP_MAX_RETRIES) { // Increment the retry_count per host 
                CcspTraceWarning(("Retry limit exceeded for host, removing.\n"));
                completed = true;
            }

            if (completed){
                // If IP addresses are obtained or retry_count exceeded 
                Send_PresenceNotification(
                        ctx->interface,
                        ctx->physAddr,
                        ctx->status,
                        ctx->hostName,
                        ctx->ipv4
                );
                CcspTraceWarning(("Notification sent from %s, line:%d\n", __FUNCTION__, __LINE__));

                // Deletion logic
                if (prev) {
                    prev->next = curr->next;
                } else {
                    // If it is head node
                    pNotifyListHead = curr->next;
                }

                // Delete the node as the notification is sent for the node
                RetryNotifyHostList *toDelete = curr;
                curr = curr->next;

                if (toDelete->ctx) {
		    free(toDelete->ctx->ipv4);
		    free(toDelete->ctx->physAddr);
		    free(toDelete->ctx->hostName);
                    free(toDelete->ctx); // memory allocated for LMPresenceNotifyAddressInfo is freed
                }
                free(toDelete);
            } else {
                prev = curr;
                curr = curr->next; // Move to next host
            }
        }
        // Instead of sleeping outside the mutex, use pthread_cond_timedwait to wait for new items or timeout
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += IP_RETRY_INTERVAL;
        // Only wait if the list is empty after processing
        if (!pNotifyListHead) {
            pthread_cond_timedwait(&LmNotifyCond, &LmRetryNotifyHostListMutex, &ts);
        }
        pthread_mutex_unlock(&LmRetryNotifyHostListMutex);
    }
    return NULL;
}

int Hosts_PresenceHandling(PLmObjectHost pHost, HostPresenceDetection presencestatus)
{
    char buf[8];
    int res;
    BOOL notify_to_webpa = FALSE;
    ClientConnectState status;
    errno_t rc = -1;

    char interface[32] = {0};

    if (!pHost)
        return -1;
    if (HOST_PRESENCE_JOIN == presencestatus)    
    {
        if (!pHost->bBoolParaValue[LM_HOST_PresenceActiveId])
        {
            pHost->ulUlongParaValue[LM_HOST_X_RDK_PresenceActiveLastChange] = time((time_t*)NULL);
            pHost->bBoolParaValue[LM_HOST_PresenceActiveId] = TRUE;
            status = CLIENT_STATE_ONLINE;
        }
        else
        {
            return 0;
        }

    }
    else
    {
        if (pHost->bBoolParaValue[LM_HOST_PresenceActiveId])
        {
            pHost->bBoolParaValue[LM_HOST_PresenceActiveId] = FALSE;
            status = CLIENT_STATE_OFFLINE;
        }
        else
        {
            return 0;
        }
    }
    if (!pHost->bBoolParaValue[LM_HOST_PresenceNotificationEnabledId])
        return -1;

    /*CID: 63335 Array compared against 0*/
    if(!syscfg_get( NULL, "notify_presence_webpa", buf, sizeof(buf)))
    {
        if (strcmp(buf, "true") == 0)
            notify_to_webpa = TRUE;
    } else {
        CcspTraceError(("Error in syscfg_get for notify_presence_webpa"));
    }

    if (notify_to_webpa)
    {

        if(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId] != NULL)
        {
            if((strstr(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],"WiFi"))) {
                rc = strcpy_s(interface, sizeof(interface), "WiFi");
                ERR_CHK(rc);
            }
#if !defined (NO_MOCA_FEATURE_SUPPORT)
            else if ((strstr(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId],"MoCA")))
            {
                rc = strcpy_s(interface, sizeof(interface),"MoCA");
                ERR_CHK(rc);
            }
#endif
            else if (strstr(pHost->pStringParaValue[LM_HOST_Layer1InterfaceId], "Ethernet")) {
                rc = strcpy_s(interface, sizeof(interface), "Ethernet");
                ERR_CHK(rc);
            } else {
                rc = strcpy_s(interface, sizeof(interface), "Other");
                ERR_CHK(rc);
            }
        }

        // Allocate context and populate
        LMPresenceNotifyAddressInfo *ctx = calloc(1, sizeof(LMPresenceNotifyAddressInfo));
        if (!ctx)
            return -1;

        ctx->pHost = pHost;
        strncpy(ctx->interface, interface, sizeof(ctx->interface) - 1);
        ctx->interface[sizeof(ctx->interface) - 1] = '\0'; // ensure null-termination
        ctx->status = status;

        // Push to retry linked list
        RetryNotifyHostList *node = calloc(1, sizeof(RetryNotifyHostList));
        if (!node) {
            free(ctx);
            return -1;
        }
        node->ctx = ctx;

        pthread_mutex_lock(&LmRetryNotifyHostListMutex);
        node->next = pNotifyListHead;
        pNotifyListHead = node;
        pthread_mutex_unlock(&LmRetryNotifyHostListMutex);
        
	// Start worker thread once
        if (!worker_thread_running) {
            CcspTraceWarning(("%s UpdateAndSendHostIPAddress_Thread creation line:%d\n", __FUNCTION__, __LINE__));
            // Start thread to handle IP retry + notification (up to 6 retries at 10-second intervals, totaling 60 seconds)
            res = pthread_create(&NotifyIPMonitorThread, NULL, UpdateAndSendHostIPAddress_Thread, NULL);
	    if (res == 0) {
		pthread_detach(NotifyIPMonitorThread);
		worker_thread_running = true;
		CcspTraceInfo(("%s: Notify thread created and detached successfully\n", __FUNCTION__));
	    } else {
		CcspTraceError(("%s: Failed to create Notify thread (res=%d)\n", __FUNCTION__, res));
		worker_thread_running = false;
	        /* Remove node from the list since thread creation failed */
		pthread_mutex_lock(&LmRetryNotifyHostListMutex);
		if (pNotifyListHead == node) {
		    // node was head
		    pNotifyListHead = node->next;
		} else {
		    // search and unlink
		    RetryNotifyHostList *prev = pNotifyListHead;
		    while (prev && prev->next != node)
			prev = prev->next;
		    if (prev)
			prev->next = node->next;
		}
		pthread_mutex_unlock(&LmRetryNotifyHostListMutex);
		free(node);
		free(ctx);
		return -1;
            }
        }
    }
    return 0;
}


void Update_RFC_Presencedetection(BOOL enablePresenceFeature)
{
    EventQData EventMsg;
    mqd_t mq;
    char buffer[MAX_SIZE];
    errno_t rc = -1;
    mq = mq_open(EVENT_QUEUE_NAME, O_WRONLY);
    CHECK((mqd_t)-1 != mq);
    memset(buffer, 0, MAX_SIZE);
    EventMsg.MsgType = MSG_TYPE_RFC;

    rc = strcpy_s(EventMsg.Msg, sizeof(EventMsg.Msg), ((enablePresenceFeature == TRUE) ? "true" : "false"));
    ERR_CHK(rc);

    memcpy(buffer,&EventMsg,sizeof(EventMsg));
    CHECK(0 <= mq_send(mq, buffer, MAX_SIZE, 0));
    CHECK((mqd_t)-1 != mq_close(mq));
}



void readPresenceFromSyscfg(BOOL * pPresenceEnabled)
{
    char cBuf[8];
    if (NULL == pPresenceEnabled)
    {
        return;
    }
    if (!syscfg_get( NULL, "PresenceDetectEnabled", cBuf, sizeof(cBuf)))
    {
        if (strcmp(cBuf,"true") == 0)
        {
            *pPresenceEnabled = TRUE;
        }
        else
        {
            *pPresenceEnabled = FALSE;
        }
    }
    else
    {
        *pPresenceEnabled = FALSE;
    }
}
