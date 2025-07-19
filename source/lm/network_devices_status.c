/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include <semaphore.h>
#include "network_devices_status.h"
#include "ccsp_lmliteLog_wrapper.h"
#include "network_devices_status_avropack.h"
#include "lm_main.h"
#include "report_common.h"
#include <stdint.h>
#include "webpa_interface.h"
#include "safec_lib_common.h"
#include "secure_wrapper.h"

static pthread_mutex_t ndsMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ndsCond = PTHREAD_COND_INITIALIZER;

#ifdef MLT_ENABLED
#include "rpl_malloc.h"
#include "mlt_malloc.h"
#endif

extern LmObjectHosts lmHosts;
ULONG NetworkDeviceStatusPeriods[] = {5,10,15,30,60,300,900,1800,3600,10800,21600,43200,86400};

ULONG NDSPollingPeriodDefault = DEFAULT_POLLING_INTERVAL;
ULONG NDSReportingPeriodDefault = DEFAULT_REPORTING_INTERVAL;

ULONG NDSPollingPeriod = DEFAULT_POLLING_INTERVAL;
ULONG NDSReportingPeriod = DEFAULT_REPORTING_INTERVAL;

ULONG currentReportingPeriod = 0;
BOOL NDSReportStatus = FALSE;

ULONG NDSOverrideTTL = TTL_INTERVAL;
ULONG NDSOverrideTTLDefault = DEFAULT_TTL_INTERVAL;

#ifndef UTC_ENABLE
int tm_offset = 0;
#endif
void* StartNetworkDeviceStatusHarvesting( void *arg );
#ifndef UTC_ENABLE
static int _syscmd(FILE *f, char *retBuf, int retBufSize);
#endif
void add_to_list(PLmObjectHost host, struct networkdevicestatusdata **head);
static struct networkdevicestatusdata *headnode = NULL;
static struct networkdevicestatusdata *headnodeextender = NULL;

extern pthread_mutex_t LmHostObjectMutex;

// RDKB-9258 : set polling and reporting periods to NVRAM after TTL expiry
extern ANSC_STATUS SetNDSPollingPeriodInNVRAM(ULONG pPollingVal);
extern ANSC_STATUS SetNDSReportingPeriodInNVRAM(ULONG pReportingVal);

#ifndef UTC_ENABLE
int getTimeOffsetFromUtc()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    char timezonearr[32] = {0};
    int ret  = 0,pcloseret = 0;
    FILE *f = NULL;
    f = v_secure_popen("r","dmcli eRT getv Device.Time.TimeOffset | grep value | awk '{print $5}'");
    if(f == NULL)
    {
         CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Parsing Error in popen \n", __FUNCTION__ ));
         return -1;
    }
    ret = _syscmd(f, timezonearr, sizeof(timezonearr));
    pcloseret = v_secure_pclose(f);
    if(pcloseret != 0)
    {
        CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Parsing Error pclose \n", __FUNCTION__ ));
    }
    if(ret)
    {
        CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Executing Syscmd for DMCLI TimeOffset [%d] \n",__FUNCTION__, ret));
        return ret;
    }
    if (sscanf(timezonearr, "%d", &tm_offset) != 1)
    {
        CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Parsing Error for TimeOffset \n", __FUNCTION__ ));
        return -1;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s TimeOffset[%d] EXIT \n", __FUNCTION__, tm_offset ));

    return tm_offset;
}
#endif

char* GetCurrentTimeString()
{
    time_t current_time;
    char* c_time_string;

    /* Obtain current time. */
    current_time = time(NULL);

    /* Convert to local time format. */
    c_time_string = ctime(&current_time);

    return c_time_string;
}


ulong GetCurrentTimeInSecond()
{
    struct timespec ts;
    // get current time in second
    clock_gettime(CLOCK_REALTIME, &ts);
    return (ulong)ts.tv_sec;
}

static void WaitForPthreadConditionTimeoutNDS()
{
    struct timespec _ts;
    struct timespec _now;
    int n;

    memset(&_ts, 0, sizeof(struct timespec));
    memset(&_now, 0, sizeof(struct timespec));

    pthread_mutex_lock(&ndsMutex);

    clock_gettime(CLOCK_REALTIME, &_now);
    _ts.tv_sec = _now.tv_sec + GetNDSPollingPeriod();

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : Waiting for %lu sec\n",__FUNCTION__,GetNDSPollingPeriod()));

    n = pthread_cond_timedwait(&ndsCond, &ndsMutex, &_ts);
    if(n == ETIMEDOUT)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : pthread_cond_timedwait TIMED OUT!!!\n",__FUNCTION__));
    }
    else if (n == 0)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : pthread_cond_timedwait SIGNALLED OK!!!\n",__FUNCTION__));
    }
    else
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : pthread_cond_timedwait ERROR!!!\n",__FUNCTION__));
    }

    pthread_mutex_unlock(&ndsMutex);

}

bool isvalueinarray(ULONG val, ULONG *arr, int size)
{
    int i;
    for (i=0; i < size; i++) {
        if (arr[i] == val)
            return true;
    }
    return false;
}


int SetNDSHarvestingStatus(BOOL status)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : Old[%d] New[%d] \n", __FUNCTION__, NDSReportStatus, status ));

    if (NDSReportStatus != status)
        NDSReportStatus = status;
    else
        return 0;

    if (NDSReportStatus)
    {
        pthread_t tid;

        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : Starting Thread to start DeviceData Harvesting  \n", __FUNCTION__ ));

        if (pthread_create(&tid, NULL, StartNetworkDeviceStatusHarvesting, NULL))
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Failed to Start Thread to start DeviceData Harvesting  \n", __FUNCTION__ ));
            return ANSC_STATUS_FAILURE;
        }
	CcspTraceWarning(("LMLite: Network Status Report STARTED %s\n",__FUNCTION__));
    }
    else
    {
        int ret;
        pthread_mutex_lock(&ndsMutex);
        ret = pthread_cond_signal(&ndsCond);
        pthread_mutex_unlock(&ndsMutex);
        if (ret == 0)
        {
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : pthread_cond_signal success\n", __FUNCTION__ ));
        }
        else
        {
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : pthread_cond_signal fail\n", __FUNCTION__ ));
        }
	CcspTraceWarning(("LMLite: Network Status Report STOPPED %s\n",__FUNCTION__));
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

    return 0;
}

BOOL GetNDSHarvestingStatus()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%d] \n", __FUNCTION__, NDSReportStatus ));
    return NDSReportStatus;
}

int SetNDSReportingPeriod(ULONG period)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT Old[%lu] New[%lu] \n", __FUNCTION__, NDSReportingPeriod, period ));

    if (NDSReportingPeriod != period)
    {
        NDSReportingPeriod = period;
    }
    else
    {
        return 0;
    }

    return 0;
}

ULONG GetNDSReportingPeriod()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%lu] \n", __FUNCTION__, NDSReportingPeriod ));
    return NDSReportingPeriod;
}

int SetNDSPollingPeriod(ULONG period)
{
    int ret;
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s Old[%lu] New[%lu] \n", __FUNCTION__, NDSPollingPeriod, period ));
    if (NDSPollingPeriod != period)
    {
        NDSPollingPeriod = period;
        SetNDSOverrideTTL(GetNDSOverrideTTLDefault());

        pthread_mutex_lock(&ndsMutex);
        currentReportingPeriod = GetNDSReportingPeriod();

        ret = pthread_cond_signal(&ndsCond);
        pthread_mutex_unlock(&ndsMutex);
        if (ret == 0)
        {
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : pthread_cond_signal success\n",__FUNCTION__));
        }
        else
        {
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : pthread_cond_signal fail\n",__FUNCTION__));
        }
    }

    return 0;
}

BOOL ValidateNDSPeriod(ULONG period)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    BOOL ret = FALSE;
    ret = isvalueinarray(period, NetworkDeviceStatusPeriods, ARRAY_SZ(NetworkDeviceStatusPeriods));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%d] \n", __FUNCTION__ , ret ));
    return ret;
} 

ULONG GetNDSPollingPeriod()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%lu] \n", __FUNCTION__, NDSPollingPeriod ));
    return NDSPollingPeriod;
}

ULONG SetNDSReportingPeriodDefault(ULONG period)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT Old[%lu] New[%lu] \n", __FUNCTION__, NDSReportingPeriodDefault, period ));

    if(NDSReportingPeriodDefault != period)
    {
       NDSReportingPeriodDefault = period;
    }
    else
    {
        return 0;
    }
    return 0;
}

ULONG GetNDSReportingPeriodDefault()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%lu] \n", __FUNCTION__, NDSReportingPeriodDefault ));
    return NDSReportingPeriodDefault;
}

ULONG SetNDSPollingPeriodDefault(ULONG period)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT Old[%lu] New[%lu] \n", __FUNCTION__, NDSPollingPeriodDefault, period ));

    if(NDSPollingPeriodDefault != period)
    {
        NDSPollingPeriodDefault = period;
    }
    else
    {
        return 0;
    }
    return 0;
}

ULONG GetNDSPollingPeriodDefault()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%lu] \n", __FUNCTION__, NDSPollingPeriodDefault ));
    return NDSPollingPeriodDefault;
}

ULONG GetNDSOverrideTTLDefault()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%lu] \n", __FUNCTION__, NDSOverrideTTLDefault ));
    return NDSOverrideTTLDefault;
}

ULONG GetNDSOverrideTTL()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%lu] \n", __FUNCTION__, NDSOverrideTTL ));
    return NDSOverrideTTL;
}

int SetNDSOverrideTTL(ULONG ttl)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%lu] \n", __FUNCTION__, NDSOverrideTTL ));
    NDSOverrideTTL = ttl;
    return 0;
}

#ifndef UTC_ENABLE
static int _syscmd(FILE *f, char *retBuf, int retBufSize)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));

    char *ptr = retBuf;
    int bufSize = retBufSize, bufbytes = 0, readbytes = 0;

    if (f == NULL) {
        CcspLMLiteTrace(("RDK_LOG_DEBUG, LMLite %s : popen %s error\n",__FUNCTION__, cmd));
        return -1;
    }

    while (!feof(f))
    {
        *ptr = 0;
        if (bufSize >= 128) {
            bufbytes = 128;
        } else {
            bufbytes = bufSize - 1;
        }

        fgets(ptr, bufbytes, f);
        readbytes = strlen(ptr);
        if ( readbytes == 0)
            break;
        bufSize -= readbytes;
        ptr += readbytes;
    }
    retBuf[retBufSize - 1] = 0;

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT\n", __FUNCTION__ ));

    return 0;
}
#endif

char* NDS_GetIpAddress(PLmObjectHost host)
{
    PLmObjectHostIPAddress pIpAddrList;
    size_t ipv4_len;
    size_t ipv6_index1_len;
    size_t ipv6_index3_len;
    size_t total_len;
    char *pIpv4address = NULL;
    char *pIpv6addressindex1 = NULL;
    char *pIpv6addressindex3 = NULL;

    if (!host)
        return strdup("Unknown");

    // By default PLmObjectHost pStringParaValue ipaddress holds ipv4 address.
    if(host->pStringParaValue[LM_HOST_IPAddressId])
    {
        pIpv4address = host->pStringParaValue[LM_HOST_IPAddressId];
    }

    if ((!host->ipv6Active) && (!pIpv4address))
        return strdup("Unknown");

    /*
     * Get 1st instance ipv6 address ( pass index value 2 to get first instance ipv6 address ,
     * because linked list stored in stack order hence first instance store last index)
    */
    pIpAddrList = LM_GetIPArr_FromIndex(host,2,IP_V6);
    if (pIpAddrList)
    {
        if (pIpAddrList->pStringParaValue[LM_HOST_IPAddress_IPAddressId])
        {
            char* ipadd = pIpAddrList->pStringParaValue[LM_HOST_IPAddress_IPAddressId];
            if (strcmp(ipadd," ") && strcmp(ipadd,"EMPTY"))
            {
                pIpv6addressindex1 = ipadd;
            }
        }
    }

    /*
     * If valid ipv6 not found in 1st instance then check 3rd instance
     * Get 3rd instance ipv6 address ( pass index value 0 to get 3rd instance ipv6 address ,
     * because linked list stored in stack order hence last instance store first index)
    */
    pIpAddrList = LM_GetIPArr_FromIndex(host,0,IP_V6);
    if (pIpAddrList)
    {
        if (pIpAddrList->pStringParaValue[LM_HOST_IPAddress_IPAddressId])
        {
            char* ipadd = pIpAddrList->pStringParaValue[LM_HOST_IPAddress_IPAddressId];
            if (strcmp(ipadd," ") && strcmp(ipadd,"EMPTY"))
            {
                pIpv6addressindex3 = ipadd;
            }
        }
    }

    ipv4_len = pIpv4address ? strlen(pIpv4address) : 0;
    ipv6_index1_len = pIpv6addressindex1 ? strlen(pIpv6addressindex1) : 0;
    ipv6_index3_len = pIpv6addressindex3 ? strlen(pIpv6addressindex3) : 0;

    total_len = ipv4_len + ipv6_index1_len + ipv6_index3_len;

    // Below logic to send ipv4, ipv6 index1 and index3 together with delimeter space.
    if (total_len > 0)
    {
        char *dest = malloc(total_len + 3);

        if (dest)
        {
            char *d = dest;

            *d = 0;

            if (ipv4_len)
            {
                memcpy(d, pIpv4address, ipv4_len);
                d[ipv4_len] = ' ';
                d += ipv4_len + 1;
            }

            if (ipv6_index1_len)
            {
                memcpy(d, pIpv6addressindex1, ipv6_index1_len);
                d[ipv6_index1_len] = ' ';
                d += ipv6_index1_len + 1;
            }

            if (ipv6_index3_len)
            {
                memcpy(d, pIpv6addressindex3, ipv6_index3_len);
                d[ipv6_index3_len] = ' ';
                d += ipv6_index3_len + 1;
            }

            if (d > dest)
                d[-1] = 0;

            return dest;
        }
    }

    return strdup("Unknown");
}

void add_to_list(PLmObjectHost host, struct networkdevicestatusdata **head)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));

    struct networkdevicestatusdata *ptr = malloc(sizeof(*ptr));
    if (ptr == NULL)
    {
        CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s :  Linked List Allocation Failed \n", __FUNCTION__ ));
        return;
    }
    else
    {
        ptr->device_mac = strdup(host->pStringParaValue[LM_HOST_PhysAddressId]);
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, DeviceMAC[%s] \n",ptr->device_mac ));

        if(host->pStringParaValue[LM_HOST_Layer1InterfaceId])
                ptr->interface_name = strdup(host->pStringParaValue[LM_HOST_Layer1InterfaceId]);
        else
                ptr->interface_name = strdup("Unknown");

        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, InterfaceName[%s] \n",ptr->interface_name ));
        ptr->is_active = host->bBoolParaValue[LM_HOST_ActiveId];
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Active[%d] \n",ptr->is_active ));
        ptr->next = NULL;
        gettimeofday(&(ptr->timestamp), NULL);
#ifndef UTC_ENABLE
        ptr->timestamp.tv_sec -= tm_offset;
#endif
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Timestamp[%u] \n", (unsigned int)ptr->timestamp.tv_sec ));

         if(host->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Parent])
                ptr->parent = strdup(host->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Parent]);
        else
                ptr->parent = strdup("Unknown");

        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Parent[%s] \n",ptr->parent ));

         if(host->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_DeviceType])
                ptr->device_type = strdup(host->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_DeviceType]);
        else
                ptr->device_type = strdup("Unknown");
                       
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, DeviceType[%s] \n",ptr->device_type ));

        if(host->pStringParaValue[LM_HOST_HostNameId])
                ptr->hostname = strdup(host->pStringParaValue[LM_HOST_HostNameId]);
        else
                ptr->hostname = strdup("Unknown");

	CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, HostName[%s] \n",ptr->hostname ));

    
        ptr->ipaddress = NDS_GetIpAddress(host);;

        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, IPAddress[%s] \n",ptr->ipaddress ));


        if (*head == NULL)
        {
            *head = ptr;
        }
        else
        {
            struct networkdevicestatusdata *prevnode, *currnode;

            // transverse to end of list and append new list
            prevnode = *head;
            currnode = (*head)->next;
            while ( currnode != NULL)
            {
                prevnode = currnode;
                currnode = currnode->next;
            };
            prevnode->next = ptr; // add to list
        }
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT\n", __FUNCTION__ ));

    return;
}

void print_list(struct networkdevicestatusdata *head)
{
    int z = 0;
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    struct networkdevicestatusdata  *ptr = head;
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Head Ptr [%lx]\n", (ulong)head));
    while (ptr != NULL)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : Head Ptr [%lx] TimeStamp[%d] for Node[%d] with SSID[%s] \n", __FUNCTION__ ,(ulong)ptr, (int)ptr->timestamp.tv_sec, z, ptr->device_mac));
        ptr = ptr->next;
        z++;
    }
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT \n", __FUNCTION__ ));
    return;
}

/* Function to delete the entire linked list */
void delete_list(struct networkdevicestatusdata **head)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));

    struct networkdevicestatusdata* currnode = *head;
    struct networkdevicestatusdata* next = NULL;

    while (currnode != NULL)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : Deleting ND Node Head Ptr [%lx] with SSID[%s] \n",__FUNCTION__, (ulong)currnode, currnode->device_mac));
        next = currnode->next;
        free(currnode->device_mac);
        currnode->device_mac = NULL;
        free(currnode->interface_name);
        currnode->interface_name = NULL;
        free(currnode->parent);
        currnode->parent = NULL;
        free(currnode->device_type);
        currnode->device_type = NULL;        
        free(currnode->hostname);
        currnode->hostname = NULL;
        free(currnode->ipaddress);
        currnode->ipaddress = NULL;
        free(currnode);
        currnode=NULL;
        currnode = next;
    }
    
    *head = NULL;
    
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT \n", __FUNCTION__ ));

    return;
}

void GetLMHostData()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    int i = 0;
    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    int array_size = lmHosts.numHost;
    if (array_size)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Hosts Array Size is %d \n", array_size));

        for(i = 0; i < array_size; i++)
        {

            int LeaseTimeRemaining = lmHosts.hostArray[i]->LeaseTime - time(NULL);
            //CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LeaseTime [%d]  CurrentTime[%d] LeaseTimeRemaining [%d] \n", lmHosts.hostArray[i]->LeaseTime, time(NULL), LeaseTimeRemaining));
            //CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, AddressSource [%s] \n", lmHosts.hostArray[i]->pStringParaValue[LM_HOST_AddressSource]));
            
            //CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, bClientReady [%d] \n", lmHosts.hostArray[i]->bClientReady ));
	    //CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, ipv4Active [%d] \n", lmHosts.hostArray[i]->ipv4Active ));

            if (lmHosts.hostArray[i]->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Parent] != NULL)
                {
                    /*CID: 125016 Invalid type in argument to printf format specifier*/
                    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Parent [%s] \n", lmHosts.hostArray[i]->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Parent]));
                }
            else
                {
                    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Parent pointer is NULL \n"));
                }

            //printf("RDK_LOG_DEBUG, bClientReady [%d] \n", lmHosts.hostArray[i]->bClientReady);

	    if ( (!lmHosts.hostArray[i]->bClientReady) && (!strcmp(lmHosts.hostArray[i]->pStringParaValue[LM_HOST_AddressSource], "DHCP")) && ( LeaseTimeRemaining <= 0 ) && ((lmHosts.hostArray[i]->ipv4Active) || (lmHosts.hostArray[i]->ipv6Active)))
                continue;

            if (lmHosts.hostArray[i]->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Parent] != NULL)
            {
                if(!strcasecmp(lmHosts.hostArray[i]->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_Parent], (const char *)getFullDeviceMac()))
                    {
                        add_to_list(lmHosts.hostArray[i], &headnode);
                    }
                else
                    {
                        add_to_list(lmHosts.hostArray[i], &headnodeextender);
                    }
            }
            else
            {
                add_to_list(lmHosts.hostArray[i], &headnode);
            }

        }
        
        print_list(headnode);
        print_list(headnodeextender);

    } // end of if statement
    else
    {
        CcspLMLiteTrace(("RDK_LOG_DEBUG, LMLite %s array_size [%d] \n",__FUNCTION__, array_size));
    } 

    pthread_mutex_unlock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT \n", __FUNCTION__ ));
}

void ResetNDSReportingConfiguration()
{
    SetNDSPollingPeriod(GetNDSPollingPeriodDefault());
    SetNDSReportingPeriod(GetNDSReportingPeriodDefault());
    SetNDSOverrideTTL(GetNDSOverrideTTLDefault());
    currentReportingPeriod = 0;
    nds_avro_cleanup(); // AVRO Clean up 
}

void* StartNetworkDeviceStatusHarvesting( void *arg )
{
    UNREFERENCED_PARAMETER(arg);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER \n", __FUNCTION__ ));

	ULONG uDefaultVal = 0;

    currentReportingPeriod = GetNDSReportingPeriod();
#ifndef UTC_ENABLE
    getTimeOffsetFromUtc();
#endif

    if(GetNDSOverrideTTL() < currentReportingPeriod)
    {
         SetNDSOverrideTTL(currentReportingPeriod);
    }

    do 
    {
        GetLMHostData();
        currentReportingPeriod = currentReportingPeriod + GetNDSPollingPeriod();

        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Before Sending to WebPA and AVRO currentReportingPeriod [%ld] GetNDSReportingPeriod()[%ld]  \n", currentReportingPeriod, GetNDSReportingPeriod()));

        if (currentReportingPeriod >= GetNDSReportingPeriod())
        {
            struct networkdevicestatusdata* ptr = headnode;
            if(ptr)
                {
                    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Before Sending to WebPA and AVRO currentPollingPeriod [%ld] NDSReportingPeriod[%ld]  \n", GetNDSPollingPeriod(), GetNDSReportingPeriod()));
                    network_devices_status_report(ptr, FALSE, (char *)getFullDeviceMac());
                    delete_list(&headnode);
                }

            ptr = headnodeextender;
            if(ptr)
                {
                    int i = 0;
                    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Before Sending to WebPA and AVRO currentPollingPeriod [%ld] NDSReportingPeriod[%ld]  \n", GetNDSPollingPeriod(), GetNDSReportingPeriod()));
                    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
                    pthread_mutex_lock(&LmHostObjectMutex);
                    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
                    int array_size = lmHosts.numHost;
                    if (array_size)
                    {
                        for(i = 0; i < array_size; i++)
                        {
                            if((lmHosts.hostArray[i]->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_DeviceType] != NULL) && !strcmp(lmHosts.hostArray[i]->pStringParaValue[LM_HOST_X_RDKCENTRAL_COM_DeviceType], "extender"))
                                {
                                    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Before Calling network_devices_status_report with Extender [%s] \n", lmHosts.hostArray[i]->pStringParaValue[LM_HOST_PhysAddressId] ));
                                    network_devices_status_report(ptr, TRUE, lmHosts.hostArray[i]->pStringParaValue[LM_HOST_PhysAddressId]);
                                }
                        }
                    }

                    pthread_mutex_unlock(&LmHostObjectMutex);
                    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
                    delete_list(&headnodeextender);
                }

            currentReportingPeriod = 0;
        }


        
        if(!GetNDSOverrideTTL())
        {
            uDefaultVal = GetNDSPollingPeriodDefault();
            SetNDSPollingPeriod( uDefaultVal );
            //RDKB-9258 : Saving polling period to NVRAM.
            SetNDSPollingPeriodInNVRAM( uDefaultVal );

            uDefaultVal = GetNDSReportingPeriodDefault();
            SetNDSReportingPeriod( uDefaultVal );
            //RDKB-9258 : Saving reporting period to NVRAM.
            SetNDSReportingPeriodInNVRAM( uDefaultVal );

            SetNDSOverrideTTL(GetNDSOverrideTTLDefault());
        }

        if(GetNDSOverrideTTL())
        {
            SetNDSOverrideTTL(GetNDSOverrideTTL() - GetNDSPollingPeriod());
        }

        WaitForPthreadConditionTimeoutNDS();

        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, GetNDSPollingPeriod[%ld]\n", GetNDSPollingPeriod()));

    } while (GetNDSHarvestingStatus());
    
    ResetNDSReportingConfiguration();

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT \n", __FUNCTION__ ));

    return NULL; // shouldn't return;
}

// End of File

