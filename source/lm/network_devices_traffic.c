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
#include "network_devices_traffic.h"
#include "ccsp_lmliteLog_wrapper.h"
#include "network_devices_traffic_avropack.h"
#include "lm_main.h"
#include "report_common.h"
#include "secure_wrapper.h"

static pthread_mutex_t ndtMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ndtCond = PTHREAD_COND_INITIALIZER;


#ifdef MLT_ENABLED
#include "rpl_malloc.h"
#include "mlt_malloc.h"
#endif

#ifndef UTC_ENABLE
extern int tm_offset;
#endif

ULONG NetworkDeviceTrafficPeriods[] = {30,60,300,900,1800,3600,10800,21600,43200,86400};

ULONG NDTPollingPeriodDefault = DEFAULT_TRAFFIC_POLLING_INTERVAL;
ULONG NDTReportingPeriodDefault = DEFAULT_TRAFFIC_REPORTING_INTERVAL;

ULONG NDTPollingPeriod = DEFAULT_TRAFFIC_POLLING_INTERVAL;
ULONG NDTReportingPeriod = DEFAULT_TRAFFIC_REPORTING_INTERVAL;

ULONG currentNDTReportingPeriod = 0;
BOOL NDTReportStatus = FALSE;

ULONG NDTOverrideTTL = TTL_INTERVAL;
ULONG NDTOverrideTTLDefault = DEFAULT_TTL_INTERVAL;

struct timeval reset_timestamp;

void* StartNetworkDevicesTrafficHarvesting( void *arg );
#if 0
static int _syscmd_ndt(char *cmd, char *retBuf, int retBufSize);
#endif

#ifndef UTC_ENABLE
extern int getTimeOffsetFromUtc();
#endif

#ifdef UNIT_TEST_DOCKER_SUPPORT
#define STATIC
#else
#define STATIC static
#endif

STATIC struct networkdevicetrafficdata *headnode = NULL;
STATIC struct networkdevicetrafficdata *currnode = NULL;

// RDKB-9258 : set polling and reporting periods to NVRAM after TTL expiry
extern ANSC_STATUS SetNDTPollingPeriodInNVRAM(ULONG pPollingVal);
extern ANSC_STATUS SetNDTReportingPeriodInNVRAM(ULONG pReportingVal);


static void WaitForPthreadConditionTimeoutNDT()
{
    struct timespec _ts;
    struct timespec _now;
    int n;

    memset(&_ts, 0, sizeof(struct timespec));
    memset(&_now, 0, sizeof(struct timespec));

    pthread_mutex_lock(&ndtMutex);

    clock_gettime(CLOCK_REALTIME, &_now);
    _ts.tv_sec = _now.tv_sec + GetNDTPollingPeriod();

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : Waiting for %lu sec\n",__FUNCTION__,GetNDTPollingPeriod()));

    n = pthread_cond_timedwait(&ndtCond, &ndtMutex, &_ts);
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

    pthread_mutex_unlock(&ndtMutex);

}

bool isvalueinarray_ndt(ULONG val, ULONG *arr, int size)
{
    int i;
    for (i=0; i < size; i++) {
        if (arr[i] == val)
            return true;
    }
    return false;
}

int ResetEBTables()
{
    int ret  = 0;
    ret = v_secure_system("/usr/ccsp/tad/rxtx_sta.sh > /dev/null");

    if(ret)
    {
        CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Executing Syscmd for RXTX STA shell script failed. ret:[%d] \n",__FUNCTION__, ret));
        return -1;
    }
    else
    {
        gettimeofday(&(reset_timestamp), NULL);
#ifndef UTC_ENABLE
        reset_timestamp.tv_sec -= tm_offset;
#endif
        CcspLMLiteTrace(("RDK_LOG_DEBUG, LMLite %s : Executing Syscmd for RXTX STA shell script [%d] \n",__FUNCTION__, ret));

        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s Reset Timestamp[%lu] \n", __FUNCTION__, reset_timestamp.tv_sec ));

        return 0;
    }
}

int SetNDTHarvestingStatus(BOOL status)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : Old[%d] New[%d] \n", __FUNCTION__, NDTReportStatus, status ));

    if (NDTReportStatus != status)
        NDTReportStatus = status;
    else
        return 0;

    if (NDTReportStatus)
    {
        pthread_t tid;

        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : Starting Thread to start DeviceData Harvesting  \n", __FUNCTION__ ));

        if (pthread_create(&tid, NULL, StartNetworkDevicesTrafficHarvesting, NULL))
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Failed to Start Thread to start DeviceData Harvesting  \n", __FUNCTION__ ));
            return ANSC_STATUS_FAILURE;
        }
	CcspTraceWarning(("LMLite: Network Traffic Report STARTED %s\n",__FUNCTION__));
    }
    else
    {
        int ret;
        pthread_mutex_lock(&ndtMutex);
        ret = pthread_cond_signal(&ndtCond);
        pthread_mutex_unlock(&ndtMutex);
        if (ret == 0)
        {
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : pthread_cond_signal success\n", __FUNCTION__ ));
        }
        else
        {
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : pthread_cond_signal fail\n", __FUNCTION__ ));
        }
	CcspTraceWarning(("LMLite: Network Traffic Report STOPPED %s\n",__FUNCTION__));
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

    return 0;
}

BOOL GetNDTHarvestingStatus()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%d] \n", __FUNCTION__, NDTReportStatus ));
    return NDTReportStatus;
}

int SetNDTReportingPeriod(ULONG period)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT Old[%lu] New[%lu] \n", __FUNCTION__, NDTReportingPeriod, period ));
    if (NDTReportingPeriod != period)
    {
        NDTReportingPeriod = period;
    }
    else
    {
        return 0;
    }

    return 0;
}

ULONG GetNDTReportingPeriod()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%lu] \n", __FUNCTION__, NDTReportingPeriod ));
    return NDTReportingPeriod;
}

int SetNDTPollingPeriod(ULONG period)
{
    int ret;
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s Old[%lu] New[%lu] \n", __FUNCTION__, NDTPollingPeriod, period ));
    if (NDTPollingPeriod != period)
    {
        NDTPollingPeriod = period;
        SetNDTOverrideTTL(GetNDTOverrideTTLDefault());

        pthread_mutex_lock(&ndtMutex);
        currentNDTReportingPeriod = GetNDTReportingPeriod();

        ret = pthread_cond_signal(&ndtCond);
        pthread_mutex_unlock(&ndtMutex);
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

BOOL ValidateNDTPeriod(ULONG period)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    BOOL ret = FALSE;
    ret = isvalueinarray_ndt(period, NetworkDeviceTrafficPeriods, ARRAY_SZ(NetworkDeviceTrafficPeriods));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%d] \n", __FUNCTION__ , ret ));
    return ret;
} 

ULONG GetNDTPollingPeriod()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%lu] \n", __FUNCTION__, NDTPollingPeriod ));
    return NDTPollingPeriod;
}

ULONG SetNDTReportingPeriodDefault(ULONG period)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT Old[%lu] New[%lu] \n", __FUNCTION__, NDTReportingPeriodDefault, period ));

    if(NDTReportingPeriodDefault != period)
    {
       NDTReportingPeriodDefault = period;
    }
    else
    {
        return 0;
    }
    return 0;
}

ULONG GetNDTReportingPeriodDefault()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%lu] \n", __FUNCTION__, NDTReportingPeriodDefault ));
    return NDTReportingPeriodDefault;
}

ULONG SetNDTPollingPeriodDefault(ULONG period)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT Old[%lu] New[%lu] \n", __FUNCTION__, NDTPollingPeriodDefault, period ));

   if(NDTPollingPeriodDefault != period)
    {
        NDTPollingPeriodDefault = period;
    }
    else
    {
        return 0;
    }
    return 0;
}

ULONG GetNDTPollingPeriodDefault()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%lu] \n", __FUNCTION__, NDTPollingPeriodDefault ));
    return NDTPollingPeriodDefault;
}

ULONG GetNDTOverrideTTLDefault()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%lu] \n", __FUNCTION__, NDTOverrideTTLDefault ));
    return NDTOverrideTTLDefault;
}

ULONG GetNDTOverrideTTL()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%lu] \n", __FUNCTION__, NDTOverrideTTL ));
    return NDTOverrideTTL;
}

int SetNDTOverrideTTL(ULONG ttl)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT RET[%lu] \n", __FUNCTION__, NDTOverrideTTL ));
    NDTOverrideTTL = ttl;
    return 0;
}

#if 0
static int _syscmd_ndt(char *cmd, char *retBuf, int retBufSize)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));

    FILE *f;
    char *ptr = retBuf;
    int bufSize = retBufSize, bufbytes = 0, readbytes = 0;

    if ((f = popen(cmd, "r")) == NULL) {
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
    pclose(f);
    retBuf[retBufSize - 1] = 0;

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT\n", __FUNCTION__ ));

    return 0;
}
#endif

void add_to_list_ndt(char* ip_table_line)
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));

    char * st = NULL;
    const char * delim = "|";
    long long rx_packets = 0, tx_packets = 0;
    /*CID: 61764 Uninitialized scalar variable*/
    long long external_bytes_down = 0, external_bytes_up = 0;
    char *device_mac = NULL, *rx_packets_str = NULL, *external_bytes_down_str = NULL, *tx_packets_str = NULL, *external_bytes_up_str = NULL;
    struct networkdevicetrafficdata *ptr = NULL;

    device_mac = strtok_r(ip_table_line, delim, &st);
    if (!device_mac)
    {
	    CcspLMLiteTrace(("RDK_LOG_ERROR, DeviceMAC is NULL \n"));
	    return;
    }
    rx_packets_str =  strtok_r(NULL, delim, &st);
    if (rx_packets_str) 
    {
	    external_bytes_down_str = strtok_r(NULL, delim, &st);
	    if (external_bytes_down_str) 
	    {
		    tx_packets_str =  strtok_r(NULL, delim, &st);
		    if (tx_packets_str)
		    {
			    external_bytes_up_str = strtok_r(NULL, delim, &st);
		    }
	    }
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, DeviceMAC[%s] \n", device_mac ));

    if(rx_packets_str)
    {
	    rx_packets = atoll(rx_packets_str);
	    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, rx_packets[%lld] \n",rx_packets ));
    }

    if(external_bytes_down_str)
    {
	    external_bytes_down = atoll(external_bytes_down_str);
	    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, external_bytes_down[%lld] \n",external_bytes_down ));
    }

    if(tx_packets_str)
    {
	    tx_packets = atoll(tx_packets_str);
	    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, tx_packets [%lld] \n", tx_packets ));
    }

    if(external_bytes_up_str)
    {
	    external_bytes_up = atoll(external_bytes_up_str);
	    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, external_bytes_up[%lld] \n", external_bytes_up ));
    }

    ptr = malloc(sizeof(*ptr));
    if (ptr == NULL)
    {
       CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s :  Linked List Allocation Failed \n", __FUNCTION__ ));
       return;
    }

    gettimeofday(&(ptr->timestamp), NULL);
#ifndef UTC_ENABLE
    ptr->timestamp.tv_sec -= tm_offset;
#endif
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Timestamp[%lu] \n",ptr->timestamp.tv_sec ));

    ptr->device_mac = strdup(device_mac);
    /*CID: 73300 Logically dead code - returns at LINE NUM 418 if the device_mac ==NULL*/

    ptr->external_bytes_down = external_bytes_down;

    ptr->external_bytes_up = external_bytes_up;

    ptr->parent = strdup(NDT_DEFAULT_PARENT_MAC);

    ptr->device_type = strdup(NDT_DEFAULT_DEVICE_TYPE);

    ptr->next = NULL;

    if (headnode == NULL)
    {
        headnode = currnode = ptr;
    }
    else
    {
        currnode->next = ptr;
        currnode = ptr;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT\n", __FUNCTION__ ));

    return;
}

void print_list_ndt()
{
    int z = 0;
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    struct networkdevicetrafficdata  *ptr = headnode;
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Head Ptr [%lx]\n", (ulong)headnode));
    while (ptr != NULL)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : Head Ptr [%lx] TimeStamp[%d] for Node[%d] with DeviceMAC[%s] \n", __FUNCTION__ ,(ulong)ptr, (int)ptr->timestamp.tv_sec, z, ptr->device_mac));
        ptr = ptr->next;
        z++;
    }
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT \n", __FUNCTION__ ));
    return;
}

/* Function to delete the entire linked list */
void delete_list_ndt()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));

    currnode = headnode;
    struct networkdevicetrafficdata* next = NULL;

    while (currnode != NULL)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : Deleting ND Node Head Ptr [%lx] with SSID[%s] \n",__FUNCTION__, (ulong)currnode, currnode->device_mac));
        next = currnode->next;
        free(currnode->device_mac);
        free(currnode->parent);
        free(currnode->device_type);                
        free(currnode);
        currnode = next;
    }
    headnode = currnode = NULL;
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT \n", __FUNCTION__ ));

    return;
}

/* RDKB-6434 : Keep previous poll entries */
/* Function to delete the selected entries in headnode */
void delete_partial_list_ndt()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));

    struct networkdevicetrafficdata *list = headnode;
    time_t last_timestamp = 0;
    struct networkdevicetrafficdata* next = NULL;
    struct networkdevicetrafficdata* prev = NULL;

    if( currnode!=NULL )
	last_timestamp = currnode->timestamp.tv_sec;

    while (list != NULL)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : Deleting ND Node Head Ptr [%lx] with SSID[%s],timestamp[%u] \n",__FUNCTION__, (ulong)list, ( list ?  ( list->device_mac ?  list->device_mac : "NULL" ) : "LIST NULL" ), (unsigned int)list->timestamp.tv_sec));

        next = list->next;
	
	// retain the entries with timestamp from last polling cycle 
	if( list->timestamp.tv_sec != last_timestamp )
	{
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : Deleting node [%lx] with SSID[%s] \n",__FUNCTION__, (ulong)list, ( list ?  ( list->device_mac ?  list->device_mac : "NULL" ) : "LIST NULL" ) ));
        	free(list->device_mac);
        	list->device_mac = NULL;
        	free(list->parent);
        	list->parent = NULL;
        	free(list->device_type); 
        	list->device_type = NULL;               
                /*CID 340771 Unused value fix */
		free(list);
		if( prev!= NULL )
			prev->next = next;
	}
	else
	{
             CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : Last polled timestamp [%lx] with SSID[%s] \n",__FUNCTION__, (ulong)list, ( list ?  ( list->device_mac ?  list->device_mac : "NULL" ) : "LIST NULL" )));
		if( prev == NULL )
			headnode = list;
		prev = list;
	}

       	list = next;
    }//while
	if( prev!=NULL )
		currnode = prev;
	else{
    	    headnode = currnode = NULL;
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : Deleted all nodes",__FUNCTION__));
	}
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT \n", __FUNCTION__ ));
	
    return;
}

void GetIPTableData()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));
    char ip_table_line[256];
    FILE *fp = NULL;

    int ret  = 0;
    ret = v_secure_system("/usr/ccsp/tad/rxtx_cur.sh > /dev/null");

    if(ret)
    {
        CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Executing Syscmd for RXTX Cur shell script failed. ret:[%d] \n",__FUNCTION__, ret));
        return;
    }

    fp = fopen("/tmp/rxtx_cur.txt" , "r");
    if(!fp)
    {
        CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Error Opening File /tmp/rxtx_cur.txt \n",__FUNCTION__));
        return;
    }

    while (fgets(ip_table_line, 256, fp) != NULL)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Read Line from IP Table File is %s \n", ip_table_line));
        add_to_list_ndt(ip_table_line);
    }

    fclose(fp);

    print_list_ndt();

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT \n", __FUNCTION__ ));
}




void* StartNetworkDevicesTrafficHarvesting( void *arg )
{
    UNREFERENCED_PARAMETER(arg);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER \n", __FUNCTION__ ));

    ULONG uDefaultVal = 0;
	
    currentNDTReportingPeriod = GetNDTReportingPeriod();
#ifndef UTC_ENABLE
    getTimeOffsetFromUtc();
#endif

    if(GetNDTOverrideTTL() < currentNDTReportingPeriod)
    {
        SetNDTOverrideTTL(currentNDTReportingPeriod);
    }

    int ret = ResetEBTables();
    if(ret)
    {
        CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Failed to Reset EBTables  \n", __FUNCTION__ ));
    }

    do 
    {
        GetIPTableData();
        currentNDTReportingPeriod = currentNDTReportingPeriod + GetNDTPollingPeriod();

        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Before Sending to WebPA and AVRO currentNDTReportingPeriod [%ld] GetNDTReportingPeriod()[%ld]  \n", currentNDTReportingPeriod, GetNDTReportingPeriod()));

        if (currentNDTReportingPeriod >= GetNDTReportingPeriod())
        {
            struct networkdevicetrafficdata* ptr = headnode;
            if(ptr)
                {
                    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Before Sending to WebPA and AVRO NDTReportingPeriod[%ld]  \n", GetNDTReportingPeriod()));
                    network_devices_traffic_report(ptr, &reset_timestamp);
		    /* RDKB-7047 : Cleanup of headnode after report is sent */
    		    //delete_list_ndt();
		    /* RDKB-6434 : Keep previous polling entries */
	  	    // headnode needs to be cleanedup,retain the last poll entries
		    delete_partial_list_ndt();
                }
            currentNDTReportingPeriod = 0;
        }
        
        if(!GetNDTOverrideTTL())
        {
            //Polling
            uDefaultVal = GetNDTPollingPeriodDefault();
            SetNDTPollingPeriod( uDefaultVal );
            //RDKB-9258  
            //Saving polling period to NVRAM.
            SetNDTPollingPeriodInNVRAM( uDefaultVal );

            //Reporting
            uDefaultVal = GetNDTReportingPeriodDefault();
            SetNDTReportingPeriod( uDefaultVal );
            //RDKB-9258  
            //Saving reporting period to NVRAM.
            SetNDTReportingPeriodInNVRAM( uDefaultVal );

            //TTL
            SetNDTOverrideTTL(GetNDTOverrideTTLDefault());
        }

        if(GetNDTOverrideTTL())
        {
            SetNDTOverrideTTL(GetNDTOverrideTTL() - GetNDTPollingPeriod());
        }

        WaitForPthreadConditionTimeoutNDT();

        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, GetNDTPollingPeriod[%ld]\n", GetNDTPollingPeriod()));

    } while (GetNDTHarvestingStatus());
    
    delete_list_ndt();
     ndt_avro_cleanup();
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT \n", __FUNCTION__ ));

    return NULL; // shouldn't return;
}

// End of File

