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
#include "network_devices_interface.h"
#include "ccsp_lmliteLog_wrapper.h"
#include "lm_main.h"
#include "report_common.h"
#include <stdint.h>

extern pthread_mutex_t LmHostObjectMutex;


int Hosts_InitPresenceDetection()
{
    int ret = 0;
    ret = PresenceDetection_Init();
    return ret;
}

int Hosts_DeInitPresenceDetection()
{
    int ret = 0;
    ret = PresenceDetection_DeInit();
    return ret;
}

int Hosts_StartPresenceDetection()
{
    PresenceDetection_Start();
    return 0;
}

int Hosts_StopPresenceDetection()
{
    PresenceDetection_Stop();
    return 0;
}


int Hosts_UpdatePresenceDetectionParam(LmHostPresenceDetectionParam *pParam, HostPresenceParamUpdate flag)
{
    if (!pParam)
        return -1;

    /*CID 340068 340170 340335 340421 340402 Data race condition*/
    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));

    switch (flag)
    {
        case HOST_PRESENCE_IPV4_ARP_LEAVE_INTERVAL:
        {
            PresenceDetection_set_ipv4leaveinterval(pParam->ipv4CheckInterval);
        }
        break;
        case HOST_PRESENCE_IPV6_ARP_LEAVE_INTERVAL:
        {
            PresenceDetection_set_ipv6leaveinterval(pParam->ipv6CheckInterval);
        }
        break;
        case HOST_PRESENCE_IPV4_RETRY_COUNT:
        {
            PresenceDetection_set_ipv4retrycount(pParam->ipv4RetryCount);
        }
        break;
        case HOST_PRESENCE_IPV6_RETRY_COUNT:
        {
            PresenceDetection_set_ipv6retrycount(pParam->ipv6RetryCount);
        }
        break;
        case HOST_PRESENCE_BKG_JOIN_INTERVAL:
        {
            PresenceDetection_set_bkgndjoininterval(pParam->bkgrndjoinInterval);
        }
        break;
        case HOST_PRESENCE_PARAM_ALL:
        {
            PresenceDetection_set_ipv4leaveinterval(pParam->ipv4CheckInterval);
            PresenceDetection_set_ipv6leaveinterval(pParam->ipv6CheckInterval);
            PresenceDetection_set_ipv4retrycount(pParam->ipv4RetryCount);
            PresenceDetection_set_ipv6retrycount(pParam->ipv6RetryCount);
            PresenceDetection_set_bkgndjoininterval(pParam->bkgrndjoinInterval);
        }
        break;
        default:
        break;
    }

    pthread_mutex_unlock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    return 0;
}

int Hosts_UpdatePresenceDetectionStatus(LmPresenceDetectionInfo *pStatus, BOOL bIsMacConfigurationEnabled)
{
    int ret = 0;
    if (pStatus)
    {
        if (pStatus->enable)
        {
            LmPresenceDeviceInfo info;
            memset(&info, 0, sizeof(LmPresenceDeviceInfo));
            /*CID: 135559 Buffer not null terminated*/
            strncpy (info.mac,pStatus->physaddress,MAC_SIZE-1);
            info.mac[MAC_SIZE-1] = '\0';
            info.currentActive = pStatus->currentActive;
            info.ipv4Active = pStatus->ipv4Active;
            info.ipv6Active = pStatus->ipv6Active;
            /*CID: 135559 Buffer not null terminated*/
            strncpy (info.ipv4,pStatus->ipv4,IPV4_SIZE-1);
            info.ipv4[IPV4_SIZE-1] = '\0';
            strncpy(info.ipv6, pStatus->ipv6,IPV6_SIZE-1);
            info.ipv6[IPV6_SIZE-1] = '\0';
            ret = PresenceDetection_AddDevice(&info, bIsMacConfigurationEnabled);
        }
        else
        {
            ret = PresenceDetection_RemoveDevice(pStatus->physaddress, bIsMacConfigurationEnabled);
        }
    }
    else
    {
        ret = -1;
    }

    return ret;
}
// End of File
