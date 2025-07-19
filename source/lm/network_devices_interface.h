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

#ifndef  NETWORK_DEVICES_INTERFACE_H
#define  NETWORK_DEVICES_INTERFACE_H

#include "ansc_platform.h"
#include "device_presence_detection.h"


typedef enum {
    HOST_PRESENCE_LEAVE = 0,
    HOST_PRESENCE_JOIN
}HostPresenceDetection;

typedef enum {
    HOST_PRESENCE_PARAM_NONE,
    HOST_PRESENCE_IPV4_ARP_LEAVE_INTERVAL,
    HOST_PRESENCE_IPV4_RETRY_COUNT,
    HOST_PRESENCE_IPV4_RETRY_INTERVAL,
    HOST_PRESENCE_IPV6_ARP_LEAVE_INTERVAL,
    HOST_PRESENCE_IPV6_RETRY_COUNT,
    HOST_PRESENCE_IPV6_RETRY_INTERVAL,
    HOST_PRESENCE_BKG_JOIN_INTERVAL,
    HOST_PRESENCE_PARAM_ALL
}HostPresenceParamUpdate;

typedef struct LmPresenceNotifyInfo
{
    char physaddress[MAC_SIZE];
    char ipv4address[IPV4_SIZE];
    char ipv6address[IPV6_SIZE];
    HostPresenceDetection status;
}LmPresenceNotifyInfo,*PLmPresenceNotifyInfo;

typedef struct LmHostPresenceDetectionParam
{
    unsigned int ipv4CheckInterval; // ARP interval
    unsigned int ipv4RetryCount;
    unsigned int ipv4RetryInterval;
    unsigned int ipv6CheckInterval; // ARP interval
    unsigned int ipv6RetryCount;
    unsigned int ipv6RetryInterval;
    unsigned int bkgrndjoinInterval; // ipv4/ipv6
}LmHostPresenceDetectionParam,*PLmHostPresenceDetectionParam;

typedef struct LmPresenceDetectionInfo
{
    char physaddress[MAC_SIZE];
    BOOL enable;
    char ipv4[IPV4_SIZE];
    char ipv6[IPV6_SIZE];
    BOOL currentActive;
    BOOL ipv4Active;
    BOOL ipv6Active;
}LmPresenceDetectionInfo,*PLmPresenceDetectionInfo;



int Hosts_UpdatePresenceDetectionParam(LmHostPresenceDetectionParam *pParam, HostPresenceParamUpdate flag);
int Hosts_UpdatePresenceDetectionStatus(LmPresenceDetectionInfo *pStatus, BOOL bIsMacConfigurationEnabled);
int Hosts_InitPresenceDetection();
int Hosts_StartPresenceDetection();
int Hosts_StopPresenceDetection();
int Hosts_DeInitPresenceDetection();
#endif 
