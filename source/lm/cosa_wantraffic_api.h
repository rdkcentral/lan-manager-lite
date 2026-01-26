/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2022 RDK Management
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

    module: cosa_wantraffic_api.h

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file defines the apis for objects to support Data Model Library.

    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        06/13/2022    initial revision.

**************************************************************************/


#ifndef  _COSA_WANTRAFFIC_API_H
#define  _COSA_WANTRAFFIC_API_H

#include <rbus/rbus.h>
#include "platform_hal.h"



/**********************************************************************
               CONSTANT DEFINITIONS
**********************************************************************/
#define BUFLEN_4                    4
#define BUFLEN_8                    8
#define BUFLEN_16                   16
#define BUFLEN_24                   24
#define BUFLEN_32                   32
#define BUFLEN_40                   40
#define BUFLEN_64                   64
#define BUFLEN_128                  128
#define BUFLEN_256                  256
#define BUFLEN_512                  512
#define BUFLEN_1024                 1024
#define BUFLEN_10240                10240
#define BUFLEN_20480                20480

#define UNIT_KB                     1024
#if defined (_SCER11BEL_PRODUCT_REQ_) || defined (_SCXF11BFL_PRODUCT_REQ_)
#define SUPPORTED_WAN_MODES         1
#else
#define SUPPORTED_WAN_MODES         2
#endif
#define ALL_DSCP_VALUE              "-1"
#define DEFAULT_THREAD_SLEEP        5
#define CLIENT_ALLOC_SLAB           10
#define TR181_LANMODE               "Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode"
#define TR181_WANMODE               "Device.X_RDKCENTRAL-COM_EthernetWAN.CurrentOperationalMode"

#define TR181_COUNTENABLE           "Device.X_RDK_WAN.Interface.1.Stats.DscpCountEnable"
#define TR181_SLEEPINTERVAL         "Device.X_RDK_WAN.Interface.1.Stats.DscpCountInterval"
#define TR181_COUNTPERINTERVAL      "Device.X_RDK_WAN.Interface.1.Stats.DscpCountPerInterval"
#define TR181_COUNTTOTAL            "Device.X_RDK_WAN.Interface.1.Stats.DscpCountTotal"
#ifdef _SR300_PRODUCT_REQ_
#define TR181_ACTIVE_INTERFACE      "Device.X_RDK_WanManager.InterfaceActiveStatus"
#define DSL                         DOCSIS
#endif
#ifdef _RDKB_GLOBAL_PRODUCT_REQ_
#define TR181_ACTIVE_INTERFACE      "Device.X_RDK_WanManager.InterfaceActiveStatus"
#endif


#define LMLITE_RBUS_COMPONENT_NAME  "CcspLMLite"

#ifndef VOID
 #define VOID    void
#endif

#ifndef UINT
 #define UINT    unsigned int
#endif

#ifndef INT
 #define INT     int
#endif

#ifndef CHAR
 #define CHAR    char
#endif

#ifndef UCHAR
 #define UCHAR   unsigned char
#endif


#define WTC_LOG_INFO(format, ...)     \
                              CcspTraceInfo   (("%s - "format"\n", __FUNCTION__, ##__VA_ARGS__))
#define WTC_LOG_ERROR(format, ...)    \
                              CcspTraceError  (("%s - "format"\n", __FUNCTION__, ##__VA_ARGS__))
#define WTC_LOG_NOTICE(format, ...)   \
                              CcspTraceNotice (("%s - "format"\n", __FUNCTION__, ##__VA_ARGS__))
#define WTC_LOG_WARNING(format, ...)  \
                              CcspTraceWarning(("%s - "format"\n", __FUNCTION__, ##__VA_ARGS__))

/**********************************************************************
               ENUMERATION DEFINITIONS
**********************************************************************/
typedef enum _RETURN_STATUS {
    STATUS_SUCCESS = 0,
    STATUS_FAILURE = -1
} RETURN_STATUS;

typedef enum _eWTCEvent_t {
    WTC_DCSPCOUNTENABLE = 0,
    WTC_COUNTINTERVAL,
    WTC_COUNTPERINTERVAL,
    WTC_COUNTTOTAL
} eWTCEvent_t;

typedef enum _eWTCThreadState_t {
    WTC_THRD_NONE = 0,
    WTC_THRD_INITIALIZE,
    WTC_THRD_RUN,
    WTC_THRD_SUSPEND,
    WTC_THRD_DISMISS
} eWTCThreadState_t;

typedef enum _eWTCThreadStatus_t {
    WTC_THRD_IDLE = 0,
    WTC_THRD_INITIALIZING,
    WTC_THRD_INITIALIZED,
    WTC_THRD_RUNNING,
    WTC_THRD_SUSPENDED,
    WTC_THRD_DISMISSED,
    WTC_THRD_ERROR = 0xFFFFFFFF
} eWTCThreadStatus_t;

typedef enum _eWTCConfig_t {
    WTC_DSCP_CONFIGURED          = 0x01,
    WTC_SLEEPINTRVL_CONFIGURED   = 0x02,
    WTC_LANMODE_CHANGE           = 0x04,
    WTC_WANMODE_CHANGE           = 0x08,
    WTC_INPUT_CHANGE             = 0x10
} eWTCConfig_t;


/**********************************************************************
               STRUCTURE DEFINITIONS
**********************************************************************/
typedef struct _stWTCInfo_t {
    UCHAR                 WTCConfigFlag[SUPPORTED_WAN_MODES];
    BOOL                  LanMode;
    WAN_INTERFACE         WanMode;
    UINT                  SubscribeRefCount;
    pthread_t             WanTrafficThreadId;
    pthread_mutex_t       WanTrafficMutexVar;
    rbusHandle_t          handle;
} stWTCInfo_t, *pstWTCInfo_t;

typedef struct _stClientInfo_t {
    BOOL                  IsUpdated;
    CHAR                  Mac[BUFLEN_24];
    ULONG                 RxBytes;
    ULONG                 TxBytes;
    ULONG                 RxBytesTot;
    ULONG                 TxBytesTot;
} stClientInfo_t,  *pstClientInfo_t;

typedef struct _stDSCPInfo_t  {
    BOOL                  IsUpdated;
    UINT                  Dscp;
    UINT                  NumClients;
    UINT                  MemorySlab;
    struct _stDSCPInfo_t  *Left, *Right; //  BST mode
    //struct _stDSCPInfo_t  *Next;         //  Sorted Linear List Mode
    pstClientInfo_t       ClientList;    //  Contains contiguous list of ClientInfo
}  stDCSPInfo_t,  *pstDSCPInfo_t;

typedef struct _stWanTrafficCountInfo_t {
    BOOL                  IsRbusSubscribed;
    BOOL                  IsDscpListSet;
    BOOL                  IsSleepIntvlSet;
    UINT                  NumElements;
    UINT                  InstanceNum;
    UINT                  SleepInterval;
    CHAR*                 EnabledDSCPList;
    eWTCThreadState_t     ThreadState;
    eWTCThreadStatus_t    ThreadStatus;
    pstDSCPInfo_t         DscpTree;
} stWanTrafficCountInfo_t, *pstWanTrafficCountInfo_t;


/**********************************************************************
               FUNCTION PROTOTYPES
**********************************************************************/


/**********************************************************************
    function:
        WTC_SetConfig
    description:
        This function is called to set syscfg parameters.
**********************************************************************/
RETURN_STATUS WTC_SetConfig(CHAR *param, CHAR* value, WAN_INTERFACE ethWanMode);


/**********************************************************************
    function:
        WTC_GetConfig
    description:
        This function is called to get syscfg parameters.
**********************************************************************/
RETURN_STATUS WTC_GetConfig(CHAR *param, CHAR* value, ULONG valueLen, WAN_INTERFACE ethWanMode);


/**********************************************************************
    function:
        WTC_Init
    description:
        This function is to initialize the DscpTree.
**********************************************************************/
VOID WTC_Init(VOID);


/**********************************************************************
    function:
        WTC_ApplyStateChange
    description:
        This function is to fetch dscp inputs params and change thread state accordingly.
**********************************************************************/
VOID WTC_ApplyStateChange(VOID);


/**********************************************************************
    function:
        WTC_GetCount
    description:
        This function is called to get the Wan traffic counts.
**********************************************************************/
VOID WTC_GetCount(CHAR* pValue, ULONG* pUlSize, BOOL countPerInterval,
                                pstWanTrafficCountInfo_t WAN_Traffic);

/**********************************************************************
    function:
        WTC_EventPublish
    description:
        This function is called to publish the evenst to Rbus
**********************************************************************/
rbusError_t WTC_EventPublish(eWTCEvent_t wtcEvent, CHAR* data, INT index);

#endif
