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

    module: cosa_wantraffic_api.c

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

        06/13/2022    initial revision.

**************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#include <rbus/rbus.h>

#include "ansc_platform.h"
#include "ccsp_lmliteLog_wrapper.h"
#include "syscfg/syscfg.h"
#include "safec_lib_common.h"
#include "cosa_wantraffic_api.h"
#include "lm_util.h"
#include "ccsp_base_api.h"
#include "ssp_internal.h"
#include "cosa_wantraffic_utils.h"
#include "wtc_rbus_apis.h"

/*
 * Global definitions
 */
DSCP_list_t  CliList;
pstWTCInfo_t WTCinfo;
pstWanTrafficCountInfo_t WanTrafficCountInfo_t[SUPPORTED_WAN_MODES];

CHAR *AllValidDscp = "32, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,"
                     "15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,"
                     "31,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,"
                     "48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63";

#if  defined (_SCER11BEL_PRODUCT_REQ_) || defined (_SCXF11BFL_PRODUCT_REQ_)
static CHAR wanMode[SUPPORTED_WAN_MODES][BUFLEN_4] = { "EWN"  /*   Ethwan */
                                                     };
#else
static CHAR wanMode[SUPPORTED_WAN_MODES][BUFLEN_4] = { "DCS",  /*   Docsis      */
                                                       "EWN"   /*   Ethwan      */
                                                       /* "LTE",    LTE         */
                                                       /* "DSL",    DSL         */
                                                       /* "STL"     STARLINK :) */
                                                     };
#endif
static CHAR gPrintBuf[BUFLEN_20480] = {0};

/*
 * Static function prototypes
 */
static RETURN_STATUS WTC_SendTrafficCountRbus(UINT index);
static RETURN_STATUS WTC_RbusSubscribe(UINT index);
static VOID  WTC_RbusUnsubscribe(UINT index);
static VOID  WTC_CreateThread(VOID);
static VOID* WTC_Thread();
static VOID  WTC_DeInit(UINT index, BOOL doUnSubscribe);
static VOID  WTC_EventHandler(rbusHandle_t handle, rbusEvent_t const* event,
                                rbusEventSubscription_t* subscription);
static inline CHAR* WTC_ThreadStateToStr(eWTCThreadState_t threadState);
static inline CHAR* WTC_ThreadStatusToStr(eWTCThreadStatus_t threadStatus);
static inline VOID  WTC_SetThreadState(UINT index, eWTCThreadState_t newState);
static inline VOID  WTC_SetThreadStatus(UINT index, eWTCThreadStatus_t newStatus);

static pstDSCPInfo_t PrintDscpTree(CHAR* pValue, ULONG* pUlSize, UINT* offset,
                                   BOOL countPerInterval, pstDSCPInfo_t DscpTree);
#if 0
// Retaining these changes as backup incase of future need.
// better if moved to utils
static VOID  PrintDscpTreeLinearly(CHAR* pValue, ULONG* pUlSize,
                                    BOOL countPerInterval,pstDSCPInfo_t DscpTree);
static pstDSCPInfo_t GetLinearHeadFromTree(pstDSCPInfo_t DscpTree);
#endif
/*
 * External function definitions
 */
/**********************************************************************
    function:
        WTC_Init
    description:
        This function is to initialize the DscpTree.
    argument:
        VOID
    return:
        VOID
**********************************************************************/
VOID WTC_Init
    (
        VOID
    )
{
    if(WTCinfo == NULL)
    {
        WTCinfo = (stWTCInfo_t *) malloc(sizeof(stWTCInfo_t));
        if(WTCinfo != NULL)
        {
            //Init Global Struct
            WTCinfo->SubscribeRefCount = 0;
            WTCinfo->LanMode = IsBridgeMode();
            WTCinfo->WanMode = GetEthWANIndex();
            #if defined(_SR300_PRODUCT_REQ_) || defined(_RDKB_GLOBAL_PRODUCT_REQ_)
            if ((INVALID_MODE == WTCinfo->LanMode))
            #else
            if ((INVALID_MODE == WTCinfo->LanMode) || (INVALID_MODE == WTCinfo->WanMode))
            #endif
            {
                WTC_LOG_ERROR("INVALID LAN/WAN MODE %d/%d", WTCinfo->LanMode, WTCinfo->WanMode);
                free(WTCinfo);
                WTCinfo = NULL;
                return;
            }
            WTCinfo->WanTrafficThreadId = 0;
            WTCinfo->handle = NULL;
            pthread_mutex_init(&WTCinfo->WanTrafficMutexVar,0);
        }
        else
        {
            WTC_LOG_ERROR("Init struct malloc Failed");
            return;
        }
    }

    int rc = WTC_RbusInit();
    if(rc)
    {
        WTC_LOG_ERROR("WTC_RbusInit failure, reason = %d", rc);
        if(WTCinfo)
        {
            free(WTCinfo);
            WTCinfo = NULL;
        }
        return;
    }

    for(UINT i=0; i<SUPPORTED_WAN_MODES; i++)
    {
        if (WanTrafficCountInfo_t[i] == NULL)
        {
            WanTrafficCountInfo_t[i] = (stWanTrafficCountInfo_t*)
                                         malloc(sizeof(stWanTrafficCountInfo_t));
            if (WanTrafficCountInfo_t[i] == NULL)
            {
                WTC_LOG_ERROR("WAN Traffic List Allocation Failed");
                return;
            }
            WanTrafficCountInfo_t[i]->IsRbusSubscribed = FALSE;
            WanTrafficCountInfo_t[i]->IsDscpListSet = FALSE;
            WanTrafficCountInfo_t[i]->IsSleepIntvlSet = FALSE;
            WanTrafficCountInfo_t[i]->NumElements = 0;
            WanTrafficCountInfo_t[i]->InstanceNum = i+1;
            WanTrafficCountInfo_t[i]->SleepInterval = 0;
            WanTrafficCountInfo_t[i]->EnabledDSCPList = NULL;
            WanTrafficCountInfo_t[i]->DscpTree = NULL;
            WTC_SetThreadState(i, WTC_THRD_NONE);
            WTC_SetThreadStatus(i, WTC_THRD_IDLE);
            WTCinfo->WTCConfigFlag[i] = 0;

            CHAR buf[BUFLEN_256] = {0};
            CHAR buf1[BUFLEN_32] = {0};

            if( !WTC_GetConfig("DscpEnabledList", buf, sizeof(buf), i+1) &&
                !WTC_GetConfig("DscpSleepInterval", buf1, sizeof(buf1), i+1) )
            {
                if(*buf && atoi(buf1))
                {
                    if(CheckIfValidDscp(buf) && IsDigit(buf1))
                    {
                        WTCinfo->WTCConfigFlag[i] |= WTC_DSCP_CONFIGURED;
                        WTCinfo->WTCConfigFlag[i] |= WTC_SLEEPINTRVL_CONFIGURED;
                    }
                    else
                    {
                        WTC_LOG_ERROR("Invalid dscp");
                    }
                }
            }

            if ( (!WTCinfo->LanMode) && (i == WTCinfo->WanMode-1) )
            {
                WTC_ApplyStateChange();
            }
            else
            {
                if( (WTCinfo->WTCConfigFlag[i] & WTC_DSCP_CONFIGURED) &&
                    (WTCinfo->WTCConfigFlag[i] & WTC_SLEEPINTRVL_CONFIGURED) )
                {
                    WTC_RbusSubscribe(i);
                }
            }
        }
    }
    WTC_LOG_INFO("WAN Traffic Init Success.");
    return;
}

/**********************************************************************
    function:
        WTC_EventHandler
    description:
        This function is handle rbus event
    argument:
        rbusHandle_t               handle,
        rbusEvent_t const*         event,
        rbusEventSubscription_t*   subscription
    return:
        VOID
**********************************************************************/
static VOID WTC_EventHandler
    (
        rbusHandle_t               handle,
        rbusEvent_t const*         event,
        rbusEventSubscription_t*   subscription
    )
{
    (VOID)handle;
    (VOID)subscription;

    const CHAR* eventName = event->name;
    errno_t rc = -1;
    INT ind = -1;
    rbusValue_t valBuff;
    valBuff = rbusObject_GetValue(event->data, NULL );
    if(!valBuff)
    {
        WTC_LOG_ERROR("FAILED , value is NULL");
        return;
    }
    else
    {
        UINT index = WTCinfo->WanMode-1;
        rc = strcmp_s(eventName, strlen(eventName), TR181_LANMODE, &ind);
        ERR_CHK(rc);
        if ((rc == EOK) && (!ind))
        {
            WTCinfo->LanMode = IsBridgeMode();
            CHK_LAN_MODE(WTCinfo->LanMode);

            WTCinfo->WTCConfigFlag[index] |= WTC_LANMODE_CHANGE;
            WTC_ApplyStateChange();
        }
        rc = strcmp_s(eventName, strlen(eventName), TR181_WANMODE, &ind);
        ERR_CHK(rc);
        if ((rc == EOK) && (!ind))
        {
            if(WTCinfo->LanMode)
            {
                WTC_LOG_INFO("In Bridge mode during change of WAN mode, Do nothing.");
                return;
            }
            else
            {
                WTCinfo->WTCConfigFlag[index] |= WTC_WANMODE_CHANGE;
                WTC_ApplyStateChange();
            }
        }
    }
}

/**********************************************************************
    function:
        WTC_ApplyStateChange
    description:
        This function is to fetch dscp inputs params and change thread state accordingly.
    argument:
        VOID
    return:
        VOID
**********************************************************************/
VOID WTC_ApplyStateChange
    (
        VOID
    )
{
    UINT index = WTCinfo->WanMode-1;
    UINT i;
    eWTCThreadStatus_t thrdStatus = WTC_THRD_IDLE;

    pthread_mutex_lock(&WTCinfo->WanTrafficMutexVar);
       thrdStatus = WanTrafficCountInfo_t[index]->ThreadStatus;
    pthread_mutex_unlock(&WTCinfo->WanTrafficMutexVar);

    switch(thrdStatus)
    {
        case WTC_THRD_IDLE:
        case WTC_THRD_DISMISSED:
            if(WTCinfo->WTCConfigFlag[index] & WTC_WANMODE_CHANGE)
            {
                WTC_LOG_INFO("[%s-%s] WAN Mode flag is SET, unset it"
                             , wanMode[index]
                             , WTC_ThreadStatusToStr(thrdStatus));
                WTCinfo->WTCConfigFlag[index] &= ~WTC_WANMODE_CHANGE;
                WTCinfo->WanMode = GetEthWANIndex();
                CHK_WAN_MODE(WTCinfo->WanMode);
                index = WTCinfo->WanMode-1;
            }
            else if(WTCinfo->WTCConfigFlag[index] & WTC_LANMODE_CHANGE)
            {
                WTC_LOG_INFO("[%s-%s] LAN Mode flag is SET, unset it"
                             , wanMode[index]
                             , WTC_ThreadStatusToStr(thrdStatus));
                WTCinfo->WTCConfigFlag[index] &= ~WTC_LANMODE_CHANGE;
            }
            if ((!WTCinfo->LanMode) &&
                (WTCinfo->WTCConfigFlag[index] & WTC_DSCP_CONFIGURED) &&
                (WTCinfo->WTCConfigFlag[index] & WTC_SLEEPINTRVL_CONFIGURED))
            {
                WanTrafficCountInfo_t[index]->IsDscpListSet = TRUE;
                WanTrafficCountInfo_t[index]->IsSleepIntvlSet = TRUE;
                WTC_LOG_INFO("[%s-%s] Configs are present, starting thread"
                             , wanMode[index]
                             , WTC_ThreadStatusToStr(thrdStatus));
                WTC_CreateThread();
            }
            else
            {
                //CID 560247 Data race condition (MISSING_LOCK)
                pthread_mutex_lock(&WTCinfo->WanTrafficMutexVar);
                if(WanTrafficCountInfo_t[index]->ThreadStatus == WTC_THRD_DISMISSED)
                {
                    WTC_RbusUnsubscribe(index);
                }
                pthread_mutex_unlock(&WTCinfo->WanTrafficMutexVar);
                WTC_LOG_INFO("[%s-%s] DscpList/SleepInterval is Not Configured"
                             , wanMode[index]
                             , WTC_ThreadStatusToStr(thrdStatus));
                WTC_SetThreadState(index, WTC_THRD_NONE);
            }
            break;
        case WTC_THRD_INITIALIZING:
        case WTC_THRD_INITIALIZED:
            WTC_LOG_INFO("[%s-%s] Do nothing"
                         , wanMode[index]
                         , WTC_ThreadStatusToStr(thrdStatus));
            break;
        case WTC_THRD_SUSPENDED:
            WTC_LOG_INFO("[%s-%s] set state to INITIALIZE"
                         , wanMode[index]
                         , WTC_ThreadStatusToStr(thrdStatus));
            WanTrafficCountInfo_t[index]->IsDscpListSet = TRUE;
            WanTrafficCountInfo_t[index]->IsSleepIntvlSet = TRUE;
            WTC_SetThreadState(index, WTC_THRD_INITIALIZE);
            break;
        case WTC_THRD_RUNNING:
         {
            WTC_LOG_INFO("Thread in RUNNING state");
            i = GetEthWANIndex();
            if (i == INVALID_MODE)
            {
                WTC_LOG_ERROR("INVALID WAN MODE");
                WTC_SetThreadState(index,WTC_THRD_DISMISS);
                return;
            }
            i--;

            if (WTCinfo->WTCConfigFlag[index] & WTC_WANMODE_CHANGE)
            {
                if ((WTCinfo->WTCConfigFlag[i] & WTC_DSCP_CONFIGURED) &&
                    (WTCinfo->WTCConfigFlag[i] & WTC_SLEEPINTRVL_CONFIGURED))
                {
                    WTC_LOG_INFO("[%s-%s] Dscp & Sleep Interval is Configured,"
                                 "[%s-%s] switch to SUSPEND"
                                 , wanMode[i]
                                 , WTC_ThreadStatusToStr(WanTrafficCountInfo_t[i]->ThreadStatus)
                                 , wanMode[index]
                                 , WTC_ThreadStatusToStr(thrdStatus));
                    WanTrafficCountInfo_t[i]->IsDscpListSet = TRUE;
                    WanTrafficCountInfo_t[i]->IsSleepIntvlSet = TRUE;
                    WTC_SetThreadState(index,WTC_THRD_SUSPEND);
                    WTC_SetThreadState(i, WTC_THRD_INITIALIZE);
                }
                else
                {
                    WTC_LOG_INFO("[%s-%s] Dscp/Sleep Interval is not Configured,"
                                 "[%s-%s] switch to DISMISS"
                                 , wanMode[i]
                                 , WTC_ThreadStatusToStr(WanTrafficCountInfo_t[i]->ThreadStatus)
                                 , wanMode[index]
                                 , WTC_ThreadStatusToStr(thrdStatus));
                    WTC_SetThreadState(index,WTC_THRD_DISMISS);
                    WTCinfo->WanMode = GetEthWANIndex();
                    CHK_WAN_MODE(WTCinfo->WanMode);
                }
                WTCinfo->WTCConfigFlag[index] &= ~WTC_WANMODE_CHANGE;
            }
            else if (WTCinfo->WTCConfigFlag[index] & WTC_LANMODE_CHANGE)
            {
                WTC_LOG_INFO("[%s-%s] Lan mode change flag is set, switch to DISMISS"
                             , wanMode[index]
                             , WTC_ThreadStatusToStr(thrdStatus));
                WTC_SetThreadState(index, WTC_THRD_DISMISS);
                WTCinfo->WTCConfigFlag[index] &= ~WTC_LANMODE_CHANGE;
            }
            else if (WTCinfo->WTCConfigFlag[index] & WTC_INPUT_CHANGE)
            {
                WTC_LOG_INFO("[%s-%s] Input change flag is set, switch to INITIALIZE"
                             , wanMode[index]
                             , WTC_ThreadStatusToStr(thrdStatus));
                WTC_SetThreadState(index, WTC_THRD_INITIALIZE);
            }
            else
            {
                WTC_LOG_INFO("[%s-%s] No Flag is set"
                             , wanMode[index]
                             , WTC_ThreadStatusToStr(thrdStatus));
            }
            break;
         }
        case WTC_THRD_ERROR:
        default:
            WTC_LOG_WARNING("[%s-%s] Default/ERROR case"
                             , wanMode[index]
                             , WTC_ThreadStatusToStr(thrdStatus));
    }
}

/**********************************************************************
    function:
        WTC_GetCount
    description:
        This function is called to get the Wan traffic counts.
    argument:
        CHAR*    pValue,            - Dscp, Mac and its Rx,Tx count
        ULONG*   pUlSize,           - pValue size
        BOOL     countPerInterval   - Per Interval/Total count
    return:
        VOID
**********************************************************************/

VOID WTC_GetCount
    (
        CHAR*                      pValue,
        ULONG*                     pUlSize,
        BOOL                       countPerInterval,
        pstWanTrafficCountInfo_t   WAN_Traffic
    )
{
    if( (WAN_Traffic != NULL) && (WAN_Traffic->DscpTree != NULL) )
    {
        UINT offset = 0;
        PrintDscpTree(pValue, pUlSize, &offset, countPerInterval, WAN_Traffic->DscpTree);
#if 0
        PrintDscpTreeLinearly(pValue, pUlSize, countPerInterval, WAN_Traffic->DscpTree);
#endif
    }
    return;
}

/**********************************************************************
    function:
        WTC_EventPublish
    description:
        This function is called to publish the evenst to Rbus
    argument:
        eWTCEvent_t    wtcEvent,
        CHAR*          data,
        INT            index
    return:
        RTMESSAGE_BUS_SUCCESS if succeeded;
        rbusError_t if error.
**********************************************************************/
rbusError_t WTC_EventPublish
    (
        eWTCEvent_t    wtcEvent,
        CHAR*          data,
        INT            index
    )
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    char eventName[BUFLEN_64] = {0};
    rbusError_t rc = RBUS_ERROR_SUCCESS;

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    switch(wtcEvent)
    {
        case WTC_DCSPCOUNTENABLE:
            snprintf(eventName, BUFLEN_64,
                     "Device.X_RDK_WAN.Interface.%d.Stats.DscpCountEnable", index);
            rbusValue_SetString(value, data);
            break;
        case WTC_COUNTPERINTERVAL:
            snprintf(eventName, BUFLEN_64,
                     "Device.X_RDK_WAN.Interface.%d.Stats.DscpCountPerInterval", index);
            rbusValue_SetString(value, data);
            break;
        case WTC_COUNTTOTAL:
            snprintf(eventName, BUFLEN_64,
                     "Device.X_RDK_WAN.Interface.%d.Stats.DscpCountTotal", index);
            rbusValue_SetString(value, data);
            break;
        case WTC_COUNTINTERVAL:
            WTC_LOG_INFO("Event : %d, Data : %d, Index = %d", wtcEvent, atoi(data), index);
            snprintf(eventName, BUFLEN_64,
                     "Device.X_RDK_WAN.Interface.%d.Stats.DscpCountInterval", index);
            rbusValue_SetUInt32(value, atoi(data));
            break;
        default:
            WTC_LOG_WARNING("Invalid Event");
            break;
    }

    rbusObject_SetValue(rdata, eventName, value);
    event.name = eventName;
    event.data = rdata;
    event.type = RBUS_EVENT_VALUE_CHANGED;

    rc = rbusEvent_Publish(WTCinfo->handle, &event);

    if(rc == RBUS_ERROR_NOSUBSCRIBERS)
    {
        WTC_LOG_INFO("rbusEvent_Publish Event NO SUBSCRIBERS %d", rc);
        rc = RBUS_ERROR_SUCCESS;
    }
    else if(rc != RBUS_ERROR_SUCCESS)
    {
        WTC_LOG_ERROR("rbusEvent_Publish Event failed: %d", rc);
    }
    rbusValue_Release(value);
    rbusObject_Release(rdata);
    return rc;
}

/**********************************************************************
    function:
        WTC_SetConfig
    description:
        This function is called to set syscfg parameters.
    argument:
        CHAR*   param             -   Parameter to which the value has to be set
        CHAR*   value             -   Value that needs to be set
        WAN_INTERFACE ethWanMode  -   Wan mode
    return:
        VOID
**********************************************************************/
RETURN_STATUS WTC_SetConfig
    (
        CHAR*           param,
        CHAR*           value,
        WAN_INTERFACE   ethWanMode
    )
{
    CHAR buf[BUFLEN_32] = {0};
    snprintf(buf, BUFLEN_32, "%s_%d", param, ethWanMode);

    //syscfg_set
    if (syscfg_set_commit(NULL, buf, value) != 0)
    {
        WTC_LOG_ERROR("syscfg_set %s:%s failed", buf, value);
        return STATUS_FAILURE;
    }
    else
    {
        WTC_LOG_INFO("syscfg_set %s:%s success ", buf, value);
        return STATUS_SUCCESS;
    }
}

/**********************************************************************
    function:
        WTC_GetConfig
    description:
        This function is called to get syscfg parameters.
    argument:
        CHAR*   param             -   Parameter to which the value has to be fetched
        CHAR*   value             -   Value read
        WAN_INTERFACE ethWanMode  -   Wan mode
    return:
        1 - success
        0 - failure
**********************************************************************/
RETURN_STATUS WTC_GetConfig
    (
        CHAR*           param,
        CHAR*           value,
        ULONG           valueLen,
        WAN_INTERFACE   ethWanMode
    )
{
    CHAR buf1[BUFLEN_32] = {0};
    snprintf(buf1, BUFLEN_32, "%s_%d", param, ethWanMode);

    //syscfg_get
    if (!syscfg_get(NULL, buf1, value, valueLen))
    {
        WTC_LOG_INFO("syscfg_get %s:%s success", buf1, value);
        return STATUS_SUCCESS;
    }
    else
    {
        WTC_LOG_ERROR("syscfg_get %s:%s failed", buf1, value);
        return STATUS_FAILURE;
    }
}

/*
 *  Static function definitions
 */

/**********************************************************************
    function:
        WTC_RbusUnsubscribe
    description:
        This function is called to unsubscribe for bridge/router mode
    argument:
        UINT   index
    return:
        None
**********************************************************************/
static VOID WTC_RbusUnsubscribe
    (
        UINT index
    )
{
    if (WanTrafficCountInfo_t[index]->IsRbusSubscribed)
    {
        if(!--WTCinfo->SubscribeRefCount)
        {
            INT ret = RBUS_ERROR_SUCCESS;

            ret = rbusEvent_Unsubscribe(WTCinfo->handle, TR181_LANMODE);
            if(ret != RBUS_ERROR_SUCCESS)
            {
                WTC_LOG_ERROR("rbusEvent_Unsubscribe failed for Lanmode. Err = %s",
                                 rbusError_ToString(ret));
            }
            else
            {
                WTC_LOG_INFO("Unsubscribe Successful for LanMode");
            }

            ret = rbusEvent_Unsubscribe(WTCinfo->handle, TR181_WANMODE);
            if(ret != RBUS_ERROR_SUCCESS)
            {
                WTC_LOG_ERROR("rbusEvent_Unsubscribe failed for WanMode. Err = %s",
                                 rbusError_ToString(ret));
            }
            else
            {
                WTC_LOG_INFO("Unsubscribe Successful for WanMode");
            }
        }
        else
        {
            WTC_LOG_INFO("%s Unsubscribed. SubsRefCount = %d", wanMode[index],
                             WTCinfo->SubscribeRefCount);
        }
        WanTrafficCountInfo_t[index]->IsRbusSubscribed = FALSE;
    }
    else
    {
        WTC_LOG_INFO("%s : Not Subscribed", wanMode[index]);
    }
}

/**********************************************************************
    function:
        WTC_RbusSubscribe
    description:
        This function is called to subscribe for bridge/router mode
    argument:
        UINT     index
    return:
        STATUS_SUCCESS if succeeded;
        STATUS_FAILURE if error.
**********************************************************************/
static RETURN_STATUS WTC_RbusSubscribe
    (
        UINT index
    )
{
    INT ret = STATUS_SUCCESS;

    if (!WanTrafficCountInfo_t[index]->IsRbusSubscribed)
    {
        if(!WTCinfo->SubscribeRefCount)
        {
            ret = rbusEvent_Subscribe(WTCinfo->handle, TR181_LANMODE, WTC_EventHandler, NULL, 0);
            if(ret != RBUS_ERROR_SUCCESS)
            {
                WTC_LOG_ERROR("rbusEvent_Subscribe failed for Lanmode: %d", ret);
                WanTrafficCountInfo_t[index]->IsRbusSubscribed = FALSE;
                return STATUS_FAILURE;
            }

            ret = rbusEvent_Subscribe(WTCinfo->handle, TR181_WANMODE, WTC_EventHandler, NULL, 0);
            if(ret != RBUS_ERROR_SUCCESS)
            {
                WTC_LOG_ERROR("rbusEvent_Subscribe failed for CurrentOperationalMode: %d", ret);
                WanTrafficCountInfo_t[index]->IsRbusSubscribed = FALSE;
                return STATUS_FAILURE;
            }
            WTC_LOG_INFO("RbusSubscription successful");
        }
        else
        {
            WTC_LOG_INFO("%s Subscribed, SubscribeRefCount = %d", wanMode[index],
                             WTCinfo->SubscribeRefCount);
        }
        WTCinfo->SubscribeRefCount++;
        WanTrafficCountInfo_t[index]->IsRbusSubscribed = TRUE;
    }
    else
    {
        WTC_LOG_INFO("%s : Already subscribed, SubscribeRefCount = %d",
                           wanMode[index], WTCinfo->SubscribeRefCount);
    }
    return ret;
}

/**********************************************************************
    function:
        WTC_SendTrafficCountRbus
    description:
        This function is called to send the traffic count to Rbus
    argument:
        INT    index
    return:
        STATUS_SUCCESS if succeeded;
        STATUS_FAILURE if error.
**********************************************************************/
static RETURN_STATUS WTC_SendTrafficCountRbus
    (
        UINT index
    )
{
    rbusError_t ret = RBUS_ERROR_SUCCESS;
    CHAR* pValue;
    ULONG pUlSize = BUFLEN_10240;
    errno_t rc = -1;

    pValue = (CHAR*)malloc(BUFLEN_10240);
    if(!pValue)
    {
        WTC_LOG_ERROR("Malloc failure");
        return STATUS_FAILURE;
    }

    rc = memset_s(pValue, BUFLEN_10240, 0, BUFLEN_10240);
    ERR_CHK(rc);
    WTC_GetCount(pValue, &pUlSize, 1, WanTrafficCountInfo_t[index]);
    ret = WTC_EventPublish(WTC_COUNTPERINTERVAL, pValue, index+1);

    pValue = (CHAR*)realloc(pValue, BUFLEN_20480);
    if(!pValue)
    {
        WTC_LOG_ERROR("Realloc failure");
        return STATUS_FAILURE;
    }
    rc = memset_s(pValue, BUFLEN_20480, 0, BUFLEN_20480);
    ERR_CHK(rc);
    pUlSize = BUFLEN_20480;

    WTC_GetCount(pValue, &pUlSize, 0, WanTrafficCountInfo_t[index]);
    ret |= WTC_EventPublish(WTC_COUNTTOTAL, pValue, index+1);

    if(ret != RBUS_ERROR_SUCCESS)
    {
        WTC_LOG_ERROR("Rbus Event Publish FAILURE, ret = %d",ret);
    }
    free(pValue);
    return ret;
}

/**********************************************************************
    function:
        WTC_DeInit
    description:
        This function is to de-initialize wan traffic count.
    argument:
        BOOL    doUnSubscribe, Flag to determine Unsubscription
    return:
        VOID
**********************************************************************/
static VOID WTC_DeInit
    (
        UINT index,
        BOOL doUnSubscribe
    )
{
    //Intimate Hal to stop monitoring
    if ( RETURN_OK != platform_hal_setDscp(index + 1, TRAFFIC_CNT_STOP,
                              WanTrafficCountInfo_t[index]->EnabledDSCPList) )
    {
        WTC_LOG_ERROR("Platform Stop call failed!");
    }

    if ( RETURN_OK != platform_hal_resetDscpCounts(index + 1) )
    {
        WTC_LOG_ERROR("Platform reset call failed!");
    }

    if(WanTrafficCountInfo_t[index])
    {
        WanTrafficCountInfo_t[index]->IsDscpListSet = FALSE;
        WanTrafficCountInfo_t[index]->IsSleepIntvlSet = FALSE;
        WanTrafficCountInfo_t[index]->SleepInterval = 0;
        if(WanTrafficCountInfo_t[index]->EnabledDSCPList != NULL)
        {
            free(WanTrafficCountInfo_t[index]->EnabledDSCPList);
            WanTrafficCountInfo_t[index]->EnabledDSCPList = NULL;
        }

        if(WanTrafficCountInfo_t[index]->DscpTree != NULL)
        {
            DeleteDscpTree(WanTrafficCountInfo_t[index]->DscpTree);
            WanTrafficCountInfo_t[index]->DscpTree = NULL;
        }

        if(doUnSubscribe)
        {
            if( (!(WTCinfo->WTCConfigFlag[index] & WTC_DSCP_CONFIGURED)) ||
                (!(WTCinfo->WTCConfigFlag[index] & WTC_SLEEPINTRVL_CONFIGURED)) )
            {
                WTC_RbusUnsubscribe(index);
            }
        }
    }
}

/**********************************************************************
    function:
        PrintDscpTree
    description:
        This function is called to Print the dscp tree.
    argument:
        CHAR*           pValue,            - Dscp, Mac and its Rx,Tx count
        ULONG*          pUlSize,           - pValue size
        BOOL            countPerInterval   - Per Interval/Total count
        pstDSCPInfo_t   DscpTree           - Dscp tree
    return:
        pstDSCPInfo_t
**********************************************************************/
static pstDSCPInfo_t PrintDscpTree
    (
        CHAR*          pValue,
        ULONG*         pUlSize,
        UINT*          offset,
        BOOL           countPerInterval,
        pstDSCPInfo_t  DscpTree
    )
{
    if (DscpTree)
    {
        ULONG lOffset  = 0;
        ULONG rx_in_KB = 0;
        ULONG tx_in_KB = 0;

        PrintDscpTree(pValue, pUlSize, offset, countPerInterval, DscpTree->Left);

        for (UINT i=0; i<DscpTree->NumClients; i++)
        {
            // Additional guarding to avoid intcs-631 crash
            if (!DscpTree->ClientList)
            {
                WTC_LOG_ERROR("ClientList is Null. # of clients : %d", DscpTree->NumClients);
                break;
            }

            if (countPerInterval)
            {
                rx_in_KB = DscpTree->ClientList[i].RxBytes / UNIT_KB;
                tx_in_KB = DscpTree->ClientList[i].TxBytes / UNIT_KB;
            }
            else
            {
                rx_in_KB = DscpTree->ClientList[i].RxBytesTot / UNIT_KB;
                tx_in_KB = DscpTree->ClientList[i].TxBytesTot / UNIT_KB;
            }

            if (rx_in_KB || tx_in_KB)
            {
                lOffset += snprintf(gPrintBuf + lOffset, *pUlSize - lOffset, "|%s,%lu,%lu",
                                    DscpTree->ClientList[i].Mac,
                                    tx_in_KB,
                                    rx_in_KB);
            }
        }

        if (lOffset)
        {
            if (*offset)
            {
                *offset += snprintf(pValue + *offset, *pUlSize - *offset, ";");
            }
            *offset += snprintf(pValue + *offset, *pUlSize - *offset, "%d", DscpTree->Dscp);
            *offset += snprintf(pValue + *offset, *pUlSize - *offset, "%s", gPrintBuf);
        }

        PrintDscpTree(pValue, pUlSize, offset, countPerInterval, DscpTree->Right);
    }

    return DscpTree;
}

#if 0
/**********************************************************************
    function:
        GetLinearHeadFromTree
    description:
        This function is called to get the dscp tree head node.
    argument:
        pstDSCPInfo_t   DscpTree           - Dscp tree
    return:
        pstDSCPInfo_t
**********************************************************************/
static pstDSCPInfo_t GetLinearHeadFromTree
    (
        pstDSCPInfo_t  DscpTree
    )
{
  if (DscpTree)
  {
      for ( ;DscpTree->Left; DscpTree = DscpTree->Left);
  }
  return DscpTree;
}

/**********************************************************************
    function:
        PrintDscpTreeLinearly
    description:
        This function is called to Print the dscp tree.
    argument:
        CHAR*           pValue,            - Dscp, Mac and its Rx,Tx count
        ULONG*          pUlSize,           - pValue size
        BOOL            countPerInterval   - Per Interval/Total count
        pstDSCPInfo_t   DscpTree           - Dscp tree
    return:
        VOID
**********************************************************************/
static VOID PrintDscpTreeLinearly
    (
        CHAR*          pValue,
        ULONG*         pUlSize,
        BOOL           countPerInterval,
        pstDSCPInfo_t  DscpTree
    )
{
    if (DscpTree)
    {
        UINT offset = 0;
        for (pstDSCPInfo_t ListItr=GetLinearHeadFromTree(DscpTree); ListItr; ListItr=ListItr->Next)
        {
            UINT firstClient = 1;
            for (UINT i=0; i < ListItr->NumClients; i++)
            {
                if (countPerInterval)
                {
                    if ((ListItr->ClientList[i].RxBytes!=0) ||
                        (ListItr->ClientList[i].TxBytes!=0))
                    {
                        if (firstClient)
                        {
                            offset += snprintf(pValue+offset, *pUlSize-offset, "%d", ListItr->Dscp);
                        }
                        offset += snprintf(pValue + offset, *pUlSize - offset, "|%s,%lu,%lu",
                                           ListItr->ClientList[i].Mac,
                                           ListItr->ClientList[i].RxBytes / UNIT_KB,
                                           ListItr->ClientList[i].TxBytes / UNIT_KB);
                        firstClient = 0;
                    }
                }
                else
                {
                    if (firstClient)
                    {
                        offset += snprintf(pValue+offset, *pUlSize-offset, "%d", ListItr->Dscp);
                    }
                    offset += snprintf(pValue + offset, *pUlSize - offset, "|%s,%lu,%lu",
                                       ListItr->ClientList[i].Mac,
                                       ListItr->ClientList[i].RxBytesTot / UNIT_KB,
                                       ListItr->ClientList[i].TxBytesTot / UNIT_KB);
                    firstClient = 0;
                }
            }
            if (!firstClient)
            {
                offset += snprintf(pValue + offset, *pUlSize - offset, ";");
            }
        }
    }
}
#endif

/**********************************************************************
    function:
        WTC_ThreadStateToStr
    description:
        This function is to get the string equivalent of thread state
    argument:
        eWTCThreadState_t    threadState
    return:
        CHAR*
**********************************************************************/
static inline CHAR* WTC_ThreadStateToStr
    (
        eWTCThreadState_t threadState
    )
{
    switch(threadState)
    {
        case WTC_THRD_NONE:
            return "NONE";
        case WTC_THRD_INITIALIZE:
            return "INITIALIZE";
        case WTC_THRD_RUN:
            return "RUN";
        case WTC_THRD_SUSPEND:
            return "SUSPEND";
        case WTC_THRD_DISMISS:
            return "DISMISS";
        default:
            return "ERROR";
    }
}

/**********************************************************************
    function:
        WTC_ThreadStatusToStr
    description:
        This function is to get the string equivalent of thread status
    argument:
        eWTCThreadStatus_t    threadStatus
    return:
        CHAR*
**********************************************************************/
static inline CHAR* WTC_ThreadStatusToStr
    (
        eWTCThreadStatus_t threadStatus
    )
{
    switch(threadStatus)
    {
        case WTC_THRD_IDLE:
            return "IDLE";
        case WTC_THRD_INITIALIZING:
            return "INITIALIZING";
        case WTC_THRD_INITIALIZED:
            return "INITIALIZED";
        case WTC_THRD_RUNNING:
            return "RUNNING";
        case WTC_THRD_SUSPENDED:
            return "SUSPENDED";
        case WTC_THRD_DISMISSED:
            return "DISMISSED";
        default:
            return "ERROR";
    }
}

/**********************************************************************
    function:
        WTC_SetThreadState
    description:
        This function is to set thread state
    argument:
        UINT                  index
        eWTCThreadState_t     newState
    return:
        VOID
**********************************************************************/
static inline VOID WTC_SetThreadState
    (
        UINT                index,
        eWTCThreadState_t   newState
    )
{
    if(index >= SUPPORTED_WAN_MODES)
    {
        return;
    }

    pthread_mutex_lock(&WTCinfo->WanTrafficMutexVar);
      switch(newState)
      {
        case WTC_THRD_NONE:
        case WTC_THRD_INITIALIZE:
            WanTrafficCountInfo_t[index]->ThreadState = newState;
            WTC_LOG_INFO("%s - %s", wanMode[index], WTC_ThreadStateToStr(newState));
            break;
        case WTC_THRD_RUN:
            if( WanTrafficCountInfo_t[index]->ThreadStatus == WTC_THRD_INITIALIZED )
            {
                WanTrafficCountInfo_t[index]->ThreadState = newState;
                WTC_LOG_INFO("%s - %s", wanMode[index], WTC_ThreadStateToStr(newState));
            }
            else
            {
                WTC_LOG_ERROR("%s - %s ERR: Thread is NOT INITIALIZED", wanMode[index],
                               WTC_ThreadStateToStr(newState));
            }
            break;
        case WTC_THRD_SUSPEND:
        case WTC_THRD_DISMISS:
            if( WanTrafficCountInfo_t[index]->ThreadStatus == WTC_THRD_RUNNING ||
                WanTrafficCountInfo_t[index]->ThreadStatus == WTC_THRD_INITIALIZING ||
                WanTrafficCountInfo_t[index]->ThreadStatus == WTC_THRD_INITIALIZED )
            {
                WanTrafficCountInfo_t[index]->ThreadState = newState;
                WTC_LOG_INFO("%s - %s", wanMode[index], WTC_ThreadStateToStr(newState));
            }
            else
            {
                WTC_LOG_ERROR("%s - %s ERR: Thread is NOT RUNNING/INITIALIZED", wanMode[index],
                                WTC_ThreadStateToStr(newState));
            }
            break;
        default:
            WanTrafficCountInfo_t[index]->ThreadStatus = WTC_THRD_ERROR;
            WTC_LOG_INFO("Invalid Thread State %d", newState);
            break;
      }
    pthread_mutex_unlock(&WTCinfo->WanTrafficMutexVar);
}

/**********************************************************************
    function:
        WTC_SetThreadStatus
    description:
        This function is to set thread status
    argument:
        UINT                  index
        eWTCThreadStatus_t    newStatus
    return:
        VOID
**********************************************************************/
static inline VOID WTC_SetThreadStatus
    (
        UINT                  index,
        eWTCThreadStatus_t    newStatus
    )
{
    if(index >= SUPPORTED_WAN_MODES)
    {
        return;
    }

    pthread_mutex_lock(&WTCinfo->WanTrafficMutexVar);
       if( WanTrafficCountInfo_t[index]->ThreadStatus != newStatus )
       {
           WTC_LOG_INFO("[%s]  %s -> %s"
                        , wanMode[index]
                        , WTC_ThreadStatusToStr(WanTrafficCountInfo_t[index]->ThreadStatus)
                        , WTC_ThreadStatusToStr(newStatus));
           WanTrafficCountInfo_t[index]->ThreadStatus = newStatus;
       }
    pthread_mutex_unlock(&WTCinfo->WanTrafficMutexVar);
}

/**********************************************************************
    function:
        WTC_CreateThread
    description:
        This function is to create Polling thread.
    argument:
        VOID
    return:
        VOID
**********************************************************************/
static VOID WTC_CreateThread
    (
        VOID
    )
{
    /* CID: 280142 Out-of-bounds read (OVERRUN) */
    UINT index = 0;
    if(WTCinfo->WanMode)
    {
        index = WTCinfo->WanMode-1;
    }
    if(!WTCinfo->WanTrafficThreadId)
    {
        INT res = pthread_create(&WTCinfo->WanTrafficThreadId, NULL, WTC_Thread, NULL);
        if(res != 0)
        {
            WTC_LOG_ERROR("Create WTC_Thread error %d", res);
            return;
        }
        pthread_detach(WTCinfo->WanTrafficThreadId);
    }
    /* CID 560033 Data race condition (MISSING LOCK) */
    pthread_mutex_lock(&WTCinfo->WanTrafficMutexVar);
    WanTrafficCountInfo_t[index]->ThreadState = WTC_THRD_INITIALIZE;
    pthread_mutex_unlock(&WTCinfo->WanTrafficMutexVar);
    return;
}

/**********************************************************************
    function:
        WTC_Thread
    description:
        This function is to poll traffic counts from hal.
    argument:
        VOID
    return:
        VOID
**********************************************************************/
static VOID* WTC_Thread()
{
    eWTCThreadState_t  thrdState = WTC_THRD_NONE;
    errno_t rc = -1;
    /* CID: 280269  Out-of-bounds access (OVERRUN) */
    UINT index = 0;
    /* CID 280141 Branch past initialization */
    BOOL doDismiss = FALSE;
    BOOL isDscpUpdated = FALSE;
    CHAR dscpStr[BUFLEN_256] = {0};
    CHAR dscpStr_1[BUFLEN_256] = {0};
    CHAR *dscpStr_2 = NULL;

    if(WTCinfo->WanMode)
    {
        index = WTCinfo->WanMode-1;
    }

    WTC_LOG_INFO("Successfully created Thread");

    while(1)
    {
        if(index < SUPPORTED_WAN_MODES)
        {
          pthread_mutex_lock(&WTCinfo->WanTrafficMutexVar);
             thrdState = WanTrafficCountInfo_t[index]->ThreadState;
          pthread_mutex_unlock(&WTCinfo->WanTrafficMutexVar);

        switch(thrdState)
        {
            case WTC_THRD_NONE:
                WTC_SetThreadStatus(index, WTC_THRD_IDLE);
                sleep(DEFAULT_THREAD_SLEEP);
                continue;
            case WTC_THRD_INITIALIZE:
            {
                WTC_LOG_INFO("Thread in INITIALIZE state");
                doDismiss = FALSE;
                isDscpUpdated = FALSE;
                dscpStr[0] = '\0';
                dscpStr_1[0] = '\0';
                dscpStr_2 = NULL;

                WTC_SetThreadStatus(index, WTC_THRD_INITIALIZING);

                if(WanTrafficCountInfo_t[index]->IsDscpListSet)
                {
                    CHAR buf[BUFLEN_256] = {0};

                    if(!WTC_GetConfig("DscpEnabledList", buf, sizeof(buf), WTCinfo->WanMode))
                    {
                        if(*buf)
                        {
                            if (WanTrafficCountInfo_t[index]->EnabledDSCPList == NULL)
                            {
                                WanTrafficCountInfo_t[index]->EnabledDSCPList =
                                                    (CHAR*)malloc(sizeof(CHAR)*BUFLEN_256);
                                if(WanTrafficCountInfo_t[index]->EnabledDSCPList == NULL)
                                {
                                    WTC_LOG_ERROR("Enabled DSCP List Allocation Failed");
                                    WTC_SetThreadState(index, WTC_THRD_DISMISS);
                                    continue;
                                }
                            }
                            rc = memset_s(WanTrafficCountInfo_t[index]->EnabledDSCPList,
                                          BUFLEN_256, 0, BUFLEN_256);
                            ERR_CHK(rc);
                            RemoveSpaces(buf);
                            if (CheckForAllDscpValuePresence(buf))
                            {
                                if(WTC_SetConfig("DscpEnabledList", "-1",
                                               WanTrafficCountInfo_t[index]->InstanceNum))
                                {
                                    WTC_LOG_ERROR("syscfg set failure");
                                    sleep(DEFAULT_THREAD_SLEEP);
                                    continue;
                                }
                                dscpStr_2 = AllValidDscp;
                            }
                            else
                            {
                                dscpStr_2 = buf;
                            }
                            rc = memcpy_s(WanTrafficCountInfo_t[index]->EnabledDSCPList,
                                          BUFLEN_256, dscpStr_2, BUFLEN_256);
                            ERR_CHK(rc);
                            rc = strcpy_s(dscpStr, BUFLEN_256, dscpStr_2);
                            ERR_CHK(rc);
                            rc = strcpy_s(dscpStr_1, BUFLEN_256, dscpStr_2);
                            ERR_CHK(rc);
                            isDscpUpdated = TRUE;
                        }
                        else
                        {
                            WTC_LOG_INFO("Dscp is NULL in syscfg, unset flag, Switch to DISMISS");
                            WTCinfo->WTCConfigFlag[index] &= ~WTC_DSCP_CONFIGURED;
                            doDismiss = TRUE;
                        }
                    }
                    else
                    {
                        WTC_LOG_ERROR("Get DscpList syscfg Failure, sleep & wait in init state");
                        sleep(DEFAULT_THREAD_SLEEP);
                        continue;
                    }
                    WanTrafficCountInfo_t[index]->IsDscpListSet = FALSE;
                }

                if(WanTrafficCountInfo_t[index]->IsSleepIntvlSet)
                {
                    CHAR buf1[BUFLEN_32] = {0};
                    if(!WTC_GetConfig("DscpSleepInterval", buf1, sizeof(buf1), WTCinfo->WanMode))
                    {
                        if(atoi(buf1))
                        {
                            WanTrafficCountInfo_t[index]->SleepInterval = atoi(buf1);
                        }
                        else
                        {
                            WTCinfo->WTCConfigFlag[index] &= ~WTC_SLEEPINTRVL_CONFIGURED;
                            doDismiss = TRUE;
                        }
                    }
                    else
                    {
                        WTC_LOG_ERROR("Get SleepIntrvl syscfg Failure, sleep&wait in init state");
                        sleep(DEFAULT_THREAD_SLEEP);
                        continue;
                    }
                    WanTrafficCountInfo_t[index]->IsSleepIntvlSet = FALSE;
                }
                if(doDismiss)
                {
                    WTC_LOG_INFO("doDismiss = TRUE, DISMISS thread");
                    WTC_SetThreadState(index, WTC_THRD_DISMISS);
                    continue;
                }
                else if(isDscpUpdated)
                {
                    pthread_mutex_lock(&WTCinfo->WanTrafficMutexVar);

                       WanTrafficCountInfo_t[index]->DscpTree = UpdateDscpCount(dscpStr,
                                                    WanTrafficCountInfo_t[index]->DscpTree);
                    pthread_mutex_unlock(&WTCinfo->WanTrafficMutexVar);

                    if (!WanTrafficCountInfo_t[index]->DscpTree)
                    {
                        WTC_LOG_ERROR("UpdateDscpCount Failure, sleep and retry in next iter");
                        sleep(DEFAULT_THREAD_SLEEP);
                        continue;
                    }

                    if ( RETURN_OK == platform_hal_setDscp(WTCinfo->WanMode, TRAFFIC_CNT_START,
                                                            dscpStr_1) )
                    {
                        WTC_LOG_INFO("Traffic count start Success");
                        WTC_RbusSubscribe(index);
                    }
                    else
                    {
                        WTC_LOG_ERROR("Platform_hal_setDscp Returned ERROR. Sleep and retry");
                        sleep(DEFAULT_THREAD_SLEEP);
                        continue;
                    }
                }
                WTC_SetThreadStatus(index, WTC_THRD_INITIALIZED);
                WTC_SetThreadState(index, WTC_THRD_RUN);
                sleep(WanTrafficCountInfo_t[index]->SleepInterval);
                continue;
            }
            case WTC_THRD_RUN:
                WTC_SetThreadStatus(index, WTC_THRD_RUNNING);
                break;
            case WTC_THRD_SUSPEND:
                WTC_DeInit(index, FALSE);
                WTC_SetThreadStatus(index, WTC_THRD_SUSPENDED);
                WTCinfo->WanMode = GetEthWANIndex();
              /*  CID: 280133 Out-of-bounds read (OVERRUN) */
                if(WTCinfo->WanMode)
                {
                    index = WTCinfo->WanMode-1;
                }
                sleep(DEFAULT_THREAD_SLEEP);
                continue;
            case WTC_THRD_DISMISS:
                WTC_DeInit(index, TRUE);
                WTC_SetThreadStatus(index, WTC_THRD_DISMISSED);
                WTCinfo->WanMode = GetEthWANIndex();

                goto wtc_exit;
            default:
                WTC_LOG_INFO("Default Thread state");
                sleep(DEFAULT_THREAD_SLEEP);
                continue;
        }
        if ( RETURN_OK != platform_hal_getDscpClientList(WTCinfo->WanMode, &CliList) )
        {
            WTC_LOG_ERROR("Platform get failed. Sleep and try on the next cycle");
            sleep(WanTrafficCountInfo_t[index]->SleepInterval);
            continue;
        }

        pthread_mutex_lock(&WTCinfo->WanTrafficMutexVar);

           ResetIsUpdatedFlag(WanTrafficCountInfo_t[index]->DscpTree);
           WanTrafficCountInfo_t[index]->DscpTree =
                             InsertClient(WanTrafficCountInfo_t[index]->DscpTree, &CliList);
        pthread_mutex_unlock(&WTCinfo->WanTrafficMutexVar);

        if(!WanTrafficCountInfo_t[index]->DscpTree)
        {
            WTC_LOG_ERROR("InsertClient failure, sleep and retry in next iter");
            sleep(WanTrafficCountInfo_t[index]->SleepInterval);
            continue;
        }

        WTC_SendTrafficCountRbus(index);
        sleep(WanTrafficCountInfo_t[index]->SleepInterval);
        continue;
        }
        else
        {
            break;
          // TODO: Exit gracefully, so that the thread info would be meaningful to start back.
        }
    }

wtc_exit:
    WTC_LOG_INFO("Exit Thread");
    WTCinfo->WanTrafficThreadId = 0;
    pthread_exit(NULL);
}
