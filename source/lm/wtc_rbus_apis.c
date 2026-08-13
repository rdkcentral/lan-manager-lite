/*
 * If not stated otherwise in this file or this component's Licenses.txt file
 * the following copyright and licenses apply:
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


#include <stdio.h>
#include <ctype.h>
#include <pthread.h>
#include "wtc_rbus_apis.h"
#include "wtc_rbus_handler_apis.h"
#include "cosa_wantraffic_api.h"
#include "cosa_wantraffic_utils.h"
#include "safec_lib.h"

#define ALL_DSCP            -1
#define NUM_OF_RBUS_PARAMS  sizeof(WTCRbusDataElements)/sizeof(WTCRbusDataElements[0])

extern pstWTCInfo_t WTCinfo;
extern pstWanTrafficCountInfo_t WanTrafficCountInfo_t[2];

BOOL IsRbusEnabled = FALSE;

rbusDataElement_t WTCRbusDataElements[5] =
{
//RBUS_TABLE
    { "Device.X_RDK_WAN.Interface.{i}", RBUS_ELEMENT_TYPE_TABLE, {NULL, NULL, WTC_TableAddRowHandler, WTC_TableRemoveRowHandler, NULL, NULL} },
    { "Device.X_RDK_WAN.Interface.{i}.Stats.DscpCountEnable", RBUS_ELEMENT_TYPE_EVENT, {WTC_TableStringGetHandler, WTC_TableStringSetHandler, NULL, NULL, WTC_TableStringEventSubHandler, NULL} },
    { "Device.X_RDK_WAN.Interface.{i}.Stats.DscpCountInterval", RBUS_ELEMENT_TYPE_EVENT, {WTC_TableUlongGetHandler, WTC_TableUlongSetHandler, NULL, NULL, WTC_TableUlongEventSubHandler, NULL} },
    { "Device.X_RDK_WAN.Interface.{i}.Stats.DscpCountPerInterval", RBUS_ELEMENT_TYPE_EVENT, {WTC_TableStringGetHandler, NULL, NULL, NULL, WTC_TableStringEventSubHandler, NULL} },
    { "Device.X_RDK_WAN.Interface.{i}.Stats.DscpCountTotal", RBUS_ELEMENT_TYPE_EVENT, {WTC_TableStringGetHandler, NULL, NULL, NULL, WTC_TableStringEventSubHandler, NULL} }

};


/**********************************************************************
    function:
        WTC_RbusInit
    description:
        This function is called to Init Rbus
    argument:
        VOID
    return:
        RBUS_ERROR_SUCCESS if succeeded;
        RBUS_ERROR_BUS_ERROR if error.
**********************************************************************/
rbusError_t WTC_RbusInit(VOID)
{
    int rc = RBUS_ERROR_SUCCESS;

    if(RBUS_ENABLED == rbus_checkStatus())
    {
        IsRbusEnabled = TRUE;
        WTC_LOG_INFO("RBUS enabled, Proceed with Wan traffic Count");
    }
    else
    {
        WTC_LOG_INFO("RBUS is NOT ENABLED, Do not proceed with WAN traffic count");
        return RBUS_ERROR_BUS_ERROR;
    }

    rc = rbus_open(&WTCinfo->handle, LMLITE_RBUS_COMPONENT_NAME);
    if (rc != RBUS_ERROR_SUCCESS)
    {
        WTC_LOG_ERROR("LMLite rbus initialization failed");
        rc = RBUS_ERROR_NOT_INITIALIZED;
        return rc;
    }
    // Register data elements
    rc = rbus_regDataElements(WTCinfo->handle, NUM_OF_RBUS_PARAMS, WTCRbusDataElements);
    if (rc != RBUS_ERROR_SUCCESS)
    {
        WTC_LOG_ERROR("rbus register data elements failed");
        rc = rbus_close(WTCinfo->handle);
        return rc;
    }

    // Initializing the "Device.X_RDK_GatewayManagement.Gateway." table with rows.
    for(unsigned int i=1; i<=SUPPORTED_WAN_MODES; i++)
    {
        WTC_LOG_INFO("Adding row '%d' to the Wan traffic table.", i);
        rc = rbusTable_addRow(WTCinfo->handle, "Device.X_RDK_WAN.Interface.", NULL, NULL);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            WTC_LOG_ERROR("rbusTable_addRow failed %d", rc);
        }
    }
    return rc;
}

/**********************************************************************
    function:
        GetParamName
    description:
        This function is called to get the paramname
    argument:
        CHAR const*    path
    return:
        CHAR const*    path
**********************************************************************/

CHAR const* GetParamName(CHAR const* path)
{
    char const* p = path + strlen(path);
    while(p > path && *(p-1) != '.')
        p--;
    return p;
}

/**********************************************************************
    function:
        IsDigit
    description:
        This function is to check if digit is present in the input string
    argument:
        CHAR*    str
    return:
        TRUE,   if only digit is present
        FALSE,  Otherwise
**********************************************************************/
BOOL IsDigit(CHAR* str)
{
    UINT i = 0;
    for(i=0; str[i] != '\0'; i++)
    {
        WTC_LOG_INFO("Inside FOR");
        if(isdigit(str[i]) == 0)
        {
            WTC_LOG_INFO("Is Digit returns FALSE");
            return FALSE;
        }
    }
    WTC_LOG_INFO("IsDigit returns TRUE");
    return TRUE;
}

/**********************************************************************
    function:
        CheckIfValidDscp
    description:
        This function is to check if the string has valid dscp's
    argument:
        CHAR*    str
    return:
        TRUE,   if only valid dscp's are present
        FALSE,  Otherwise
**********************************************************************/
BOOL CheckIfValidDscp(CHAR* pString)
{
    INT dscp;
    CHAR dscpStr[BUFLEN_256] = {0};
    errno_t rc = -1;
    rc = strncpy_s(dscpStr, BUFLEN_256, pString, BUFLEN_256);
    ERR_CHK(rc);
    CHAR *token = strtok(dscpStr, ",");

    while (token != NULL)
    {
        dscp = atoi(token);
        WTC_LOG_INFO("Dscp = %d", dscp);
        if ((dscp != ALL_DSCP) &&
            !(dscp >= MIN_VALID_DSCP && dscp <= MAX_VALID_DSCP))
        {
            WTC_LOG_ERROR("Invalid value present");
            return FALSE;
        }
        else if(dscp == 0 && !IsDigit(token))
        {
            WTC_LOG_INFO("Invalid value present");
            return FALSE;
        }
        else
        {
            WTC_LOG_INFO("Valid dscp = %d", dscp);
        }
        token = strtok(NULL, ",");
    }
    return TRUE;
}

/**********************************************************************
    function:
        Stats_GetParamStringValue
    description:
        This function is called to retrieve the string parameter value.
    argument:
        ANSC_HANDLE    hInsContext, The Instance handle
        CHAR*          ParamName,   Parameter name
        CHAR*          pValue,      string value
        ULONG*         pUlSize,     buffer length of the string
    return:
        BOOL           0 if succeeded
**********************************************************************/
BOOL Stats_GetParamStringValue
      (
          ANSC_HANDLE                 hInsContext,
          CHAR*                       ParamName,
          CHAR*                       pValue,
          ULONG*                      pUlSize
      )
{
    pthread_mutex_lock(&WTCinfo->WanTrafficMutexVar);
    pstWanTrafficCountInfo_t client = (pstWanTrafficCountInfo_t) hInsContext;

    if (!hInsContext)
    {
        WTC_LOG_ERROR("hcontext is NULL, return FALSE");
        pthread_mutex_unlock(&WTCinfo->WanTrafficMutexVar);//CID 279998: Missing unlock (LOCK)
        return FALSE;
    }

    if (strcmp(ParamName, "DscpCountEnable") == 0)
    {
        if(!WTC_GetConfig("DscpEnabledList", pValue, *pUlSize, client->InstanceNum))
        {
            if(RBUS_ERROR_SUCCESS == WTC_EventPublish(WTC_DCSPCOUNTENABLE, pValue, client->InstanceNum))
            {
                WTC_LOG_INFO("WTC_DCSPCOUNTENABLE WTC_EventPublish Success");
            }
            else
            {
                WTC_LOG_ERROR("WTC_DCSPCOUNTENABLE WTC_EventPublish FAILURE");
            }
        }
        else
        {
            WTC_LOG_ERROR("Dscp list syscfg get FAILURE");
        }
    }
    else if (strcmp(ParamName, "DscpCountPerInterval") == 0)
    {
        if(client->InstanceNum == WTCinfo->WanMode)
        {
            WTC_GetCount(pValue, pUlSize, TRUE, client);
            if(RBUS_ERROR_SUCCESS == WTC_EventPublish(WTC_COUNTPERINTERVAL, pValue, client->InstanceNum))
            {
                WTC_LOG_INFO("WTC_COUNTPERINTERVAL WTC_EventPublish Success");
            }
            else
            {
                WTC_LOG_ERROR("WTC_COUNTPERINTERVAL WTC_EventPublish FAILURE");
            }
        }
        else
        {
            WTC_LOG_INFO("client->InstanceNum != WTCinfo->WanMode, \
                                    Do not call GetWantrafficCount");
        }
    }
    else if (strcmp(ParamName, "DscpCountTotal") == 0)
    {
        if(client->InstanceNum == WTCinfo->WanMode)
        {
            WTC_GetCount(pValue, pUlSize, FALSE, client);
            if(RBUS_ERROR_SUCCESS == WTC_EventPublish(WTC_COUNTTOTAL, pValue, client->InstanceNum))
            {
                WTC_LOG_INFO("WTC_COUNTTOTAL WTC_EventPublish Success");
            }
            else
            {
                WTC_LOG_ERROR("WTC_COUNTTOTAL WTC_EventPublish FAILURE");
            }
        }
        else
        {
            WTC_LOG_INFO("client->InstanceNum != WTCinfo->WanMode, \
                                    Do not call GetWantrafficCount");
        }
    }
    else
    {
        WTC_LOG_ERROR("Unsupported Param");
        pthread_mutex_unlock(&WTCinfo->WanTrafficMutexVar);//CID 279998: Missing unlock (LOCK)
        return FALSE;
    }
    pthread_mutex_unlock(&WTCinfo->WanTrafficMutexVar);
    return TRUE;
}

/**********************************************************************
    function:
        Stats_GetParamUlongValue
    description:
        This function is called to retrieve the Ulong parameter value.
    argument:
        ANSC_HANDLE    hInsContext, The Instance handle
        CHAR*          ParamName,   Parameter name
        ULONG*         pInt         Buffer of returned ULONG value
    return:
        TRUE if succeeded
        FALSE if failure
**********************************************************************/
BOOL Stats_GetParamUlongValue
      (
          ANSC_HANDLE                 hInsContext,
          CHAR*                       ParamName,
          ULONG*                      pInt
      )
{
    pstWanTrafficCountInfo_t client = (pstWanTrafficCountInfo_t) hInsContext;

    if (!hInsContext)
    {
        WTC_LOG_ERROR("hcontext is NULL, return FALSE");
        return FALSE;
    }

    if (strcmp(ParamName, "DscpCountInterval") == 0)
    {
        CHAR buf[BUFLEN_32] = {0};
        if(!WTC_GetConfig("DscpSleepInterval", buf, sizeof(buf), client->InstanceNum))
        {
            *pInt = atoi(buf);
            WTC_LOG_INFO("Sleep Interval = %lu", *pInt);
            if(RBUS_ERROR_SUCCESS == WTC_EventPublish(WTC_COUNTINTERVAL, buf, client->InstanceNum))
            {
                WTC_LOG_INFO("WTC_COUNTINTERVAL WTC_EventPublish Success");
            }
            else
            {
                WTC_LOG_ERROR("WTC_COUNTINTERVAL WTC_EventPublish FAILURE");
            }
        }
        else
        {
            WTC_LOG_ERROR("SleepInterval syscfg get FAILURE");
        }
        return TRUE;
    }
    WTC_LOG_ERROR("Invalid Param");
    return FALSE;
}

/**********************************************************************
    function:
        Stats_SetParamStringValue
    description:
        This function is called to set the string parameter value.
    argument:
        ANSC_HANDLE    hInsContext, The Instance handle
        CHAR*          ParamName,   Parameter name
        CHAR*          pString      Value to be set to the parameter
    return:
        TRUE if succeeded
        FALSE if failure
**********************************************************************/
BOOL Stats_SetParamStringValue
      (
          ANSC_HANDLE                 hInsContext,
          CHAR*                       ParamName,
          CHAR*                       pString
      )
{
    pstWanTrafficCountInfo_t client = (pstWanTrafficCountInfo_t) hInsContext;

    if (!hInsContext)
    {
        WTC_LOG_ERROR("hcontext is NULL, return FALSE");
        return FALSE;
    }

    //WTCinfo->WanMode = GetEthWANIndex();
    if (strcmp(ParamName, "DscpCountEnable") == 0)
    {
        if(!CheckIfValidDscp(pString))
        {
            WTC_LOG_ERROR("Invalid dscp");
            return FALSE;
        }
        if(WTC_SetConfig("DscpEnabledList", pString, client->InstanceNum))
        {
            WTC_LOG_ERROR("syscfg set failure, return");
            return TRUE;
        }
        if(RBUS_ERROR_SUCCESS == WTC_EventPublish(WTC_DCSPCOUNTENABLE, pString, client->InstanceNum))
        {
            WTC_LOG_INFO("WTC_DCSPCOUNTENABLE WTC_EventPublish Success");
        }
        else
        {
            WTC_LOG_ERROR("WTC_DCSPCOUNTENABLE WTC_EventPublish FAILURE");
        }
        client->IsDscpListSet = TRUE;
        if(client->InstanceNum == GetEthWANIndex() && !IsBridgeMode())
        {
            WTC_LOG_INFO("WanMode = %d & !BridgeMode, Set Input change flag\
                                  Call WTC_ApplyStateChange", WTCinfo->WanMode);
            WTCinfo->WTCConfigFlag[client->InstanceNum-1] |= WTC_INPUT_CHANGE;
            WTCinfo->WTCConfigFlag[client->InstanceNum-1] |= WTC_DSCP_CONFIGURED;
            WTC_ApplyStateChange();
        }
        return TRUE;
    }
    WTC_LOG_ERROR("Unsupported Param");
    return FALSE;
}

/**********************************************************************
    function:
        Stats_SetParamUlongValue
    description:
        This function is called to set the ULONG parameter value.
    argument:
        ANSC_HANDLE    hInsContext, The Instance handle
        char*          ParamName,   Parameter name
        ULONG          iValue       Value to be set to the parameter
    return:
        TRUE if succeeded
        FALSE if failure
**********************************************************************/
BOOL Stats_SetParamUlongValue
      (
          ANSC_HANDLE                 hInsContext,
          CHAR*                       ParamName,
          ULONG                       iValue
      )
{
    pstWanTrafficCountInfo_t client = (pstWanTrafficCountInfo_t) hInsContext;

    if (!hInsContext)
    {
        WTC_LOG_ERROR("hcontext is NULL, return FALSE");
        return FALSE;
    }

    if (strcmp(ParamName, "DscpCountInterval") == 0)
    {
        CHAR buf[BUFLEN_32] = {0};
        snprintf(buf, sizeof(buf), "%lu", iValue);

        if(!IsDigit(buf))
        {
            WTC_LOG_ERROR("Invalid Input");
            return FALSE;
        }

        if(WTC_SetConfig("DscpSleepInterval", buf, client->InstanceNum))
        {
            WTC_LOG_ERROR("syscfg set failure, return");
            return TRUE;
        }

        client->IsSleepIntvlSet = TRUE;
        if(RBUS_ERROR_SUCCESS == WTC_EventPublish(WTC_COUNTINTERVAL, buf, client->InstanceNum))
        {
            WTC_LOG_INFO("WTC_COUNTINTERVAL WTC_EventPublish Success");
        }
        else
        {
            WTC_LOG_ERROR("WTC_COUNTINTERVAL WTC_EventPublish FAILURE");
        }

        if(client->InstanceNum == GetEthWANIndex() && !IsBridgeMode())
        {
            WTC_LOG_INFO("Sleep Interval isset and not in bridge mode.\
                          Set Input change flag & Call WTC_ApplyStateChange");
            WTCinfo->WTCConfigFlag[client->InstanceNum-1] |= WTC_INPUT_CHANGE;
            WTCinfo->WTCConfigFlag[client->InstanceNum-1] |= WTC_SLEEPINTRVL_CONFIGURED;
            WTC_ApplyStateChange();
        }
        return TRUE;
    }
    WTC_LOG_ERROR("Unsupported param, return FALSE");
    return FALSE;
}
