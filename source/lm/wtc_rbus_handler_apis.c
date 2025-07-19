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


#include "safec_lib_common.h"
#include "wtc_rbus_handler_apis.h"
#include "wtc_rbus_apis.h"
#include "cosa_wantraffic_api.h"

extern pstWanTrafficCountInfo_t WanTrafficCountInfo_t[2];

/**********************************************************************
    function:
        WTC_TableUlongGetHandler
    description:
        This Handler function is to get Ulong Value from the table
    argument:
        rbusHandle_t   handle
        rbusProperty_t   property
        rbusGetHandlerOptions_t opts
    return:
        rbusError_t
**********************************************************************/

rbusError_t WTC_TableUlongGetHandler(rbusHandle_t handle, rbusProperty_t property,
                                     rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    BOOL rc;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    rbusValue_t val;
    ULONG value;
    unsigned int instNum;
    int ret;
    WTC_LOG_INFO("Called for [%s]",param);
    //fetch instance number from requested property
    ret = sscanf(propName, "Device.X_RDK_WAN.Interface.%d.", &instNum);
    WTC_LOG_INFO("PropName = %s, param = %s, instnum = %d, ret = %d",
                           propName, param, instNum, ret);
    if(ret==1 && instNum > 0 && instNum <= SUPPORTED_WAN_MODES)
    {
        // Get pointer to Wan traffic table instance
        pstWanTrafficCountInfo_t p_WanTrafficTable = WanTrafficCountInfo_t[instNum-1];
        rc = Stats_GetParamUlongValue(p_WanTrafficTable, param, &value);
        if(!rc)
        {
            WTC_LOG_ERROR("Stats_GetParamUlongValue failed");
            free(param);
            return RBUS_ERROR_BUS_ERROR;
        }
        rbusValue_Init(&val);
        rbusValue_SetUInt32(val, value);
        rbusProperty_SetValue(property, val);
        rbusValue_Release(val);
        free(param);
        return RBUS_ERROR_SUCCESS;
    }
    else
    {
        WTC_LOG_ERROR("Invalid instance '%d' requested", instNum);
        free(param);
        return RBUS_ERROR_INVALID_INPUT;
    }
}

/**********************************************************************
    function:
        WTC_TableUlongSetHandler
    description:
        This Handler function is to set Ulong Value to the table
    argument:
        rbusHandle_t                handle
        rbusProperty_t              property
        rbusGetHandlerOptions_t     opts
    return:
        rbusError_t
**********************************************************************/

rbusError_t WTC_TableUlongSetHandler(rbusHandle_t handle, rbusProperty_t property,
                                     rbusSetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    bool rc = false;
    int ret;
    unsigned int instNum;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    rbusValue_t val = rbusProperty_GetValue(property);
    WTC_LOG_INFO("Called for [%s]", param);

    ret = sscanf(propName, "Device.X_RDK_WAN.Interface.%d.", &instNum);
    WTC_LOG_INFO("PropName = %s, param = %s, instnum = %d, ret = %d",
                           propName, param, instNum, ret);
    if(ret==1 && instNum > 0 && instNum <= SUPPORTED_WAN_MODES)
    {
        // Get pointer to Wan traffic table instance
        pstWanTrafficCountInfo_t p_WanTrafficTable = WanTrafficCountInfo_t[instNum-1];
        if(val)
        {
            if(rbusValue_GetType(val) == RBUS_UINT32)
            {
	        rc = Stats_SetParamUlongValue(p_WanTrafficTable, param, rbusValue_GetUInt32(val));
                free(param);
                if(!rc)
                {
                    WTC_LOG_ERROR("Stats_SetParamUlongValue failed");
                    return RBUS_ERROR_INVALID_INPUT;
                }
            }
	    else
	    {
                WTC_LOG_ERROR("%s result:FAIL error:'unexpected type %d'\n", __FUNCTION__, rbusValue_GetType(val));
                if(param != NULL)
                {
                    free(param);
                    param=NULL;
                }
                return RBUS_ERROR_INVALID_INPUT;
	    }
        }
        else
        {
             if(param != NULL)
             {
                 WTC_LOG_ERROR("%s result:FAIL value=NULL param='%s'\n", __FUNCTION__, param);
                 free(param);
                 param=NULL;
             }
             else
             {
                 WTC_LOG_ERROR("%s param is NULL\n", __FUNCTION__);
             }
             return RBUS_ERROR_INVALID_INPUT;
        }
    }
    else
    {
        WTC_LOG_ERROR("Invalid instance '%d' requested", instNum);
        if(param != NULL)
        {
            free(param);
            param=NULL;
        }
        return RBUS_ERROR_INVALID_INPUT;
    }
    return RBUS_ERROR_SUCCESS;
}

/**********************************************************************
    function:
        WTC_TableUlongEventSubHandler
    description:
        This is an Event Handler for Ulong parameters in the table
    argument:
        rbusHandle_t             handle
        rbusEventSubAction_t     action
        const char*              eventName
        rbusFilter_t             filter
        int32_t                  interval
        bool                     autoPublish
    return:
        rbusError_t
**********************************************************************/

rbusError_t WTC_TableUlongEventSubHandler(rbusHandle_t handle, rbusEventSubAction_t action,
                                          const char *eventName, rbusFilter_t filter,
                                          int32_t interval, bool *autoPublish)
{
    (void)handle;
    (void)filter;
    (void)interval;
    char* param = strdup(GetParamName(eventName));
    unsigned int instNum;
    int ret;
    *autoPublish = false;
    WTC_LOG_INFO("Called for [%s]", param);

    ret = sscanf(eventName, "Device.X_RDK_WAN.Interface.%d.", &instNum);
    WTC_LOG_INFO("Action = %d, EventName = %s, param = %s, instnum = %d, ret = %d",
                           action, eventName, param, instNum, ret);
    if(ret==1 && instNum > 0 && instNum <= SUPPORTED_WAN_MODES)
    {
        WTC_LOG_INFO("Subscribtion handler for param = %s, action = %d, InstNum = %d",
                            param, action, instNum);
    }
    else
    {
        WTC_LOG_ERROR("Invalid instance '%d' requested", instNum);
    }
    /* CID :280138 Resource leak */
    free(param);
    param = NULL;
    return RBUS_ERROR_SUCCESS;
}

/**********************************************************************
    function:
        WTC_TableStringGetHandler
    description:
        This Handler function is to get String Value from the table
    argument:
        rbusHandle_t              handle
        rbusProperty_t            property
        rbusGetHandlerOptions_t   opts
    return:
        rbusError_t
**********************************************************************/

rbusError_t WTC_TableStringGetHandler(rbusHandle_t handle, rbusProperty_t property, 
                                      rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    int32_t rc;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    rbusValue_t val;
    char * value;
    ULONG ulen;
    unsigned int instNum;
    int ret;

    if(!strcmp(param, "DscpCountEnable"))
    {
        value = (char*)malloc(BUFLEN_1024);
        if(!value)
        {
            WTC_LOG_ERROR("Malloc failure");
	    /* CID :280128 Resource leak */
            free(param);
            param = NULL;
            return RBUS_ERROR_BUS_ERROR;
        }
        rc = memset_s(value, BUFLEN_1024, 0, BUFLEN_1024);
        ERR_CHK(rc);
        ulen = BUFLEN_1024;
    }
    else if(!strcmp(param, "DscpCountPerInterval"))
    {
        value = (char*)malloc(BUFLEN_10240);
        if(!value)
        {
            WTC_LOG_ERROR("Malloc failure");
	    /* CID :280128 Resource leak */
	    free(param);
            param = NULL;
            return RBUS_ERROR_BUS_ERROR;
        }
        rc = memset_s(value, BUFLEN_10240, 0, BUFLEN_10240);
        ERR_CHK(rc);
        ulen = (ULONG)BUFLEN_10240;
    }
    else if(!strcmp(param, "DscpCountTotal"))
    {
        value = (char*)malloc(BUFLEN_20480);
        if(!value)
        {
            WTC_LOG_ERROR("Malloc failure");
	    /* CID :280128 Resource leak */
            free(param);
            param = NULL;
            return RBUS_ERROR_BUS_ERROR;
        }
        rc = memset_s(value, BUFLEN_20480, 0, BUFLEN_20480);
        ERR_CHK(rc);
        ulen = (ULONG)BUFLEN_20480;
    }
    else
    {
        WTC_LOG_ERROR("Invalid param '%s'", param);
        free(param);
        return RBUS_ERROR_INVALID_INPUT;
    }

    WTC_LOG_INFO("Called for [%s]", param);
    //fetch instance number from requested property
    ret = sscanf(propName, "Device.X_RDK_WAN.Interface.%d.", &instNum);
    WTC_LOG_INFO("PropName = %s, param = %s, instnum = %d, ret = %d",
                           propName, param, instNum, ret);
    if(ret==1 && instNum > 0 && instNum <= SUPPORTED_WAN_MODES)
    {
        // Get pointer to Wan traffic table instance
        pstWanTrafficCountInfo_t p_WanTrafficTable = WanTrafficCountInfo_t[instNum-1];
        rc = Stats_GetParamStringValue(p_WanTrafficTable, param, value, &ulen);
        free(param);
        if(!rc)
        {
            WTC_LOG_ERROR("Stats_GetParamStringValue failed");
            free(value);
            return RBUS_ERROR_BUS_ERROR;
        }
        rbusValue_Init(&val);
        rbusValue_SetString(val, value);
        rbusProperty_SetValue(property, val);
        rbusValue_Release(val);
        free(value);
        return RBUS_ERROR_SUCCESS;
    }
    else
    {
        WTC_LOG_ERROR("Invalid instance '%d' requested", instNum);
        free(value);
        free(param);
        return RBUS_ERROR_INVALID_INPUT;
    }
}

/**********************************************************************
    function:
        WTC_TableStringSetHandler
    description:
        This Handler function is to set string Value to the table
    argument:
        rbusHandle_t              handle
        rbusProperty_t            property
        rbusGetHandlerOptions_t   opts
    return:
        rbusError_t
**********************************************************************/

rbusError_t WTC_TableStringSetHandler(rbusHandle_t handle, rbusProperty_t property,
                                     rbusSetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    bool rc = false;
    int ret;
    unsigned int instNum;
    char const* propName = rbusProperty_GetName(property);
    rbusValue_t val = rbusProperty_GetValue(property);
    rbusValueType_t type;
    if(val) 
    {
        type = rbusValue_GetType(val);
    } 
    else
    {
	WTC_LOG_ERROR("Invalid input to set\n");
        return RBUS_ERROR_INVALID_INPUT;
    }

    char* pValue = rbusValue_ToString(val,NULL,0);
    char* param = strdup(GetParamName(propName));
    WTC_LOG_INFO("Called for [%s]", param);

    ret = sscanf(propName, "Device.X_RDK_WAN.Interface.%d.", &instNum);
    WTC_LOG_INFO("PropName = %s, param = %s, instnum = %d, ret = %d",
                           propName, param, instNum, ret);
    if(ret==1 && instNum > 0 && instNum <= SUPPORTED_WAN_MODES)
    {
        // Get pointer to Wan traffic table instance
        pstWanTrafficCountInfo_t p_WanTrafficTable = WanTrafficCountInfo_t[instNum-1];

        if((pValue != NULL) && (type == RBUS_STRING))
	{
            rc = Stats_SetParamStringValue(p_WanTrafficTable, param, pValue);
            free(param);
            param = NULL;
            free(pValue);
            pValue = NULL;
            if(!rc)
            {
                WTC_LOG_ERROR("Stats_SetParamStringValue failed");
                return RBUS_ERROR_INVALID_INPUT;
            }
        }
        else
        {
            WTC_LOG_ERROR("%s result:FAIL error:'unexpected type '\n", __FUNCTION__);
            if(param != NULL)
            {
            	free(param);
            	param = NULL;
            }
            
            if(pValue != NULL)
            {
                free(pValue);
                pValue = NULL;
            }
            return RBUS_ERROR_INVALID_INPUT;
	}
    }
    else
    {
        WTC_LOG_ERROR("Invalid instance '%d' requested", instNum);
        free(param);
        param = NULL;
	/* CID :280132  Resource leak  */
	free(pValue);
        pValue = NULL;
        return RBUS_ERROR_INVALID_INPUT;
    }
    return RBUS_ERROR_SUCCESS;
}

/**********************************************************************
    function:
        WTC_TableStringEventSubHandler
    description:
        This is an Event handler function for String parameters in the table
    argument:
        rbusHandle_t             handle
        rbusEventSubAction_t     action
        const char*              eventName
        rbusFilter_t             filter
        int32_t                  interval
        bool                     autoPublish
    return:
        rbusError_t
**********************************************************************/

rbusError_t WTC_TableStringEventSubHandler(rbusHandle_t handle, rbusEventSubAction_t action,
                                           const char *eventName, rbusFilter_t filter,
                                           int32_t interval, bool *autoPublish)
{
    (void)handle;
    (void)filter;
    (void)interval;
    char* param = strdup(GetParamName(eventName));
    unsigned int instNum;
    int ret;
    *autoPublish = false;
    WTC_LOG_INFO("Called for [%s]", param);

    ret = sscanf(eventName, "Device.X_RDK_WAN.Interface.%d.", &instNum);
    WTC_LOG_INFO("Action = %d, EventName = %s, param = %s, instnum = %d, ret = %d",
                           action, eventName, param, instNum, ret);
    if(ret==1 && instNum > 0 && instNum <= SUPPORTED_WAN_MODES)
    {
        WTC_LOG_INFO("Subscribtion handler for param = %s, action = %d, InstNum = %d",
                            param, action, instNum);
    }
    else
    {
        WTC_LOG_ERROR("Invalid instance '%d' requested", instNum);
    }
    /* CID :280139 Resource leak */
    free(param);
    param = NULL;
    return RBUS_ERROR_SUCCESS;
}

/**********************************************************************
    function:
        WTC_TableAddRowHandler
    description:
        Handler function to Add rows
    argument:
        rbusHandle_t   handle
        char const*    tableName
        char const*    aliasName
        uint32_t*      instNum
    return:
        rbusError_t
**********************************************************************/

rbusError_t WTC_TableAddRowHandler(rbusHandle_t handle, char const* tableName,
                                   char const* aliasName, uint32_t* instNum)
{
    (void)handle;
    (void)aliasName;
    static uint32_t instance = 1;
    *instNum = instance++;

    WTC_LOG_INFO("TableName = %s, InstNum = %d", tableName, *instNum);
    return RBUS_ERROR_SUCCESS;
}

/**********************************************************************
    function:
        WTC_TableRemoveRowHandler
    description:
        Handler function to Remove rows
    argument:
        rbusHandle_t   handle
        char const*    rowName
    return:
        rbusError_t
**********************************************************************/

rbusError_t WTC_TableRemoveRowHandler(rbusHandle_t handle, char const* rowName)
{
    (void)handle;
    WTC_LOG_INFO("RowName = %s", rowName);
    return RBUS_ERROR_SUCCESS;
}
