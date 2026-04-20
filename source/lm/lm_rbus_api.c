/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
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
   Copyright [2026] [Cisco Systems, Inc.]
 
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
#include "lm_rbus_api.h"
#include "ccsp_lmliteLog_wrapper.h"
#include "ansc_platform.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static rbusHandle_t rbus_handle;

pthread_mutex_t g_mloRfcMutex = PTHREAD_MUTEX_INITIALIZER;

/* Global variable for MLO RFC enable status */
static bool g_MLORfcEnabled = false;

//Initiate Rbus
rbusError_t lmliteRbusInit(const char *pComponentName)
{
	int ret = RBUS_ERROR_SUCCESS;
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, rbus_open for component %s\n", pComponentName));
	ret = rbus_open(&rbus_handle, pComponentName);
	if(ret != RBUS_ERROR_SUCCESS)
	{
		CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLiteRbusInit failed with error code %d\n", ret));
		return ret;
	}
	CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLiteRbusInit is success. ret is %d\n", ret));
	return ret;
}

//Checking the Rbus active status
bool checkRbusEnabled()
{
    int isRbus = RBUS_ERROR_SUCCESS;
    
    if(RBUS_ENABLED == rbus_checkStatus())
	{
		isRbus = true;
	}
	else
	{
		isRbus = false;
	}
	CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite RBUS mode active status = %s\n", isRbus ? "true":"false"));
	return isRbus;
}

rbusHandle_t get_rbus_handle(void)
{
    return rbus_handle;
}

/**
 * To persist TR181 parameter values in PSM DB.
 */
int rbus_StoreValueIntoPsmDB(char *paramName, char *value)
{
    rbusHandle_t rbus_handle = get_rbus_handle();
    rbusObject_t inParams;
    rbusObject_t outParams;
    rbusValue_t setvalue;
    int rc = RBUS_ERROR_SUCCESS;

    if(!rbus_handle)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, %s: failed as rbus_handle is empty\n", __FUNCTION__));
        return 1;
    }

    rbusObject_Init(&inParams, NULL);
    rbusValue_Init(&setvalue);
    rbusValue_SetString(setvalue, value);
    rbusObject_SetValue(inParams, paramName, setvalue);
    rbusValue_Release(setvalue);

    rc = rbusMethod_Invoke(rbus_handle, "SetPSMRecordValue()", inParams, &outParams);
    rbusObject_Release(inParams);
    if(rc != RBUS_ERROR_SUCCESS)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, %s: SetPSMRecordValue failed with err %d: %s\n", __FUNCTION__, rc, rbusError_ToString(rc)));
    }
    else
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s: SetPSMRecordValue is success\n", __FUNCTION__));
        rbusObject_Release(outParams);
        return 0;
    }
    return 1;
}

/**
 * To fetch TR181 parameter values from PSM DB.
 */
int rbus_GetValueFromPsmDB( char* paramName, char** paramValue)
{
    rbusHandle_t rbus_handle = get_rbus_handle();
    rbusObject_t inParams;
    rbusObject_t outParams;
    rbusValue_t setvalue;
    int rc = RBUS_ERROR_SUCCESS;

    if(!rbus_handle)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, %s: failed as rbus_handle is empty\n", __FUNCTION__));
        return 1;
    }

    rbusObject_Init(&inParams, NULL);
    rbusValue_Init(&setvalue);
    rbusValue_SetString(setvalue, "value");
    rbusObject_SetValue(inParams, paramName, setvalue);
    rbusValue_Release(setvalue);

    rc = rbusMethod_Invoke(rbus_handle, "GetPSMRecordValue()", inParams, &outParams);
    rbusObject_Release(inParams);
    if(rc != RBUS_ERROR_SUCCESS)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, %s: GetPSMRecordValue failed with err %d: %s\n", __FUNCTION__, rc, rbusError_ToString(rc)));
    }
    else
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s: GetPSMRecordValue is success\n", __FUNCTION__));
        rbusProperty_t prop = NULL;
        rbusValue_t value = NULL;
        const char *str_value = NULL;
        prop = rbusObject_GetProperties(outParams);
        while(prop)
        {
            value = rbusProperty_GetValue(prop);
            if(value)
            {
                str_value = rbusValue_ToString(value,NULL,0);
                if(str_value)
                {
                    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s: Parameter Name : %s\n", __FUNCTION__, rbusProperty_GetName(prop)));
                    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s: Parameter Value fetched: %s\n", __FUNCTION__, str_value));
                }
            }
            prop = rbusProperty_GetNext(prop);
        }
        if(str_value != NULL)
        {
            *paramValue = strdup(str_value);
            if(*paramValue == NULL)
            {
                CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, %s: strdup failed for parameter value\n", __FUNCTION__));
                rbusObject_Release(outParams);
                return 1;
            }
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s: Requested param DB value [%s]\n", __FUNCTION__, *paramValue));
            rbusObject_Release(outParams);
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Set MLO RFC enable status and persist to PSM
 */
int set_lmLiteMLORfcEnable(bool bValue)
{
    // Update PSM DB Value
    rbusError_t retPsmSet = RBUS_ERROR_SUCCESS;
    char *buf = NULL;

    buf = bValue ? strdup("true") : strdup("false");
    if (buf == NULL)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, %s: strdup failed\n", __FUNCTION__));
        return 1;
    }

    retPsmSet = rbus_StoreValueIntoPsmDB(LMLITE_MLO_RFC_PARAM, buf);
    if (retPsmSet != RBUS_ERROR_SUCCESS)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, %s: PSM set failed ret %d for parameter %s and value %s\n", __FUNCTION__, retPsmSet, LMLITE_MLO_RFC_PARAM, buf));
        free(buf);
        return 1;
    }
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s: PSM set success for parameter %s and value %s\n", __FUNCTION__, LMLITE_MLO_RFC_PARAM, buf));

    /* Update global MLO RFC variable under mutex to avoid data races */
    pthread_mutex_lock(&g_mloRfcMutex);
    g_MLORfcEnabled = bValue;
    pthread_mutex_unlock(&g_mloRfcMutex);
    if(bValue == true)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s: lmLite MLO RFC is enabled\n", __FUNCTION__));
    }
    else
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s: lmLite MLO RFC is disabled\n", __FUNCTION__));
    }
    free(buf);
    return 0;
}

/**
 * @brief Get MLO RFC enable status
 */
bool get_lmLiteMLORfcEnable(void)
{
    bool isRfc = false;
    pthread_mutex_lock(&g_mloRfcMutex);
    isRfc = g_MLORfcEnabled;
    pthread_mutex_unlock(&g_mloRfcMutex);
    return isRfc;
}

/**
 * @brief RBUS Set handler for MLO RFC parameter
 */
static rbusError_t lmLiteMLO_RfcSetHandler(rbusHandle_t handle, rbusProperty_t prop, rbusSetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    const char *propertyName;
    propertyName = rbusProperty_GetName(prop);
    if (propertyName == NULL)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, %s: Unable to handle set request for property\n", __FUNCTION__));
        return RBUS_ERROR_INVALID_INPUT;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s: Property Name is %s\n", __FUNCTION__, propertyName));

    if (strcmp(propertyName, LMLITE_MLO_RFC_PARAM) != 0)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, %s: Unexpected parameter %s\n", __FUNCTION__, propertyName));
        return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    }
    
    rbusValue_t paramValue_t = NULL;
    rbusValueType_t type;

    paramValue_t = rbusProperty_GetValue(prop);
    if (paramValue_t == NULL)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, %s: value is NULL\n", __FUNCTION__));
        return RBUS_ERROR_INVALID_INPUT;
    }

    type = rbusValue_GetType(paramValue_t);
    if (type != RBUS_BOOLEAN)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, %s: Unexpected value type %d\n", __FUNCTION__, type));
        return RBUS_ERROR_INVALID_INPUT;
    }

    bool paramVal = rbusValue_GetBoolean(paramValue_t);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s: Setting MLO RFC to %s\n", __FUNCTION__, paramVal ? "true" : "false"));

    if (set_lmLiteMLORfcEnable(paramVal) != 0) {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, %s: set_lmLiteMLORfcEnable failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s: MLO RFC set successfully to %s\n", 
                        __FUNCTION__, paramVal ? "true" : "false"));
    return RBUS_ERROR_SUCCESS;
}

/**
 * @brief RBUS Get handler for MLO RFC parameter
 */
static rbusError_t lmLiteMLO_RfcGetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;

    const char *propertyName;
    propertyName = rbusProperty_GetName(property);
    if (propertyName == NULL)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, %s: Unable to handle get request for property\n", __FUNCTION__));
        return RBUS_ERROR_INVALID_INPUT;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s: Property Name is %s\n", __FUNCTION__, propertyName));

    if (strcmp(propertyName, LMLITE_MLO_RFC_PARAM) != 0)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, %s: Unexpected parameter %s\n", __FUNCTION__, propertyName));
        return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    }

    rbusError_t retPsmGet = RBUS_ERROR_SUCCESS;
    rbusValue_t value;
    bool mloRfcEnabled = false;

    char *tmpchar = NULL;

    /* Get value from PSM DB */
    retPsmGet = rbus_GetValueFromPsmDB(LMLITE_MLO_RFC_PARAM, &tmpchar);
    if (retPsmGet == RBUS_ERROR_SUCCESS)
    {
      if (tmpchar != NULL)
      {
          if ((strcmp(tmpchar, "true") == 0) || (strcmp(tmpchar, "TRUE") == 0))
          {
            pthread_mutex_lock(&g_mloRfcMutex);
            g_MLORfcEnabled = true;
            pthread_mutex_unlock(&g_mloRfcMutex);
          }
          else
          {
            pthread_mutex_lock(&g_mloRfcMutex);
            g_MLORfcEnabled = false;
            pthread_mutex_unlock(&g_mloRfcMutex);
          }
          CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s: MLO RFC value from PSM = %s\n", __FUNCTION__, tmpchar));
          free(tmpchar);
      }
    }
    else
    {
        if (tmpchar)
            free(tmpchar);
        pthread_mutex_lock(&g_mloRfcMutex);
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s: PSM get failed ret %d, using cached value %d\n",__FUNCTION__, retPsmGet, g_MLORfcEnabled));
        pthread_mutex_unlock(&g_mloRfcMutex);
    }

    /* Use cached in-memory value; PSM is read at init and on set */
    pthread_mutex_lock(&g_mloRfcMutex);
    mloRfcEnabled = g_MLORfcEnabled;
    pthread_mutex_unlock(&g_mloRfcMutex);

    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, mloRfcEnabled);
    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s: Mlo Rfc value fetched is %s\n", __FUNCTION__, mloRfcEnabled ? "true" : "false"));
    return RBUS_ERROR_SUCCESS;
}

/**
 * @brief Initialize and register MLO RFC RBUS data elements
 * @return 0 for success, -1 for failure
 */
int regLMLiteDataModel()
{
    rbusError_t ret = RBUS_ERROR_SUCCESS;
    rbusHandle_t handle = get_rbus_handle();


    if (handle == NULL)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, %s: rbus handle is NULL\n", __FUNCTION__));
        return -1;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s: Registering MLO RFC parameter %s\n", __FUNCTION__, LMLITE_MLO_RFC_PARAM));

    rbusDataElement_t dataElements[1] = {
      {LMLITE_MLO_RFC_PARAM, RBUS_ELEMENT_TYPE_PROPERTY, {lmLiteMLO_RfcGetHandler, lmLiteMLO_RfcSetHandler, NULL, NULL, NULL, NULL}}
    };

    ret = rbus_regDataElements(handle, 1, dataElements);

    if (ret != RBUS_ERROR_SUCCESS)
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, %s: rbus_regDataElements failed with error %d\n", __FUNCTION__, ret));
        return -1;
    }
    return 0;
}
