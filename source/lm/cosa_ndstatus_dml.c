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

#include "ansc_platform.h"
#include "cosa_ndstatus_dml.h"
#include "cosa_reports_internal.h"
#include "ssp_global.h"
#include "ccsp_trace.h"
#include "ccsp_psm_helper.h"
#include "lm_main.h"
#include "network_devices_status.h"

/*Added for rdkb-4343*/
#include "ccsp_lmliteLog_wrapper.h"

#include "safec_lib_common.h"


extern ANSC_HANDLE bus_handle;
extern char g_Subsystem[32];
extern COSA_DATAMODEL_REPORTS* g_pReports;

static char *NetworkDevicesStatusEnabled              = "eRT.com.cisco.spvtg.ccsp.lmlite.NetworkDevicesStatusEnabled";
static char *NetworkDevicesStatusReportingPeriod      = "eRT.com.cisco.spvtg.ccsp.lmlite.NetworkDevicesStatusReportingPeriod";
static char *NetworkDevicesStatusPollingPeriod        = "eRT.com.cisco.spvtg.ccsp.lmlite.NetworkDevicesStatusPollingPeriod";
static char *NetworkDevicesStatusDefReportingPeriod   = "eRT.com.cisco.spvtg.ccsp.lmlite.NetworkDevicesStatusDefReportingPeriod";
static char *NetworkDevicesStatusDefPollingPeriod     = "eRT.com.cisco.spvtg.ccsp.lmlite.NetworkDevicesStatusDefPollingPeriod";

extern char* GetNDStatusSchemaBuffer();
extern int GetNDStatusSchemaBufferSize();
extern char* GetNDStatusSchemaIDBuffer();
extern int GetNDStatusSchemaIDBufferSize();

//RDKB-9258 : save periods after TTL expiry to NVRAM
static pthread_mutex_t g_ndsNvramMutex = PTHREAD_MUTEX_INITIALIZER;

ANSC_STATUS GetNVRamULONGConfiguration(char* setting, ULONG* value)
{
    char *strValue = NULL;
    int retPsmGet = CCSP_SUCCESS;

    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, setting, NULL, &strValue);
    if (retPsmGet == CCSP_SUCCESS) {
        *value = _ansc_atoi(strValue);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
    }
    return retPsmGet;
}

ANSC_STATUS SetNVRamULONGConfiguration(char* setting, ULONG value)
{
    int retPsmSet = CCSP_SUCCESS;
    char psmValue[32] = {};
    ULONG psm_value = 0;
    errno_t rc      = -1;

    retPsmSet = GetNVRamULONGConfiguration(setting,&psm_value);

    if ((retPsmSet == CCSP_SUCCESS) && (psm_value == value))
    {
      CcspLMLiteConsoleTrace(("%s PSM value is same for setting [%s] Value [%lu]\n",__FUNCTION__,setting, value));
      return retPsmSet;
    }

    rc = sprintf_s(psmValue, sizeof(psmValue), "%lu", value);
    if(rc < EOK)
    {
        ERR_CHK(rc);
        return CCSP_FAILURE;
    }

    retPsmSet = PSM_Set_Record_Value2(bus_handle,g_Subsystem, setting, ccsp_string, psmValue);
    if (retPsmSet != CCSP_SUCCESS) 
        {
        CcspLMLiteConsoleTrace(("%s PSM_Set_Record_Value2 returned ERROR [%d] while setting [%s] Value [%lu]\n",__FUNCTION__, retPsmSet, setting, value));
        }
    else
        {
        CcspLMLiteConsoleTrace(("%s PSM_Set_Record_Value2 returned SUCCESS[%d] while Setting [%s] Value [%lu]\n",__FUNCTION__, retPsmSet, setting, value));
        }
    return retPsmSet;
}

// Persisting Polling period
ANSC_STATUS
SetNDSPollingPeriodInNVRAM(ULONG pPollingVal)
{
    ANSC_STATUS     returnStatus = ANSC_STATUS_SUCCESS;

    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }
    //Acquire mutex
    pthread_mutex_lock(&g_ndsNvramMutex);	

    g_pReports->uNDSPollingPeriod = pPollingVal;
    returnStatus = SetNVRamULONGConfiguration(NetworkDevicesStatusPollingPeriod,  pPollingVal);
    g_pReports->bNDSPollingPeriodChanged = false;

    //Release mutex
    pthread_mutex_unlock(&g_ndsNvramMutex);

    return returnStatus;
}

// Persisting Reporting period
ANSC_STATUS
SetNDSReportingPeriodInNVRAM(ULONG pReportingVal)
{
    ANSC_STATUS     returnStatus = ANSC_STATUS_SUCCESS;

    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }
    //Acquire mutex
    pthread_mutex_lock(&g_ndsNvramMutex);	

    g_pReports->uNDSReportingPeriod = pReportingVal;
    returnStatus = SetNVRamULONGConfiguration(NetworkDevicesStatusReportingPeriod, pReportingVal);
    g_pReports->bNDSReportingPeriodChanged = false;

    //Release mutex
    pthread_mutex_unlock(&g_ndsNvramMutex);

    return returnStatus;
}

ANSC_STATUS
CosaDmlNetworkDevicesStatusInit
    (
        ANSC_HANDLE                 hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;
    int retPsmGet = CCSP_SUCCESS;
    ULONG psmValue = 0;
    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    retPsmGet = GetNVRamULONGConfiguration(NetworkDevicesStatusEnabled, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pReports->bNDSEnabled = psmValue;
        SetNDSHarvestingStatus(g_pReports->bNDSEnabled);
    }

    retPsmGet = GetNVRamULONGConfiguration(NetworkDevicesStatusReportingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pReports->uNDSReportingPeriod = psmValue;
        SetNDSReportingPeriod(g_pReports->uNDSReportingPeriod);
    }

    retPsmGet = GetNVRamULONGConfiguration(NetworkDevicesStatusPollingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pReports->uNDSPollingPeriod = psmValue;
        SetNDSPollingPeriod(g_pReports->uNDSPollingPeriod);
    }

    retPsmGet = GetNVRamULONGConfiguration(NetworkDevicesStatusDefReportingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pReports->uNDSReportingPeriodDefault = psmValue;
        SetNDSReportingPeriodDefault(g_pReports->uNDSReportingPeriodDefault);
    }

    retPsmGet = GetNVRamULONGConfiguration(NetworkDevicesStatusDefPollingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pReports->uNDSPollingPeriodDefault = psmValue;
        SetNDSPollingPeriodDefault(g_pReports->uNDSPollingPeriodDefault);
    }

    return returnStatus;
}


BOOL
NetworkDevicesStatus_GetParamBoolValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    BOOL*                       pBool
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));

    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "Enabled") == 0)
    {
        /* collect value */
        *pBool    =  GetNDSHarvestingStatus();
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%d] \n", __FUNCTION__ , ParamName, *pBool ));
        return TRUE;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}

BOOL
NetworkDevicesStatus_SetParamBoolValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    BOOL                        bValue
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));
    /* check the parameter name and set the corresponding value */
    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return FALSE;
    }

    if (strcmp(ParamName, "Enabled") == 0)
    {
        g_pReports->bNDSEnabledChanged = true;
        g_pReports->bNDSEnabled = bValue;
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%d] \n", __FUNCTION__ , ParamName, bValue ));
	if(g_pReports->bNDSEnabled) {
		CcspTraceInfo(("NetworkDevicesStatus:Enabled\n"));
	}
	else {
		CcspTraceInfo(("NetworkDevicesStatus:Disabled\n"));
	}
        return TRUE;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}

BOOL
NetworkDevicesStatus_GetParamUlongValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    ULONG*                      puLong
)
{
	UNREFERENCED_PARAMETER(hInsContext);
	CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));

    if (strcmp(ParamName, "PollingPeriod") == 0)
    {
        *puLong =  GetNDSPollingPeriod();
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    if (strcmp(ParamName, "ReportingPeriod") == 0)
    {
        *puLong =  GetNDSReportingPeriod();
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

    return FALSE;
}

BOOL
NetworkDevicesStatus_SetParamUlongValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    ULONG                       uValue
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));
    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return FALSE;
    }

    if (strcmp(ParamName, "PollingPeriod") == 0)
    {
        g_pReports->bNDSPollingPeriodChanged = true;
        g_pReports->uNDSPollingPeriod = uValue;
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    if (strcmp(ParamName, "ReportingPeriod") == 0)
    {
        g_pReports->bNDSReportingPeriodChanged = true;
        g_pReports->uNDSReportingPeriod = uValue;
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}

ULONG
NetworkDevicesStatus_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));
    errno_t  rc = -1;

    if (strcmp(ParamName, "Schema") == 0)
    {
        /* collect value */
        int bufsize = GetNDStatusSchemaBufferSize();
        if(!bufsize)
        {
            rc = strcpy_s(pValue, *pUlSize, "Schema Buffer is empty");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return -1;
            }
            return 0;
        }
        else
	{
	CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Buffer Size [%d] InputSize [%lu]\n", bufsize, *pUlSize));
        if (bufsize < (int)*pUlSize)
        {
             /* LIMITATION
             * Following AnscCopyString() can't modified to safec strcpy_s() api
             * Because, safec has the limitation of copying only 4k ( RSIZE_MAX ) to destination pointer
             * And here, we have source pointer size more than 4k, i.e simetimes 190k also
            */
            AnscCopyString(pValue, GetNDStatusSchemaBuffer());
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, pValue Buffer Size [%d] \n", (int)strlen(pValue)));
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));
            return 0;
        }
        else
        {
            *pUlSize = bufsize + 1;
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));
            return 1;
        }
	}
    }

    if (strcmp(ParamName, "SchemaID") == 0)
    {
        /* collect value */
        int bufsize = GetNDStatusSchemaIDBufferSize();
        if(!bufsize)
        {
            rc = strcpy_s(pValue, *pUlSize, "SchemaID Buffer is empty");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return -1;
            }
            return 0;
        }
        else
        {

	CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Buffer Size [%d] InputSize [%lu]\n", bufsize, *pUlSize));
        if (bufsize < (int)*pUlSize)
        {
            rc = strcpy_s(pValue, *pUlSize, GetNDStatusSchemaIDBuffer());
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return -1;
            }
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, pValue Buffer Size [%d] \n", (int)strlen(pValue)));
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));
            return 0;
        }
        else
        {
            *pUlSize = bufsize + 1;
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));
            return 1;
        }
	}
    }

    AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

    return -1;
}



/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        NetworkDevicesStatus_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
NetworkDevicesStatus_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));
    errno_t  rc  = -1;
    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return FALSE;
    }

    if(g_pReports->bNDSPollingPeriodChanged)
    {
        BOOL validated = ValidateNDSPeriod(g_pReports->uNDSPollingPeriod);    
        if(!validated)
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : PollingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pReports->uNDSPollingPeriod));
            rc = strcpy_s(pReturnParamName, *puLength, "PollingPeriod");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return FALSE;
            }

            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;
        }
        if( GetNDSHarvestingStatus() && g_pReports->uNDSPollingPeriod > GetNDSPollingPeriod())
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : PollingPeriod Validation Failed : New Polling Period [%lu] > Current Polling Period [%lu] \n", __FUNCTION__ , g_pReports->uNDSPollingPeriod, GetNDSPollingPeriod() ));
            rc = strcpy_s(pReturnParamName, *puLength, "PollingPeriod");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return FALSE;
            }
            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;           
        }

        ULONG period = (g_pReports->bNDSReportingPeriodChanged == TRUE) ? g_pReports->uNDSReportingPeriod : GetNDSReportingPeriod();

        if(g_pReports->uNDSPollingPeriod > period )
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : PollingPeriod Validation Failed : New Polling Period [%lu] > Current Reporting Period [%lu] \n", __FUNCTION__ , g_pReports->uNDSPollingPeriod, period ));
            rc = strcpy_s(pReturnParamName, *puLength, "PollingPeriod");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return FALSE;
            }

            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;           
        }
    }

    if(g_pReports->bNDSReportingPeriodChanged)
    {
        BOOL validated = ValidateNDSPeriod(g_pReports->uNDSReportingPeriod);    
        if(!validated)
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : NeighboringAPPollingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pReports->uNDSReportingPeriod));
            rc = strcpy_s(pReturnParamName, *puLength, "ReportingPeriod");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return FALSE;
            }
            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;
        }

        ULONG period = (g_pReports->bNDSPollingPeriodChanged == TRUE) ? g_pReports->uNDSPollingPeriod : GetNDSPollingPeriod();

        if(g_pReports->uNDSReportingPeriod < period )
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : ReportingPeriod Validation Failed : New Reporting Period [%lu] < Current Polling Period [%lu] \n", __FUNCTION__ , g_pReports->uNDSReportingPeriod, period ));
            rc = strcpy_s(pReturnParamName, *puLength, "ReportingPeriod");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return FALSE;
            }

            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;           
        }
        if(GetNDSHarvestingStatus() && g_pReports->uNDSReportingPeriod > GetNDSReportingPeriod())
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : ReportingPeriod Validation Failed : New Reporting Period [%lu] > Current Reporting Period [%lu] \n", __FUNCTION__ , g_pReports->uNDSReportingPeriod, GetNDSReportingPeriod() ));
            rc = strcpy_s(pReturnParamName, *puLength, "ReportingPeriod");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return FALSE;
            }

            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;           
        }
    }

     CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        NetworkDevicesStatus_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
NetworkDevicesStatus_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));
    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return 1;
    }

    if(g_pReports->bNDSEnabledChanged)
    {
    g_pReports->bNDSEnabled = GetNDSHarvestingStatus();
    g_pReports->bNDSEnabledChanged = false;
    }

    if(g_pReports->bNDSPollingPeriodChanged)
    {
    g_pReports->uNDSPollingPeriod = GetNDSPollingPeriod();
    g_pReports->bNDSPollingPeriodChanged = false;
    }
    if(g_pReports->bNDSReportingPeriodChanged)
    {
    g_pReports->uNDSReportingPeriod = GetNDSReportingPeriod();
    g_pReports->bNDSReportingPeriodChanged = false;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

    return 0;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        NetworkDevicesStatus_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
NetworkDevicesStatus_Commit
(
    ANSC_HANDLE                 hInsContext
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));
    ULONG psmValue = 0;
    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return 1;
    }
    /* Network Device Parameters*/

    if(g_pReports->bNDSEnabledChanged)
    {
    SetNDSHarvestingStatus(g_pReports->bNDSEnabled);
    psmValue = g_pReports->bNDSEnabled;
    SetNVRamULONGConfiguration(NetworkDevicesStatusEnabled, psmValue);
    g_pReports->bNDSEnabledChanged = false;
    }

    if(g_pReports->bNDSPollingPeriodChanged)
    {
    psmValue = g_pReports->uNDSPollingPeriod;
    SetNDSPollingPeriod(psmValue);
    SetNDSOverrideTTL(GetNDSOverrideTTLDefault());
    SetNDSPollingPeriodInNVRAM( psmValue );
    }

    if(g_pReports->bNDSReportingPeriodChanged)
    {
    psmValue = g_pReports->uNDSReportingPeriod;
    SetNDSReportingPeriod(psmValue);
    SetNDSOverrideTTL(GetNDSOverrideTTLDefault());  
    SetNDSReportingPeriodInNVRAM( psmValue );
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

    return 0;
}

BOOL
NetworkDevicesStatus_Default_GetParamUlongValue
    (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));

    if (strcmp(ParamName, "PollingPeriod") == 0)
    {
        *puLong =  GetNDSPollingPeriodDefault();
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return TRUE;
    }

    if (strcmp(ParamName, "ReportingPeriod") == 0)
    {
        *puLong =  GetNDSReportingPeriodDefault();
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    if (strcmp(ParamName, "OverrideTTL") == 0)
    {
        *puLong =  GetNDSOverrideTTLDefault();
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

    return FALSE;
}

BOOL
NetworkDevicesStatus_Default_SetParamUlongValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    ULONG                       uValue
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));
    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return FALSE;
    }

    if (strcmp(ParamName, "PollingPeriod") == 0)
    {
        g_pReports->bNDSDefPollingPeriodChanged = true;
        g_pReports->uNDSPollingPeriodDefault = uValue;
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    if (strcmp(ParamName, "ReportingPeriod") == 0)
    {
        g_pReports->bNDSDefReportingPeriodChanged = true;
        g_pReports->uNDSReportingPeriodDefault = uValue;
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        NetworkDevicesStatus_Default_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
NetworkDevicesStatus_Default_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));
    errno_t  rc  = -1;
    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return FALSE;
    }

    if(g_pReports->bNDSDefPollingPeriodChanged)
    {
        BOOL validated = ValidateNDSPeriod(g_pReports->uNDSPollingPeriodDefault);
        if(!validated)
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Default PollingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pReports->uNDSPollingPeriodDefault));
            rc = strcpy_s(pReturnParamName, *puLength, "PollingPeriod");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return FALSE;
            }
            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;
        }
  
        ULONG period = (g_pReports->bNDSDefReportingPeriodChanged == TRUE) ? g_pReports->uNDSReportingPeriodDefault : GetNDSReportingPeriodDefault();

        if (g_pReports->uNDSPollingPeriodDefault > period)
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Default PollingPeriod Validation Failed : New Default Polling Period [%lu] > Current Default Reporting Period [%lu] \n", __FUNCTION__ , g_pReports->uNDSPollingPeriodDefault, period ));
            rc = strcpy_s(pReturnParamName, *puLength, "PollingPeriod");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return FALSE;
            }

            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;
        }
    }

    if(g_pReports->bNDSDefReportingPeriodChanged)
    {
        BOOL validated = ValidateNDSPeriod(g_pReports->uNDSReportingPeriodDefault);
        if(!validated)
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Default ReportingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pReports->uNDSReportingPeriodDefault));
            rc = strcpy_s(pReturnParamName, *puLength, "ReportingPeriod");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return FALSE;
            }

            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;
        }
        
	ULONG period = (g_pReports->bNDSDefPollingPeriodChanged == TRUE) ? g_pReports->uNDSPollingPeriodDefault : GetNDSPollingPeriodDefault();
        
	if (g_pReports->uNDSReportingPeriodDefault < period)
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Default ReportingPeriod Validation Failed : New Default Reporting Period [%lu] < Current Default Polling Period [%lu] \n", __FUNCTION__ , g_pReports->uNDSReportingPeriodDefault, period ));
            rc = strcpy_s(pReturnParamName, *puLength, "ReportingPeriod");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return FALSE;
            }

            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;
        }
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));
    
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        NetworkDevicesStatus_Default_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
NetworkDevicesStatus_Default_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));
    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return 1;
    }

    if(g_pReports->bNDSDefPollingPeriodChanged)
    {
    g_pReports->uNDSPollingPeriodDefault = GetNDSPollingPeriodDefault();
    g_pReports->bNDSDefPollingPeriodChanged = false;
    }
    if(g_pReports->bNDSDefReportingPeriodChanged)
    {
    g_pReports->uNDSReportingPeriodDefault = GetNDSReportingPeriodDefault();
    g_pReports->bNDSDefReportingPeriodChanged = false;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

    return 0;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        NetworkDevicesStatus_Default_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
NetworkDevicesStatus_Default_Commit
(
    ANSC_HANDLE                 hInsContext
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));
    ULONG psmValue = 0;

    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return 1;
    }
    if(g_pReports->bNDSDefReportingPeriodChanged)
    {
    SetNDSReportingPeriodDefault(g_pReports->uNDSReportingPeriodDefault);
    psmValue = g_pReports->uNDSReportingPeriodDefault;
    SetNVRamULONGConfiguration(NetworkDevicesStatusDefReportingPeriod, psmValue);
    SetNDSOverrideTTL(GetNDSOverrideTTLDefault());
    g_pReports->bNDSDefReportingPeriodChanged = false;
    }

    if(g_pReports->bNDSDefPollingPeriodChanged)
    {
    SetNDSPollingPeriodDefault(g_pReports->uNDSPollingPeriodDefault);
    psmValue = g_pReports->uNDSPollingPeriodDefault;
    SetNVRamULONGConfiguration(NetworkDevicesStatusDefPollingPeriod, psmValue);
    SetNDSOverrideTTL(GetNDSOverrideTTLDefault());
    g_pReports->bNDSDefPollingPeriodChanged = false;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

    return 0;
}

