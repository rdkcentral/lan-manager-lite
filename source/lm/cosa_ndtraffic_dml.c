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
#include "network_devices_traffic.h"

/*Added for rdkb-4343*/
#include "ccsp_lmliteLog_wrapper.h"

#include "safec_lib_common.h"

extern ANSC_HANDLE bus_handle;
extern char g_Subsystem[32];
extern COSA_DATAMODEL_REPORTS* g_pReports;

static char *NetworkDevicesTrafficEnabled              = "eRT.com.cisco.spvtg.ccsp.lmlite.NetworkDevicesTrafficEnabled";
static char *NetworkDevicesTrafficReportingPeriod      = "eRT.com.cisco.spvtg.ccsp.lmlite.NetworkDevicesTrafficReportingPeriod";
static char *NetworkDevicesTrafficPollingPeriod        = "eRT.com.cisco.spvtg.ccsp.lmlite.NetworkDevicesTrafficPollingPeriod";
static char *NetworkDevicesTrafficDefReportingPeriod   = "eRT.com.cisco.spvtg.ccsp.lmlite.NetworkDevicesTrafficDefReportingPeriod";
static char *NetworkDevicesTrafficDefPollingPeriod     = "eRT.com.cisco.spvtg.ccsp.lmlite.NetworkDevicesTrafficDefPollingPeriod";

//RDKB-9258 : save periods after TTL expiry to NVRAM
static pthread_mutex_t g_ndtNvramMutex = PTHREAD_MUTEX_INITIALIZER;

extern char* GetNDTrafficSchemaBuffer();
extern int GetNDTrafficSchemaBufferSize();
extern char* GetNDTrafficSchemaIDBuffer();
extern int GetNDTrafficSchemaIDBufferSize();


extern ANSC_STATUS GetNVRamULONGConfiguration(char* setting, ULONG* value);
extern ANSC_STATUS SetNVRamULONGConfiguration(char* setting, ULONG value);


// Persisting Polling period
ANSC_STATUS
SetNDTPollingPeriodInNVRAM(ULONG pPollingVal)
{
    ANSC_STATUS     returnStatus = ANSC_STATUS_SUCCESS;

    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }
    //Acquire mutex
    pthread_mutex_lock(&g_ndtNvramMutex);

    g_pReports->uNDTPollingPeriod = pPollingVal;
    returnStatus = SetNVRamULONGConfiguration(NetworkDevicesTrafficPollingPeriod, pPollingVal);
    g_pReports->bNDTPollingPeriodChanged = false;

    //Release mutex
    pthread_mutex_unlock(&g_ndtNvramMutex);

    return returnStatus;
}

// Persisting Reporting period
ANSC_STATUS
SetNDTReportingPeriodInNVRAM(ULONG pReportingVal)
{
    ANSC_STATUS     returnStatus = ANSC_STATUS_SUCCESS;
    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    //Acquire mutex
    pthread_mutex_lock(&g_ndtNvramMutex);

    g_pReports->uNDTReportingPeriod = pReportingVal;
    returnStatus = SetNVRamULONGConfiguration(NetworkDevicesTrafficReportingPeriod, pReportingVal);
    g_pReports->bNDTReportingPeriodChanged = false;

    //Release mutex
    pthread_mutex_unlock(&g_ndtNvramMutex);

    return returnStatus;
}

ANSC_STATUS
CosaDmlNetworkDevicesTrafficInit
    (
        ANSC_HANDLE                 hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;
    int retPsmGet = CCSP_SUCCESS;
    ULONG psmValue = 0;

    retPsmGet = GetNVRamULONGConfiguration(NetworkDevicesTrafficEnabled, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pReports->bNDTEnabled = psmValue;
        SetNDTHarvestingStatus(g_pReports->bNDTEnabled);
    }

    retPsmGet = GetNVRamULONGConfiguration(NetworkDevicesTrafficReportingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pReports->uNDTReportingPeriod = psmValue;
        SetNDTReportingPeriod(g_pReports->uNDTReportingPeriod);
    }

    retPsmGet = GetNVRamULONGConfiguration(NetworkDevicesTrafficPollingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pReports->uNDTPollingPeriod = psmValue;
        SetNDTPollingPeriod(g_pReports->uNDTPollingPeriod);
    }

    retPsmGet = GetNVRamULONGConfiguration(NetworkDevicesTrafficDefReportingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pReports->uNDTReportingPeriodDefault = psmValue;
        SetNDTReportingPeriodDefault(g_pReports->uNDTReportingPeriodDefault);
    }

    retPsmGet = GetNVRamULONGConfiguration(NetworkDevicesTrafficDefPollingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pReports->uNDTPollingPeriodDefault = psmValue;
        SetNDTPollingPeriodDefault(g_pReports->uNDTPollingPeriodDefault);
    }

    return returnStatus;
}

BOOL
NetworkDevicesTraffic_GetParamUlongValue
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
        *puLong =  GetNDTPollingPeriod();
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    if (strcmp(ParamName, "ReportingPeriod") == 0)
    {
        *puLong =  GetNDTReportingPeriod();
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

    return FALSE;
}

BOOL
NetworkDevicesTraffic_SetParamUlongValue
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
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s report is not initialized and it not supported in Ext mode", __FUNCTION__));
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return FALSE;
    }

    if (strcmp(ParamName, "PollingPeriod") == 0)
    {
        g_pReports->bNDTPollingPeriodChanged = true;
        g_pReports->uNDTPollingPeriod = uValue;
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    if (strcmp(ParamName, "ReportingPeriod") == 0)
    {
        g_pReports->bNDTReportingPeriodChanged = true;
        g_pReports->uNDTReportingPeriod = uValue;
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}

ULONG
NetworkDevicesTraffic_GetParamStringValue
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
        int bufsize = GetNDTrafficSchemaBufferSize();
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
            AnscCopyString(pValue, GetNDTrafficSchemaBuffer());
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
        int bufsize = GetNDTrafficSchemaIDBufferSize();
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
            rc = strcpy_s(pValue, *pUlSize, GetNDTrafficSchemaIDBuffer());
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


BOOL
NetworkDevicesTraffic_GetParamBoolValue
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
        *pBool    =  GetNDTHarvestingStatus();
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%d] \n", __FUNCTION__ , ParamName, *pBool ));
        return TRUE;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}

BOOL
NetworkDevicesTraffic_SetParamBoolValue
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
        g_pReports->bNDTEnabledChanged = true;
        g_pReports->bNDTEnabled = bValue;
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%d] \n", __FUNCTION__ , ParamName, bValue ));
	if(g_pReports->bNDTEnabled) {
		CcspTraceInfo(("NetworkDevicesTraffic:Enabled\n"));
	}
	else {
		CcspTraceInfo(("NetworkDevicesTraffic:Disabled\n"));
	}
        return TRUE;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}


/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        NetworkDevicesTraffic_Validate
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
NetworkDevicesTraffic_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));
    errno_t  rc = -1;
    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return FALSE;
    }

    if(g_pReports->bNDTPollingPeriodChanged)
    {
        BOOL validated = ValidateNDTPeriod(g_pReports->uNDTPollingPeriod);    
        if(!validated)
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : PollingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pReports->uNDTPollingPeriod));
            rc = strcpy_s(pReturnParamName, *puLength, "PollingPeriod");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return FALSE;
            }
            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;
        }
        if(GetNDTHarvestingStatus() && g_pReports->uNDTPollingPeriod > GetNDTPollingPeriod())
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : PollingPeriod Validation Failed : New Polling Period [%lu] > Current Polling Period [%lu] \n", __FUNCTION__ , g_pReports->uNDTPollingPeriod, GetNDTPollingPeriod() ));
            rc = strcpy_s(pReturnParamName, *puLength, "PollingPeriod");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return FALSE;
            }

            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;           
        }

        ULONG period = (g_pReports->bNDTReportingPeriodChanged == TRUE) ? g_pReports->uNDTReportingPeriod : GetNDTReportingPeriod();

        if(g_pReports->uNDTPollingPeriod > period )
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : PollingPeriod Validation Failed : New Polling Period [%lu] > Current Reporting Period [%lu] \n", __FUNCTION__ , g_pReports->uNDTPollingPeriod, period ));
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

    if(g_pReports->bNDTReportingPeriodChanged)
    {
        BOOL validated = ValidateNDTPeriod(g_pReports->uNDTReportingPeriod);    
        if(!validated)
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : NeighboringAPPollingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pReports->uNDTReportingPeriod));
            rc = strcpy_s(pReturnParamName, *puLength, "ReportingPeriod");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return FALSE;
            }

            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;
        }

        ULONG period = (g_pReports->bNDTPollingPeriodChanged == TRUE) ? g_pReports->uNDTPollingPeriod : GetNDTPollingPeriod();

        if(g_pReports->uNDTReportingPeriod < period )
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : ReportingPeriod Validation Failed : New Reporting Period [%lu] < Current Polling Period [%lu] \n", __FUNCTION__ , g_pReports->uNDTReportingPeriod, period ));
            rc = strcpy_s(pReturnParamName, *puLength, "ReportingPeriod");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return FALSE;
            }

            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;           
        }
        if(GetNDTHarvestingStatus() && g_pReports->uNDTReportingPeriod > GetNDTReportingPeriod())
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : ReportingPeriod Validation Failed : New Reporting Period [%lu] > Current Reporting Period [%lu] \n", __FUNCTION__ , g_pReports->uNDTReportingPeriod, GetNDTReportingPeriod() ));
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
        NetworkDevicesTraffic_Commit
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
NetworkDevicesTraffic_Commit
(
    ANSC_HANDLE                 hInsContext
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));
    ULONG psmValue = 0;
    ULONG uVal = 0;
    /* Network Device Parameters*/
    
    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return 1;
    }

    if(g_pReports->bNDTEnabledChanged)
    {
    SetNDTHarvestingStatus(g_pReports->bNDTEnabled);
    psmValue = g_pReports->bNDTEnabled;
    SetNVRamULONGConfiguration(NetworkDevicesTrafficEnabled, psmValue);
    g_pReports->bNDTEnabledChanged = false;
    }

    if(g_pReports->bNDTPollingPeriodChanged)
    {
    uVal = g_pReports->uNDTPollingPeriod;
    SetNDTPollingPeriod(uVal);
    SetNDTPollingPeriodInNVRAM(uVal);
    SetNDTOverrideTTL(GetNDTOverrideTTLDefault());
    }

    if(g_pReports->bNDTReportingPeriodChanged)
    {
    uVal = g_pReports->uNDTReportingPeriod;
    SetNDTReportingPeriod(uVal);
    SetNDTReportingPeriodInNVRAM(uVal);
    SetNDTOverrideTTL(GetNDTOverrideTTLDefault());  
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        NetworkDevicesTraffic_Rollback
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
NetworkDevicesTraffic_Rollback
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

    if(g_pReports->bNDTEnabledChanged)
    {
    g_pReports->bNDTEnabled = GetNDTHarvestingStatus();
    g_pReports->bNDTEnabledChanged = false;
    }

    if(g_pReports->bNDTPollingPeriodChanged)
    {
    g_pReports->uNDTPollingPeriod = GetNDTPollingPeriod();
    g_pReports->bNDTPollingPeriodChanged = false;
    }
    if(g_pReports->bNDTReportingPeriodChanged)
    {
    g_pReports->uNDTReportingPeriod = GetNDTReportingPeriod();
    g_pReports->bNDTReportingPeriodChanged = false;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

    return 0;
}

BOOL
NetworkDevicesTraffic_Default_GetParamUlongValue
    (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
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
        *puLong =  GetNDTPollingPeriodDefault();
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    if (strcmp(ParamName, "ReportingPeriod") == 0)
    {
        *puLong =  GetNDTReportingPeriodDefault();
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    if (strcmp(ParamName, "OverrideTTL") == 0)
    {
        *puLong =  GetNDTOverrideTTLDefault();
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

    return FALSE;
}

BOOL
NetworkDevicesTraffic_Default_SetParamUlongValue
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
        g_pReports->bNDTDefPollingPeriodChanged = true;
        g_pReports->uNDTPollingPeriodDefault = uValue;
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    if (strcmp(ParamName, "ReportingPeriod") == 0)
    {
        g_pReports->bNDTDefReportingPeriodChanged = true;
        g_pReports->uNDTReportingPeriodDefault = uValue;
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
        NetworkDevicesTraffic_Default_Validate
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
NetworkDevicesTraffic_Default_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));
    if (g_pReports == NULL ) 
    {
        CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, LMLite %s NDS report is not initialized", __FUNCTION__));
        return FALSE;
    }
    errno_t  rc = -1;

    if(g_pReports->bNDTDefPollingPeriodChanged)
    {
        BOOL validated = ValidateNDTPeriod(g_pReports->uNDTPollingPeriodDefault);
        if(!validated)
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Default PollingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pReports->uNDTPollingPeriodDefault));
            rc = strcpy_s(pReturnParamName, *puLength, "PollingPeriod");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return FALSE;
            }

            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;
        }

        ULONG period = (g_pReports->bNDTDefReportingPeriodChanged == TRUE) ? g_pReports->uNDTReportingPeriodDefault : GetNDTReportingPeriodDefault();

        if (g_pReports->uNDTPollingPeriodDefault > period)
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Default PollingPeriod Validation Failed : New Default Polling Period [%lu] > Current Default Reporting Period [%lu] \n", __FUNCTION__ , g_pReports->uNDTPollingPeriodDefault, period ));
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

    if(g_pReports->bNDTDefReportingPeriodChanged)
    {
        BOOL validated = ValidateNDTPeriod(g_pReports->uNDTReportingPeriodDefault);
        if(!validated)
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Default ReportingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pReports->uNDTReportingPeriodDefault));
            rc = strcpy_s(pReturnParamName, *puLength, "ReportingPeriod");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return FALSE;
            }

            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;
        }

        ULONG period = (g_pReports->bNDTDefPollingPeriodChanged == TRUE) ? g_pReports->uNDTPollingPeriodDefault : GetNDTPollingPeriodDefault();

	if (g_pReports->uNDTReportingPeriodDefault < period)
        {
            CcspLMLiteTrace(("RDK_LOG_ERROR, LMLite %s : Default ReportingPeriod Validation Failed : New Default Reporting Period [%lu] < Current Default Polling Period [%lu] \n", __FUNCTION__ , g_pReports->uNDTReportingPeriodDefault, period ));
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
        NetworkDevicesTraffic_Default_Rollback
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
NetworkDevicesTraffic_Default_Rollback
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

    if(g_pReports->bNDTDefPollingPeriodChanged)
    {
    g_pReports->uNDTPollingPeriodDefault = GetNDTPollingPeriodDefault();
    g_pReports->bNDTDefPollingPeriodChanged = false;
    }
    if(g_pReports->bNDTDefReportingPeriodChanged)
    {
    g_pReports->uNDTReportingPeriodDefault = GetNDTReportingPeriodDefault();
    g_pReports->bNDTDefReportingPeriodChanged = false;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

    return 0;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        NetworkDevicesTraffic_Default_Commit
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
NetworkDevicesTraffic_Default_Commit
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

    if(g_pReports->bNDTDefReportingPeriodChanged)
    {
    SetNDTReportingPeriodDefault(g_pReports->uNDTReportingPeriodDefault);
    psmValue = g_pReports->uNDTReportingPeriodDefault;
    SetNVRamULONGConfiguration(NetworkDevicesTrafficDefReportingPeriod, psmValue);
    SetNDTOverrideTTL(GetNDTOverrideTTLDefault());
    g_pReports->bNDTDefReportingPeriodChanged = false;
    }

    if(g_pReports->bNDTDefPollingPeriodChanged)
    {
    SetNDTPollingPeriodDefault(g_pReports->uNDTPollingPeriodDefault);
    psmValue = g_pReports->uNDTPollingPeriodDefault;
    SetNVRamULONGConfiguration(NetworkDevicesTrafficDefPollingPeriod, psmValue);
    SetNDTOverrideTTL(GetNDTOverrideTTLDefault());
    g_pReports->bNDTDefPollingPeriodChanged = false;
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

    return 0;
}

