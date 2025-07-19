/************************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
**************************************************************************/
/*********************************************************************************

    description:

        This is the template file of ssp_action.c for XxxxSsp.
        Please replace "XXXX" with your own ssp name with the same up/lower cases.

        SSP implementation of functions:

        *   ssp_create
        *   ssp_engage
        *   ssp_cancel
        *   ssp_CcdIfGetComponentName
        *   ssp_CcdIfGetComponentVersion
        *   ssp_CcdIfGetComponentAuthor
        *   ssp_CcdIfGetComponentHealth
        *   ssp_CcdIfGetComponentState
        *   ssp_CcdIfGetLoggingEnabled
        *   ssp_CcdIfSetLoggingEnabled
        *   ssp_CcdIfGetLoggingLevel
        *   ssp_CcdIfSetLoggingLevel
        *   ssp_CcdIfGetMemMaxUsage
        *   ssp_CcdIfGetMemMinUsage
        *   ssp_CcdIfGetMemConsumed

  ------------------------------------------------------------------------------

    revision:

        09/08/2011    initial revision.

**********************************************************************************/

#include "ssp_global.h"
#include "plugin_main.h"
#include "dslh_dmagnt_interface.h"
#include "ccsp_trace.h"
#include "dm_pack_create_func.h"
#ifdef MLT_ENABLED
#include "rpl_malloc.h"
#include "mlt_malloc.h"
#endif
#include "safec_lib_common.h"

PDSLH_CPE_CONTROLLER_OBJECT     pDslhCpeController        = NULL;
PCOMPONENT_COMMON_LMLITE          g_pComponent_COMMON_lmlite  = NULL;
PCCSP_CCD_INTERFACE             pSsdCcdIf                 = (PCCSP_CCD_INTERFACE        )NULL;
PDSLH_LCB_INTERFACE             pDslhLcbIf                = (PDSLH_LCB_INTERFACE        )NULL;
extern char                     g_Subsystem[32];
extern  ANSC_HANDLE                        bus_handle;
extern  ULONG                              g_ulAllocatedSizePeak;

ANSC_STATUS
ssp_create
    (
    )
{
    /* Create component common data model object */

     g_pComponent_COMMON_lmlite = (PCOMPONENT_COMMON_LMLITE)AnscAllocateMemory(sizeof(COMPONENT_COMMON_LMLITE));

    if ( ! g_pComponent_COMMON_lmlite )
    {
        return ANSC_STATUS_RESOURCES;
    }

    ComponentCommonDmInit( g_pComponent_COMMON_lmlite);

     g_pComponent_COMMON_lmlite->Name     = AnscCloneString(CCSP_COMPONENT_NAME_LMLITE);
     g_pComponent_COMMON_lmlite->Version  = 1;
     g_pComponent_COMMON_lmlite->Author   = AnscCloneString("Your name");
     errno_t                     rc       = -1;

    /* Create ComponentCommonDatamodel interface*/
    if ( !pSsdCcdIf )
    {
        pSsdCcdIf = (PCCSP_CCD_INTERFACE)AnscAllocateMemory(sizeof(CCSP_CCD_INTERFACE));

        if ( !pSsdCcdIf )
        {
            return ANSC_STATUS_RESOURCES;
        }
        else
        {
            rc = strcpy_s(pSsdCcdIf->Name, sizeof(pSsdCcdIf->Name),CCSP_CCD_INTERFACE_NAME);
            ERR_CHK(rc);

            pSsdCcdIf->InterfaceId              = CCSP_CCD_INTERFACE_ID;
            pSsdCcdIf->hOwnerContext            = NULL;
            pSsdCcdIf->Size                     = sizeof(CCSP_CCD_INTERFACE);

            pSsdCcdIf->GetComponentName         = ssp_CcdIfGetComponentName;
            pSsdCcdIf->GetComponentVersion      = ssp_CcdIfGetComponentVersion;
            pSsdCcdIf->GetComponentAuthor       = ssp_CcdIfGetComponentAuthor;
            pSsdCcdIf->GetComponentHealth       = ssp_CcdIfGetComponentHealth;
            pSsdCcdIf->GetComponentState        = ssp_CcdIfGetComponentState;
            pSsdCcdIf->GetLoggingEnabled        = ssp_CcdIfGetLoggingEnabled;
            pSsdCcdIf->SetLoggingEnabled        = ssp_CcdIfSetLoggingEnabled;
            pSsdCcdIf->GetLoggingLevel          = ssp_CcdIfGetLoggingLevel;
            pSsdCcdIf->SetLoggingLevel          = ssp_CcdIfSetLoggingLevel;
            pSsdCcdIf->GetMemMaxUsage           = ssp_CcdIfGetMemMaxUsage;
            pSsdCcdIf->GetMemMinUsage           = ssp_CcdIfGetMemMinUsage;
            pSsdCcdIf->GetMemConsumed           = ssp_CcdIfGetMemConsumed;
            pSsdCcdIf->ApplyChanges             = ssp_CcdIfApplyChanges;
        }
    }

    /* Create ComponentCommonDatamodel interface*/
    if ( !pDslhLcbIf )
    {
        pDslhLcbIf = (PDSLH_LCB_INTERFACE)AnscAllocateMemory(sizeof(DSLH_LCB_INTERFACE));

        if ( !pDslhLcbIf )
        {
            return ANSC_STATUS_RESOURCES;
        }
        else
        {
            rc = strcpy_s(pDslhLcbIf->Name, sizeof(pDslhLcbIf->Name),CCSP_LIBCBK_INTERFACE_NAME);
            ERR_CHK(rc);

            pDslhLcbIf->InterfaceId              = CCSP_LIBCBK_INTERFACE_ID;
            pDslhLcbIf->hOwnerContext            = NULL;
            pDslhLcbIf->Size                     = sizeof(DSLH_LCB_INTERFACE);

            pDslhLcbIf->InitLibrary              = COSA_Init;
        }
    }

    pDslhCpeController = DslhCreateCpeController(NULL, NULL, NULL);

    if ( !pDslhCpeController )
    {
        CcspTraceWarning(("CANNOT Create pDslhCpeController... Exit!\n"));

        return ANSC_STATUS_RESOURCES;
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
ssp_engage
    (
    )
{
	ANSC_STATUS					    returnStatus                = ANSC_STATUS_SUCCESS;
    PCCC_MBI_INTERFACE              pSsdMbiIf                   = (PCCC_MBI_INTERFACE)MsgHelper_CreateCcdMbiIf((void*)bus_handle, g_Subsystem);
    char                            CrName[256];
    errno_t                         rc                          = -1;

     g_pComponent_COMMON_lmlite->Health = CCSP_COMMON_COMPONENT_HEALTH_Yellow;

    /* data model configuration */
    pDslhCpeController->AddInterface((ANSC_HANDLE)pDslhCpeController, (ANSC_HANDLE)pDslhLcbIf);
    pDslhCpeController->AddInterface((ANSC_HANDLE)pDslhCpeController, (ANSC_HANDLE)pSsdMbiIf);
    pDslhCpeController->AddInterface((ANSC_HANDLE)pDslhCpeController, (ANSC_HANDLE)pSsdCcdIf);
    pDslhCpeController->SetDbusHandle((ANSC_HANDLE)pDslhCpeController, (ANSC_HANDLE)bus_handle);
    pDslhCpeController->Engage((ANSC_HANDLE)pDslhCpeController);

    rc = sprintf_s(CrName, sizeof(CrName), "%s%s", g_Subsystem, CCSP_DBUS_INTERFACE_CR);
    if(rc < EOK)
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }

    returnStatus =
        pDslhCpeController->RegisterCcspDataModel2
            (
                (ANSC_HANDLE)pDslhCpeController,
                CrName, /* CCSP_DBUS_INTERFACE_CR,*/              /* CCSP CR ID */
                DMPackCreateDataModelXML,             /* Data Model XML file. Can be empty if only base data model supported. */
                CCSP_COMPONENT_NAME_LMLITE,            /* Component Name    */
                CCSP_COMPONENT_VERSION_LMLITE,         /* Component Version */
                CCSP_COMPONENT_PATH_LMLITE,            /* Component Path    */
                g_Subsystem /* Component Prefix  */
            );

    if ( returnStatus == ANSC_STATUS_SUCCESS || returnStatus == CCSP_SUCCESS )
    {
        /* System is fully initialized */
         g_pComponent_COMMON_lmlite->Health = CCSP_COMMON_COMPONENT_HEALTH_Green;
    }

    return ANSC_STATUS_SUCCESS;
}


ANSC_STATUS
ssp_cancel
    (
    )
{
	int                             nRet  = 0;
    char                            CrName[256];
    char                            CpName[256];
    errno_t                         rc = -1;

    if(  g_pComponent_COMMON_lmlite == NULL)
    {
        return ANSC_STATUS_SUCCESS;
    }

    rc = sprintf_s(CrName, sizeof(CrName), "%s%s", g_Subsystem, CCSP_DBUS_INTERFACE_CR);
    if(rc < EOK)
    {
       ERR_CHK(rc);
       return ANSC_STATUS_FAILURE;
    }

    rc = sprintf_s(CpName, sizeof(CpName), "%s%s", g_Subsystem, CCSP_COMPONENT_NAME_LMLITE);
    if(rc < EOK)
    {
       ERR_CHK(rc);
       return ANSC_STATUS_FAILURE;
    }
    /* unregister component */
    nRet = CcspBaseIf_unregisterComponent(bus_handle, CrName, CpName );  
    AnscTrace("unregisterComponent returns %d\n", nRet);

    pDslhCpeController->Cancel((ANSC_HANDLE)pDslhCpeController);
    AnscFreeMemory(pDslhCpeController);

    if ( pSsdCcdIf ) AnscFreeMemory(pSsdCcdIf);
    if (  g_pComponent_COMMON_lmlite ) AnscFreeMemory( g_pComponent_COMMON_lmlite);

     g_pComponent_COMMON_lmlite = NULL;
    pSsdCcdIf                = NULL;
    pDslhCpeController       = NULL;

    return ANSC_STATUS_SUCCESS;
}


char*
ssp_CcdIfGetComponentName
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return  g_pComponent_COMMON_lmlite->Name;
}


ULONG
ssp_CcdIfGetComponentVersion
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return  g_pComponent_COMMON_lmlite->Version;
}


char*
ssp_CcdIfGetComponentAuthor
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return  g_pComponent_COMMON_lmlite->Author;
}


ULONG
ssp_CcdIfGetComponentHealth
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return  g_pComponent_COMMON_lmlite->Health;
}


ULONG
ssp_CcdIfGetComponentState
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return  g_pComponent_COMMON_lmlite->State;
}



BOOL
ssp_CcdIfGetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return  g_pComponent_COMMON_lmlite->LogEnable;
}


ANSC_STATUS
ssp_CcdIfSetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject,
        BOOL                            bEnabled
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    if( g_pComponent_COMMON_lmlite->LogEnable == bEnabled) return ANSC_STATUS_SUCCESS;
     g_pComponent_COMMON_lmlite->LogEnable = bEnabled;
    if(bEnabled) g_iTraceLevel = (INT)  g_pComponent_COMMON_lmlite->LogLevel;
    else g_iTraceLevel = CCSP_TRACE_INVALID_LEVEL;

    return ANSC_STATUS_SUCCESS;
}


ULONG
ssp_CcdIfGetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return  g_pComponent_COMMON_lmlite->LogLevel;
}


ANSC_STATUS
ssp_CcdIfSetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject,
        ULONG                           LogLevel
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    if( g_pComponent_COMMON_lmlite->LogLevel == LogLevel) return ANSC_STATUS_SUCCESS;
     g_pComponent_COMMON_lmlite->LogLevel = LogLevel;
    if( g_pComponent_COMMON_lmlite->LogEnable) g_iTraceLevel = (INT)  g_pComponent_COMMON_lmlite->LogLevel;

    return ANSC_STATUS_SUCCESS;
}


ULONG
ssp_CcdIfGetMemMaxUsage
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_ulAllocatedSizePeak;
}


ULONG
ssp_CcdIfGetMemMinUsage
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return  g_pComponent_COMMON_lmlite->MemMinUsage;
}


ULONG
ssp_CcdIfGetMemConsumed
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    LONG             size = 0;

    size = AnscGetComponentMemorySize(CCSP_COMPONENT_NAME_LMLITE);
    if (size == -1 )
        size = 0;

    return size;
}


ANSC_STATUS
ssp_CcdIfApplyChanges
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS                         returnStatus    = ANSC_STATUS_SUCCESS;
    /* Assume the parameter settings are committed immediately. */
    /* AnscSetTraceLevel((INT) g_pComponent_COMMON_lmlite->LogLevel); */

    return returnStatus;
}
