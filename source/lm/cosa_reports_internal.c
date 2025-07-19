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

/**************************************************************************

    module: cosa_wifi_dml.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file implementes back-end apis for the COSA Data Model Library

        *  CosaWifiCreate
        *  CosaWifiInitialize
        *  CosaWifiRemove
    -------------------------------------------------------------------

    environment:

        platform independent

**************************************************************************/

#include "cosa_reports_internal.h"
#include "cosa_ndstatus_dml.h"
#include "cosa_ndtraffic_dml.h"
#ifdef MLT_ENABLED
#include "rpl_malloc.h"
#include "mlt_malloc.h"
#endif
#if defined(DEVICE_GATEWAY_ASSOCIATION_FEATURE)
#include "cosa_managementserver_dml.h"
#endif
//extern void* g_pDslhDmlAgent;

/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        CosaWifiCreate
            (
            );

    description:

        This function constructs cosa wifi object and return handle.

    argument:  

    return:     newly created wifi object.

**********************************************************************/

ANSC_HANDLE
CosaReportsCreate
    (
        VOID
    )
{
	PCOSA_DATAMODEL_REPORTS       pMyObject    = (PCOSA_DATAMODEL_REPORTS)NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
     */
    pMyObject = (PCOSA_DATAMODEL_REPORTS)AnscAllocateMemory(sizeof(COSA_DATAMODEL_REPORTS));

    if ( !pMyObject )
    {
        return  (ANSC_HANDLE)NULL;
    }

    return  (ANSC_HANDLE)pMyObject;
}


/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        CosaWifiInitialize
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate  cosa wifi object and return handle.

    argument:	ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
CosaReportsInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;
    PCOSA_DATAMODEL_REPORTS       pMyObject           = (PCOSA_DATAMODEL_REPORTS)hThisObject;
   

    returnStatus = CosaDmlNetworkDevicesStatusInit((ANSC_HANDLE)pMyObject);
    
    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {        
        return  returnStatus;
    }
    
    returnStatus = CosaDmlNetworkDevicesTrafficInit((ANSC_HANDLE)pMyObject);
    
    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {        
        return  returnStatus;
    }
#if defined(DEVICE_GATEWAY_ASSOCIATION_FEATURE)
   returnStatus = CosaDmlManagedDeviceInit((ANSC_HANDLE)hThisObject);
#endif
    return returnStatus;
}


/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        CosaWifiRemove
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate  cosa wifi object and return handle.

    argument:	ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/
ANSC_STATUS
CosaReportsRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PCOSA_DATAMODEL_REPORTS            pMyObject    = (PCOSA_DATAMODEL_REPORTS)hThisObject;    
        
    /* Remove self */
    AnscFreeMemory((ANSC_HANDLE)pMyObject);

	return returnStatus;
}
