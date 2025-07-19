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

    module: cosa_xhosts_dml.c

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


**************************************************************************/

#include <time.h>
#include "ansc_platform.h"
#include "cosa_hosts_dml.h"
#include "cosa_xhosts_dml.h"
#include "lm_util.h"

#include "lm_main.h"
#include "safec_lib_common.h"

extern LmObjectHosts XlmHosts;
extern ULONG XHostsUpdateTime;

extern pthread_mutex_t XLmHostObjectMutex;

#define COSA_DML_USERS_USER_ACCESS_INTERVAL     10

/***********************************************************************
 IMPORTANT NOTE:

 According to TR69 spec:
 On successful receipt of a SetParameterValues RPC, the CPE MUST apply 
 the changes to all of the specified Parameters atomically. That is, either 
 all of the value changes are applied together, or none of the changes are 
 applied at all. In the latter case, the CPE MUST return a fault response 
 indicating the reason for the failure to apply the changes. 
 
 The CPE MUST NOT apply any of the specified changes without applying all 
 of them.

 In order to set parameter values correctly, the back-end is required to
 hold the updated values until "Validate" and "Commit" are called. Only after
 all the "Validate" passed in different objects, the "Commit" will be called.
 Otherwise, "Rollback" will be called instead.

 The sequence in COSA Data Model will be:

 SetParamBoolValue/SetParamIntValue/SetParamUlongValue/SetParamStringValue
 -- Backup the updated values;

 if( Validate_XXX())
 {
     Commit_XXX();    -- Commit the update all together in the same object
 }
 else
 {
     Rollback_XXX();  -- Remove the update at backup;
 }
 
***********************************************************************/

/***********************************************************************

 APIs for Object:

    XHosts.

    *  XHosts_GetParamUlongValue
    *  XHosts_SetParamUlongValue

***********************************************************************/
/**********************************************************************  

	caller: 	owner of this object 

	prototype: 

		BOOL
		XHosts_GetParamUlongValue
			(
				ANSC_HANDLE 				hInsContext,
				char*						ParamName,
				ULONG*						puLong
			);

	description:

		This function is called to retrieve ULONG parameter value; 

	argument:	ANSC_HANDLE 				hInsContext,
				The instance handle;

				char*						ParamName,
				The parameter name;

				ULONG*						puLong
				The buffer of returned ULONG value;

	return: 	TRUE if succeeded.

**********************************************************************/


BOOL
XHosts_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "X_CISCO_COM_ConnectedDeviceNumber") == 0)
    {
        *puLong = XLM_get_online_device(); 
        return TRUE;
    }

    return FALSE;
}

/***********************************************************************

 APIs for Object:

    XHosts.XHost.{i}.

    *  XHost_GetEntryCount
    *  XHost_GetEntry
    *  XHost_IsUpdated
    *  XHost_Synchronize
    *  XHost_GetParamBoolValue
    *  XHost_GetParamIntValue
    *  XHost_GetParamUlongValue
    *  XHost_GetParamStringValue
    *  XHost_SetParamBoolValue
    *  XHost_SetParamIntValue
    *  XHost_SetParamUlongValue
    *  XHost_SetParamStringValue
    *  XHost_Validate
    *  XHost_Commit
    *  XHost_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        XHost_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/
ULONG
XHost_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
	UNREFERENCED_PARAMETER(hInsContext);
	ULONG host_count = 0;

	pthread_mutex_lock(&XLmHostObjectMutex);   
	host_count = XlmHosts.numHost;
    pthread_mutex_unlock(&XLmHostObjectMutex);

	return host_count;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ANSC_HANDLE
        XHost_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/
ANSC_HANDLE
XHost_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
	UNREFERENCED_PARAMETER(hInsContext);
	ANSC_HANDLE host = NULL;
	pthread_mutex_lock(&XLmHostObjectMutex); 
	*pInsNumber = XlmHosts.hostArray[nIndex]->instanceNum;

    host = (ANSC_HANDLE) (XlmHosts.hostArray[nIndex]);
	pthread_mutex_unlock(&XLmHostObjectMutex);
	return host;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        XHost_IsUpdated
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is checking whether the table is updated or not.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     TRUE or FALSE.

**********************************************************************/
BOOL
XHost_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    if ( XHostsUpdateTime == 0 ) 
    {
        XHostsUpdateTime = AnscGetTickInSeconds();

        return TRUE;
    }
    
    if ( XHostsUpdateTime >= TIME_NO_NEGATIVE(AnscGetTickInSeconds() - COSA_DML_USERS_USER_ACCESS_INTERVAL ) )
    {
        return FALSE;
    }
    else 
    {
        XHostsUpdateTime = AnscGetTickInSeconds();

        return TRUE;
    }
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        XHost_Synchronize
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to synchronize the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
XHost_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    )
{
	UNREFERENCED_PARAMETER(hInsContext);
	XLM_get_host_info(); 
    XHostsUpdateTime = AnscGetTickInSeconds();

    return 0;
}
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        XHost_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
XHost_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{

    //printf("Host_GetParamBoolValue %p, %s\n", hInsContext, ParamName);
	pthread_mutex_lock(&XLmHostObjectMutex); 
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;
    int i = 0;
    for(; i<LM_HOST_NumBoolPara; i++){
        if (strcmp(ParamName, XlmHosts.pHostBoolParaName[i]) == 0)
        {
            /* collect value */
            *pBool = pHost->bBoolParaValue[i];
			pthread_mutex_unlock(&XLmHostObjectMutex); 
            return TRUE;
        }
    }

	pthread_mutex_unlock(&XLmHostObjectMutex); 
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        XHost_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
XHost_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{


	pthread_mutex_lock(&XLmHostObjectMutex);  
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;
    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "X_CISCO_COM_ActiveTime") == 0)
    {
        /* collect dynamic value */
        if(pHost->bBoolParaValue[LM_HOST_ActiveId]){
	    time_t currentTime = time(NULL);
            if(currentTime > pHost->activityChangeTime){
                pHost->iIntParaValue[LM_HOST_X_CISCO_COM_ActiveTimeId] = currentTime - pHost->activityChangeTime;
            }else{
                pHost->iIntParaValue[LM_HOST_X_CISCO_COM_ActiveTimeId] = 0;
            }
        }
	else
	{
		pHost->iIntParaValue[LM_HOST_X_CISCO_COM_ActiveTimeId] = 0;
	}
        *pInt = pHost->iIntParaValue[LM_HOST_X_CISCO_COM_ActiveTimeId];
		pthread_mutex_unlock(&XLmHostObjectMutex); 
        return TRUE;
    }

    if (strcmp(ParamName, "X_CISCO_COM_InactiveTime") == 0)
    {
        /* collect dynamic value */
        if(!pHost->bBoolParaValue[LM_HOST_ActiveId]){
            time_t currentTime = time(NULL);
            if(currentTime > pHost->activityChangeTime){
                pHost->iIntParaValue[LM_HOST_X_CISCO_COM_InactiveTimeId] = currentTime - pHost->activityChangeTime;
            }else{
                pHost->iIntParaValue[LM_HOST_X_CISCO_COM_InactiveTimeId] = 0;
            }
        }
        else
        {
                pHost->iIntParaValue[LM_HOST_X_CISCO_COM_InactiveTimeId] = 0;
        }
        *pInt = pHost->iIntParaValue[LM_HOST_X_CISCO_COM_InactiveTimeId];
		pthread_mutex_unlock(&XLmHostObjectMutex); 
        return TRUE;
    }

    if (strcmp(ParamName, "X_CISCO_COM_RSSI") == 0)
    {
        /* collect value */
        *pInt = pHost->iIntParaValue[LM_HOST_X_CISCO_COM_RSSIId];
		pthread_mutex_unlock(&XLmHostObjectMutex); 
        return TRUE;
    }

    if (strcmp(ParamName, "LeaseTimeRemaining") == 0)
    {
        time_t currentTime = time(NULL);
        if(pHost->LeaseTime == 0xffffffff){
            *pInt = -1;
        }else if(currentTime <  (time_t)pHost->LeaseTime){
            *pInt = pHost->LeaseTime - currentTime;
        }else{
            *pInt = 0;
        }
		pthread_mutex_unlock(&XLmHostObjectMutex); 
        return TRUE;
    }

 	pthread_mutex_unlock(&XLmHostObjectMutex); 
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        XHost_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
XHost_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{


    //printf("Host_GetParamUlongValue %p, %s\n", hInsContext, ParamName);
	pthread_mutex_lock(&XLmHostObjectMutex); 
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;
    int i = 0;
    for(; i<LM_HOST_NumUlongPara; i++){
        if (strcmp(ParamName, COSA_HOSTS_Extension1_Name) == 0)
        {
            time_t currentTime = time(NULL);
            if(currentTime > pHost->activityChangeTime){
                *puLong = currentTime - pHost->activityChangeTime;
            }else{
                *puLong = 0;
            }
			pthread_mutex_unlock(&XLmHostObjectMutex); 
            return TRUE;
        }
        else if (strcmp(ParamName, XlmHosts.pHostUlongParaName[i]) == 0)
        {
            /* collect value */
            *puLong = pHost->ulUlongParaValue[i];
			pthread_mutex_unlock(&XLmHostObjectMutex); 
            return TRUE;
        }
    }

	pthread_mutex_unlock(&XLmHostObjectMutex); 
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        XHost_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
XHost_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    //printf("Host_GetParamStringValue %p, %s\n", hInsContext, ParamName);
	pthread_mutex_lock(&XLmHostObjectMutex); 
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;
    errno_t  rc  = -1;
    int i = 0;
    for(; i<LM_HOST_NumStringPara; i++){
        if (strcmp(ParamName, XlmHosts.pHostStringParaName[i]) == 0)
        {
            /* collect value */
            size_t len = 0;
            if(pHost->pStringParaValue[i]) len = strlen(pHost->pStringParaValue[i]);
            if(*pUlSize <= len){
                *pUlSize = len + 1;
				pthread_mutex_unlock(&XLmHostObjectMutex); 
                return 1;
            }

            /* Here, check the NULL condition before copy*/
            if(pHost->pStringParaValue[i]){
                 rc = strcpy_s(pValue, *pUlSize, pHost->pStringParaValue[i]);
                 if(rc != EOK){
                    ERR_CHK(rc);
                    pthread_mutex_unlock(&XLmHostObjectMutex);
                    return -1;
                 }
            }
			pthread_mutex_unlock(&XLmHostObjectMutex); 
            return 0;
        }
    }

    if (strcmp(ParamName, "Layer3Interface") == 0)
    {
        /* collect value */
        rc = strcpy_s(pValue, *pUlSize, pHost->Layer3Interface);
        if(rc != EOK)
        {
            ERR_CHK(rc);
            pthread_mutex_unlock(&XLmHostObjectMutex);
            return -1;
        }
        pthread_mutex_unlock(&XLmHostObjectMutex);
        return 0;
    }

	pthread_mutex_unlock(&XLmHostObjectMutex); 
	return -1;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        XHost_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
XHost_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{

    /* check the parameter name and set the corresponding value */
	pthread_mutex_lock(&XLmHostObjectMutex); 
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;

    if (strcmp(ParamName, "Comments") == 0)
    {
        /* save update to backup */
        LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_Comments]) , pString);
		pthread_mutex_unlock(&XLmHostObjectMutex); 
        return TRUE;
    }
	pthread_mutex_unlock(&XLmHostObjectMutex); 
    return FALSE;

}
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        XHost_Validate
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
XHost_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Host_Commit
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
XHost_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{

    pthread_mutex_lock(&XLmHostObjectMutex);     
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;
    pthread_mutex_unlock(&XLmHostObjectMutex); 
    
    LMDmlHostsSetHostComment(pHost->pStringParaValue[LM_HOST_PhysAddressId], pHost->pStringParaValue[LM_HOST_Comments]);
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        XHost_Rollback
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
XHost_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    pthread_mutex_lock(&XLmHostObjectMutex);     
    pthread_mutex_unlock(&XLmHostObjectMutex); 

    return 0;
}
/***********************************************************************

 APIs for Object:

    XHosts.XHost.{i}.XIPv4Address.{i}.

    *  XHost_IPv4Address_GetEntryCount
    *  XHost_IPv4Address_GetEntry
    *  XHost_IPv4Address_GetParamBoolValue
    *  XHost_IPv4Address_GetParamIntValue
    *  XHost_IPv4Address_GetParamUlongValue
    *  XHost_IPv4Address_GetParamStringValue

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        XHost_IPv4Address_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/
ULONG
XHost_IPv4Address_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    ULONG count = 0; 

    pthread_mutex_lock(&XLmHostObjectMutex);       
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;    
    count = pHost->numIPv4Addr;
    pthread_mutex_unlock(&XLmHostObjectMutex);  
    return count;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ANSC_HANDLE
        XHost_IPv4Address_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/
ANSC_HANDLE
XHost_IPv4Address_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{

    PLmObjectHostIPAddress IPArr = NULL;
    pthread_mutex_lock(&XLmHostObjectMutex);     
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;    
    IPArr = LM_GetIPArr_FromIndex(pHost, nIndex, IP_V4);
    if(IPArr)
        *pInsNumber  = IPArr->instanceNum; 
    pthread_mutex_unlock(&XLmHostObjectMutex); 
    return  (ANSC_HANDLE)IPArr;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        XHost_IPv4Address_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
XHost_IPv4Address_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{

    pthread_mutex_lock(&XLmHostObjectMutex);
    PLmObjectHostIPAddress pIPv4Address = (PLmObjectHostIPAddress) hInsContext;
    errno_t  rc  = -1;
    int i = 0;
    for(; i<LM_HOST_IPv4Address_NumStringPara; i++){
        if (strcmp(ParamName, XlmHosts.pIPv4AddressStringParaName[i]) == 0)
        {
            /* collect value */
            size_t len = 0;
            if(pIPv4Address->pStringParaValue[i]) len = strlen(pIPv4Address->pStringParaValue[i]);
            if(*pUlSize <= len){
                *pUlSize = len + 1;
                pthread_mutex_unlock(&XLmHostObjectMutex);
                return 1;
            }

            /* Here, check the NULL condition before copy*/
            if(pIPv4Address->pStringParaValue[i]){
                rc = strcpy_s(pValue, *pUlSize, pIPv4Address->pStringParaValue[i]);
                if(rc != EOK){
                    ERR_CHK(rc);
                    pthread_mutex_unlock(&XLmHostObjectMutex);
                    return -1;
                }
            }
            pthread_mutex_unlock(&XLmHostObjectMutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&XLmHostObjectMutex);
    return -1;
}
/***********************************************************************

 APIs for Object:

    XHosts.XHost.{i}.XIPv6Address.{i}.

    *  XHost_IPv6Address_GetEntryCount
    *  XHost_IPv6Address_GetEntry
    *  XHost_IPv6Address_GetParamBoolValue
    *  XHost_IPv6Address_GetParamIntValue
    *  XHost_IPv6Address_GetParamUlongValue
    *  XHost_IPv6Address_GetParamStringValue

***********************************************************************/

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        XHost_IPv6Address_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/
ULONG
XHost_IPv6Address_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    ULONG count = 0; 
	pthread_mutex_lock(&XLmHostObjectMutex);    
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;    
    count = pHost->numIPv6Addr;
    pthread_mutex_unlock(&XLmHostObjectMutex);
	return count;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ANSC_HANDLE
        XHost_IPv6Address_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/
ANSC_HANDLE
XHost_IPv6Address_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    PLmObjectHostIPAddress IPArr = NULL;
	
    pthread_mutex_lock(&XLmHostObjectMutex);    
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;    
    IPArr = LM_GetIPArr_FromIndex(pHost, nIndex, IP_V6);
    if(IPArr)
        *pInsNumber  = IPArr->instanceNum; 
    pthread_mutex_unlock(&XLmHostObjectMutex);
	return  (ANSC_HANDLE)IPArr;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        XHost_IPv6Address_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
XHost_IPv6Address_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
   
    pthread_mutex_lock(&XLmHostObjectMutex);
    PLmObjectHostIPAddress pIPv6Address = (PLmObjectHostIPAddress) hInsContext;
    errno_t rc = -1;
    int i = 0;
    for(; i<LM_HOST_IPv6Address_NumStringPara; i++){
        if (strcmp(ParamName, XlmHosts.pIPv6AddressStringParaName[i]) == 0)
        {
            /* collect value */
            size_t len = 0;
            if(pIPv6Address->pStringParaValue[i]) len = strlen(pIPv6Address->pStringParaValue[i]);
            if(*pUlSize <= len){
                *pUlSize = len + 1;
                pthread_mutex_unlock(&XLmHostObjectMutex);
                return 1;
            }

            /* Here, check the NULL condition before copy*/
            if(pIPv6Address->pStringParaValue[i]){
                rc = strcpy_s(pValue, *pUlSize, pIPv6Address->pStringParaValue[i]);
                if(rc != EOK){
                    ERR_CHK(rc);
                    pthread_mutex_unlock(&XLmHostObjectMutex);
                    return -1;
                }
            }
            pthread_mutex_unlock(&XLmHostObjectMutex);
            return 0;
        }
    }

    pthread_mutex_unlock(&XLmHostObjectMutex);
    return -1;
}

