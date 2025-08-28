/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
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

    module: cosa_hosts_dml.c

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

        01/14/2011    initial revision.

**************************************************************************/
#include <time.h>
#include "ansc_platform.h"
#include "cosa_hosts_dml.h"
#include "lm_main.h"
#include "lm_util.h"
#include "ctype.h"
#include <syscfg/syscfg.h>
#include "safec_lib_common.h"
#include "lm_wrapper.h"
#include "device_presence_detection.h"

extern LmObjectHosts lmHosts;

extern ULONG HostsUpdateTime;
extern pthread_mutex_t LmHostObjectMutex;
extern int g_Client_Poll_interval;
//#define TIME_NO_NEGATIVE(x) ((long)(x) < 0 ? 0 : (x))
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

    Hosts.

    *  Hosts_GetParamBoolValue
    *  Hosts_SetParamBoolValue
    *  Hosts_GetParamIntValue
    *  Hosts_GetParamUlongValue
    *  Hosts_GetParamStringValue
    *  Hosts_SetParamStringValue

***********************************************************************/

/*
   Generic exit processing for XXX_GetParamStringValue() functions.
   If rc is 0 then return value string (or an empty string if value is NULL)
   with appropriate size limit checks. Otherwise just return the value in rc
   (which is expected to be -1).
*/
static ULONG GetParamStringValue_common (char *pValue, ULONG *pUlSize, char *value, int rc, pthread_mutex_t *mutex)
{
    if (rc == 0)
    {
        size_t len;

        if (value == NULL)
        {
            value = "";
        }

        len = strlen (value);
        if (len >= *pUlSize)
        {
            *pUlSize = len + 1;
            rc = 1;
        }
        else
        {
            memcpy (pValue, value, len + 1);
        }
    }

    pthread_mutex_unlock (mutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));

    return (ULONG) rc;
}


/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Hosts_GetParamBoolValue
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
Hosts_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    char buf[8];

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_WebPA_PresenceNotificationEnable") == 0)
    {
        syscfg_get( NULL, "notify_presence_webpa", buf, sizeof(buf));

        if (strcmp(buf, "true") == 0)
            *pBool = TRUE;
        else
            *pBool = FALSE;

        return TRUE;
    }

    if (strcmp(ParamName, "X_RDK_PresenceDetectEnable") == 0)
    {
        syscfg_get( NULL, "PresenceDetectEnabled", buf, sizeof(buf));

        if (strcmp(buf, "true") == 0)
            *pBool = TRUE;
        else
            *pBool = FALSE;

        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Hosts_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Hosts_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_WebPA_PresenceNotificationEnable") == 0)
    {
        char buf[8];

        syscfg_get( NULL, "PresenceDetectEnabled", buf, sizeof(buf));

        if (strcmp(buf, "false") == 0)
        {
            AnscTraceWarning(("Not supported (%s) to set when Presence Feature is disabled \n",ParamName));
            return FALSE;
        }

        syscfg_set_commit(NULL, "notify_presence_webpa", (bValue == TRUE) ? "true" : "false");
        return TRUE;
    }

    if (strcmp(ParamName, "X_RDK_PresenceDetectEnable") == 0)
    {
        Update_RFC_Presencedetection(bValue);
        return TRUE;
    }
    
    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Hosts_GetParamIntValue
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
Hosts_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pInt);

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Hosts_GetParamUlongValue
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
Hosts_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_PresenceLeaveIPv4CheckInterval") == 0)
    {
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        *puLong = lmHosts.param_val.ipv4CheckInterval;
        pthread_mutex_unlock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        return TRUE;
    }

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_PresenceLeaveIPv4Retries") == 0)
    {
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        *puLong = lmHosts.param_val.ipv4RetryCount;
        pthread_mutex_unlock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        return TRUE;
    }

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_PresenceLeaveIPv6CheckInterval") == 0)
    {
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        *puLong = lmHosts.param_val.ipv6CheckInterval;
        pthread_mutex_unlock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        return TRUE;
    }

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_PresenceLeaveIPv6Retries") == 0)
    {
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        *puLong = lmHosts.param_val.ipv6RetryCount;
        pthread_mutex_unlock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        return TRUE;
    }

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_BackgroundPresenceJoinInterval") == 0)
    {
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        *puLong = lmHosts.param_val.bkgrndjoinInterval;
        pthread_mutex_unlock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        if (access("/tmp/enablePresenceTableLogging", F_OK)== 0)
        {
            CcspTraceWarning(("%s:%d Presence Table logging is enabled\n",__FUNCTION__,__LINE__));
            printPresenceTable();
        }
        return TRUE;
    }

    if (strcmp(ParamName, "X_CISCO_COM_ConnectedDeviceNumber") == 0)
    {
        //*puLong = CosaDmlHostsGetOnline();
        *puLong = LM_get_online_device();
        //*puLong = HostsConnectedDeviceNum;
        return TRUE;
    }

    if (strcmp(ParamName, "X_CISCO_COM_ConnectedWiFiNumber") == 0)
    {
        *puLong = 0;
        return TRUE;
    }
    
    if (strcmp(ParamName, "X_RDKCENTRAL-COM_HostVersionId") == 0)
    {
        *puLong = lmHosts.lastActivity;
        return TRUE;
    }

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_HostCountPeriod") == 0)
    {
        *puLong = g_Client_Poll_interval;
        return TRUE;
    }

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_LMHost_Sync") == 0)
    {
        *puLong = 0;
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

BOOL
Hosts_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    BOOL updatePresenceParam = FALSE;
    HostPresenceParamUpdate flag = HOST_PRESENCE_PARAM_NONE;

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_PresenceLeaveIPv4CheckInterval") == 0)
    {
        updatePresenceParam = TRUE;
        flag = HOST_PRESENCE_IPV4_ARP_LEAVE_INTERVAL;
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        lmHosts.param_val.ipv4CheckInterval = uValue;
    }
    else if (strcmp(ParamName, "X_RDKCENTRAL-COM_PresenceLeaveIPv4Retries") == 0)
    {
        updatePresenceParam = TRUE;
        flag = HOST_PRESENCE_IPV4_RETRY_COUNT;
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        lmHosts.param_val.ipv4RetryCount = uValue;
    }
    else if (strcmp(ParamName, "X_RDKCENTRAL-COM_PresenceLeaveIPv6CheckInterval") == 0)
    {
        updatePresenceParam = TRUE;
        flag = HOST_PRESENCE_IPV6_ARP_LEAVE_INTERVAL;
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        lmHosts.param_val.ipv6CheckInterval = uValue;
    }
    else if (strcmp(ParamName, "X_RDKCENTRAL-COM_PresenceLeaveIPv6Retries") == 0)
    {
        updatePresenceParam = TRUE;
        flag = HOST_PRESENCE_IPV6_RETRY_COUNT;
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        lmHosts.param_val.ipv6RetryCount = uValue;
    }
    else if (strcmp(ParamName, "X_RDKCENTRAL-COM_BackgroundPresenceJoinInterval") == 0)
    {
        updatePresenceParam = TRUE;
        flag = HOST_PRESENCE_BKG_JOIN_INTERVAL;
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        lmHosts.param_val.bkgrndjoinInterval = uValue;
    }

    if (updatePresenceParam)
    {
        pthread_mutex_unlock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        Hosts_UpdatePresenceDetectionParam (&lmHosts.param_val,flag);
        return Hosts_UpdateSysDb(ParamName,uValue);
    }

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_HostCountPeriod") == 0)
    {
        g_Client_Poll_interval = uValue;
        if (syscfg_set_u_commit(NULL, "X_RDKCENTRAL-COM_HostCountPeriod", uValue) != 0) {
            CcspTraceWarning(("X_RDKCENTRAL-COM_HostCountPeriod syscfg_set failed\n"));
            return FALSE;
        }
        return TRUE;
    }

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_LMHost_Sync") == 0)
    {
        return TRUE;
    }

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Hosts_GetParamStringValue
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
Hosts_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pUlSize);
    errno_t  rc   = -1;

    if ((strcmp(ParamName, "X_RDKCENTRAL-COM_LMHost_Sync_From_WiFi") == 0) ||
        (strcmp(ParamName, "X_RDKCENTRAL-COM_AddPresenceNotificationMac") == 0) ||
        (strcmp(ParamName, "X_RDKCENTRAL-COM_DeletePresenceNotificationMac") == 0) ||
        (strcmp(ParamName, "X_RDKCENTRAL-COM_LMHost_Sync_From_MoCA") == 0) ||
        (strcmp(ParamName, "X_RDKCENTRAL-COM_EthHost_Sync") == 0))
    {
        /* collect value */
        rc = strcpy_s(pValue, *pUlSize, "");
        if (rc != EOK) {
            ERR_CHK(rc);
            return -1;
        }
        return 0;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

static int DelimiterCount (char *inputstring)
{
    int c;
    int count = 0;

    while ((c = *inputstring++) != 0) {
        if (c == ',')
            count++;
    }

    return count;
}

/*returns 1 if the passed string is a number or a negative number otherwise returns 0*/
static int IsNumberString(char *string)
{
    int j;
    if (!string) {
      return 0;
    }
    j = strlen(string);
    while(j--)
        {
            if(string[j] >= '0' && string[j] <= '9')
            continue;
            if (j == 0) {
                if (string[j] == '-')
                break;
            }
            return 0;
        }
    return 1;
}

static int IsProperMac(const char* mac) //Adding input validation to address SECVULN-21127
{
    int i = 0;
    int s = 0;
    int count = 0;

    while (*mac)
    {
        if (isxdigit(*mac))
        {
            i++;
            count++;
        }
        else if (*mac == ':' && count == 2)
        {
            ++s;
            count=0;
        }
        else
        {
            s = -1;
            break;
        }
        ++mac;
    }
    return (i == 12 && s == 5);
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Hosts_SetParamStringValue
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
Hosts_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_AddPresenceNotificationMac") == 0)
    {        
        // To DO
        if (!pString)
            return FALSE;
        // Add into queue
        BOOL retStatus = Presencedetection_DmlNotifyMac(pString,TRUE);
        return retStatus;
    }

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_DeletePresenceNotificationMac") == 0)
    {
        // To DO
        if (!pString)
            return FALSE;
        // Add into queue
        BOOL retStatus = Presencedetection_DmlNotifyMac(pString,FALSE);
        return retStatus;
    }

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_LMHost_Sync_From_WiFi") == 0)
    {
        if (!pString)
            return FALSE;
#ifdef USE_NOTIFY_COMPONENT
		char *st,
			 *ssid, 
			 *AssociatedDevice, 
			 *phyAddr, 
			 *RSSI, 
			 *Status;
		int  iRSSI,
			 iStatus,
             count_tok;
			 
        count_tok = DelimiterCount(pString);
        if (count_tok != 4) {
            CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > Missing required tokens in ParamString  \n",__FUNCTION__,__LINE__));
            return FALSE;
        }

        /* save update to backup */
		phyAddr 		 = strtok_r(pString, ",", &st);
		AssociatedDevice = strtok_r(NULL, ",", &st);
		ssid 			 = strtok_r(NULL, ",", &st);
		RSSI 			 = strtok_r(NULL, ",", &st);
		Status 			 = strtok_r(NULL, ",", &st);

        if ((phyAddr == NULL) || (AssociatedDevice == NULL) || (ssid == NULL) || (RSSI == NULL) || (Status == NULL)) {
            CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > One or more tokens are missing in ParamString  \n",__FUNCTION__,__LINE__));
         return FALSE;
        }

         if (IsProperMac(phyAddr) == 0)
          {
                CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > Not a proper phy addr in ParamString  \n",__FUNCTION__,__LINE__));
          return FALSE;
          }

        CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > <phyAddr=%s> <AssociatedDevice=%s> <ssid=%s> <RSSI=%s> <Status=%s>\n",__FUNCTION__,__LINE__, phyAddr,AssociatedDevice,ssid,RSSI,Status));
  if (IsNumberString(RSSI)) {
         iRSSI = atoi(RSSI);
     } else {
        CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > Inapproriate RSSI value in ParamString  \n",__FUNCTION__,__LINE__));
         return FALSE;
     }

     if (IsNumberString(Status)) {
         iStatus = atoi(Status);
     }else {
        CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > Inapproriate STATUS value in ParamString  \n",__FUNCTION__,__LINE__));
        return FALSE;
    }
    if (!(iStatus >= 0 && iStatus <= 1)){
        CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > STATUS value in ParamString should be 0 or 1 \n",__FUNCTION__,__LINE__));
        return FALSE;
    }

		Wifi_Server_Sync_Function( phyAddr, AssociatedDevice, ssid, iRSSI, iStatus );
#endif /* USE_NOTIFY_COMPONENT */
		
        return TRUE;
    }
    if (strcmp(ParamName, "X_RDKCENTRAL-COM_EthHost_Sync") == 0)
    {
        CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > X_RDKCENTRAL-COM_EthHost_Sync Param received\n",__FUNCTION__,__LINE__));
        if (!pString)
            return FALSE;
        printf(" \n Notification : < %s : %d > ParamName = %s \n",__FUNCTION__,__LINE__, pString);
        char* st;
        char *macAddr;
        char *status;
		int active;
	    int count_token;
        count_token = DelimiterCount(pString);
        if (count_token != 1) {
            CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > Missing required tokens in ParamString  \n",__FUNCTION__,__LINE__));
            return FALSE;
        }
        macAddr = strtok_r(pString, ",", &st);
        status = strtok_r(NULL, ",", &st);
        if ((macAddr == NULL) || (status == NULL)) {
            CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > One or more tokens are missing in ParamString  \n",__FUNCTION__,__LINE__));
         return FALSE;
        }
         if (IsProperMac(macAddr) == 0)
          {
                CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > Not a proper mac address in ParamString  \n",__FUNCTION__,__LINE__));
          return FALSE;
          }
       if (strcmp(status, "true") == 0)
	   {
		   active = 1;
	   }
       else
       {
			active = 0;
       }
CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > <macAddr=%s> <status=%s>\n",__FUNCTION__,__LINE__, macAddr,status));
        EthClient_AddtoQueue(macAddr,active);
        return TRUE;
    }
#if !defined (NO_MOCA_FEATURE_SUPPORT)
    if (strcmp(ParamName, "X_RDKCENTRAL-COM_LMHost_Sync_From_MoCA") == 0)
    {
     
        if (!pString)
            return FALSE;
#ifdef USE_NOTIFY_COMPONENT
        char *st,
             *ssid, 
             *AssociatedDevice, 
             *phyAddr, 
             *deviceType, 
             *parentMac, 
             *RSSI, 
             *Status;
        int  iRSSI,
             iStatus,
             count_tok;
             
        count_tok = DelimiterCount(pString);
        if (count_tok != 6) {
            CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > Missing required tokens in ParamString  \n",__FUNCTION__,__LINE__));
            return FALSE;
        }
        /* save update to backup */
        phyAddr             = strtok_r(pString, ",", &st);
        AssociatedDevice    = strtok_r(NULL, ",", &st);
        ssid                = strtok_r(NULL, ",", &st);
        parentMac           = strtok_r(NULL, ",", &st);
        deviceType          = strtok_r(NULL, ",", &st);
        RSSI                = strtok_r(NULL, ",", &st);
        Status              = strtok_r(NULL, ",", &st);
        if ((phyAddr == NULL) || (AssociatedDevice == NULL) || (parentMac == NULL) || (deviceType == NULL) || (ssid == NULL) || (RSSI == NULL) || (Status == NULL)) {
            CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > One or more tokens are missing in ParamString  \n",__FUNCTION__,__LINE__));
         return FALSE;
        }
         if (IsProperMac(phyAddr) == 0)
          {
                CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > Not a proper phy addr in ParamString  \n",__FUNCTION__,__LINE__));
          return FALSE;
          }
         if (IsProperMac(parentMac) == 0)
          {
                CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > parent mac is not proper in ParamString  \n",__FUNCTION__,__LINE__));
          return FALSE;
          }
        CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > <phyAddr=%s> <AssociatedDevice=%s> <ssid=%s> <parentMac=%s> <deviceType=%s> <RSSI=%s> <Status=%s>\n",__FUNCTION__,__LINE__, phyAddr,AssociatedDevice,ssid,parentMac,deviceType,RSSI,Status));
        
  if (IsNumberString(RSSI)) {
         iRSSI = atoi(RSSI);
     } else {
        CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > Inapproriate RSSI value in ParamString  \n",__FUNCTION__,__LINE__));
         return FALSE;
     }

     if (IsNumberString(Status)) {
         iStatus = atoi(Status);
     }else {
        CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > Inapproriate STATUS value in ParamString  \n",__FUNCTION__,__LINE__));
        return FALSE;
    }

    if (!(iStatus >= 0 && iStatus <= 1)){
        CcspTraceWarning((" \n Hosts_SetParamStringValue : < %s : %d > STATUS value in ParamString should be 0 or 1 \n",__FUNCTION__,__LINE__));
        return FALSE;
    }


        MoCA_Server_Sync_Function( phyAddr, AssociatedDevice, ssid, parentMac, deviceType, iRSSI, iStatus );
#endif /* USE_NOTIFY_COMPONENT */
        
        return TRUE;
    }
#endif
    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/***********************************************************************

 APIs for Object:

    Hosts.Host.{i}.

    *  Host_GetEntryCount
    *  Host_GetEntry
    *  Host_IsUpdated
    *  Host_Synchronize
    *  Host_GetParamBoolValue
    *  Host_GetParamIntValue
    *  Host_GetParamUlongValue
    *  Host_GetParamStringValue
    *  Host_SetParamBoolValue
    *  Host_SetParamIntValue
    *  Host_SetParamUlongValue
    *  Host_SetParamStringValue
    *  Host_Validate
    *  Host_Commit
    *  Host_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Host_GetEntryCount
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
Host_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
	UNREFERENCED_PARAMETER(hInsContext);
	ULONG host_count = 0;

    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
	pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
	host_count = lmHosts.numHost;
	pthread_mutex_unlock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));

	return host_count;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ANSC_HANDLE
        Host_GetEntry
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
Host_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
	UNREFERENCED_PARAMETER(hInsContext);
	ANSC_HANDLE host = NULL;	

    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
	pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
	*pInsNumber = lmHosts.hostArray[nIndex]->instanceNum;
	host = (ANSC_HANDLE) (lmHosts.hostArray[nIndex]);
	pthread_mutex_unlock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));

	return host;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Host_IsUpdated
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
Host_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    if ( HostsUpdateTime == 0 ) 
    {
        HostsUpdateTime = AnscGetTickInSeconds();

        return TRUE;
    }
    
    if ( HostsUpdateTime >= TIME_NO_NEGATIVE(AnscGetTickInSeconds() - COSA_DML_USERS_USER_ACCESS_INTERVAL ) )
    {
        return FALSE;
    }
    else 
    {
        HostsUpdateTime = AnscGetTickInSeconds();

        return TRUE;
    }
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Host_Synchronize
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
Host_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    //CosaDmlHostsGetHosts(NULL,&count);

	LM_get_host_info();
    HostsUpdateTime = AnscGetTickInSeconds();

    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Host_GetParamBoolValue
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
Host_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;
    int i;

    //printf("Host_GetParamBoolValue %p, %s\n", hInsContext, ParamName);

    for(i = 0; i < LM_HOST_NumBoolPara; i++) {
        if (strcmp(ParamName, lmHosts.pHostBoolParaName[i]) == 0)
        {
            CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            pthread_mutex_lock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            *pBool = pHost->bBoolParaValue[i];
            pthread_mutex_unlock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            return TRUE;
        }
    }

    if (strcmp(ParamName, "X_CISCO_COM_TrueStaticIPClient") == 0)
    {
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        *pBool = pHost->bTrueStaticIPClient;
        pthread_mutex_unlock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        return TRUE;
    }

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Host_GetParamIntValue
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
Host_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;

    if (strcmp(ParamName, "X_CISCO_COM_ActiveTime") == 0)
    {
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
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
        pthread_mutex_unlock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        return TRUE;
    }

    if (strcmp(ParamName, "X_CISCO_COM_InactiveTime") == 0)
    {
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
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
        pthread_mutex_unlock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        return TRUE;
    }

    if (strcmp(ParamName, "X_CISCO_COM_RSSI") == 0)
    {
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        *pInt = pHost->iIntParaValue[LM_HOST_X_CISCO_COM_RSSIId];
        pthread_mutex_unlock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        return TRUE;
    }

    if (strcmp(ParamName, "LeaseTimeRemaining") == 0)
    {
        time_t currentTime;

        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        currentTime = time(NULL);
        if(pHost->LeaseTime == 0xffffffff){
            *pInt = -1;
        }else if(currentTime <  (time_t)pHost->LeaseTime){
            *pInt = pHost->LeaseTime - currentTime;
        }else{
            *pInt = 0;
        }

        pthread_mutex_unlock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        return TRUE;
    }

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Host_GetParamUlongValue
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
Host_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;
    int i;

    //printf("Host_GetParamUlongValue %p, %s\n", hInsContext, ParamName);

    for (i = 0; i < LM_HOST_NumUlongPara; i++) {
        if (strcmp(ParamName, COSA_HOSTS_Extension1_Name) == 0)
        {
            time_t currentTime;

            CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            pthread_mutex_lock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            currentTime = time(NULL);
            if(currentTime > pHost->activityChangeTime){
                *puLong = currentTime - pHost->activityChangeTime;
            }else{
                *puLong = 0;
            }
            pthread_mutex_unlock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            return TRUE;
        }
        else if (strcmp(ParamName, lmHosts.pHostUlongParaName[i]) == 0)
        {
            CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            pthread_mutex_lock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            *puLong = pHost->ulUlongParaValue[i];
            pthread_mutex_unlock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            return TRUE;
        }
    }

#if 0
    if (strcmp(ParamName, "X_CISCO_COM_DeviceType") == 0)
    {
        /* collect value */
        return TRUE;
    }

    if (strcmp(ParamName, "X_CISCO_COM_NetworkInterface") == 0)
    {
        /* collect value */
        return TRUE;
    }

    if (strcmp(ParamName, "X_CISCO_COM_ConnectionStatus") == 0)
    {
        /* collect value */
        return TRUE;
    }
#endif

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Host_GetParamStringValue
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
Host_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;
    char *value = NULL;
    int rc = -1;
    int i;

    //printf("Host_GetParamStringValue %p, %s\n", hInsContext, ParamName);

    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock (&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));

    /*
       Note that there two different ways to get Layer3Interface:

         pHost->Layer3Interface
         pHost->pStringParaValue[LM_HOST_Layer3InterfaceId]

       The first one (ie pHost->Layer3Interface) should be used, so
       add a special case to do that.
    */
    if (strcmp (ParamName, "Layer3Interface") == 0)
    {
        rc = 0;
        value = pHost->Layer3Interface;
    }
    else
    {
        for (i = 0; i < LM_HOST_NumStringPara; i++)
        {
            if (strcmp (ParamName, lmHosts.pHostStringParaName[i]) == 0)
            {
                rc = 0;
                value = pHost->pStringParaValue[i];
                break;
            }
        }
        if(strcmp(ParamName, "AddressSource") == 0)
        {
            getAddressSource(pHost->pStringParaValue[LM_HOST_PhysAddressId], pValue);
            LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_AddressSource]) , pValue);
            pthread_mutex_unlock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            return 0;
        }
        if(strcmp(ParamName, "IPAddress") == 0)
        {
            getIPAddress(pHost->pStringParaValue[LM_HOST_PhysAddressId], pValue);

            /*if both static/dhcp get failes, CPE will choose a 'primary' address.*/
            if ((pValue[0] == '\0') && (pHost->pStringParaValue[LM_HOST_IPAddressId]))
            {
                memcpy(pValue, pHost->pStringParaValue[LM_HOST_IPAddressId], strlen(pHost->pStringParaValue[LM_HOST_IPAddressId])+1);
                //  AnscTraceWarning(("[primary] client : MAC %s IP %s\n", pHost->pStringParaValue[LM_HOST_PhysAddressId], pValue));
            }
            else if (pHost->pStringParaValue[LM_HOST_IPAddressId])
            {
                AnscCopyString(pHost->pStringParaValue[LM_HOST_IPAddressId],pValue) ;
            }
            pthread_mutex_unlock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            return 0;
        }

    }

    return GetParamStringValue_common (pValue, pUlSize, value, rc, &LmHostObjectMutex);
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Host_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Host_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(bValue);
    
    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Host_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Host_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(iValue);

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Host_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Host_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(uValue);

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Host_SetParamStringValue
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
Host_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;

    if (strcmp(ParamName, "Comments") == 0)
    {
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));

        /* save update to backup */
#if defined(_HUB4_PRODUCT_REQ_)
        /* to avoid failure scenario check the parameter value is empty or not, if it is empty reset the existing value
         * and updates DM with empty */
        if(pString && !strlen(pString) && pHost->pStringParaValue[LM_HOST_Comments])
        {
            memset(pHost->pStringParaValue[LM_HOST_Comments],0,strlen(pHost->pStringParaValue[LM_HOST_Comments]));
            (pHost->pStringParaValue[LM_HOST_Comments])[0] = '\0';
        }
        else
#endif
            LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_Comments]) , pString);

        pthread_mutex_unlock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        return TRUE;
    }

	if (strcmp(ParamName, "AddressSource") == 0)
	{
		/* save update to AddressSource */
		if( strcasecmp(pString, "DHCP") == 0 )
		{
            CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
			pthread_mutex_lock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
			LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_AddressSource]) , pString);
			pthread_mutex_unlock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
			return TRUE;
		}
		else if ( (strcasecmp(pString, "Static") == 0) || (strcasecmp(pString, "Reserved") == 0) )
		{
            CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
			pthread_mutex_lock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
			LanManager_CheckCloneCopy(&(pHost->pStringParaValue[LM_HOST_AddressSource]) , "Reserved");
			pthread_mutex_unlock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
			return TRUE;
		}
		else
		{
			AnscTraceWarning(("<%s> Enter Valid AddressSource [%s] is invalid\n",__FUNCTION__,pString));
		}
	}

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Host_Validate
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
Host_Validate
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
Host_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;
    
    LMDmlHostsSetHostComment(pHost->pStringParaValue[LM_HOST_PhysAddressId], pHost->pStringParaValue[LM_HOST_Comments]);

    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Host_Rollback
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
Host_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
	UNREFERENCED_PARAMETER(hInsContext);

    return 0;
}

/***********************************************************************

 APIs for Object:

    Hosts.Host.{i}.IPv4Address.{i}.

    *  IPv4Address_GetEntryCount
    *  IPv4Address_GetEntry
    *  IPv4Address_GetParamBoolValue
    *  IPv4Address_GetParamIntValue
    *  IPv4Address_GetParamUlongValue
    *  IPv4Address_GetParamStringValue

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        IPv4Address_GetEntryCount
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
Host_IPv4Address_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
	ULONG count = 0;		
    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
	pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;    
    //printf("IPv4Address_GetEntryCount %d\n", pHost->numIPv4Addr);
	count = pHost->numIPv4Addr;
	pthread_mutex_unlock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    return count;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ANSC_HANDLE
        IPv4Address_GetEntry
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
Host_IPv4Address_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
	PLmObjectHostIPAddress IPArr = NULL;
    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
	pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;    
    //printf("IPv4Address_GetEntry %p, %ld\n", pHost, nIndex);
	IPArr = LM_GetIPArr_FromIndex(pHost, nIndex, IP_V4);
	if(IPArr)
		*pInsNumber  = nIndex + 1;
	pthread_mutex_unlock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    return  (ANSC_HANDLE)IPArr;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        IPv4Address_GetParamBoolValue
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
Host_IPv4Address_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pBool);

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        IPv4Address_GetParamIntValue
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
Host_IPv4Address_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pInt);

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        IPv4Address_GetParamUlongValue
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
Host_IPv4Address_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(puLong);

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        IPv4Address_GetParamStringValue
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
Host_IPv4Address_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PLmObjectHostIPAddress pIPv4Address = (PLmObjectHostIPAddress) hInsContext;
    char *value = NULL;
    int rc = -1;
    int i;

    //printf("IPv4Address_GetParamStringValue %p, %s\n", hInsContext, ParamName);

    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));

    for (i = 0; i < LM_HOST_IPv4Address_NumStringPara; i++)
    {
        if (strcmp(ParamName, lmHosts.pIPv4AddressStringParaName[i]) == 0)
        {
            rc = 0;
            value = pIPv4Address->pStringParaValue[i];
            break;
        }
    }

    return GetParamStringValue_common (pValue, pUlSize, value, rc, &LmHostObjectMutex);
}

/***********************************************************************

 APIs for Object:

    Hosts.Host.{i}.IPv6Address.{i}.

    *  IPv6Address_GetEntryCount
    *  IPv6Address_GetEntry
    *  IPv6Address_GetParamBoolValue
    *  IPv6Address_GetParamIntValue
    *  IPv6Address_GetParamUlongValue
    *  IPv6Address_GetParamStringValue

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        IPv6Address_GetEntryCount
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
Host_IPv6Address_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
	ULONG count = 0;	
    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
	pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;    
    //printf("IPv6Address_GetEntryCount %d\n", pHost->numIPv6Addr);
	count = pHost->numIPv6Addr;
	pthread_mutex_unlock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    return count;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ANSC_HANDLE
        IPv6Address_GetEntry
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
Host_IPv6Address_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
	PLmObjectHostIPAddress IPArr = NULL;
    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
	pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    PLmObjectHost pHost = (PLmObjectHost) hInsContext;    
    //printf("IPv6Address_GetEntry %p, %ld\n", pHost, nIndex);
	IPArr = LM_GetIPArr_FromIndex(pHost, nIndex, IP_V6);
	if(IPArr)
		*pInsNumber  = nIndex + 1;
	pthread_mutex_unlock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    return  (ANSC_HANDLE)IPArr;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        IPv6Address_GetParamBoolValue
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
Host_IPv6Address_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pBool);

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        IPv6Address_GetParamIntValue
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
Host_IPv6Address_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pInt);

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        IPv6Address_GetParamUlongValue
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
Host_IPv6Address_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(puLong);

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        IPv6Address_GetParamStringValue
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
Host_IPv6Address_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PLmObjectHostIPAddress pIPv6Address = (PLmObjectHostIPAddress) hInsContext;
    char *value = NULL;
    int rc = -1;
    int i;

    //printf("IPv6Address_GetParamStringValue %p, %s\n", hInsContext, ParamName);

    CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&LmHostObjectMutex);
    CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));

    for (i = 0; i < LM_HOST_IPv6Address_NumStringPara; i++)
    {
        if (strcmp (ParamName, lmHosts.pIPv6AddressStringParaName[i]) == 0)
        {
            rc = 0;
            value = pIPv6Address->pStringParaValue[i];
            break;
        }
    }

    return GetParamStringValue_common (pValue, pUlSize, value, rc, &LmHostObjectMutex);
}

