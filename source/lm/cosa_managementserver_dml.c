/*********************************************************************
 * Copyright 2017-2019 ARRIS Enterprises, LLC.
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
 **********************************************************************/
#include "cosa_managementserver_dml.h"
#if defined(DEVICE_GATEWAY_ASSOCIATION_FEATURE)
static time_t lastModifiedv4 = {0};
static BOOL findAndUpdateMatchedEntry(COSA_DATAMODEL_REPORTS*, PCOSA_DML_MANG_DEV);
static ANSC_STATUS CosaSListPushEntryByInsNum(PSLIST_HEADER, PCOSA_CONTEXT_LINK_OBJ);
#endif
#ifdef USE_NOTIFY_COMPONENT
extern ANSC_HANDLE bus_handle;
#if defined(DEVICE_GATEWAY_ASSOCIATION_FEATURE)
static void Notify_ManageableDevice_Entry(ULONG, ULONG);
/***********************************************************************
 APIs for Object:
    ManagementServer.ManageableDevice.{i}.
    *  ManageableDevice_GetEntryCount
    *  ManageableDevice_GetEntry
    *  ManageableDevice_IsUpdated
    *  ManageableDevice_Synchronize
    *  ManageableDevice_GetParamBoolValue
    *  ManageableDevice_GetParamIntValue
    *  ManageableDevice_GetParamUlongValue
    *  ManageableDevice_GetParamStringValue
***********************************************************************/
static void Notify_ManageableDevice_Entry(ULONG old_value, ULONG new_value)
{

        char  compo[] = "eRT.com.cisco.spvtg.ccsp.notifycomponent";
        char  bus[] = "/com/cisco/spvtg/ccsp/notifycomponent";
        parameterValStruct_t notif_val[1];
        char* faultParam = NULL;
        char  str[512];
        int   ret;
        CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
        snprintf(str,sizeof(str)/sizeof(str[0]),"Device.ManagementServer.ManageableDeviceNumberOfEntries,%lu,%lu,%lu,%d",(ULONG)0,new_value,old_value,ccsp_unsignedInt);
        notif_val[0].parameterName  = "Device.NotifyComponent.SetNotifi_ParamName" ;
        notif_val[0].parameterValue = str;
        notif_val[0].type           = ccsp_string;
        ret = CcspBaseIf_setParameterValues(
                  bus_handle,
                  compo,
                  bus,
                  0,
                  0,
                  notif_val,
                  1,
                  TRUE,
                  &faultParam
              );
        if(ret != CCSP_SUCCESS)
        {
                CcspTraceError(("NOTIFICATION: %s : CcspBaseIf_setParameterValues failed. ret value = %d \n", __FUNCTION__, ret));
                CcspTraceError(("NOTIFICATION: %s : Parameter = %s \n", __FUNCTION__, notif_val[0].parameterValue));
                if(faultParam)
                {
                        CcspTraceWarning(("Failed to Send Notification with param : '%s'\n", faultParam));
                        bus_info->freefunc(faultParam);
                }
        }
}
#endif
#endif
/**********************************************************************
    caller:     owner of this object
    prototype:
        BOOL
        ManageableDevice_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );
    description:
        This function is returns the total number of entries in 
        ManagedDevice table. 
    argument:   ANSC_HANDLE                 hInsContext
                The instance handle;
    return:     TRUE or FALSE.
**********************************************************************/
ULONG
ManageableDevice_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    if (g_pReports == NULL ) 
    {
        CcspTraceError(("LMLite %s report is not initialized", __FUNCTION__));
        return 0;
    }
#if defined(DEVICE_GATEWAY_ASSOCIATION_FEATURE)
    return AnscSListQueryDepth(&g_pReports->MangDevList);
#else
    return 0;
#endif
    //added to avoid unused parameter error during compilation
    UNREFERENCED_PARAMETER(hInsContext);
}
/**********************************************************************
    caller:     owner of this object
    prototype:
        ANSC_HANDLE
        ManageableDevice_GetEntry
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
ManageableDevice_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
#if defined(DEVICE_GATEWAY_ASSOCIATION_FEATURE)
    PCOSA_CONTEXT_LINK_OBJ           pLinkObj    = NULL;
    PSINGLE_LINK_ENTRY                  pSLinkEntry = NULL;
    if (g_pReports == NULL ) 
    {
        CcspTraceError(("LMLite %s report is not initialized", __FUNCTION__));
        return 0;
    }
    pSLinkEntry = AnscQueueGetEntryByIndex((ANSC_HANDLE)&g_pReports->MangDevList, nIndex);
    if (pSLinkEntry)
    {
        pLinkObj = ACCESS_COSA_CONTEXT_LINK_OBJ(pSLinkEntry);
        *pInsNumber = pLinkObj->InstanceNumber;
    }
 
    return pLinkObj;
#else
    UNREFERENCED_PARAMETER(nIndex);
    UNREFERENCED_PARAMETER(pInsNumber);
   return 0;
#endif
    UNREFERENCED_PARAMETER(hInsContext);

}
/**********************************************************************
    caller:     owner of this object
    prototype:
        BOOL
        ManageableDevice_IsUpdated
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
ManageableDevice_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

#if defined(DEVICE_GATEWAY_ASSOCIATION_FEATURE)
    int retValv4 = 0;
    struct stat fileStatv4 = {0};
    PCOSA_CONTEXT_LINK_OBJ              pCxtLink          = NULL;
    PSINGLE_LINK_ENTRY                  pSListEntry       = NULL;
    PCOSA_DML_MANG_DEV                  pMangDevEntry     = NULL;
    int                                leaseUpdated = 0;
    retValv4 = stat(DHCP_VENDOR_CLIENT_V4_PATH, &fileStatv4);
    
    if (g_pReports == NULL ) 
    {
        CcspTraceError(("LMLite %s report is not initialized", __FUNCTION__));
        return FALSE;
    }
    if (retValv4 == 0)
    {
        /* Check whether the file is modified or not. */
        if ( lastModifiedv4 != fileStatv4.st_mtime )
        {
            buildDhcpVendorClientsFile();
            lastModifiedv4 = fileStatv4.st_mtime;
            return TRUE;
        }
        else
        {
            pSListEntry =   AnscSListGetFirstEntry(&g_pReports->MangDevList);
            while (pSListEntry)
            {
                pCxtLink          = ACCESS_COSA_CONTEXT_LINK_OBJ(pSListEntry);
                pSListEntry       = AnscSListGetNextEntry(pSListEntry);
                pMangDevEntry     = (PCOSA_DML_MANG_DEV)pCxtLink->hContext;
                if(!(IsLeaseAvailable(pMangDevEntry->MacAddr)))
                {
                    /*Lease expired. List need to be resynchronised */
                    leaseUpdated = 1;
                    break;
                }
            }
            if(leaseUpdated)
            {
                return TRUE;
            }
        }
        
    }
    else
    {
        if ( lastModifiedv4 != 0 )
        {
            if (access(DHCP_VENDOR_CLIENT_ALL_PATH, F_OK) == 0)
            {
                unlink(DHCP_VENDOR_CLIENT_ALL_PATH);
            }
            lastModifiedv4 = 0;
            // Return true to let synchronize function remove all existing link entries.
            return TRUE;
        }
         
    }
    return FALSE;
#else
    return TRUE;
#endif
}

#if defined(DEVICE_GATEWAY_ASSOCIATION_FEATURE)
/**********************************************************************
    description:
        This function is called to retrieve Host string from Hosts table
        based on the input MAC address.
    argument:   
                COSA_DATAMODEL_REPORTS*             g_pReports,
                DML structure holding the existing list of Managed devices
                PCOSA_DML_MANG_DEV                  pMangDevTableEntry
                The latest list of Managed devices
                ULONG*                      hostPathSize
                The maximum length of Host string;
    return:     TRUE if the managed device exists in both lists;
                FALSE if the managed device is removed from new list.
**********************************************************************/
static BOOL findAndUpdateMatchedEntry
(
    COSA_DATAMODEL_REPORTS*         g_pReports, 
    PCOSA_DML_MANG_DEV              pMangDevTableEntry
)
{
    BOOL foundMatch = FALSE;
    PSINGLE_LINK_ENTRY                   pSListEntry       = NULL;
    PCOSA_CONTEXT_LINK_OBJ            pCxtLink          = NULL;
    PCOSA_DML_MANG_DEV                   pMangDevEntry     = NULL;

    //Check what to be return if g_pReports is not initialized
    if (g_pReports == NULL ) 
    {
        CcspTraceError(("LMLite %s report is not initialized", __FUNCTION__));
        return FALSE;
    }
    pSListEntry =   AnscSListGetFirstEntry(&g_pReports->MangDevList);
    while (pSListEntry)
    {
        pCxtLink          = ACCESS_COSA_CONTEXT_LINK_OBJ(pSListEntry);
        pSListEntry       = AnscSListGetNextEntry(pSListEntry);
        pMangDevEntry     = (PCOSA_DML_MANG_DEV)pCxtLink->hContext;
        /*
         * Since ProductClass is an optional parameter, it will not be compared.
         * <TR-069 CMWP F.2.5 DHCP Vendor Options>
         * For a DHCP request from the Device that contains the Device Identity,
         * the DHCP Option MUST contain the following Encapsulated Vendor-Specific Option-Data fields:
         * DeviceManufacturerOUI
         * DeviceSerialNumber
         * DeviceProductClass (this MAY be left out if the corresponding source Parameter is not present)
         */
        if ((strcmp(pMangDevEntry->ManufacturerOUI, pMangDevTableEntry->ManufacturerOUI) == 0) &&
            (strcmp(pMangDevEntry->SerialNumber, pMangDevTableEntry->SerialNumber) == 0))
        {
            if (pCxtLink->bNew == TRUE)
            {
                AnscZeroMemory(pMangDevEntry->Host, MANG_DEV_HOST_STR_LEN+1);
            }
            foundMatch = TRUE;
            pCxtLink->bNew = FALSE;
            // Update Host path.
            if (ANSC_STATUS_NOT_READY == CosaDmlGetHostPath(pMangDevTableEntry->MacAddr, pMangDevEntry->Host, MANG_DEV_HOST_STR_LEN+1))
            {
                // Keep unsynchronized LMLite is ready.
                lastModifiedv4 = 0;
            }
            break;
        }
    }
    return foundMatch;
}

static ANSC_STATUS
CosaSListPushEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        PCOSA_CONTEXT_LINK_OBJ   pCosaContext
    )
{
    PCOSA_CONTEXT_LINK_OBJ       pCosaContextEntry = (PCOSA_CONTEXT_LINK_OBJ)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    ULONG                           ulIndex           = 0;
    if ( pListHead->Depth == 0 )
    {
        AnscSListPushEntryAtBack(pListHead, &pCosaContext->Linkage);
    }
    else
    {
        pSLinkEntry = AnscSListGetFirstEntry(pListHead);
        for ( ulIndex = 0; ulIndex < pListHead->Depth; ulIndex++ )
        {
            pCosaContextEntry = ACCESS_COSA_CONTEXT_LINK_OBJ(pSLinkEntry);
            pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);
            if ( pCosaContext->InstanceNumber < pCosaContextEntry->InstanceNumber )
            {
                AnscSListPushEntryByIndex(pListHead, &pCosaContext->Linkage, ulIndex);
                return ANSC_STATUS_SUCCESS;
            }
        }
        AnscSListPushEntryAtBack(pListHead, &pCosaContext->Linkage);
    }
    return ANSC_STATUS_SUCCESS;
}
#endif

/**********************************************************************
    caller:     owner of this object
    prototype:
        ULONG
        ManageableDevice_Synchronize
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
ManageableDevice_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    
#if defined(DEVICE_GATEWAY_ASSOCIATION_FEATURE)
    ULONG tableEntryCount = 0;
    ULONG tableIndex = 0;
    BOOL *tableMatch = NULL;
    ANSC_STATUS  returnStatus  = ANSC_STATUS_SUCCESS;
    PCOSA_DML_MANG_DEV  pMangDevTable = NULL;
    PCOSA_DML_MANG_DEV  pMangDevEntry = NULL;
   
    PCOSA_CONTEXT_LINK_OBJ            pCxtLink          = NULL;
    PSINGLE_LINK_ENTRY                   pSListEntry       = NULL;
    PSINGLE_LINK_ENTRY                   pTmpSListEntry    = NULL;
    if (g_pReports == NULL ) 
    {
        CcspTraceError(("LMLite %s report is not initialized", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }
    pMangDevTable = CosaDmlGetManageableDevices(&tableEntryCount, DHCP_VENDOR_CLIENT_ALL_PATH);
    if ((pMangDevTable != NULL) && (tableEntryCount > 0))
    {
        tableMatch = AnscAllocateMemory(tableEntryCount * sizeof(BOOL));
        if (tableMatch == NULL)
        {
            AnscFreeMemory(pMangDevTable);
            return ANSC_STATUS_RESOURCES;
        }
    }
    else
    {
        // dhcp_vendor_clients_all.txt may not exists, remove all existing link entries.
        
        pSListEntry =   AnscSListGetFirstEntry(&g_pReports->MangDevList);
        while (pSListEntry)
        {
            pCxtLink          = ACCESS_COSA_CONTEXT_LINK_OBJ(pSListEntry);
            pTmpSListEntry      = pSListEntry;
            pSListEntry       = AnscSListGetNextEntry(pSListEntry);
            AnscSListPopEntryByLink(&g_pReports->MangDevList, pTmpSListEntry);
            AnscFreeMemory(pCxtLink->hContext);
            AnscFreeMemory(pCxtLink);
        }
        if (pMangDevTable)
        {
            AnscFreeMemory(pMangDevTable);
        }
        return ANSC_STATUS_SUCCESS;
    }
    /* Check if the lease expired for any of the managed devices. */
     /* Search the whole link and mark bNew of exist entry to TRUE */
    pSListEntry =   AnscSListGetFirstEntry(&g_pReports->MangDevList);
    while (pSListEntry)
    {
        pCxtLink          = ACCESS_COSA_CONTEXT_LINK_OBJ(pSListEntry);
        pSListEntry       = AnscSListGetNextEntry(pSListEntry);
        pCxtLink->bNew = TRUE;
    }
    /* Go over all entries, find them in current link table and mark them. */
    for (tableIndex = 0; tableIndex < tableEntryCount; tableIndex++)
    {
        tableMatch[tableIndex] = findAndUpdateMatchedEntry(g_pReports, &pMangDevTable[tableIndex]);
    }
    /* We need remove unreferred entry if it does not exist in dhcp_vendor_clients.txt */
    pSListEntry =   AnscSListGetFirstEntry(&g_pReports->MangDevList);
    while (pSListEntry)
    {
        pCxtLink          = ACCESS_COSA_CONTEXT_LINK_OBJ(pSListEntry);
        pTmpSListEntry      = pSListEntry;
        pSListEntry       = AnscSListGetNextEntry(pSListEntry);
        if (pCxtLink->bNew == TRUE)
        {
            AnscSListPopEntryByLink(&g_pReports->MangDevList, pTmpSListEntry);
            AnscFreeMemory(pCxtLink->hContext);
            AnscFreeMemory(pCxtLink);
        }
    }
    /* We add new entry into our link table. */
    for (tableIndex = 0; tableIndex < tableEntryCount; tableIndex++ )
    {
        if ((FALSE == tableMatch[tableIndex]) &&
            (FALSE == findAndUpdateMatchedEntry(g_pReports, &pMangDevTable[tableIndex])))
        {
            /* Add new one */
            pCxtLink = AnscAllocateMemory(sizeof(COSA_CONTEXT_LINK_OBJ));
            if (!pCxtLink)
            {
                returnStatus =  ANSC_STATUS_RESOURCES;
                break;
            }

            pMangDevEntry = AnscAllocateMemory(sizeof(COSA_DML_MANG_DEV));
            if (!pMangDevEntry)
            {
                AnscFreeMemory(pCxtLink);
                returnStatus =  ANSC_STATUS_RESOURCES;
                break;
            }

            /* Now we have this link content */
            if (g_pReports->MangDevNextInsNum == 0)
            {
                g_pReports->MangDevNextInsNum = 1;
            }
            pCxtLink->InstanceNumber = g_pReports->MangDevNextInsNum;
            pMangDevEntry->InstanceNumber = g_pReports->MangDevNextInsNum;
            g_pReports->MangDevNextInsNum++;
            /* Copy new content to the new entry. */
            *pMangDevEntry = pMangDevTable[tableIndex];
    
            // Update Host path.
            if (ANSC_STATUS_NOT_READY == CosaDmlGetHostPath(pMangDevEntry->MacAddr, pMangDevEntry->Host, MANG_DEV_HOST_STR_LEN+1))
            {
                // Keep unsynchronized until LMLite is ready.
                lastModifiedv4 = 0;
                CcspTraceWarning(("ManageableDevice: LMLite is not ready\n"));
            }
            if(strstr(pMangDevEntry->Host,"Device.Hosts.Host."))
            {
                CcspTraceInfo(("ManageableDevice: Host table is now updated for the Device '%s'. ManageableDevice table is now in sync with Host table \n", pMangDevEntry->MacAddr));
            }
            pCxtLink->hContext     = (ANSC_HANDLE)pMangDevEntry;
            pCxtLink->hParentTable = NULL;
            pCxtLink->bNew         = FALSE;
            #ifdef USE_NOTIFY_COMPONENT
            if ( g_pReports->MangDevNextInsNum >= 2 && tableIndex == tableEntryCount-1 )
            {
                Notify_ManageableDevice_Entry(g_pReports->MangDevNextInsNum-2, g_pReports->MangDevNextInsNum-1);
            }
            #endif
            returnStatus = CosaSListPushEntryByInsNum((PSLIST_HEADER)&g_pReports->MangDevList, (PCOSA_CONTEXT_LINK_OBJ)pCxtLink);
        }
    }
    if (tableMatch)
    {
        AnscFreeMemory(tableMatch);
    }
    if (pMangDevTable)
    {
        AnscFreeMemory(pMangDevTable);
    }
    return returnStatus;
#else
    return ANSC_STATUS_SUCCESS;
#endif
}
/**********************************************************************
    caller:     owner of this object
    prototype:
        ULONG
        ManageableDevice_GetParamStringValue
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
               -1 if not supported.
**********************************************************************/
ULONG
ManageableDevice_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
#if defined(DEVICE_GATEWAY_ASSOCIATION_FEATURE)
    UNREFERENCED_PARAMETER(pUlSize);
    PCOSA_CONTEXT_LINK_OBJ     pLinkObj = (PCOSA_CONTEXT_LINK_OBJ)hInsContext;
    COSA_DML_MANG_DEV            *pMangDev = (COSA_DML_MANG_DEV*)pLinkObj->hContext;
    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "ManufacturerOUI") == 0)
    {
        AnscCopyString(pValue, pMangDev->ManufacturerOUI);
        return 0;
    }
    if (strcmp(ParamName, "SerialNumber") == 0)
    {
        AnscCopyString(pValue, pMangDev->SerialNumber);
        return 0;
    }
    if (strcmp(ParamName, "ProductClass") == 0)
    {
        AnscCopyString(pValue, pMangDev->ProductClass);
        return 0;
    }
    if (strcmp(ParamName, "Host") == 0)
    {
        AnscCopyString(pValue, pMangDev->Host);
        return 0;
    }
    return -1;
#else
    //added this to avoid unused parameter error during compilation
    UNREFERENCED_PARAMETER(pUlSize);
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pValue);
    return 0;
#endif
}
/**********************************************************************
    caller:     owner of this object
    prototype:
        ANSC_STATUS
        CosaDmlManagedDeviceInit
            (
                ANSC_HANDLE                 hThisObject
            );
    description:
        This function initializes the Managed Devices table.
    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
    return:     status of operation.
**********************************************************************/
ANSC_STATUS
CosaDmlManagedDeviceInit
    (
        ANSC_HANDLE                 hThisObject
    )
{
#if defined(DEVICE_GATEWAY_ASSOCIATION_FEATURE)
    PCOSA_DATAMODEL_REPORTS       pMyObject = (PCOSA_DATAMODEL_REPORTS)hThisObject;
    
    pMyObject->MangDevNextInsNum = 0;
    AnscSListInitializeHeader(&pMyObject->MangDevList);
#else
  UNREFERENCED_PARAMETER(hThisObject);
#endif
    return ANSC_STATUS_SUCCESS;
}
