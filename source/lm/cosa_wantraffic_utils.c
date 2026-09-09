/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
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


/**************************************************************************

    module: cosa_wantraffic_utils.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file defines the apis for objects to support Data Model Library.

    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        06/13/2022    initial revision.

**************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "utapi/utapi.h"
#include "ansc_platform.h"
#include "syscfg/syscfg.h"
#include "safec_lib_common.h"
#include "cosa_wantraffic_api.h"
#include "cosa_wantraffic_utils.h"

#define ETH_WAN_ENABLE_STRING    "eth_wan_enabled"
//this is to test FORCE MERGE
extern rbusHandle_t rbus_handle;

static UINT EnabledDscpCount = 0;

static INT SetMemoryslab(INT i);
static pstDSCPInfo_t NewNode(UINT Dscp);
static pstDSCPInfo_t InsertDscpNode(pstDSCPInfo_t DscpTree, UINT dscp);
static pstDSCPInfo_t DeleteDisabledDscp(pstDSCPInfo_t DscpTree);
static pstDSCPInfo_t DeleteDisabledClients(pstDSCPInfo_t DscpTree);

#if 0
 // Retaining these changes as backup incase of future need.
static pstDSCPInfo_t InsertDscpNode(pstDSCPInfo_t DscpTree, UINT dscp,
                                    pstDSCPInfo_t* tail, INT* opCount, INT* flowReverse);
static pstDSCPInfo_t DeleteDisabledDscp(pstDSCPInfo_t DscpTree, pstDSCPInfo_t* inorderPrev);
#endif
/**********************************************************************
    function:
        RemoveSpaces
    description:
        This function is called to remove spaces in dscp list
    argument:
        CHAR*    str,    dscp list
    return:
        CHAR*    dscp list
**********************************************************************/
CHAR* RemoveSpaces(CHAR *str)
{
    INT i=0,j=0;
    while(str[i] != '\0')
    {
        if (str[i] != ' ')
            str[j++] = str[i];
        i++;
    }
    str[j] = '\0';
    return str;
}
/**********************************************************************
    function:
        GetWanModeAndWtcIndex
    description:
        This function retrieves active WAN mode and corresponding WTC index.
    argument:
        WAN_INTERFACE*  wanMode
        UINT*           wtcIndex
    return:     TRUE if succeeded; FALSE otherwise.
**********************************************************************/
BOOL GetWanModeAndWtcIndex(WAN_INTERFACE *wanMode, UINT *wtcIndex)
{
    rbusValue_t value = NULL;
    const CHAR *status = NULL;
    CHAR activeStatus[BUFLEN_256] = { '\0' };
    CHAR availableStatus[BUFLEN_256] = { '\0' };
    CHAR *entry = NULL;
    CHAR *entryContext = NULL;
    CHAR *name = NULL;
    CHAR *nameContext = NULL;
    CHAR *activeFlag = NULL;
    WAN_INTERFACE activeMode = INVALID_MODE;
    errno_t rc = -1;
    INT ind = -1;
    CHAR eth_wan_enabled[BUFLEN_64] = {'\0'};

    if ((wanMode == NULL) || (wtcIndex == NULL))
    {
        return FALSE;
    }

    if ((rbus_get(rbus_handle, TR181_ACTIVE_INTERFACE, &value) == RBUS_ERROR_SUCCESS) &&
        ((status = rbusValue_ToString(value, NULL, 0)) != NULL) &&
        (strcpy_s(activeStatus, sizeof(activeStatus), status) == EOK))
    {
        rbusValue_Release(value);
        value = NULL;
    }
    else
    {
        WTC_LOG_ERROR("Failed to get %s; using syscfg fallback", TR181_ACTIVE_INTERFACE);
        if (value != NULL)
        {
            rbusValue_Release(value);
        }
        goto syscfg_fallback;
    }

    if ((rbus_get(rbus_handle, TR181_AVAILABLE_INTERFACE, &value) != RBUS_ERROR_SUCCESS) ||
        ((status = rbusValue_ToString(value, NULL, 0)) == NULL) ||
        (strcpy_s(availableStatus, sizeof(availableStatus), status) != EOK))
    {
        WTC_LOG_INFO("WanManager interface status unavailable; using syscfg fallback");
        if (value != NULL)
        {
            rbusValue_Release(value);
        }
        goto syscfg_fallback;
    }
    rbusValue_Release(value);
    value = NULL;

    entry = strtok_r(activeStatus, "|", &entryContext);
    while (entry != NULL)
    {
        name = strtok_r(entry, ",", &nameContext);
        activeFlag = strtok_r(NULL, ",", &nameContext);
        if ((name != NULL) && (activeFlag != NULL) && (strcmp(activeFlag, "1") == 0))
        {
            if ((strcmp(name, "DOCSIS") == 0) || (strcmp(name, "DSL") == 0) ||
                (strcmp(name, "ADSL") == 0))
            {
                activeMode = DOCSIS;
            }
            else if (strcmp(name, "WANOE") == 0)
            {
                activeMode = EWAN;
            }
            else if (strcmp(name, "EPON") == 0)
            {
                activeMode = EPON;
            }
            else if (strcmp(name, "XGSPON") == 0)
            {
                activeMode = XGSPON;
            }
            if (activeMode != INVALID_MODE)
            {
                break;
            }
        }
        entry = strtok_r(NULL, "|", &entryContext);
    }

    if (activeMode == INVALID_MODE)
    {
        WTC_LOG_ERROR("No supported active WAN interface in %s; using syscfg fallback", activeStatus);
        goto syscfg_fallback;
    }

#if 0 /* Single-WTC-row path retained for reference; use the common index resolver. */
    *wanMode = activeMode;
    *wtcIndex = 0;
    WTC_LOG_INFO("WanManager resolved WAN mode %d, WTC index %d", *wanMode, *wtcIndex);
    return TRUE;
#else
    {
    CHAR availableStatusCopy[BUFLEN_256] = { '\0' };
    WAN_INTERFACE modeOrder[] = { DOCSIS, EWAN, EPON, XGSPON };
    WAN_INTERFACE availableMode = INVALID_MODE;
    UINT modeIndex = 0;
    UINT index = 0;
    BOOL modePresent = FALSE;

    *wanMode = activeMode;
    for (modeIndex = 0; modeIndex < (sizeof(modeOrder) / sizeof(modeOrder[0])); modeIndex++)
    {
        if (strcpy_s(availableStatusCopy, sizeof(availableStatusCopy), availableStatus) != EOK)
        {
            return FALSE;
        }

        modePresent = FALSE;
        entryContext = NULL;
        entry = strtok_r(availableStatusCopy, "|", &entryContext);
        while (entry != NULL)
        {
            name = strtok_r(entry, ",", &nameContext);
            availableMode = INVALID_MODE;
            if (name != NULL)
            {
                if ((strcmp(name, "DOCSIS") == 0) || (strcmp(name, "DSL") == 0) ||
                    (strcmp(name, "ADSL") == 0))
                {
                    availableMode = DOCSIS;
                }
                else if (strcmp(name, "WANOE") == 0)
                {
                    availableMode = EWAN;
                }
                else if (strcmp(name, "EPON") == 0)
                {
                    availableMode = EPON;
                }
                else if (strcmp(name, "XGSPON") == 0)
                {
                    availableMode = XGSPON;
                }
            }

            if (availableMode == modeOrder[modeIndex])
            {
                modePresent = TRUE;
                break;
            }
            entry = strtok_r(NULL, "|", &entryContext);
        }

        if (!modePresent)
        {
            continue;
        }

        if (modeOrder[modeIndex] == activeMode)
        {
            if (index >= SUPPORTED_WAN_MODES)
            {
                WTC_LOG_ERROR("WTC index %d exceeds supported WAN modes %d",
                              index, SUPPORTED_WAN_MODES);
                return FALSE;
            }
            *wtcIndex = index;
            WTC_LOG_INFO("WanManager resolved WAN mode %d, WTC index %d", *wanMode, *wtcIndex);
            return TRUE;
        }
        index++;
    }

    WTC_LOG_ERROR("Active WAN mode %d is not available in %s", activeMode, availableStatus);
    return FALSE;
    }
#endif

syscfg_fallback:
    if(syscfg_get(NULL,ETH_WAN_ENABLE_STRING,eth_wan_enabled,sizeof(eth_wan_enabled)) != 0)
    {
        WTC_LOG_ERROR("Syscfg_get failed to get wan mode");
        return FALSE;
    }
    rc = strcmp_s(eth_wan_enabled, strlen(eth_wan_enabled), "true", &ind);
    ERR_CHK(rc);
    *wanMode = ((rc == EOK) && (!ind)) ? EWAN : DOCSIS;
#if SUPPORTED_WAN_MODES == 1
    *wtcIndex = 0;
#else
    *wtcIndex = (*wanMode == DOCSIS) ? 0 : 1;
#endif
    WTC_LOG_INFO("Syscfg resolved WAN mode %d, WTC index %d", *wanMode, *wtcIndex);
    return TRUE;
}

/**********************************************************************
    function:
        IsBridgeMode
    description:
        This function is called to retrieve the bridge mode
    argument:
        None
    return:     0 if Router mode;
                1 if Bridge mode.
**********************************************************************/

INT IsBridgeMode(VOID)
{
    UtopiaContext ctx = {0};
    bridgeInfo_t bridge_info = {0};

    if (Utopia_Init(&ctx))
    {
        Utopia_GetBridgeSettings(&ctx, &bridge_info);
        Utopia_Free(&ctx, 0);
        if(bridge_info.mode == BRIDGE_MODE_OFF)
        {
            WTC_LOG_INFO("Router Mode");
            return 0;
        }
        else
        {
            WTC_LOG_INFO("Bridge Mode");
            return 1;
        }
    }
    else
    {
        WTC_LOG_ERROR("Utopia Init failure. Unable to get Bridge mode");
        return INVALID_MODE;
    }
}

/**********************************************************************
    function:
        SetMemoryslab
    description:
        This function is called to set the memory slab based on the incoming clients.
    argument:
        INT    i  -  Number of clients
    return:
        INT
**********************************************************************/
static INT SetMemoryslab(INT i)
{
    return (!!i) * CLIENT_ALLOC_SLAB * ((i/CLIENT_ALLOC_SLAB)+1);
}

/**********************************************************************
    function:
        CheckForAllDscpValuePresence
    description:
        This function is called to find if invalid dscp -1 is present in input string or not.
    argument:
        CHAR*           str    - Dscp string
    return:
        TRUE            if -1 present
        FALSE           if -1 not present
**********************************************************************/
BOOL CheckForAllDscpValuePresence(CHAR *str)
{
    if(strstr(str, ALL_DSCP_VALUE))
    {
        WTC_LOG_INFO("ALL_DSCP_VALUE -1 is present");
        return TRUE;
    }
    WTC_LOG_INFO("ALL_DSCP_VALUE -1 is not present");
    return FALSE;
}

/**********************************************************************
    function:
        NewNode
    description:
        This function is called to create a new node for a dscp value.
    argument:
        INT    Dscp    -   Dscp value
    return:
        pstDSCPInfo_t
**********************************************************************/
static pstDSCPInfo_t NewNode(UINT Dscp)
{
    pstDSCPInfo_t DscpNode = (stDCSPInfo_t *) malloc (sizeof(stDCSPInfo_t));
    if(DscpNode == NULL)
    {
        WTC_LOG_ERROR("New Node creation failed.");
        return NULL;
    }
    DscpNode->Dscp = Dscp;
    DscpNode->NumClients = 0;
    DscpNode->Left = NULL;
    DscpNode->Right = NULL;
#if 0
    DscpNode->Next = NULL;
#endif
    DscpNode->ClientList = NULL;
    DscpNode->IsUpdated = TRUE;
    DscpNode->MemorySlab = 0;
    return DscpNode;
}

/**********************************************************************
    function:
        InsertDscpNode
    description:
        This function is called to Insert a new Dscp node to the DSCP tree.
    argument:
        pstDSCPInfo_t    DscpTree,       -  Dscp tree
        UINT             dscp,           -  Dscp value
    return:
        pstDSCPInfo_t
**********************************************************************/
static pstDSCPInfo_t InsertDscpNode(pstDSCPInfo_t DscpTree, UINT dscp)
{
    if (!DscpTree)
        return NewNode(dscp);

    if(dscp == DscpTree->Dscp)
    {
        WTC_LOG_INFO("Dscp node already exists, Dscp = %d",DscpTree->Dscp);
        DscpTree->IsUpdated = TRUE;
        return DscpTree;
    }

    if (dscp < DscpTree->Dscp)
        DscpTree->Left = InsertDscpNode(DscpTree->Left, dscp);
    else if (dscp > DscpTree->Dscp)
        DscpTree->Right = InsertDscpNode(DscpTree->Right, dscp);
    return DscpTree;
}

#if 0
/**********************************************************************
    function:
        InsertDscpNode
    description:
        This function is called to Insert a new Dscp node to the DSCP tree.
    argument:
        pstDSCPInfo_t    DscpTree       -  Dscp tree
        UINT             dscp           -  Dscp value
        pstDSCPInfo_t    tail           -  The previous node in the inorder traversed.
        INT*             opCount        -  Counter for performing 2 ops after new node creation.
        INT*             flowReverse    -  Flag to notify the unwinding flow of tree traversal. 
    return:
        pstDSCPInfo_t
**********************************************************************/
static pstDSCPInfo_t InsertDscpNode(pstDSCPInfo_t DscpTree, UINT dscp,
                                    pstDSCPInfo_t* tail, INT* opCount, INT* flowReverse)
{
    int skipTailing = 0;

    if (!DscpTree)
    {
       if  (!(*flowReverse = !!(DscpTree = NewNode(dscp))))
       {
            return NULL;
       }
    }
    else if(dscp == DscpTree->Dscp)
    {
        WTC_LOG_INFO("Dscp node already exists, Dscp = %d",DscpTree->Dscp);
        DscpTree->IsUpdated = TRUE;
        *opCount = 0;
        return DscpTree;
    }

    if (dscp < DscpTree->Dscp)
    {
        DscpTree->Left = InsertDscpNode(DscpTree->Left, dscp, tail, opCount, flowReverse);
    }
    else
    {   // Since we skipped the left traversal, avoid the tail linking below.
        skipTailing = 1;
    }

    if (*opCount)
    {
        if ((!skipTailing || dscp == DscpTree->Dscp) && *tail)
        {
            WTC_LOG_INFO("[DBG-ToBeRemoved] %d -> %d", (*tail)->Dscp, DscpTree->Dscp);
            (*tail)->Next = DscpTree;
        }
        *tail = DscpTree;
        *opCount = (*flowReverse)? (*opCount)-1 : *opCount;
    }

    if (dscp > DscpTree->Dscp)
    {
        DscpTree->Right = InsertDscpNode(DscpTree->Right, dscp, tail, opCount, flowReverse);
    }

    return DscpTree;
}

/*
static pstDSCPInfo_t LinearizeDscpTree(pstDSCPInfo_t DscpTree, pstDSCPInfo_t* tail)
{
    if (DscpTree->Left)
        LinearizeDscpTree(DscpTree->Left, tail);

    if (*tail)
        (*tail)->Next = DscpTree;

    *tail = DscpTree;

    if (DscpTree->Right)
        LinearizeDscpTree(DscpTree->Right, tail);

    return DscpTree;
}
*/
#endif
/**********************************************************************
    function:
        ResetIsUpdatedFlag
    description:
        This function is called to disable IsUpdated flag of every node in DscpTree.
    argument:
        pstDSCPInfo_t    DscpTree,       -  Dscp tree
    return:
        pstDSCPInfo_t
**********************************************************************/
pstDSCPInfo_t ResetIsUpdatedFlag(pstDSCPInfo_t DscpTree)
{
    if (DscpTree == NULL)
        return NULL;
    ResetIsUpdatedFlag(DscpTree->Left);
    ResetIsUpdatedFlag(DscpTree->Right);
    DscpTree->IsUpdated = FALSE;
    for (UINT i=0; i<DscpTree->NumClients; i++)
    {
        DscpTree->ClientList[i].IsUpdated = FALSE;
    }
    return DscpTree;
}

/**********************************************************************
    function:
        UpdateDscpCount
    description:
        This function is called to update the EnabledDscpCount value.
    argument:
        CHAR*           Enabled_DSCP_List,    - Dscp string
        pstDSCPInfo_t   DscpTree,             - DscpTree
    return:
        INT
**********************************************************************/
pstDSCPInfo_t UpdateDscpCount(CHAR* Enabled_DSCP_List, pstDSCPInfo_t DscpTree)
{
    INT count = 0, dscp;
    CHAR *token = strtok(Enabled_DSCP_List, ",");

    ResetIsUpdatedFlag(DscpTree);
    while (token != NULL)
    {
        count++;
        dscp = atoi(token);
        DscpTree = InsertDscpNode(DscpTree, dscp);
        token = strtok(NULL, ",");
    }
    EnabledDscpCount = count;
    DscpTree =  DeleteDisabledDscp(DscpTree);
    return DscpTree;
}

/**********************************************************************
    function:
        DeleteDscpTree
    description:
        This function is called to delete the DscpTree.
    argument:
        pstDSCPInfo_t    DscpTree       -  Dscp tree
    return:
        pstDSCPInfo_t
**********************************************************************/
pstDSCPInfo_t DeleteDscpTree(pstDSCPInfo_t DscpTree)
{
    if (!DscpTree)
        return DscpTree;
    else if (DscpTree->Left != NULL)
        DeleteDscpTree(DscpTree->Left);
    else if (DscpTree->Right != NULL)
        DeleteDscpTree(DscpTree->Right);
    else
    {
        if (DscpTree->ClientList != NULL)
        {
            free(DscpTree->ClientList);
            DscpTree->ClientList = NULL;
        }
        free(DscpTree);
        DscpTree = NULL;
    }
    return DscpTree;
}

/**********************************************************************
    function:
        DeleteDisabledDscp
    description:
        This function is called to delete the disabled Dscp nodes.
    argument:
        pstDSCPInfo_t    DscpTree       -  Dscp tree
    return:
        pstDSCPInfo_t
**********************************************************************/
static pstDSCPInfo_t DeleteDisabledDscp(pstDSCPInfo_t DscpTree)
{
    if (!DscpTree)
    {
        WTC_LOG_INFO("DscpTree NULL");
        return NULL;
    }

    DscpTree->Left = DeleteDisabledDscp(DscpTree->Left);
    DscpTree->Right = DeleteDisabledDscp(DscpTree->Right);
    if (DscpTree->IsUpdated == FALSE)
    {
        pstDSCPInfo_t temp;
        if (DscpTree->Left == NULL)
        {
            temp = DscpTree->Right;
        }
        else if (DscpTree->Right == NULL)
        {
            temp = DscpTree->Left;
        }
        else
        {
            pstDSCPInfo_t temparent = DscpTree;
            temp = DscpTree->Right;
            if (temp->Left)
            {
               while (temparent=temp, temp = temp->Left, temp->Left);
               temparent->Left = temp->Right;
               temp->Right = DscpTree->Right;
            }
            temp->Left = DscpTree->Left;
        }
        free(DscpTree);
        DscpTree = temp;
        EnabledDscpCount--;
    }
    return DscpTree;
}

#if 0
/**********************************************************************
    function:
        DeleteDisabledDscp
    description:
        This function is called to delete the disabled Dscp nodes.
    argument:
        pstDSCPInfo_t    DscpTree       -  Dscp tree
        pstDSCPInfo_t*   inorderPrev    -  The previous node in the inorder traversal.
    return:
        pstDSCPInfo_t
**********************************************************************/
static pstDSCPInfo_t DeleteDisabledDscp(pstDSCPInfo_t DscpTree, pstDSCPInfo_t* inorderPrev)
{
    pstDSCPInfo_t prev = NULL;

    if (!DscpTree)
    {
        return NULL;
    }

    DscpTree->Left = DeleteDisabledDscp(DscpTree->Left, inorderPrev);
    /* Storing the inorder previous node, local to the current stack(node), as it might get
     * changed during the right sub-tree traversal.
     */
    {
        prev = *inorderPrev;
        *inorderPrev = DscpTree;
    }

    DscpTree->Right = DeleteDisabledDscp(DscpTree->Right, inorderPrev);

    if (DscpTree->IsUpdated == FALSE)
    {
        pstDSCPInfo_t temp = NULL;
        if (!DscpTree->Left && !DscpTree->Right)
        {    // Make current stack's previous as the next stack's previous
             *inorderPrev = prev;
        }

        if (DscpTree->Left == NULL)
        {      // Replacement node
            if ((temp = DscpTree->Right ))
            {
                if (prev)
                {
                    WTC_LOG_INFO("[DBG-ToBeRemoved]  p %d -> %d", prev->Dscp, temp->Dscp);
                    // Linear continuity for node with right child
                    prev->Next = temp;
                }
            }
            else if (prev)
            {
                // Linear continuity for leaf node
                prev->Next = DscpTree->Next;
            }
        }
        else if (DscpTree->Right == NULL)
        {       // Replacement node
            if ((temp = DscpTree->Left)) {
               WTC_LOG_INFO("[DBG-ToBeRemoved]  ii %d -> %d", temp->Dscp, DscpTree->Dscp);

               while(temp->Right) temp = temp->Right;
               // Linear continuity
               temp->Next = DscpTree->Next;
               // Tree node replacement
               temp = DscpTree->Left;
            }
        }
        else
        {
            pstDSCPInfo_t temparent = DscpTree;
            /* Finding the replacement of a node with 2 child. One right and the left most is the
             * rule of replacement.
             */
            temp = DscpTree->Right;
            if (temp->Left)
            {
               while (temparent=temp, temp = temp->Left, temp->Left);

               temparent->Left = temp->Right;
               temp->Right = DscpTree->Right;
            }
            temp->Left = DscpTree->Left;

            // Finding the previous node in the linear sequence.
            {
               pstDSCPInfo_t linear = DscpTree->Left;

               while(temparent=linear, (linear=linear->Right));
               temparent->Next = temp;
             WTC_LOG_INFO("[DBG-ToBeRemoved]  iii %d -> %d", temparent->Dscp, temp->Dscp);
            }
        }
        free(DscpTree);
        DscpTree = temp;
        EnabledDscpCount--;
    }
    return DscpTree;
}
#endif
/**********************************************************************
    function:
        DeleteDisabledClients
    description:
        This function is called to delete the disconnected clients from DscpNode
    argument:
        pstDSCPInfo_t    DscpTree   -  Dscp tree
    return:
        pstDSCPInfo_t
**********************************************************************/
static pstDSCPInfo_t DeleteDisabledClients(pstDSCPInfo_t DscpTree)
{
    UINT index = DscpTree->NumClients;
    errno_t rc = -1;
    for(UINT i=0; i<index; i++)
    {
        if (DscpTree->ClientList[i].IsUpdated == FALSE)
        {
            rc = memcpy_s(&DscpTree->ClientList[i], sizeof(stClientInfo_t),
                          &DscpTree->ClientList[index-1], sizeof(stClientInfo_t));
            ERR_CHK(rc);
            rc = memset_s(&DscpTree->ClientList[index-1], sizeof(stClientInfo_t), 0,
                          sizeof(stClientInfo_t));
            ERR_CHK(rc);
            i--;
            DscpTree->NumClients--;
            index = DscpTree->NumClients;
        }
    }
    return DscpTree;
}

/**********************************************************************
    function:
        InsertClient
    description:
        This function is called to get the Wan traffic counts.
    argument:
        pstDSCPInfo_t    DscpTree   -  Dscp tree
        pDSCP_list_t      CliList    -  Incoming Client list from HAL
    return:
        pstDSCPInfo_t
**********************************************************************/
pstDSCPInfo_t InsertClient(pstDSCPInfo_t DscpTree, pDSCP_list_t CliList)
{
    if ( (DscpTree != NULL) && (CliList != NULL) )
    {
            if(DscpTree->Dscp == CliList->DSCP_Element[DscpTree->Dscp].dscp_value)
            {
                UINT count = 0;
                UINT dscpIndex = DscpTree->NumClients;
                UINT cliIndex = CliList->DSCP_Element[DscpTree->Dscp].numClients;

                if( (cliIndex > 0) || (dscpIndex > 0) )
                {
                  UINT resetMemorySlab = 0;

                  do
                  {
                    if( ((INT)(DscpTree->MemorySlab - cliIndex)) < 0 || resetMemorySlab )
                    {
                        if ( !((INT)(DscpTree->MemorySlab = SetMemoryslab(cliIndex))) )
                        {
                            DscpTree->NumClients = 0;
                        }

                        // Below logic takes care of alloc, realloc and freeing of client list.
                        if ( !(DscpTree->ClientList = (stClientInfo_t*)realloc(DscpTree->ClientList,
                                                DscpTree->MemorySlab * sizeof(stClientInfo_t)))
                             && DscpTree->MemorySlab )
                        {
                            WTC_LOG_ERROR("Realloc failure.");
                            return DscpTree;
                        }

                        WTC_LOG_INFO("[DSCP-%d] Memory Slab : %d", DscpTree->Dscp
                                                                 , DscpTree->MemorySlab);
                        if ( resetMemorySlab )
                        {
                            break;
                        }
                    }
                    else if ( (DscpTree->MemorySlab - cliIndex) >= CLIENT_ALLOC_SLAB )
                    {
                         resetMemorySlab = 1;

                         if ( !cliIndex )
                         {
                             // this is a better flow for the client list free() case.
                             continue;
                         }
                    }
                    if (DscpTree->ClientList == NULL)
                    {
                      WTC_LOG_INFO("ClientList is NULL");
                      return DscpTree;
                    }
                    /* Number of clients associated with the DSCP value in DSCP_Element. Maximum value for numClients is 255 range [ 0-255] */
                    for(UINT i=0; (i<255 && i<cliIndex); i++) // CID 560298 Overflowed array index read
                    {
                        UINT j;
                        for(j=0; j<dscpIndex; j++)
                        {
                            errno_t rc = -1;
                            INT ind = -1;
                            rc = strcmp_s(DscpTree->ClientList[j].Mac,
                                          strlen(DscpTree->ClientList[j].Mac),
                                          CliList->DSCP_Element[DscpTree->Dscp].Client[i].mac, &ind);
                            ERR_CHK(rc);
                            
                            //Update existing client
                            if ((rc == EOK) && (!ind))
                            {
                                DscpTree->ClientList[j].RxBytes =
                                                CliList->DSCP_Element[DscpTree->Dscp].Client[i].rxBytes -
                                                DscpTree->ClientList[j].RxBytesTot;
                                DscpTree->ClientList[j].TxBytes =
                                                CliList->DSCP_Element[DscpTree->Dscp].Client[i].txBytes -
                                                DscpTree->ClientList[j].TxBytesTot;
                                DscpTree->ClientList[j].RxBytesTot =
                                                CliList->DSCP_Element[DscpTree->Dscp].Client[i].rxBytes;
                                DscpTree->ClientList[j].TxBytesTot =
                                                CliList->DSCP_Element[DscpTree->Dscp].Client[i].txBytes;
                                DscpTree->ClientList[j].IsUpdated = TRUE;
                                DscpTree->IsUpdated = TRUE;
                                count++;
                                WTC_LOG_INFO("Mac = %s, rx = %lu, tx = %lu,"
                                             "rxTot = %lu, txTot = %lu, Count = %d",
                                                   DscpTree->ClientList[j].Mac,
                                                   DscpTree->ClientList[j].RxBytes,
                                                   DscpTree->ClientList[j].TxBytes,
                                                   DscpTree->ClientList[j].RxBytesTot,
                                                   DscpTree->ClientList[j].TxBytesTot, count);
                                break;
                            }
                        }
                    }

                    // Remove stale client entries
                    if (dscpIndex > count)
                    {
                        DeleteDisabledClients(DscpTree);
                    }

                    // Add new client entries
                    if (cliIndex > count)
                    {
                        for(UINT i=0; (i<255 && i<cliIndex); i++) // CID 560298 Overflowed array index read
                        {
                            UINT j;
                            for(j=0; j<DscpTree->NumClients; j++)
                            {
                                errno_t rc = -1;
                                INT ind = -1;
                                rc = strcmp_s(DscpTree->ClientList[j].Mac,
                                              strlen(DscpTree->ClientList[j].Mac),
                                              CliList->DSCP_Element[DscpTree->Dscp].Client[i].mac, &ind);
                                ERR_CHK(rc);

                                if ((rc == EOK) && (!ind))
                                {
                                    break;
                                }
                            }

                            //New Client addition
                            if (j == DscpTree->NumClients)
                            {
                                memcpy_s(DscpTree->ClientList[j].Mac,
                                         sizeof(DscpTree->ClientList[j].Mac),
                                         CliList->DSCP_Element[DscpTree->Dscp].Client[i].mac,
                                         sizeof(DscpTree->ClientList[j].Mac) - 1);
                                DscpTree->ClientList[j].Mac[sizeof(DscpTree->ClientList[j].Mac) - 1] = '\0';
                                DscpTree->ClientList[j].RxBytes = 0;
                                DscpTree->ClientList[j].TxBytes = 0;
                                DscpTree->ClientList[j].RxBytesTot = 0;
                                DscpTree->ClientList[j].TxBytesTot = 0;
                                DscpTree->ClientList[j].IsUpdated = TRUE;
                                DscpTree->NumClients++;
                                DscpTree->IsUpdated = TRUE;
                                WTC_LOG_INFO("j = %d, Dscp = %d, MAC = %s, RxBytes = %lu,"
                                             "TxBytes = %lu, RxBytesTot = %lu, TxBytesTot = %lu,"
                                             "Is_Updated = %d",
                                              j, DscpTree->Dscp,
                                              DscpTree->ClientList[j].Mac,
                                              DscpTree->ClientList[j].RxBytes,
                                              DscpTree->ClientList[j].TxBytes,
                                              DscpTree->ClientList[j].RxBytesTot,
                                              DscpTree->ClientList[j].TxBytesTot,
                                              DscpTree->IsUpdated);
                            }
                        }
                    }
                  } while (resetMemorySlab);
                }
            }
        else if (0xFFFF != CliList->DSCP_Element[DscpTree->Dscp].dscp_value)
        {
            WTC_LOG_INFO("Values are not hashed with dscp as index.");
        }
        DscpTree->Left = InsertClient(DscpTree->Left, CliList);
        DscpTree->Right = InsertClient(DscpTree->Right, CliList);
    }
    else if(DscpTree != NULL)
    {
        WTC_LOG_INFO("CliList is NULL");
    }
    return DscpTree;
}
