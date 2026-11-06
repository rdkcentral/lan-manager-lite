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

    module: cosa_wantraffic_utils.h

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


#ifndef  _COSA_WANTRAFFIC_UTILS_H
#define  _COSA_WANTRAFFIC_UTILS_H

/*  Constant definitions  */
#define INVALID_MODE             0xFF
#define MIN_VALID_DSCP           0
#define MAX_VALID_DSCP           63

#define CHK_WAN_MODE(WanMode)                               \
        if (WanMode == INVALID_MODE)                        \
        {                                                   \
            WTC_LOG_ERROR("INVALID WAN MODE %d", WanMode);  \
            return;                                         \
        }                                                   \

#define CHK_LAN_MODE(LanMode)                               \
        if (LanMode == INVALID_MODE)                        \
        {                                                   \
            WTC_LOG_ERROR("INVALID LAN MODE %d", LanMode);  \
            return;                                         \
        }                                                   \

/*  FUNCTION PROTOTYPES  */
INT            IsBridgeMode(VOID);
WAN_INTERFACE  GetEthWANIndex(VOID);
CHAR*          RemoveSpaces(CHAR *str);
BOOL           CheckForAllDscpValuePresence(CHAR *str);

pstDSCPInfo_t ResetIsUpdatedFlag(pstDSCPInfo_t DscpTree);
pstDSCPInfo_t UpdateDscpCount(CHAR* Enabled_DSCP_List, pstDSCPInfo_t DscpTree);
pstDSCPInfo_t DeleteDscpTree(pstDSCPInfo_t DscpTree);
pstDSCPInfo_t InsertClient(pstDSCPInfo_t DscpTree, pDSCP_list_t CliList);

#endif
