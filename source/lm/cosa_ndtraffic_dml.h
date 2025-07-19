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

#include "slap_definitions.h"

BOOL
NetworkDevicesTraffic_Default_GetParamUlongValue
    (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
    );


BOOL
NetworkDevicesTraffic_Default_SetParamUlongValue
   (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
       ULONG                      uValue
    );
    
BOOL
NetworkDevicesTraffic_GetParamUlongValue
    (
		ANSC_HANDLE                 hInsContext,
		char*                       ParamName,
		ULONG*                      puLong
    );

BOOL
NetworkDevicesTraffic_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
       ULONG                      uValue
    );

ULONG
NetworkDevicesTraffic_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );
    
BOOL
NetworkDevicesTraffic_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
NetworkDevicesTraffic_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );


ULONG
NetworkDevicesTraffic_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

BOOL
NetworkDevicesTraffic_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
NetworkDevicesTraffic_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
NetworkDevicesTraffic_Default_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

BOOL
NetworkDevicesTraffic_Default_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
NetworkDevicesTraffic_Default_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

ANSC_STATUS
CosaDmlNetworkDevicesTrafficInit
    (
        ANSC_HANDLE                 hThisObject
    );
