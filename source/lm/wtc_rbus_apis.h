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


#ifndef  _WTC_RBUS_APIS_H
#define  _WTC_RBUS_APIS_H


#include "ansc_platform.h"
#include <rbus/rbus.h>

rbusError_t WTC_RbusInit
    (
        VOID
    );

CHAR const* GetParamName
    (
        CHAR const* path
    );

BOOL CheckIfValidDscp
    (
        CHAR* pString
    );

BOOL IsDigit
    (
        CHAR* str
    );

BOOL Stats_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        CHAR*                       ParamName,
        CHAR*                       pValue,
        ULONG*                      pUlSize
    );

BOOL Stats_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        CHAR*                       ParamName,
        ULONG*                      pInt
    );

BOOL Stats_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        CHAR*                       ParamName,
        CHAR*                       pString
    );

BOOL Stats_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        CHAR*                       ParamName,
        ULONG                       iValue
    );

#endif
