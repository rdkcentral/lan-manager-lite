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

#ifndef  _COSA_MANAGEMENTSERVER_DML_H
#define  _COSA_MANAGEMENTSERVER_DML_H


#include "cosa_managementserver_apis.h"
#include "cosa_reports_internal.h"

#define  COSA_CONTEXT_LINK_CLASS_CONT                                                    \
         SINGLE_LINK_ENTRY                Linkage;                                          \
         ANSC_HANDLE                      hContext;                                         \
         ANSC_HANDLE                      hParentTable;  /* Back pointer */                 \
         ULONG                            InstanceNumber;                                   \
         BOOL                             bNew;                                             \
         ANSC_HANDLE                      hPoamIrepUpperFo;                                 \
         ANSC_HANDLE                      hPoamIrepFo;                                      \

typedef  struct
_COSA_CONTEXT_LINK_OBJ
{
    COSA_CONTEXT_LINK_CLASS_CONT
}
COSA_CONTEXT_LINK_OBJ,  *PCOSA_CONTEXT_LINK_OBJ;

#define  ACCESS_COSA_CONTEXT_LINK_OBJ(p)              \
         ACCESS_CONTAINER(p, COSA_CONTEXT_LINK_OBJ, Linkage)

         
extern COSA_DATAMODEL_REPORTS* g_pReports;

ULONG
ManageableDevice_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    );

ANSC_HANDLE
ManageableDevice_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );
BOOL
ManageableDevice_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    );
ULONG
ManageableDevice_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    );
	
ULONG
ManageableDevice_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );
    
ANSC_STATUS
CosaDmlManagedDeviceInit
    (
        ANSC_HANDLE                 hThisObject
    );
	
#endif
