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

#ifndef  _COSA_REPORTS_INTERNAL_H
#define  _COSA_REPORTS_INTERNAL_H


#include "ansc_platform.h"
#include "ansc_string_util.h"

#define COSA_DATAMODEL_REPORTS_OID                                                        1

/* Collection */

#define  COSA_DATAMODEL_REPORTS_CLASS_CONTENT                       \
    /* start of WIFI object class content */                        \
    BOOLEAN                         bNDSEnabled;                   \
    BOOLEAN                         bNDSEnabledChanged;            \
    ULONG                           uNDSPollingPeriod;             \
    BOOLEAN                         bNDSPollingPeriodChanged;      \
    ULONG                           uNDSReportingPeriod;           \
    BOOLEAN                         bNDSReportingPeriodChanged;    \
    ULONG                           uNDSPollingPeriodDefault;      \
    ULONG                           uNDSReportingPeriodDefault;    \
    BOOLEAN                         bNDSDefPollingPeriodChanged;    \
    BOOLEAN                         bNDSDefReportingPeriodChanged;    \
    ULONG                           uNDSOverrideTTL;                \
    BOOLEAN                         bNDTEnabled;                   \
    BOOLEAN                         bNDTEnabledChanged;            \
    ULONG                           uNDTPollingPeriod;             \
    BOOLEAN                         bNDTPollingPeriodChanged;      \
    ULONG                           uNDTReportingPeriod;           \
    BOOLEAN                         bNDTReportingPeriodChanged;    \
    ULONG                           uNDTPollingPeriodDefault;      \
    ULONG                           uNDTReportingPeriodDefault;    \
    BOOLEAN                         bNDTDefPollingPeriodChanged;    \
    BOOLEAN                         bNDTDefReportingPeriodChanged;    \
    ULONG                           uNDTOverrideTTL;                  

typedef  struct
_COSA_DATAMODEL_REPORTS                                               
{
	COSA_DATAMODEL_REPORTS_CLASS_CONTENT
#if defined(DEVICE_GATEWAY_ASSOCIATION_FEATURE)
     SLIST_HEADER                    MangDevList;                      
     ULONG                           MangDevNextInsNum;
#endif
}
COSA_DATAMODEL_REPORTS,  *PCOSA_DATAMODEL_REPORTS;

/*
    Standard function declaration 
*/
ANSC_HANDLE
CosaReportsCreate
    (
        VOID
    );

ANSC_STATUS
CosaReportsInitialize
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
CosaReportsRemove
    (
        ANSC_HANDLE                 hThisObject
    );
    
#endif 
