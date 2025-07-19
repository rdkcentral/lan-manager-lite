/*
 * If not stated otherwise in this file or this component's Licenses.txt file
 * the following copyright and licenses apply:
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


#ifndef  _WTC_RBUS_HANDLER_APIS_H
#define  _WTC_RBUS_HANDLER_APIS_H

#include <rbus/rbus.h>

rbusError_t WTC_TableUlongGetHandler(rbusHandle_t handle, rbusProperty_t property,
                                     rbusGetHandlerOptions_t* opts);
rbusError_t WTC_TableUlongSetHandler(rbusHandle_t handle, rbusProperty_t property,
                                     rbusSetHandlerOptions_t* opts);
rbusError_t WTC_TableUlongEventSubHandler(rbusHandle_t handle, rbusEventSubAction_t action,
                                          const char *eventName, rbusFilter_t filter,
                                          int32_t interval, bool *autoPublish);
rbusError_t WTC_TableStringGetHandler(rbusHandle_t handle, rbusProperty_t property,
                                      rbusGetHandlerOptions_t* opts);
rbusError_t WTC_TableStringSetHandler(rbusHandle_t handle, rbusProperty_t property,
                                     rbusSetHandlerOptions_t* opts);
rbusError_t WTC_TableStringEventSubHandler(rbusHandle_t handle, rbusEventSubAction_t action,
                                           const char *eventName, rbusFilter_t filter,
                                           int32_t interval, bool *autoPublish);
rbusError_t WTC_TableAddRowHandler(rbusHandle_t handle, char const* tableName,
                                   char const* aliasName, uint32_t* instNum);
rbusError_t WTC_TableRemoveRowHandler(rbusHandle_t handle, char const* rowName);

#endif
