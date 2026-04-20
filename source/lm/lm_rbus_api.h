/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
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
   Copyright [2026] [Cisco Systems, Inc.]
 
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

#ifndef  _LM_RBUS_API_H_
#define  _LM_RBUS_API_H_

#include <rbus/rbus.h>
#include <stdbool.h>

#define LMLITE_COMPONENT_NAME "lmlite"
bool checkRbusEnabled();
rbusError_t lmliteRbusInit(const char *pComponentName);
rbusHandle_t get_rbus_handle(void);
#define LMLITE_MLO_RFC_PARAM "Device.DeviceInfo.X_RDKCENTRAL-COM_Report.NetworkDevicesStatus.MloRfcEnable"

/**
 * @brief Get MLO RFC enable status
 * @return true if MLO lmLite is enabled, false otherwise
 */
bool get_lmLiteMLORfcEnable(void);

/**
 * @brief Set MLO RFC enable status and persist to PSM
 * @return 0 on success, 1 on failure
 */
int set_lmLiteMLORfcEnable(bool bValue);

/**
 * To persist TR181 parameter values in PSM DB.
 * @return status 0 for success or 1 for failure
 */
int rbus_StoreValueIntoPsmDB(char *paramName, char *value);

/**
 * To fetch TR181 parameter values from PSM DB.
 * @return status 0 for success or 1 for failure
 */
int rbus_GetValueFromPsmDB( char* paramName, char** paramValue);

/**
 * @brief Gets the rbus_handle for lmLite.
 *
 * @return rbusHandle_t value
 */
rbusHandle_t get_rbus_handle(void);

/**
 * @brief Initialize and register MLO RFC RBUS data elements
 * @return 0 for success, -1 for failure
 */
int regLMLiteDataModel(void);
#endif
