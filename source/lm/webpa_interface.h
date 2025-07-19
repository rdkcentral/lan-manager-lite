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

#ifndef WEB_INTERFACE_H_
#define WEB_INTERFACE_H_

#ifdef WAN_FAILOVER_SUPPORTED

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <rbus/rbus.h>

#define LMLITE_COMPONENT_NAME "lmlite"
#define LMLITE_INTERFACE_ACTIVESTATUS_PARAM "Device.X_RDK_WanManager.InterfaceActiveStatus"

typedef enum
{
    LMLITE_SUCCESS = 0,
    LMLITE_FAILURE
} LMLITE_STATUS;

#endif
/**
 * @brief To send message to webpa and further upstream
 *
 * @param[in] serviceName Name of component/service trying to send message upstream, sending entity
 * @param[in] dest Destination to identify the type of upstream message or receiving entity
 * @param[in] trans_id Transaction UUID unique identifier for the message/transaction
 * @param[in] payload The actual message data
 * @param[in] contentType content type of message "application/json", "avro/binary"
 * @param[in] payload_len length of payload or message length
 */
void sendWebpaMsg(char *serviceName, char *dest, char *trans_id, char *contentType, char *payload, unsigned int payload_len);

/**
 * @brief To get device CM MAC by querying stack
 * @return deviceMAC
*/
char * getDeviceMac();

/**
 * @brief To get device CM MAC by querying stack
 * @return deviceMAC
*/
char * getFullDeviceMac();
void initparodusTask();
const char *rdk_logger_module_fetch(void); 

#ifdef WAN_FAILOVER_SUPPORTED
bool checkRbusEnabled();
LMLITE_STATUS lmliteRbusInit(const char *pComponentName);
char* getInterface(char *interface);
void get_WanManager_ActiveInterface();
char * get_ActiveInterface(char *interface);
int subscribeTo_InterfaceActiveStatus_Event();
#endif

#endif /* WEB_INTERFACE_H_ */
