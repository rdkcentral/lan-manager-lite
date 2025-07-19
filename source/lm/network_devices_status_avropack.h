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

#ifndef NETWORK_DEVICES_STATUS_AVROPACK_H
#define NETWORK_DEVICES_STATUS_AVROPACK_H

#include <sys/time.h>

#if (defined SIMULATION)
#define NETWORK_DEVICE_STATUS_AVRO_FILENAME			"NetworkDevicesStatus.avsc"
#else
#define NETWORK_DEVICE_STATUS_AVRO_FILENAME			"/usr/ccsp/lm/NetworkDevicesStatus.avsc"
#endif
#define CHK_AVRO_ERR (( NULL != avro_strerror() ) && ( strlen(avro_strerror()) > 0) )

struct networkdevicestatusdata
{
struct timeval timestamp;
char* device_mac;
char* interface_name;
BOOL is_active;
char* parent;
char* device_type;
char* hostname;
char* ipaddress;
struct networkdevicestatusdata *next;
};

/**
 * @brief To send the network devices report to webpa
*/
void network_devices_status_report(struct networkdevicestatusdata *ptr, BOOL extender, char* parent_mac);

/*Cleanup Avro variables and interfaces
*/
void nds_avro_cleanup(); 
#endif /* !NETWORK_DEVICES_STATUS_AVROPACK_H */
