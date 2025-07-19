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

#ifndef NETWORK_DEVICES_TRAFFIC_AVROPACK_H
#define NETWORK_DEVICES_TRAFFIC_AVROPACK_H

#include <sys/time.h>

#if (defined SIMULATION)
#define NETWORK_DEVICE_TRAFFIC_AVRO_FILENAME			"NetworkDevicesTraffic.avsc"
#else
#define NETWORK_DEVICE_TRAFFIC_AVRO_FILENAME			"/usr/ccsp/lm/NetworkDevicesTraffic.avsc"
#endif
#define CHK_AVRO_ERR (( NULL != avro_strerror() ) && ( strlen(avro_strerror()) > 0) )

struct networkdevicetrafficdata
{
struct timeval timestamp;
char* device_mac;
long long external_bytes_up;
long long external_bytes_down;
char* parent;
char* device_type;

struct networkdevicetrafficdata *next;
};

/**
 * @brief To send the network devices traffic report to webpa
*/
void network_devices_traffic_report(struct networkdevicetrafficdata *ptr, struct timeval *reset_timestamp);
void ndt_avro_cleanup(); // Avro Cleanup
#ifdef WAN_FAILOVER_SUPPORTED
void set_ReportSourceNDT(char * value);
char * get_ReportSourceNDT(void);
#endif
#endif /* !NETWORK_DEVICES_TRAFFIC_AVROPACK_H */
