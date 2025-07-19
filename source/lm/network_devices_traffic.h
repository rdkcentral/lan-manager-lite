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

#ifndef  NETWORK_DEVICES_TRAFFIC_H
#define  NETWORK_DEVICES_TRAFFIC_H

#include "ansc_platform.h"

// Default values
#define NDT_DEFAULT_PARENT_MAC		"11:22:33:44:55:66"
#define NDT_DEFAULT_DEVICE_TYPE		"empty"


/**
 * @brief Set the Harvesting Status for Network Devices.
 *
 * @param[in] status New Harvesting Status.
 * @return status 0 for success and 1 for failure
 */
int SetNDTHarvestingStatus(BOOL status);

/**
 * @brief Gets the Harvesting Status for Network Devices.
 *
 * @return status true if enabled and false if disabled
 */
BOOL GetNDTHarvestingStatus();

/**
 * @brief Set the Reporting Period for Network Devices Scan.
 *
 * @param[in] period Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetNDTReportingPeriod(ULONG period);

/**
 * @brief Gets the Network Devices Reporting Period
 *
 * @return period : The Current Reporting Period
 */
ULONG GetNDTReportingPeriod();

/**
 * @brief Set the Polling Period for Network Devices Scan.
 *
 * @param[in] period Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetNDTPollingPeriod(ULONG period);

/**
 * @brief Gets the Network Devices Polling Period
 *
 * @return period : The Current Polling Period
 */
ULONG GetNDTPollingPeriod();

/**
 * @brief Gets the Default Network Devices Reporting Period
 *
 * @return period : The Current Reporting Period
 */
ULONG GetNDTReportingPeriodDefault();

/**
 * @brief Sets the Default Network Devices Reporting Period
 *
 * @return period : The Current Reporting Period
 */
ULONG SetNDTReportingPeriodDefault(ULONG period);

/**
 * @brief Gets the Default Network Devices Polling Period
 *
 * @return period : The Current Reporting Period
 */
ULONG GetNDTPollingPeriodDefault();

/**
 * @brief Sets the Default Network Devices Polling Period
 *
 * @return period : The Current Reporting Period
 */
ULONG SetNDTPollingPeriodDefault(ULONG period);

/**
 * @brief Gets the Default timeout for Accelerated Scans
 *
 * @return period : The default timeout
 */
ULONG GetNDTOverrideTTLDefault();

/**
 * @brief Validated the Period Values for ND Scan and makes sure they are 
 *        present in the valid range of Values.
 *
 * @param[in] period period to be validated.
 * @return status 0 for success and 1 for failure
 */
BOOL ValidateNDTPeriod(ULONG period);
int SetNDTOverrideTTL(ULONG ttl);

/**
 * @brief Gets the Network Devices TTL Interval
 *
 * @return period : The Current TTL Interval
 */
ULONG GetNDTOverrideTTL();

/**
 * @brief Reset the EBTables.
 *
 * @return status 0 for success and 1 for failure
 */
int ResetEBTables();

/**
 * @brief Get the IP Table Data.
 */
void GetIPTableData();

/**
 * @brief Check if a value is present in an array.
 *
 * @param[in] val The value to check.
 * @param[in] arr The array to search in.
 * @param[in] size The size of the array.
 * @return true if the value is present, false otherwise.
 */
bool isvalueinarray_ndt(ULONG val, ULONG *arr, int size);

void add_to_list_ndt(char* ip_table_line);
void print_list_ndt();
void delete_list_ndt();
void delete_partial_list_ndt();

#endif 
