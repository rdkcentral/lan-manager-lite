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
#ifndef  _COSA_MANAGEMENTSERVER_APIS_H
#define  _COSA_MANAGEMENTSERVER_APIS_H
#include "ansc_platform.h"
#include "ccsp_base_api.h"
#include "ansc_common_structures.h"
/**********************************************************************
                STRUCTURE AND CONSTANT DEFINITIONS
**********************************************************************/
#define PARSE_ARGU_NUM_4           4
#define PARSE_ARGU_NUM_3           3
#define DHCP_VENDOR_CLIENT_ALL_PATH      "/tmp/dhcp_vendor_clients_all.txt"
#define DHCP_VENDOR_CLIENT_V4_PATH       "/tmp/dhcp_vendor_clients.txt"
// #define DHCP_VENDOR_CLIENT_V6_PATH       "/tmp/dhcp_vendor_clients_v6.txt"
// #define DIBBLER_VENDOR_CLIENT_V6_XML     "/tmp/dibbler/server-AddrMgr.xml"
#define MANG_DEV_MANUFACTURER_OUI_STR_LEN       6
#define MANG_DEV_SERIAL_NUMBER_STR_LEN          64
#define MANG_DEV_PRODUCT_CLASS_STR_LEN          64
#define MANG_DEV_HOST_STR_LEN                   1024
#define MANG_DEV_MAC_STR_LEN                    17
#define TAG_STR_MANUFACTUREROUI     "DeviceManufacturerOUI"
#define TAG_STR_SERIALNUMBER        "DeviceSerialNumber"
#define TAG_STR_PRODUCTCLASS        "DeviceProductClass"
// #define TAG_STR_ADDR_IA             "AddrIA"
// #define TAG_STR_ADDCLIENT_START     "<AddrClient>"
// #define TAG_STR_ADDCLIENT_END       "</AddrClient>"
#define MAX_BUFFER_SIZE             128
/*
 * Device.ManagementServer.ManageableDevice..{i}.
 */
typedef struct
_COSA_DML_MANG_DEV
{
#if defined(DEVICE_GATEWAY_ASSOCIATION_FEATURE)
    ULONG           InstanceNumber;
    char            ManufacturerOUI[MANG_DEV_MANUFACTURER_OUI_STR_LEN+1];
    char            SerialNumber[MANG_DEV_SERIAL_NUMBER_STR_LEN+1];
    char            ProductClass[MANG_DEV_PRODUCT_CLASS_STR_LEN+1];
    char            Host[MANG_DEV_HOST_STR_LEN+1];
    char            MacAddr[MANG_DEV_MAC_STR_LEN+1];
#endif
}
COSA_DML_MANG_DEV,       *PCOSA_DML_MANG_DEV;
ANSC_STATUS CosaDmlGetHostPath(char *value, char *hostPath, ULONG hostPathSize);
PCOSA_DML_MANG_DEV CosaDmlGetManageableDevices(ULONG *tableEntryCount, char *filename);
void buildDhcpVendorClientsFile();
void vendorClientV6XMLParser(char *xmlFile);
int IsLeaseAvailable(char* macaddr);
#endif
