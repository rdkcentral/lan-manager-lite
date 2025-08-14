/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
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

#ifndef _LM_WRAPPER_H_
#define _LM_WRAPPER_H_

#include <stddef.h>
#include <sys/socket.h>
#include <lm_api.h>
#if !defined (NO_MOCA_FEATURE_SUPPORT)
#include "moca_hal.h"
#endif
#include "lm_main.h"
/*****************
 */
//#define LM_NETWORK_NAME_SIZE 32
#define LM_MAX_INTERFACE_NUMBER 10

#define DEVICE_WIFI_ACCESS_POINT "Device.WiFi.AccessPoint." 
#define ARP_CACHE_FILE "/tmp/arp_cache"
#define DNSMASQ_LEASES_FILE "/nvram/dnsmasq.leases"
#define DNSMASQ_RESERVED_FILE "/etc/dhcp_static_hosts"

#define HOST_NAME_RETRY 3
#define HOST_NAME_RETRY_INTERVAL 3
//#define DEBUG
#ifdef DEBUG
#define PRINTD(fmt, args...) fprintf(stderr, fmt, ## args)
#else
#define PRINTD(fmt, args...)
#endif

/*****************
 * Moca header file will include some private path
 * We cannot include these file, so ...
 */
#if !defined (NO_MOCA_FEATURE_SUPPORT)
#define kMoca_MaxCpeList 256
#endif
#define STATUS int

#if !defined (NO_MOCA_FEATURE_SUPPORT)
typedef struct _moca_cpe_list
{
   unsigned char mac_addr[6];
} moca_cpe_list;
#endif

/*****************
 *
 */
enum LM_NEIGHBOR_STATE{
	LM_NEIGHBOR_STATE_REACHABLE = 0,
	LM_NEIGHBOR_STATE_STALE,
	LM_NEIGHBOR_STATE_DELAY,
	LM_NEIGHBOR_STATE_PROBE
};

/*****************
 *
 */
struct arp_pkt {
    unsigned char ether_dhost[6];
    unsigned char ether_shost[6];
    unsigned short ether_type;
    unsigned short hw_type;
    unsigned short pro_type;
    unsigned char hw_size;
    unsigned char pro_size;
    unsigned short opcode;
    unsigned char sMac[6];
    unsigned char sIP[4];
    unsigned char tMac[6];
    unsigned char tIP[4];   
};

typedef struct {
    	unsigned char ssid[LM_GEN_STR_SIZE];
    	unsigned char AssociatedDevice[LM_GEN_STR_SIZE];
		unsigned char phyAddr[32]; /* Byte alignment*/
    	int RSSI;
#ifdef USE_NOTIFY_COMPONENT
	int Status;
}__attribute__((packed, aligned(1))) LM_wifi_wsta_t;

typedef struct{
    int count;
    LM_wifi_wsta_t   host[LM_MAX_HOSTS_NUM];
}__attribute__((packed, aligned(1))) LM_wifi_hosts_t;
#else
}LM_wifi_wsta_t;
#endif

#if !defined (NO_MOCA_FEATURE_SUPPORT)
typedef struct {
  unsigned char ssid[LM_GEN_STR_SIZE];
  unsigned char AssociatedDevice[LM_GEN_STR_SIZE];
  unsigned char phyAddr[18];
  unsigned char parentMac[18];
  unsigned char deviceType[18];
  unsigned char ncId[LM_GEN_STR_SIZE];
  int Status;
  int RSSI;
}LM_moca_cpe_t;
#endif

typedef struct{
	unsigned char phyAddr[18];
	unsigned char ipAddr[64];
	enum LM_NEIGHBOR_STATE status;
    unsigned char hostName[LM_GEN_STR_SIZE];
    unsigned char ifName[LM_GEN_STR_SIZE];
    int LeaseTime;
}LM_host_entry_t;

extern ANSC_HANDLE bus_handle;

/******************
 *
 */
int lm_wrapper_init();
int lm_arping_v4_send(char netName[64], char strMac[17], unsigned char ip[4]);
int lm_wrapper_get_wifi_wsta_list(char netName[LM_NETWORK_NAME_SIZE], int *pCount, LM_wifi_wsta_t **ppWstaArray);
int lm_wrapper_get_arp_entries (char netName[LM_NETWORK_NAME_SIZE], int *pCount, LM_host_entry_t **ppArray);
void lm_wrapper_get_dhcpv4_client();
#if !defined (RESOURCE_OPTIMIZATION)
void Xlm_wrapper_get_info(PLmObjectHost pHost);
#endif

void lm_wrapper_get_dhcpv4_reserved();
#if 0
BOOL SearchWiFiClients(char *phyAddr, char *ssid);
#endif
int mac_string_to_array(char *pStr, unsigned char array[6]);
int ip_string_to_arrary(char* pStr, unsigned char array[4]);
void getAddressSource(char *physAddress, char *pAddressSource);
#ifdef USE_NOTIFY_COMPONENT
#if 0
void Wifi_Server_Thread_func();
#endif
#endif
int getIPAddress(char *physAddress,char *IPAddress);
int get_HostName(char *physAddress,char *HostName, size_t HostNameLen);
#if !defined (RESOURCE_OPTIMIZATION)
int Xlm_wrapper_get_wifi_wsta_list(int *pCount, LM_wifi_wsta_t **ppWstaArray);
#endif
void SyncWiFi();
int lm_wrap_checkIPv4AddressInRange(char* ipaddress, char* ipaddres2, char* subnetmask);
#endif
