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

#ifndef  DEVICE_PRESENCE_DETECTION_H
#define  DEVICE_PRESENCE_DETECTION_H

#include "ansc_platform.h"

#define MAC_SIZE    32
#define IPV4_SIZE    32
#define IPV6_SIZE    64

#define PRESENCE_MAX_SIZE_EVT 256

#define PORT 47031

#define PRESENCE_ARP_CACHE       "/tmp/arp_cache"
#define ARP_STRING_LEN  1023
#define ARP_BUFFER_LEN  (ARP_STRING_LEN + 1)
#define MYPROTO 2//NETLINK_USERSOCK
#define MYMGRP 1

#define MAX_PRESENCE_NOTIFY_DEV 10
#define MAX_PRESENCE_RETRY 6

// Define some constants.
#define ETH_HDRLEN 14      // Ethernet header length
#define IP4_HDRLEN 20      // IPv4 header length
#define ARP_HDRLEN 28      // ARP header length
#define ARPOP_REQUEST 1    // Taken from <linux/if_arp.h>
#define ARPOP_REPLY 2         // Taken from <linux/if_arp.h>

#define IP4_ONLY 1
#define IP6_ONLY 2
#define IP4_IP6  3

typedef enum {
    IPV4 = 0,
    IPV6 
}Ipversion;

typedef enum {
    STATE_PRESENCE_DETECTION_NONE, 
    STATE_JOIN_DETECTED_ARP,
    STATE_JOIN_DETECTED_DNSMASQ,
    STATE_JOIN_DETECTED_ND,
    STATE_LEAVE_DETECTED
}DeviceDetectionState;

typedef enum {
    STATE_DETECTION_TASK_START,
    STATE_DETECTION_TASK_STARTED,
    STATE_DETECTION_TASK_STOP,
    STATE_DETECTION_TASK_STOPPED
}DetectionTaskState;

typedef struct _DnsmasqEventQData
{
    char ip[64];
    char enable[32];
    char mac[32];
    int MsgType;
}DnsmasqEventQData;

// Define a struct for ARP header
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
};

typedef enum
{
    MSG_TYPE_PRESENCE_NOTIFICATION = 4,
    MSG_TYPE_PRESENCE_REMOVE = 8,
    MSG_TYPE_PRESENCE_ADD = 9,
    MSG_TYPE_PRESENCE_STOP = 10
} PresenceMsgType;

typedef struct _PresenceQData
{
    char Msg[PRESENCE_MAX_SIZE_EVT];
    PresenceMsgType MsgType;
}PresenceQData;

typedef void (*DEVICE_PRESENCE_DETECTION_FUNC) (void *arg);

typedef struct DeviceInfo
{
	char mac[MAC_SIZE];
	char ipv4[IPV4_SIZE];
	char ipv6[IPV6_SIZE];
    BOOL currentActive;
    BOOL ipv4Active;
    BOOL ipv6Active;
    DeviceDetectionState ipv6_state;
    DeviceDetectionState ipv4_state;
    unsigned int ipv4_retry_count;
    unsigned int ipv6_retry_count;
}LmPresenceDeviceInfo,*PLmPresenceDeviceInfo;

typedef struct DevicePresenceDetectionInfo
{
    DEVICE_PRESENCE_DETECTION_FUNC clbk;
    PLmPresenceDeviceInfo *ppdevlist;
    uint16_t numOfDevice;
    BOOL  bConfiguredMacListIsSet;
    unsigned int ipv4_leave_detection_interval;
    unsigned int ipv6_leave_detection_interval;
    unsigned int bkgnd_join_detection_interval;
    unsigned int ipv6_num_retries;
    unsigned int ipv4_num_retries;
    DetectionTaskState taskState;
    int task_count;
}LmDevicePresenceDetectionInfo,*PLmDevicePresenceDetectionInfo;
// Function prototypes
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int  getipaddressfromarp(char *inputline,char *output, int out_len);
int PresenceDetection_AddDevice(LmPresenceDeviceInfo *pinfo, BOOL bIsMacConfigurationEnabled);
int PresenceDetection_RemoveDevice(char *mac, BOOL bIsMacConfigurationEnabled);
int PresenceDetection_set_ipv4leaveinterval (unsigned int val);
int PresenceDetection_set_ipv6leaveinterval (unsigned int val);
int PresenceDetection_set_bkgndjoininterval (unsigned int val);
int PresenceDetection_set_ipv4retrycount (unsigned int val);
int PresenceDetection_set_ipv6retrycount (unsigned int val);
BOOL Presencedetection_DmlNotifyMac(char *mac,BOOL isNeedToAdd);
int PresenceDetection_Init();
int PresenceDetection_DeInit();
void PresenceDetection_Start();
void PresenceDetection_Stop();
int Handle_RecieveArpCache(char *line);
void getConfiguredMaclistStatus(BOOL *pVar);
void resetPresenceDetectionList(char * pMac);
void printPresenceTable(void);
#endif
