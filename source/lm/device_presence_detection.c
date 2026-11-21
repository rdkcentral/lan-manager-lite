/*
* If not stated otherwise in this file or this component's LICENSE file the
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

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>           // errno, perror()
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <mqueue.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>
#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <netinet/in.h>       // IPPROTO_RAW, INET_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <net/ethernet.h>
#include <net/if.h>           // struct ifreq
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "ansc_platform.h"
#include "device_presence_detection.h"
#include "lm_util.h"
#include "lm_main.h"
#include "syscfg/syscfg.h"
#include "safec_lib_common.h"
#include "secure_wrapper.h"

#define MAX_NUM_OF_DEVICE 200
#define MAX_SIZE    512

#define CHECK(x) \
    do { \
        if (!(x)) { \
            fprintf(stderr, "%s:%d: ", __func__, __LINE__); \
            perror(#x); \
            return; \
        } \
    } while (0) \

#define MSG_TYPE_DNS_PRESENCE 7 
#define DNSMASQ_PRESENCE_QUEUE_NAME  "/presence_queue"
#define PROCESS_PRESENCE_NOTIFY_QUEUE  "/presence_notify_queue"
#define PRESENCE_MAX_SIZE 512
#define BUFF_SIZE 8192

static void presenceDetected(void *arg);
extern pthread_mutex_t LmHostObjectMutex;
extern LmObjectHosts lmHosts;


typedef struct NDSNotifyInfo
{
    int32_t enable;
    char interface[64];
}NDSNotifyInfo;

#define WR_VALUE _IOW('a','a',NDSNotifyInfo*)
#define RD_VALUE _IOR('a','b',NDSNotifyInfo*)

PLmDevicePresenceDetectionInfo pDetectionObject = NULL;
/* Must be recursive: lm_main.c holds it when calling AddDevice/RemoveDevice/resetPresenceDetectionList. Initialised only in the constructor below. */
pthread_mutex_t PresenceDetectionMutex;/*H007*/
static BOOL gPresenceMutexRecursive = FALSE;

/* Runs before main() so lm_main.c can lock it at any time; the POSIX attr call avoids the glibc-only static recursive initializer. */
static void __attribute__((constructor)) PresenceDetection_MutexCtor(void)
{
    pthread_mutexattr_t attr;
    if (0 == pthread_mutexattr_init(&attr))
    {
        if ((0 == pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)) &&
            (0 == pthread_mutex_init(&PresenceDetectionMutex, &attr)))
        {
            gPresenceMutexRecursive = TRUE;
        }
        pthread_mutexattr_destroy(&attr);
    }
    if (!gPresenceMutexRecursive)
    {
        /* Keeps the mutex valid; PresenceDetection_Init() refuses to start without recursion. */
        pthread_mutex_init(&PresenceDetectionMutex, NULL);
    }
}

#define PRESENCE_DETECTION_WORKER_COUNT 6
#define PRESENCE_IO_TIMEOUT_SECS 1
#define PRESENCE_MQ_POLL_MS 200

/* Serialises Init/DeInit/Start/Stop and guards the worker handles below. */
static pthread_mutex_t PresenceDetectionLifecycleMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t presenceDetectionThreads[PRESENCE_DETECTION_WORKER_COUNT];
static unsigned int presenceDetectionThreadCount = 0;
static int presenceDetectionRunning = 0;

static pthread_cond_t PresenceDetectionCond;
static pthread_once_t PresenceCondOnce = PTHREAD_ONCE_INIT;
static clockid_t PresenceCondClock = CLOCK_REALTIME;
static BOOL gPresenceCondReady = FALSE;
/* Guarded by PresenceDetectionMutex. */
static BOOL gStopRequested = FALSE;

#if 0
   /*Reading of NA from netlink sockets is commented currently. In feature it may be required to enable it.*/
int Neighbourdiscovery_Update(BOOL enable)
{
    int ret = 0;
    char buf[64];
    int fd;
    NDSNotifyInfo input = { 0 };
    NDSNotifyInfo output = { 0 };
    errno_t rc = -1;
    
    printf("\nOpening Driver\n");
    fd = open("/dev/etx_device", O_RDWR);
    if(fd < 0) {
        printf("Cannot open device file...\n");
        return -1;
    }

    printf("Writing Value to Driver\n");
    input.enable = 0;
    if (enable)
    {
        input.enable = 1;
    }
    syscfg_get( NULL, "lan_ifname", buf, sizeof(buf));        
    rc = strcpy_s(input.interface, sizeof(input.interface), buf);
    if(rc != EOK)
    {
        ERR_CHK(rc);
        close(fd);
        return -1;
    }
    /*CID: 68224 Unchecked return value*/
    if (-1 == ioctl(fd, WR_VALUE, (NDSNotifyInfo*) &input))
    {
	    printf("%s ioctl write error\n", __FUNCTION__);
            close(fd);
	    return -1;
    }

    printf("Reading Value from Driver\n");
    /*CID: 68224 Unchecked return value*/
    if (-1 == ioctl(fd, RD_VALUE, (NDSNotifyInfo*) &output))
    {
	    printf("%s ioctl read error\n", __FUNCTION__);
            close(fd);
	    return -1;
    }
    printf("Value is %d\n", output.enable);

    printf("Closing Driver\n");
    close(fd);

    return ret;
}
#endif

static void PresenceCondInit(void)
{
    pthread_condattr_t attr;
    int rc = pthread_condattr_init(&attr);
    if (0 != rc)
    {
        CcspTraceError(("%s:%d, pthread_condattr_init failed rc:%d, using default clock\n",__FUNCTION__,__LINE__,rc));
        rc = pthread_cond_init(&PresenceDetectionCond, NULL);
    }
    else
    {
        /* Monotonic so wall-clock steps (NTP) cannot stretch or shorten the wait. */
        if (0 == pthread_condattr_setclock(&attr, CLOCK_MONOTONIC))
        {
            PresenceCondClock = CLOCK_MONOTONIC;
        }
        else
        {
            CcspTraceError(("%s:%d, pthread_condattr_setclock failed, using CLOCK_REALTIME\n",__FUNCTION__,__LINE__));
        }
        rc = pthread_cond_init(&PresenceDetectionCond, &attr);
        pthread_condattr_destroy(&attr);
    }
    if (0 != rc)
    {
        CcspTraceError(("%s:%d, pthread_cond_init failed rc:%d, waits fall back to sleep()\n",__FUNCTION__,__LINE__,rc));
        return;
    }
    gPresenceCondReady = TRUE;
}

static BOOL PresenceIsStopRequested(void)
{
    BOOL bStop;
    pthread_mutex_lock(&PresenceDetectionMutex);
    bStop = gStopRequested;
    pthread_mutex_unlock(&PresenceDetectionMutex);
    return bStop;
}

/* Replaces sleep(): returns early when Stop broadcasts. Returns TRUE if stop was requested. */
static BOOL PresenceWaitOrStopMs(unsigned int uiMs)
{
    struct timespec ts;
    BOOL bStop = FALSE;
    int rc = 0;

    pthread_once(&PresenceCondOnce, PresenceCondInit);
    if (!gPresenceCondReady || (0 != clock_gettime(PresenceCondClock, &ts)))
    {
        CcspTraceError(("%s:%d, cond wait unavailable (ready:%d errno:%d), falling back to sleep\n",__FUNCTION__,__LINE__,gPresenceCondReady,errno));
        usleep(((uiMs > 1000) ? 1000 : uiMs) * 1000);
        return PresenceIsStopRequested();
    }
    ts.tv_sec += uiMs / 1000;
    ts.tv_nsec += (long)(uiMs % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L)
    {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&PresenceDetectionMutex);
    while (!gStopRequested && (0 == rc))
    {
        rc = pthread_cond_timedwait(&PresenceDetectionCond, &PresenceDetectionMutex, &ts);
    }
    bStop = gStopRequested;
    pthread_mutex_unlock(&PresenceDetectionMutex);

    if ((0 != rc) && (ETIMEDOUT != rc))
    {
        CcspTraceError(("%s:%d, pthread_cond_timedwait failed rc:%d, falling back to sleep\n",__FUNCTION__,__LINE__,rc));
        if (!bStop)
        {
            usleep(((uiMs > 1000) ? 1000 : uiMs) * 1000);
        }
    }
    return bStop;
}

static BOOL PresenceWaitOrStop(unsigned int uiSecs)
{
    return PresenceWaitOrStopMs(uiSecs * 1000);
}

/* Caller must hold PresenceDetectionLifecycleMutex. Handles stay recorded until their join succeeds. */
static int PresenceDetection_StopWorkersLocked(void)
{
    pthread_once(&PresenceCondOnce, PresenceCondInit);
    pthread_mutex_lock(&PresenceDetectionMutex);
    gStopRequested = TRUE;
    if (gPresenceCondReady)
    {
        pthread_cond_broadcast(&PresenceDetectionCond);
    }
    pthread_mutex_unlock(&PresenceDetectionMutex);

    /* Join from the tail so un-joined handles stay contiguous in [0, count) without shifting. */
    while (presenceDetectionThreadCount > 0)
    {
        int result = pthread_join(presenceDetectionThreads[presenceDetectionThreadCount - 1], NULL);
        if (result != 0)
        {
            CcspTraceError(("%s:%d, Failed to join presence detection worker: %d, %u worker(s) still recorded\n",__FUNCTION__,__LINE__,result,presenceDetectionThreadCount));
            return -1;
        }

        --presenceDetectionThreadCount;
    }

    presenceDetectionRunning = 0;
    return 0;
}

static int PresenceDetection_CreateThread(void *(*threadFunction)(void *))
{
    pthread_t threadId;
    int result;

    if (presenceDetectionThreadCount >= PRESENCE_DETECTION_WORKER_COUNT)
    {
        CcspTraceError(("%s:%d, worker table full\n",__FUNCTION__,__LINE__));
        return EAGAIN;
    }

    result = pthread_create(&threadId, NULL, threadFunction, NULL);
    if (result == 0)
    {
        presenceDetectionThreads[presenceDetectionThreadCount++] = threadId;
        presenceDetectionRunning = 1;
    }
    return result;
}

static void PresenceDetection_FreeObject(void)
{
    CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    if (pDetectionObject)
    {
        int index = 0;
        if (pDetectionObject->ppdevlist)
        {
            for (index = 0; index < pDetectionObject->numOfDevice; ++index)
            {
                if (pDetectionObject->ppdevlist[index])
                {
                    AnscFreeMemory(pDetectionObject->ppdevlist[index]);
                    pDetectionObject->ppdevlist[index] = NULL;
                }
            }
            AnscFreeMemory(pDetectionObject->ppdevlist);
            pDetectionObject->ppdevlist = NULL;
        }
        AnscFreeMemory(pDetectionObject);
        pDetectionObject = NULL;
    }
    pthread_mutex_unlock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
}

int PresenceDetection_Init()
{
    int ret = 0;
    char cBuf [8] = {0};
    PLmDevicePresenceDetectionInfo pNewObject = NULL;

    if (!gPresenceMutexRecursive)
    {
        CcspTraceError(("%s:%d, recursive PresenceDetectionMutex could not be created, presence detection not started\n",__FUNCTION__,__LINE__));
        return -1;
    }
    pthread_mutex_lock(&PresenceDetectionLifecycleMutex);
    /* Completes a teardown left pending by a failed join so Enable can recover. */
    if (presenceDetectionThreadCount != 0 || presenceDetectionRunning)
    {
        CcspTraceWarning(("%s:%d, retrying join of workers from a previous run\n",__FUNCTION__,__LINE__));
        if (0 != PresenceDetection_StopWorkersLocked())
        {
            CcspTraceError(("%s:%d, workers from a previous run are still not joined, refusing to initialise\n",__FUNCTION__,__LINE__));
            pthread_mutex_unlock(&PresenceDetectionLifecycleMutex);
            return -1;
        }
    }
    if (pDetectionObject)
    {
        CcspTraceWarning(("%s:%d, freeing stale detection object\n",__FUNCTION__,__LINE__));
        PresenceDetection_FreeObject();
    }
    pNewObject = AnscAllocateMemory(sizeof(*pNewObject));
    if (!pNewObject)
    {
        CcspTraceError(("%s:%d, failed to allocate detection object\n",__FUNCTION__,__LINE__));
        pthread_mutex_unlock(&PresenceDetectionLifecycleMutex);
        return -1;
    }
    memset(pNewObject, 0, sizeof(*pNewObject));
    pNewObject->ppdevlist = AnscAllocateMemory(MAX_NUM_OF_DEVICE * sizeof(*pNewObject->ppdevlist));
    if (!pNewObject->ppdevlist)
    {
        CcspTraceError(("%s:%d, failed to allocate device list\n",__FUNCTION__,__LINE__));
        AnscFreeMemory(pNewObject);
        pthread_mutex_unlock(&PresenceDetectionLifecycleMutex);
        return -1;
    }
    memset(pNewObject->ppdevlist, 0, MAX_NUM_OF_DEVICE * sizeof(*pNewObject->ppdevlist));
    if(0 == syscfg_get(NULL, "ConfiguredMacListIsSet", cBuf, sizeof(cBuf)))
    {
        pNewObject->bConfiguredMacListIsSet = (atoi(cBuf) == 1) ? TRUE : FALSE;
    }
    else
    {
        pNewObject->bConfiguredMacListIsSet = FALSE;
    }
    pthread_mutex_lock(&PresenceDetectionMutex);
    pDetectionObject = pNewObject;
    pthread_mutex_unlock(&PresenceDetectionMutex);
    CcspTraceWarning(("%s:%d ConfiguredMacListIsSet:%d\n",__FUNCTION__,__LINE__,pNewObject->bConfiguredMacListIsSet));
#if 0
   /*Reading of NA from netlink sockets is commented currently. In feature it may be required to enable it.*/
    Neighbourdiscovery_Update(TRUE);
#endif
    pthread_mutex_unlock(&PresenceDetectionLifecycleMutex);
    return ret;
}

int PresenceDetection_DeInit()
{
    int ret = 0;
    pthread_mutex_lock(&PresenceDetectionLifecycleMutex);
    if (PresenceDetection_StopWorkersLocked() != 0)
    {
        CcspTraceError(("%s:%d, workers not joined, refusing to free detection object\n",__FUNCTION__,__LINE__));
        pthread_mutex_unlock(&PresenceDetectionLifecycleMutex);
        return -1;
    }
    PresenceDetection_FreeObject();
#if 0
   /*Reading of NA from netlink sockets is commented currently. In feature it may be required to enable it.*/
    Neighbourdiscovery_Update(FALSE);
#endif
    pthread_mutex_unlock(&PresenceDetectionLifecycleMutex);
    return ret;
}


PLmDevicePresenceDetectionInfo GetPresenceDetectionObject()
{
    return pDetectionObject;
}


int PresenceDetection_set_ipv4leaveinterval (unsigned int val)
{
    int ret_val = -1;
    PLmDevicePresenceDetectionInfo pobject = NULL;
    CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pobject = GetPresenceDetectionObject();
    if (pobject)
    {
        pobject->ipv4_leave_detection_interval = val;
        ret_val = 0;
    }
    pthread_mutex_unlock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    return ret_val;
}

int PresenceDetection_set_ipv6leaveinterval (unsigned int val)
{
    int ret_val = -1;
    PLmDevicePresenceDetectionInfo pobject = NULL;
    CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pobject = GetPresenceDetectionObject();
    if (pobject)
    {
        pobject->ipv6_leave_detection_interval = val;
        ret_val = 0;
    }
    pthread_mutex_unlock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    return ret_val;
}

int PresenceDetection_set_bkgndjoininterval (unsigned int val)
{
    int ret_val = -1;
    PLmDevicePresenceDetectionInfo pobject = NULL;
    CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pobject = GetPresenceDetectionObject();
    if (pobject)
    {
        pobject->bkgnd_join_detection_interval = val;
        ret_val = 0;
    }
    pthread_mutex_unlock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    return ret_val;
}

int PresenceDetection_set_ipv4retrycount (unsigned int val)
{
    int ret_val = -1;
    PLmDevicePresenceDetectionInfo pobject = NULL;
    CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pobject = GetPresenceDetectionObject();
    if (pobject)
    {
        pobject->ipv4_num_retries = val;
        ret_val = 0;
    }
    pthread_mutex_unlock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    return ret_val;
}

int PresenceDetection_set_ipv6retrycount (unsigned int val)
{
    int ret_val = -1;
    PLmDevicePresenceDetectionInfo pobject = NULL;
    CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pobject = GetPresenceDetectionObject();
    if (pobject)
    {
        pobject->ipv6_num_retries = val;
        ret_val = 0;
    }
    pthread_mutex_unlock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    return ret_val;
}

PLmPresenceDeviceInfo FindDeviceByPhysAddress(char * physAddress)
{
    int i = 0;
    PLmDevicePresenceDetectionInfo pobject = NULL;
    pobject = GetPresenceDetectionObject();
    if (pobject)
    {
        for(i = 0; i<pobject->numOfDevice; i++)
        {
            if (pobject->ppdevlist && pobject->ppdevlist[i])
            {
                if (strcasecmp(pobject->ppdevlist[i]->mac, physAddress) == 0)
                {
                    return pobject->ppdevlist[i];
                }
            }
        }
    }
    return NULL;
}

void printPresenceTable(void)
{
    PLmDevicePresenceDetectionInfo pDevPresenceDetectObject = NULL;
    CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pDevPresenceDetectObject = GetPresenceDetectionObject();
    if (NULL != pDevPresenceDetectObject)
    {
        int i = 0;
        for(i = 0; i<pDevPresenceDetectObject->numOfDevice; i++)
        {
            if (pDevPresenceDetectObject->ppdevlist && pDevPresenceDetectObject->ppdevlist[i])
            {
                CcspTraceInfo(("RDKB_PRESENCE:  Mac %s, ipv4Active:%d, ipv6Active:%d, ipv4:%s, ipv6:%s\n",pDevPresenceDetectObject->ppdevlist[i]->mac,
                    pDevPresenceDetectObject->ppdevlist[i]->ipv4Active,pDevPresenceDetectObject->ppdevlist[i]->ipv6Active,pDevPresenceDetectObject->ppdevlist[i]->ipv4,pDevPresenceDetectObject->ppdevlist[i]->ipv6));
            }
        }
    }
    pthread_mutex_unlock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
}

int PresenceDetection_AddDevice(LmPresenceDeviceInfo *pinfo, BOOL bIsMacConfigurationEnabled)
{
    int ret_val = -1;
    PLmDevicePresenceDetectionInfo pobject = NULL;
    PLmPresenceDeviceInfo pDev = NULL;
    if (!pinfo)
    {
        CcspTraceError(("%s:%d, Invalid input parameter\n",__FUNCTION__,__LINE__));
        return ret_val;
    }
    CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pDev = FindDeviceByPhysAddress(pinfo->mac);
    if (pDev)
    {
        CcspTraceDebug(("RDKB_PRESENCE: Mac %s already exist !!! \n",pinfo->mac));
        if (pinfo->ipv4Active && (!pDev->ipv4Active))
        {
            pDev->ipv4Active = pinfo->ipv4Active;
            strncpy(pDev->ipv4,pinfo->ipv4,sizeof(pDev->ipv4));
        }
        if (pinfo->ipv6Active && (!pDev->ipv6Active))
        {
            pDev->ipv6Active = pinfo->ipv6Active;
            strncpy(pDev->ipv6,pinfo->ipv6,sizeof(pDev->ipv6));
        }
        ret_val = 0;
        goto unlock;
    }
    pobject = GetPresenceDetectionObject();
    if (!pobject)
    {
        CcspTraceError(("%s:%d, Presence Detection Object is NULL, cannot add Mac %s\n",__FUNCTION__,__LINE__,pinfo->mac));
    }
    else if (pobject->numOfDevice >= MAX_NUM_OF_DEVICE)
    {
        CcspTraceError(("%s:%d, detection list full (%d), cannot add Mac %s\n",__FUNCTION__,__LINE__,pobject->numOfDevice,pinfo->mac));
    }
    else if (!pobject->ppdevlist)
    {
        CcspTraceError(("%s:%d, device list is NULL, cannot add Mac %s\n",__FUNCTION__,__LINE__,pinfo->mac));
    }
    else
    {
        pDev =  AnscAllocateMemory(sizeof(LmPresenceDeviceInfo));
        if (pDev)
        {
            memcpy (pDev,pinfo,sizeof(LmPresenceDeviceInfo));
            pDev->ipv4_state = STATE_PRESENCE_DETECTION_NONE;
            pDev->ipv6_state = STATE_PRESENCE_DETECTION_NONE;
            pDev->ipv4_retry_count = 0;
            pDev->ipv6_retry_count = 0;
            pobject->ppdevlist[pobject->numOfDevice] = pDev;
            if ((TRUE == bIsMacConfigurationEnabled) && (FALSE == pobject->bConfiguredMacListIsSet))
            {
                pobject->bConfiguredMacListIsSet = TRUE;
                syscfg_set_commit(NULL, "ConfiguredMacListIsSet", "1");
                CcspTraceWarning(("%s:%d ConfiguredMacListIsSet is set to TRUE\n",__FUNCTION__,__LINE__));
            }
            CcspTraceWarning(("RDKB_PRESENCE:  Mac %s Added into detection list \n",pDev->mac));
            ++pobject->numOfDevice;
            CcspTraceWarning(("RDKB_PRESENCE:  numOfDevice:%d\n",pobject->numOfDevice));
            ret_val = 0;
        }
        else
        {
            CcspTraceError(("%s:%d, failed to allocate memory for Mac %s\n",__FUNCTION__,__LINE__,pinfo->mac));
        }
    }
unlock:
    pthread_mutex_unlock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    return ret_val;
}

int PresenceDetection_RemoveDevice(char *mac, BOOL bIsMacConfigurationEnabled)
{
    int ret_val = -1;
    int index = 0;
    int i = 0;
    BOOL bResetList = FALSE;
    PLmDevicePresenceDetectionInfo pobject = NULL;
    PLmPresenceDeviceInfo pDev = NULL;
    if (!mac)
    {
        CcspTraceError(("%s:%d, Invalid input parameter\n",__FUNCTION__,__LINE__));
        return ret_val;
    }
    CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pobject = GetPresenceDetectionObject();
    if (!pobject) {
        CcspTraceError(("%s:%d, Presence Detection Object is NULL, cannot remove Mac %s\n",__FUNCTION__,__LINE__,mac));
        pthread_mutex_unlock(&PresenceDetectionMutex);
        CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
        return ret_val;
    }
    for(i = 0; i<pobject->numOfDevice; i++)
    {
        if (pobject->ppdevlist && pobject->ppdevlist[i])
        {
            if (strcasecmp(pobject->ppdevlist[i]->mac, mac) == 0)
            {
                pDev = pobject->ppdevlist[i];
                pobject->ppdevlist[i] = NULL;
                index = i;
                break;
            }
        }
    }
    if (!pDev)
    {
        CcspTraceWarning(("RDKB_PRESENCE:  Mac %s Not exist in detection list \n",mac));
        pthread_mutex_unlock(&PresenceDetectionMutex);
        CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
        return 0;
    }

    AnscFreeMemory(pDev);
    pDev = NULL;
    CcspTraceWarning(("RDKB_PRESENCE:  Mac %s Removed from monitor \n",mac));
    if (pobject->numOfDevice > 0)
    {
        // reshuffle the list
        for(i = index; i<pobject->numOfDevice - 1; i++)
        {
            if (pobject->ppdevlist)
            {
                if (pobject->ppdevlist[i+1])
                {
                    pobject->ppdevlist[i] = pobject->ppdevlist[i+1];
                }
            }
        }
         pobject->ppdevlist[pobject->numOfDevice - 1] = NULL;
        --pobject->numOfDevice;
    }
    if ((TRUE == bIsMacConfigurationEnabled) && ( 0 == pobject->numOfDevice) && (TRUE == pobject->bConfiguredMacListIsSet))
    {
        pobject->bConfiguredMacListIsSet = FALSE;
        syscfg_set_commit(NULL, "ConfiguredMacListIsSet", "0");
        CcspTraceWarning(("%s:%d ConfiguredMacListIsSet is set to FALSE\n",__FUNCTION__,__LINE__));
    }
    if ((TRUE == bIsMacConfigurationEnabled) && ( 0 == pobject->numOfDevice))
    {
        bResetList = TRUE;
    }
    pthread_mutex_unlock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    if (bResetList)
    {
        CcspTraceWarning(("%s:%d Configured Mac list is empty, so resetting the presence detection list\n",__FUNCTION__,__LINE__));
        addHostsToPresenceTable();
    }
    return ret_val;
}

void getConfiguredMaclistStatus(BOOL *pVar)
{
    PLmDevicePresenceDetectionInfo pobject = NULL;
    if (NULL == pVar)
    {
        CcspTraceWarning(("%s:%d Invalid input parameter\n",__FUNCTION__,__LINE__));
        return;
    }
    pthread_mutex_lock(&PresenceDetectionMutex);
    pobject = GetPresenceDetectionObject();
    if (NULL != pobject)
    {
        *pVar = pobject->bConfiguredMacListIsSet;
	pthread_mutex_unlock(&PresenceDetectionMutex);
    }
    else
    {
        pthread_mutex_unlock(&PresenceDetectionMutex);
	CcspTraceWarning(("%s:%d Presence Detection Object is NULL,Reading from Syscfg\n",__FUNCTION__,__LINE__));
        char cBuf [8] = {0};
        if(0 == syscfg_get(NULL, "ConfiguredMacListIsSet", cBuf, sizeof(cBuf)))
        {
            *pVar = (atoi(cBuf) == 1) ? TRUE : FALSE;
        }
        else
        {
            *pVar = FALSE;
        }
    }
    CcspTraceWarning(("%s:%d ConfiguredMacListIsSet:%d\n",__FUNCTION__,__LINE__,*pVar));
}

void resetPresenceDetectionList(char * pMac)
{
    BOOL bIsMacPresent = FALSE;
    int iIndex = -1;
    PLmPresenceDeviceInfo pPresenceDeviceInfo = NULL;
    PLmDevicePresenceDetectionInfo pDevicePresenceDetectInfo = NULL;

    if (NULL == pMac)
    {
        CcspTraceWarning(("%s:%d Invalid input parameter\n",__FUNCTION__,__LINE__));
        return;
    }

    CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pDevicePresenceDetectInfo = GetPresenceDetectionObject();
    if (NULL != pDevicePresenceDetectInfo)
    {
        for(int iCount = 0; iCount  < pDevicePresenceDetectInfo->numOfDevice; iCount++)
        {
            if ((NULL != pDevicePresenceDetectInfo->ppdevlist) && (NULL != pDevicePresenceDetectInfo->ppdevlist[iCount]))
            {
                pPresenceDeviceInfo = pDevicePresenceDetectInfo->ppdevlist[iCount];
                if (0 != strcmp(pPresenceDeviceInfo->mac,pMac))
                {
                    PLmObjectHost pHost = Hosts_FindHostByPhysAddress(pPresenceDeviceInfo->mac);
                    if (NULL != pHost)
                    {
                        pHost->bBoolParaValue[LM_HOST_PresenceNotificationEnabledId] = FALSE;
                        pHost->bBoolParaValue[LM_HOST_PresenceActiveId] = FALSE;
                    }
                    if (0 == iCount)
                        continue;
                    AnscFreeMemory(pDevicePresenceDetectInfo->ppdevlist[iCount]);
                    pDevicePresenceDetectInfo->ppdevlist[iCount] = NULL;
                    CcspTraceWarning(("%s:%d, Mac:%s is removed from the No Config list\n",__FUNCTION__,__LINE__,pPresenceDeviceInfo->mac));
                }
                else
                {
                    iIndex = iCount;
                    CcspTraceWarning(("%s:%d, Mac:%s is already present in the No Config list\n",__FUNCTION__,__LINE__,pMac));
                    bIsMacPresent = TRUE;
                }
            }
        }
        if (FALSE == bIsMacPresent)
        {
            CcspTraceWarning(("%s:%d, Mac:%s is not present in the No config list\n",__FUNCTION__,__LINE__,pMac));
            pDevicePresenceDetectInfo->numOfDevice = 0;
            if ((NULL != pDevicePresenceDetectInfo->ppdevlist) && (NULL != pDevicePresenceDetectInfo->ppdevlist[0]))
            {
                pPresenceDeviceInfo = pDevicePresenceDetectInfo->ppdevlist[0];
                PLmObjectHost pHost = Hosts_FindHostByPhysAddress(pPresenceDeviceInfo->mac);
                if (NULL != pHost)
                {
                    pHost->bBoolParaValue[LM_HOST_PresenceNotificationEnabledId] = FALSE;
                    pHost->bBoolParaValue[LM_HOST_PresenceActiveId] = FALSE;
                }
                AnscFreeMemory(pDevicePresenceDetectInfo->ppdevlist[0]);
                pDevicePresenceDetectInfo->ppdevlist[0] = NULL;
            }
        }
        else
        {
            if (0 == iIndex)
            {
                pDevicePresenceDetectInfo->numOfDevice = 1;
            }
            else if (-1 != iIndex)
            {
                memcpy(pDevicePresenceDetectInfo->ppdevlist[0],pDevicePresenceDetectInfo->ppdevlist[iIndex],sizeof(LmPresenceDeviceInfo));
                pDevicePresenceDetectInfo->numOfDevice = 1;
                AnscFreeMemory(pDevicePresenceDetectInfo->ppdevlist[iIndex]);
                pDevicePresenceDetectInfo->ppdevlist[iIndex] = NULL;
            }
            if ( 1 == pDevicePresenceDetectInfo->numOfDevice)
            {
                pDevicePresenceDetectInfo->bConfiguredMacListIsSet = TRUE;
                syscfg_set_commit(NULL, "ConfiguredMacListIsSet", "1");
                CcspTraceWarning(("%s:%d ConfiguredMacListIsSet is set to TRUE\n",__FUNCTION__,__LINE__));
            }
            CcspTraceWarning(("%s:%d, Mac:%s is present at index %d\n",__FUNCTION__,__LINE__,pMac, iIndex));
        }
    }
    else
    {
        CcspTraceError(("%s:%d, Presence Detection Object is NULL, cannot reset list for Mac:%s\n",__FUNCTION__,__LINE__,pMac));
    }
    pthread_mutex_unlock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
}

static int addAttribute(struct nlmsghdr *pNlMsgHdr, unsigned int uiMaxLen, int iType, const void * pVoidData, int iDataLen)
{
    if ((NULL == pNlMsgHdr) || (NULL == pVoidData) || (iDataLen <= 0))
    {
        CcspTraceError (("%s:%d Invalid input parameter\n",__FUNCTION__,__LINE__));
        return -1;
    }
    int iLen = RTA_LENGTH(iDataLen);
    if (NLMSG_ALIGN(pNlMsgHdr->nlmsg_len) + RTA_ALIGN(iLen) > uiMaxLen)
    {
        CcspTraceError (("%s:%d, Netlink message exceeds bufer size\n",__FUNCTION__,__LINE__));
        return -1;
    }

    struct rtattr * pRtAttribute = (struct rtattr *) ((char *) pNlMsgHdr + NLMSG_ALIGN(pNlMsgHdr->nlmsg_len));
    pRtAttribute->rta_type = iType;
    pRtAttribute->rta_len = iLen;
    memcpy (RTA_DATA(pRtAttribute),pVoidData, iDataLen);
    pNlMsgHdr->nlmsg_len = NLMSG_ALIGN(pNlMsgHdr->nlmsg_len) + RTA_ALIGN(iLen);
    return 0;
}

static int sendNetlinkMessage(int iSocketFd, struct nlmsghdr * pNlMsgHdr)
{
    if ((NULL == pNlMsgHdr) || (iSocketFd < 0))
    {
        CcspTraceError (("%s:%d Invalid input parameter\n",__FUNCTION__,__LINE__));
        return -1;
    }
    struct sockaddr_nl sockAddrForNetlink = {0};
    sockAddrForNetlink.nl_family = AF_NETLINK;

    struct iovec iov = {
        .iov_base = (void*)pNlMsgHdr,
        .iov_len = pNlMsgHdr->nlmsg_len,
    };

    struct msghdr msgHdr = {
        .msg_name = (void*)&sockAddrForNetlink,
        .msg_namelen = sizeof(sockAddrForNetlink),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    if (sendmsg(iSocketFd, &msgHdr, 0) < 0)
    {
        CcspTraceError (("%s:%d Failed to send message\n",__FUNCTION__,__LINE__));
        return -1;
    }
    return 0;
}

void sendProbeRequest (int iIpVersion, char * pIpAddress, char * pIface)
{
#define PROBE_BUFF_SIZE 256
    if ((NULL == pIpAddress) || (NULL == pIface))
    {
        CcspTraceError(("%s:%d Invalid input parameter\n",__FUNCTION__,__LINE__));
        return;
    }

    int iSocketFd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (iSocketFd < 0)
    {
        CcspTraceError(("%s:%d Failed to create socket\n",__FUNCTION__,__LINE__));
        return;
    }

    char cBuffer[PROBE_BUFF_SIZE] = {0};
    struct nlmsghdr *pNetlinkMsgHdr = (struct nlmsghdr *)cBuffer;
    struct ndmsg *pNeighDetectionMsg = (struct ndmsg *)NLMSG_DATA(pNetlinkMsgHdr);

    pNetlinkMsgHdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    pNetlinkMsgHdr->nlmsg_type = RTM_NEWNEIGH;
    pNetlinkMsgHdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE;
    pNetlinkMsgHdr->nlmsg_seq =1;
    pNetlinkMsgHdr->nlmsg_pid = getpid();

    memset(pNeighDetectionMsg, 0, sizeof(struct ndmsg));
    if (IPV4 == iIpVersion)
    {
        pNeighDetectionMsg->ndm_family = AF_INET;
    }
    else if (IPV6 == iIpVersion)
    {
        pNeighDetectionMsg->ndm_family = AF_INET6;
    }
    pNeighDetectionMsg->ndm_state = NUD_PROBE;
    pNeighDetectionMsg->ndm_ifindex = if_nametoindex(pIface);

    if (0 == pNeighDetectionMsg->ndm_ifindex)
    {
        CcspTraceError(("%s:%d Failed to get interface index\n",__FUNCTION__,__LINE__));
        close(iSocketFd);
        return;
    }
    pNeighDetectionMsg->ndm_flags = 0;
    pNeighDetectionMsg->ndm_type = RTN_UNICAST;

    if (IPV4 == iIpVersion)
    {
        struct in_addr inAddr = {0};
        if (inet_pton(AF_INET, pIpAddress, &inAddr) <= 0)
        {
            CcspTraceError (("%s:%d Failed to convert IP address\n",__FUNCTION__,__LINE__));
            close(iSocketFd);
            return;
        }
        if (addAttribute(pNetlinkMsgHdr, PROBE_BUFF_SIZE, NDA_DST, &inAddr, sizeof(struct in_addr)) < 0)
        {
            CcspTraceError (("%s:%d Failed to add attribute\n",__FUNCTION__,__LINE__));
            close(iSocketFd);
            return;
        }
    }
    else if (IPV6 == iIpVersion)
    {
        struct in6_addr in6Addr = {0};
        if (inet_pton(AF_INET6, pIpAddress, &in6Addr) <= 0)
        {
            CcspTraceError (("%s:%d Failed to convert IP address\n",__FUNCTION__,__LINE__));
            close(iSocketFd);
            return;
        }
        if (addAttribute(pNetlinkMsgHdr, PROBE_BUFF_SIZE, NDA_DST, &in6Addr, sizeof(struct in6_addr)) < 0)
        {
            CcspTraceError (("%s:%d Failed to add attribute\n",__FUNCTION__,__LINE__));
            close(iSocketFd);
            return;
        }
    }

    if (sendNetlinkMessage(iSocketFd, pNetlinkMsgHdr) < 0)
    {
        CcspTraceError(("%s:%d Failed to send netlink message\n",__FUNCTION__,__LINE__));
        close(iSocketFd);
        return;
    }
    CcspTraceDebug(("%s:%d, Probe request sent for IP:%s on interface:%s\n",__FUNCTION__,__LINE__,pIpAddress,pIface));
    close(iSocketFd);
    return;
}

int sendIpv4ArpMessage(PLmDevicePresenceDetectionInfo pobject,BOOL bactiveclient, BOOL bSendProbe)
{
    int status, frame_length, sd, bytes;
    char *interface, *target, *src_ip;
    arp_hdr arphdr;
    uint8_t *src_mac, *dst_mac, *ether_frame;
    struct addrinfo hints, *res;
    struct sockaddr_in *ipv4;
    struct sockaddr_ll device;
    struct ifreq ifr;
    char buf[64];
    errno_t rc = -1;

    if (pobject)
    {
        for(int iCount= 0; iCount < pobject->numOfDevice; iCount++)
        {
            if (pobject->ppdevlist && pobject->ppdevlist[iCount])
            {
                PLmPresenceDeviceInfo obj = pobject->ppdevlist[iCount];
                if ((!obj->ipv4Active) || (obj->currentActive != bactiveclient))
                {
                    continue;
                }
                ++obj->ipv4_retry_count;
                if (obj->ipv4_retry_count > pobject->ipv4_num_retries)
                {
                    CcspTraceDebug(("%s:%d, retryCount:%d\n",__FUNCTION__,__LINE__,obj->ipv4_retry_count));
                    CcspTraceDebug(("%s:%d, Mac:%s, ipv4 leave detected\n",__FUNCTION__,__LINE__,obj->mac));
                    if (obj->ipv6Active && (obj->ipv6_state != STATE_LEAVE_DETECTED && obj->ipv6_state != STATE_PRESENCE_DETECTION_NONE))
                    {
                        obj->ipv4_state = STATE_LEAVE_DETECTED;
                        obj->ipv4_retry_count = 0;
                        CcspTraceInfo(("%s:%d, Mac:%s, ipv6 is active\n",__FUNCTION__,__LINE__,obj->mac));
                        continue;
                    }
                    if ((TRUE == obj->currentActive) && (STATE_LEAVE_DETECTED != obj->ipv4_state && STATE_PRESENCE_DETECTION_NONE != obj->ipv4_state))
                    {
                        obj->currentActive = FALSE;
                        obj->ipv4_state = STATE_LEAVE_DETECTED;
                        obj->ipv4_retry_count = 0;
                        // trigger leave callback
                        CcspTraceInfo(("%s:%d, Mac:%s, leave detected\n",__FUNCTION__,__LINE__,obj->mac));
                        presenceDetected(obj);
                        continue;
                    }
                }
#if 0
                /* In IPV4 only case, To identify accurate presence leave
                 * reset IPV4 status and remove IPV4 entry from ARP.
                 * If device is in connected state for ipv4 case, ARP will updated again.
                 * otherwise this device will be in-active.
                 */
                if (obj->currentActive)
                {
                    if (obj->ipv4Active && (pobj->ipv6_state == STATE_LEAVE_DETECTED))
                    {
                        int ret =0;
                        char buf1[64];
                        syscfg_get(NULL, "lan_ifname", buf1, sizeof(buf1));
                        CcspTraceInfo (("%s:%d, Mac:%s, ipv4 only case, deleting arp entry\n",__FUNCTION__,__LINE__,obj->mac));
                        ret = v_secure_system("ip neigh del %s dev %s",obj->ipv4,buf1);
                        if(ret !=0)
                        {
                             CcspTraceError(("Failed in executing the command via v_secure_system ret: %d \n",ret));
                        }
                    }
                }
#endif
                if (TRUE == bSendProbe)
                {
                    char cBuf[64] = {0};
                    syscfg_get(NULL, "lan_ifname", cBuf, sizeof(cBuf));
                    if ( 0 == strlen(cBuf))
                    {
                        snprintf(cBuf,sizeof(cBuf),"%s","brlan0");
                    }
                    sendProbeRequest(IPV4, obj->ipv4,cBuf);
                }
                // Allocate memory for various arrays.
                src_mac = allocate_ustrmem (6);
                dst_mac = allocate_ustrmem (6);
                ether_frame = allocate_ustrmem (IP_MAXPACKET);
                interface = allocate_strmem (40);
                target = allocate_strmem (40);
                src_ip = allocate_strmem (INET_ADDRSTRLEN);

                syscfg_get( NULL, "lan_ifname", buf, sizeof(buf));        
                // Interface to send packet through.
                rc = strcpy_s(interface, 40, buf);
                ERR_CHK(rc);

                // int cnt = 0;
                // for(cnt = 0; cnt < nPresenceDev;cnt++)
                // {
                // Submit request for a socket descriptor to look up interface.               
                if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
                    perror ("socket() failed to get socket descriptor for using ioctl() ");
                    CcspTraceError (("%s:%d, socket() failed to get socket descriptor for using ioctl()\n",__FUNCTION__,__LINE__));
                    //exit (EXIT_FAILURE);
                    goto freeResources;
                }

                // Use ioctl() to look up interface name and get its MAC address.
                memset (&ifr, 0, sizeof (ifr));
                snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
                if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
                    perror ("ioctl() failed to get source MAC address ");
                    CcspTraceError(("%s:%d, ioctl() failed to get source MAC address\n",__FUNCTION__,__LINE__));
                    //return (EXIT_FAILURE);
                }
                close (sd);

                // Copy source MAC address.
                memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

                // Report source MAC address using trace debug.
                CcspTraceDebug(("%s:%d, MAC address for interface %s is %02x:%02x:%02x:%02x:%02x:%02x\n", __FUNCTION__, __LINE__, interface, src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]));

                // Find interface index from interface name and store index in
                // struct sockaddr_ll device, which will be used as an argument of sendto().
                memset (&device, 0, sizeof (device));
                if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
                    perror ("if_nametoindex() failed to obtain interface index ");
                    CcspTraceError (("%s:%d, if_nametoindex() failed to obtain interface index\n",__FUNCTION__,__LINE__));
                    //exit (EXIT_FAILURE);
                    goto freeResources;
                }
                //printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

                // Set destination MAC address: broadcast address
                memset (dst_mac, 0xff, 6 * sizeof (uint8_t));

                // Source IPv4 address:  you need to fill this out
                syscfg_get( NULL, "lan_ipaddr", buf, sizeof(buf));
                rc = strcpy_s (src_ip, INET_ADDRSTRLEN ,buf);
                ERR_CHK(rc);

                // Destination URL or IPv4 address (must be a link-local node): you need to fill this out
                //strcpy (target, "10.0.0.126");
                rc = strcpy_s(target, 40,obj->ipv4);
                ERR_CHK(rc);

                // Fill out hints for getaddrinfo().
                memset (&hints, 0, sizeof (struct addrinfo));
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_flags = hints.ai_flags | AI_CANONNAME;

                // Source IP address
                /*CID:67299 Argument cannot be negative*/
                if ((status = inet_pton (AF_INET, src_ip, &arphdr.sender_ip)) != 1) {
                    fprintf (stderr, "inet_pton() failed for source IP address.\nError message: %d - %s", status, strerror(errno));
                    CcspTraceError(("%s:%d, inet_pton() failed for source IP address.\nError message: %d - %s\n",__FUNCTION__,__LINE__,status,strerror(errno)));
                    //exit (EXIT_FAILURE);
                    goto freeResources;
                }

                // Resolve target using getaddrinfo().
                if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
                    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
                    CcspTraceError(("%s:%d, getaddrinfo() failed: %s\n",__FUNCTION__,__LINE__,gai_strerror (status)));
                    //exit (EXIT_FAILURE);
                    goto freeResources;
                }
                ipv4 = (struct sockaddr_in *) res->ai_addr;
                memcpy (&arphdr.target_ip, &ipv4->sin_addr, 4 * sizeof (uint8_t));
                freeaddrinfo (res);

                // Fill out sockaddr_ll.
                device.sll_family = AF_PACKET;
                memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
                device.sll_halen = 6;

                // ARP header

                // Hardware type (16 bits): 1 for ethernet
                arphdr.htype = htons (1);

                // Protocol type (16 bits): 2048 for IP
                arphdr.ptype = htons (ETH_P_IP);

                // Hardware address length (8 bits): 6 bytes for MAC address
                arphdr.hlen = 6;

                // Protocol address length (8 bits): 4 bytes for IPv4 address
                arphdr.plen = 4;

                // OpCode: 1 for ARP request
                arphdr.opcode = htons (ARPOP_REQUEST);

                // Sender hardware address (48 bits): MAC address
                memcpy (&arphdr.sender_mac, src_mac, 6 * sizeof (uint8_t));

                // Sender protocol address (32 bits)
                // See getaddrinfo() resolution of src_ip.

                // Target hardware address (48 bits): zero, since we don't know it yet.
                memset (&arphdr.target_mac, 0, 6 * sizeof (uint8_t));

                // Target protocol address (32 bits)
                // See getaddrinfo() resolution of target.

                // Fill out ethernet frame header.

                // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
                frame_length = 6 + 6 + 2 + ARP_HDRLEN;

                // Destination and Source MAC addresses
                memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
                memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

                // Next is ethernet type code (ETH_P_ARP for ARP).
                // http://www.iana.org/assignments/ethernet-numbers
                ether_frame[12] = ETH_P_ARP / 256;
                ether_frame[13] = ETH_P_ARP % 256;

                // Next is ethernet frame data (ARP header).

                // ARP header
                memcpy (ether_frame + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof (uint8_t));

                // Submit request for a raw socket descriptor.
                if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
                    perror ("socket() failed ");
                    CcspTraceError(("%s:%d, socket() failed\n",__FUNCTION__,__LINE__));
                    //exit (EXIT_FAILURE);
                    goto freeResources;
                }

                // Send ethernet frame to socket.
                if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
                    perror ("sendto() failed");
                    CcspTraceError(("%s:%d, sendto() failed\n",__FUNCTION__,__LINE__));
                    //exit (EXIT_FAILURE);
                }

                // Close socket descriptor.
                close (sd);
                // }
                // Free allocated memory.
    freeResources:
                free (src_mac);
                free (dst_mac);
                free (ether_frame);
                free (interface);
                free (target);
                free (src_ip);
            }

        }
    }
    return 0;
}
void *Send_arp_ipv4_thread (void *args)
{
    UNREFERENCED_PARAMETER(args);
    PLmDevicePresenceDetectionInfo pobject = NULL;
    unsigned int ActiveClientsecs = 0;
    unsigned int InActiveClientsecs = 0;
    unsigned int uiNumberOfSecs = 0;
    pobject = GetPresenceDetectionObject();
    /*CID: 68372 Dereference after null check*/
    /*CID: 65919 Dereference before null check*/
    if (!pobject)
    {
        CcspTraceError(("%s:%d, Presence Detection Object is NULL, worker exiting\n",__FUNCTION__,__LINE__));
        return NULL;
    }
    BOOL bSendProbe = FALSE;
    while (!PresenceIsStopRequested())
    {
        CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&PresenceDetectionMutex);
        CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));

        if (pobject->ipv4_leave_detection_interval == uiNumberOfSecs)
        {
            bSendProbe = TRUE;
        }

        if ((pobject->ipv4_num_retries * pobject->ipv4_leave_detection_interval) == uiNumberOfSecs)
        {
            uiNumberOfSecs = 0;
        }
        if (pobject->ipv4_leave_detection_interval)
        {
            if (ActiveClientsecs && (0 == (ActiveClientsecs % pobject->ipv4_leave_detection_interval)))
            {
                CcspTraceDebug(("%s:%d, Send Arp message to Active client\n",__FUNCTION__,__LINE__));
                sendIpv4ArpMessage(pobject,TRUE, bSendProbe); // send message to Active client
                ActiveClientsecs = 0;
                bSendProbe = FALSE;
            }
        }
        else
        {
            ActiveClientsecs = 0;
        }
        if (pobject->bkgnd_join_detection_interval)
        {
            if ( InActiveClientsecs  && (0 == (InActiveClientsecs % pobject->bkgnd_join_detection_interval)))
            {
                sendIpv4ArpMessage(pobject,FALSE, FALSE); // send message to InActive client
                InActiveClientsecs = 0;
            }
        }
        else
        {
            InActiveClientsecs = 0;
        }
        pthread_mutex_unlock(&PresenceDetectionMutex);
        CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));

        PresenceWaitOrStop(1);
        ++ActiveClientsecs;
        ++uiNumberOfSecs;
        ++InActiveClientsecs;
    }
    return args;
}

void *ReceiveArp_Thread(void *args)
{
    UNREFERENCED_PARAMETER(args);
    PLmDevicePresenceDetectionInfo pobject = NULL;
    pobject = GetPresenceDetectionObject();
    if (!pobject)
    {
        CcspTraceError(("%s:%d, Presence Detection Object is NULL, worker exiting\n",__FUNCTION__,__LINE__));
        return NULL;
    }
    while(!PresenceIsStopRequested())
    {
        char output[ARP_BUFFER_LEN];
        char buf[64];
        char cLine [256] = {0};

        syscfg_get(NULL, "lan_ifname", buf, sizeof(buf));
        snprintf(cLine,sizeof(cLine),"arp -i %s -an",buf);
        FILE *fpArpTable = popen(cLine,"r");
        if(NULL == fpArpTable)
        {
            CcspTraceError(("%s:%d, Failed to execute the command %s\n",__FUNCTION__,__LINE__,cLine));
            PresenceWaitOrStop(10);
            continue;
        }
        else
        {
            while(fgets(output, sizeof(output), fpArpTable)!=NULL)
            {
                Handle_RecieveArpCache(output);
            }
            pclose(fpArpTable);
        }
        PresenceWaitOrStop(10);
    }
    return args;
}

int  getipaddressfromarp(char *inputline,char *output, int out_len)
{
    char *startip = NULL;
    if (!inputline || !output || out_len < 18)
        return -1;
    startip = strstr(inputline,"(");
    if (startip)
    {
        char *end = NULL;
        end = strstr(startip,")");
        if (end)
        {
            memset(output,0,out_len);
            if ((end - startip - 1) > 0)
            {
                memcpy(output,startip + 1,(end - startip - 1));
                return 0;
            }
        }
    }
    return -1;
}
#if 0
// Function to extract IP, status, and interface name
void extract_info(const char *input, char *ip, char *status, char *interface,int iMaxLen)
{
     if (!input || !ip || !status || !interface)
        return;

    const char *ip_start = strchr(input, '(');
    const char *ip_end = strchr(input, ')');
    const char *status_start = strstr(input, "<");
    const char *status_end = strstr(input, ">");
    const char *iface_start = strstr(input, "on ");

    // Extract IP address
    if (ip_start && ip_end && ip_end > ip_start)
    {
        strncpy(ip, ip_start + 1, ip_end - ip_start - 1);
        ip[ip_end - ip_start - 1] = '\0';
    }
    // Extract status
    if (status_start && status_end && status_end > status_start)
    {
        strncpy(status, status_start, status_end - status_start + 1);
        status[status_end - status_start + 1] = '\0';
    }
    // Extract interface name
    if (iface_start)
    {
        strncpy(interface, iface_start + 3, iMaxLen - 1); // Skip "on "
        interface[strcspn(interface, "\n")] = '\0'; // Remove trailing newline if present
    }
}

int readIpv4NeighShow(FILE * fpToNeighTable, const char *cIfaceName, char *cObjIpv4)
{
    int result = 0;

    if (!cIfaceName || !cObjIpv4 || !fpToNeighTable)
        return -1;

    char cLine[256] = {0};
    char cInterface[64] = {0};
    char cIPv4[64] = {0};
    while (fgets(cLine, sizeof(cLine), fpToNeighTable))
    {
        char *pDevStart = strstr(cLine, "dev");
        char *pStatusStart = strstr(cLine, "FAILED");
        strncpy(cIPv4, cLine, pDevStart - cLine);
        cIPv4[pDevStart - cLine] = '\0';
        int iIpv4StrLen = strlen(cIPv4);
        while (iIpv4StrLen > 0 && (cIPv4[iIpv4StrLen - 1] == ' '))
        {
            cIPv4[iIpv4StrLen - 1] = '\0';
            iIpv4StrLen = strlen(cIPv4);
        }

        if (pDevStart && pStatusStart)
        {
            char *pIfaceStart = pDevStart + 4; // skip dev
            strncpy(cInterface, pIfaceStart, pStatusStart - pIfaceStart - 1);
            cInterface[pStatusStart - pIfaceStart - 1] = '\0';
        }

        if (pStatusStart && (0 == strcmp(cIPv4, cObjIpv4)) && (0 == strcmp(cInterface, cIfaceName)))
        {
            result = 1;
            break;
        }
    }
    return result;
}
#endif
int Handle_RecieveArpCache(char *line)
{
    int i = 0;
    BOOL bJoinDetected = FALSE;

    PLmDevicePresenceDetectionInfo pobject = NULL;
    if (!line)
        return -1;
    char cIfaceName[64] = {0};
    syscfg_get(NULL, "lan_ifname", cIfaceName, sizeof(cIfaceName));
    if (strlen(cIfaceName) == 0)
    {
        snprintf(cIfaceName,sizeof(cIfaceName),"brlan0");
    }
    CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pobject = GetPresenceDetectionObject();
    if (pobject)
    {
        for(i = 0; i<pobject->numOfDevice; i++)
        {
            if (pobject->ppdevlist && pobject->ppdevlist[i])
            {
                PLmPresenceDeviceInfo pobj = pobject->ppdevlist[i];
                if(strcasestr(line, pobj->mac))
                {
                    int retval = 0;
                    char buf[IPV4_SIZE];
                    if ((STATE_PRESENCE_DETECTION_NONE == pobj->ipv4_state || STATE_LEAVE_DETECTED == pobj->ipv4_state) &&
                        (STATE_PRESENCE_DETECTION_NONE == pobj->ipv6_state || STATE_LEAVE_DETECTED == pobj->ipv6_state))
                    {
                        CcspTraceInfo(("%s:%d, Arp Join detected for mac %s\n",__FUNCTION__,__LINE__,pobj->mac));
                        bJoinDetected = TRUE;
                    }
                    pobj->ipv4Active = TRUE;
                    pobj->currentActive = TRUE;
                    pobj->ipv4_retry_count = 0;
                    pobj->ipv4_state = STATE_JOIN_DETECTED_ARP;
                    retval = getipaddressfromarp(line,buf,sizeof(buf));
                    if (0 == retval)
                    {
                        if (strlen(buf) > 0)
                        /*CID:135467 Buffer not null terminated*/
                        strncpy(pobj->ipv4,buf,sizeof(pobj->ipv4)-1);
                        pobj->ipv4[sizeof(pobj->ipv4)-1] = '\0';
                    }
                    // trigger join callback
                    LmPresenceDeviceInfo lmPresenceObj = {0};
                    if (TRUE == bJoinDetected)
                    {
                        memcpy(&lmPresenceObj,pobj,sizeof(LmPresenceDeviceInfo));
                    }
                    pthread_mutex_unlock(&PresenceDetectionMutex);
                    CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
                    if (TRUE == bJoinDetected)
                    {
                        CcspTraceInfo(("%s:%d, Mac:%s, join detected from Arp\n",__FUNCTION__,__LINE__,lmPresenceObj.mac));
                        presenceDetected(&lmPresenceObj);
                        bJoinDetected = FALSE;
                    }
                    return 0;                  
                }
                /* Predates the whole-scan lock: rework its unlock/lock pairs before enabling. */
                #if 0
                else
                {
                /*read the incomplete entry from Arp table for matching ip
                  ex: ? (10.x.x.xxx) at <incomplete>  on brlan0
                  read the failed entry from the neigh table for matching ip
                  ex: 10.x.x.xxx dev brlan0 FAILED
                  if it is incomlete and failed then send a leave message if the IPv6 state is already leave */
                    if (FALSE == pobj->currentActive)
                    {
                        pthread_mutex_unlock(&PresenceDetectionMutex);
                        CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
                        bIsLockAcquired = FALSE;
                        continue;
                    }
                    if (STATE_LEAVE_DETECTED == pobj->ipv4_state || STATE_PRESENCE_DETECTION_NONE == pobj->ipv4_state)
                    {
                        pthread_mutex_unlock(&PresenceDetectionMutex);
                        CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
                        bIsLockAcquired = FALSE;
                        continue;
                    }
                    int iMaxLen = 256;
                    char cIPv4 [256] = {0};
                    char cStatus [256] = {0};
                    char cInterface [256] = {0};
                    extract_info(line, cIPv4, cStatus, cInterface, iMaxLen);
                    if ((0 == strcmp (cIPv4, pobj->ipv4) && 0 == strcmp(cStatus,"<incomplete>")) && (0 == strcmp(cIfaceName,cInterface)))
                    {
                        char cLine[256] = {0};
                        snprintf (cLine, sizeof(cLine), "ip -4 neigh show | grep -i %s",cIfaceName);
                        FILE *fpToNeighTable = popen(cLine, "r");
                        if (NULL != fpToNeighTable)
                        {
                            pthread_mutex_unlock(&PresenceDetectionMutex);
                            CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
                            bIsLockAcquired = FALSE;
                            int iReadResult = readIpv4NeighShow(fpToNeighTable, cIfaceName, pobj->ipv4);
                            if (NULL != fpToNeighTable)
                            {
                                pclose(fpToNeighTable);
                            }
                            CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
                            pthread_mutex_lock(&PresenceDetectionMutex);
                            CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
                            bIsLockAcquired = TRUE;
                            if (iReadResult)
                            {
                                if (STATE_LEAVE_DETECTED != pobj->ipv4_state && STATE_PRESENCE_DETECTION_NONE != pobj->ipv4_state)
                                {
                                    pobj->ipv4_state = STATE_LEAVE_DETECTED;
                                    CcspTraceInfo(("%s:%d, Mac:%s, ipv4 leave detected\n",__FUNCTION__,__LINE__,pobj->mac));
                                    if (STATE_LEAVE_DETECTED == pobj->ipv6_state || STATE_PRESENCE_DETECTION_NONE == pobj->ipv6_state)
                                    {
                                        pobj->currentActive = FALSE;
                                        CcspTraceInfo(("%s:%d, Mac:%s, leave detected\n",__FUNCTION__,__LINE__,pobj->mac));
                                        LmPresenceDeviceInfo lmPresenceObj = {0};
                                        memcpy(&lmPresenceObj,pobj,sizeof(LmPresenceDeviceInfo));
                                        pthread_mutex_unlock(&PresenceDetectionMutex);
                                        CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
                                        bIsLockAcquired = FALSE;
                                        presenceDetected(&lmPresenceObj);
                                    }
                                }
                            }
                        }
                    }
                }
                #endif
            }
        }
    }
    pthread_mutex_unlock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    return 0;
}

int CheckandupdatePresence(char *mac, int version, char *ipaddress,DeviceDetectionState state)
{
    int i = 0;
    BOOL bJoinDetected = FALSE;
    PLmDevicePresenceDetectionInfo pobject = NULL;
    if (!mac)
        return -1;
    CcspTraceDebug(("%s received mac= %s version %d state %d\n",__FUNCTION__,mac,version,state));
    CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pthread_mutex_lock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    pobject = GetPresenceDetectionObject();
    if (pobject)
    {
        for(i = 0; i<pobject->numOfDevice; i++)
        {
            if (pobject->ppdevlist && pobject->ppdevlist[i])
            {
                PLmPresenceDeviceInfo pobj = pobject->ppdevlist[i];
                if (strcasecmp(pobj->mac, mac) == 0)
                {
                    switch (version)
                    {
                        case IPV4:
                        {
                            if ((STATE_PRESENCE_DETECTION_NONE == pobj->ipv4_state || STATE_LEAVE_DETECTED == pobj->ipv4_state) &&
                                (STATE_PRESENCE_DETECTION_NONE != state && STATE_LEAVE_DETECTED != state) &&
                                (STATE_PRESENCE_DETECTION_NONE == pobj->ipv6_state || STATE_LEAVE_DETECTED == pobj->ipv6_state))
                            {
                                CcspTraceInfo(("%s:%d, IPv4 Join detected for mac %s\n",__FUNCTION__,__LINE__,mac));
                                bJoinDetected = TRUE;
                            }
                            pobj->ipv4Active = TRUE;
                            pobj->currentActive = TRUE;
                            pobj->ipv4_retry_count = 0;
                            pobj->ipv4_state = state;
                            if (ipaddress)
                            {
                                /*CID: 135267 Buffer not null terminated*/
                                strncpy(pobj->ipv4,ipaddress,sizeof(pobj->ipv4)-1);
                                pobj->ipv4[sizeof(pobj->ipv4)-1] = '\0';
                            }
                        }
                        break;
                        case IPV6:
                        {
                            if ((STATE_PRESENCE_DETECTION_NONE == pobj->ipv6_state || STATE_LEAVE_DETECTED == pobj->ipv6_state) &&
                                (STATE_PRESENCE_DETECTION_NONE != state && STATE_LEAVE_DETECTED != state) &&
                                (STATE_PRESENCE_DETECTION_NONE == pobj->ipv4_state || STATE_LEAVE_DETECTED == pobj->ipv4_state))
                            {
                                CcspTraceInfo(("%s:%d, IPv6 Join detected for mac %s\n",__FUNCTION__,__LINE__,mac));
                                bJoinDetected = TRUE;
                            }
                            if (STATE_LEAVE_DETECTED == state || STATE_PRESENCE_DETECTION_NONE == state)
                            {
                                CcspTraceInfo(("%s:%d, IPv6 Leave detected for mac %s\n",__FUNCTION__,__LINE__,mac));
                                pobj->ipv6_retry_count = 0;
                                pobj->ipv6_state = state;
                                if (STATE_LEAVE_DETECTED == pobj->ipv4_state || STATE_PRESENCE_DETECTION_NONE == pobj->ipv4_state)
                                {
                                    pobj->currentActive = FALSE;
                                    CcspTraceInfo(("%s:%d, Mac:%s, leave detected\n",__FUNCTION__,__LINE__,pobj->mac));
                                    LmPresenceDeviceInfo lmPresenceObj = {0};
                                    memcpy(&lmPresenceObj,pobj,sizeof(LmPresenceDeviceInfo));
                                    pthread_mutex_unlock(&PresenceDetectionMutex);
                                    CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
                                    presenceDetected(&lmPresenceObj);
                                    return 0;
                                }
                            }
                            else
                            {
                                pobj->ipv6Active = TRUE;
                                pobj->currentActive = TRUE;
                                pobj->ipv6_retry_count = 0;
                                pobj->ipv6_state = state;
                                if (ipaddress)
                                {
                                    strncpy(pobj->ipv6,ipaddress,sizeof(pobj->ipv6)-1);
                                    pobj->ipv6[sizeof(pobj->ipv6)-1] = '\0';
                                }
                            }
                        }
                        break;
                        default:
                            break;
                    }
                    LmPresenceDeviceInfo lmPresenceObj = {0};
                    if (TRUE == bJoinDetected)
                    {
                        memcpy(&lmPresenceObj,pobj,sizeof(LmPresenceDeviceInfo));
                    }
                    pthread_mutex_unlock(&PresenceDetectionMutex);
                    CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
                    // trigger join callback            
                    if (TRUE == bJoinDetected)
                    {
                        CcspTraceInfo(("%s:%d, Mac:%s, join detected\n",__FUNCTION__,__LINE__,lmPresenceObj.mac));
                        presenceDetected(&lmPresenceObj);
                    }
                    return 0;                  
                }
            }
        }
    }
    pthread_mutex_unlock(&PresenceDetectionMutex);
    CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
    return 0;
}

void *ReceiveIpv4ClientStatus(void *args)
{
    UNREFERENCED_PARAMETER(args);
    mqd_t mq = -1;
    char buffer[MAX_SIZE + 1];
    PLmDevicePresenceDetectionInfo pobject = NULL;

    pobject = GetPresenceDetectionObject();
    if (!pobject)
    {
        CcspTraceError(("%s:%d, Presence Detection Object is NULL, worker exiting\n",__FUNCTION__,__LINE__));
        return NULL;
    }

    mq = mq_open(DNSMASQ_PRESENCE_QUEUE_NAME, O_RDONLY | O_NONBLOCK);

    if (mq != (mqd_t)-1)
    {
        CcspTraceInfo(("%s:%d, Created the DNSMASQ_PRESENCE_QUEUE_NAME \n",__FUNCTION__,__LINE__));
    }
    do
    {
        ssize_t bytes_read;
        DnsmasqEventQData EventMsg;

        if (mq < 0)
        {
            mq = mq_open(DNSMASQ_PRESENCE_QUEUE_NAME, O_RDONLY | O_NONBLOCK);
            if (mq  != (mqd_t)-1)
            {
                CcspTraceInfo(("%s:%d, Created the DNSMASQ_PRESENCE_QUEUE_NAME \n",__FUNCTION__,__LINE__));
            }
        }
        else
        {
            /* receive the message */
            bytes_read = mq_receive(mq, buffer, MAX_SIZE, NULL);

            if (bytes_read > 0)
            {
                buffer[bytes_read] = '\0';
                memcpy(&EventMsg,buffer,sizeof(EventMsg));
                /* CID 340286 String not null terminated */
                EventMsg.mac[MAC_SIZE-1] = '\0';

                if(EventMsg.MsgType == MSG_TYPE_DNS_PRESENCE)
                {
                    CcspTraceInfo(("%s:%d, Mac:%s, ipv4 join detected from Dnsmasq\n",__FUNCTION__,__LINE__,EventMsg.mac));
                    CheckandupdatePresence(EventMsg.mac,IPV4,NULL,STATE_JOIN_DETECTED_DNSMASQ);	 // Ip is not sent from dnsmasq

                }
            }
        }
    }while(!PresenceWaitOrStop(3));

    if (mq != (mqd_t)-1)
    {
        int ret = mq_close(mq);
        if (ret == 0)
            mq_unlink(DNSMASQ_PRESENCE_QUEUE_NAME);
	else
	    CcspTraceError(("%s:%d, mq_close failed errno:%d\n",__FUNCTION__,__LINE__,errno));
    }
    return args;
}

void *processPresenceNotification(void *pArgs)
{
    UNREFERENCED_PARAMETER(pArgs);
    mqd_t messageQueue = -1;
    struct mq_attr msgQueuAttr;
    PLmObjectHost pHost;
    char cBuffer[PRESENCE_MAX_SIZE + 1];
    PLmDevicePresenceDetectionInfo pobject = NULL;

    pobject = GetPresenceDetectionObject();
    if (!pobject)
    {
        CcspTraceError(("%s:%d, Presence Detection Object is NULL, worker exiting\n",__FUNCTION__,__LINE__));
        return NULL;
    }

    // Unlink the existing message queue
    mq_unlink(PROCESS_PRESENCE_NOTIFY_QUEUE);

    /* initialize the queue attributes */
    msgQueuAttr.mq_flags = 0;
    msgQueuAttr.mq_maxmsg = 100;
    msgQueuAttr.mq_msgsize = PRESENCE_MAX_SIZE;
    msgQueuAttr.mq_curmsgs = 0;

    messageQueue = mq_open(PROCESS_PRESENCE_NOTIFY_QUEUE, O_CREAT | O_RDONLY | O_NONBLOCK, 0644, &msgQueuAttr);

    if (messageQueue == (mqd_t)-1)
    {
        CcspTraceError(("%s:%d: Failed to create the process presence nofify queue\n", __FUNCTION__, __LINE__));
        CcspTraceError(("%s:%d: errno:%d, errorMsg:%s\n", __FUNCTION__, __LINE__, errno, strerror(errno)));
        perror("messageQueue == (mqd_t)-1");
        return NULL;
    }

    CcspTraceInfo(("%s:%d, Created the PROCESS_PRESENCE_NOTIFY_QUEUE \n",__FUNCTION__,__LINE__));
    do
    {
        ssize_t bytesRead;
        PresenceQData sEventMsg;

        bytesRead = mq_receive(messageQueue, cBuffer, PRESENCE_MAX_SIZE, NULL);

        if (bytesRead < 0)
        {
            if (EAGAIN == errno)
            {
                /* On Linux mqd_t is a descriptor: wake as soon as a message arrives, time out to re-check stop. */
                struct pollfd sPollFd = { .fd = (int)messageQueue, .events = POLLIN, .revents = 0 };
                if ((poll(&sPollFd, 1, PRESENCE_MQ_POLL_MS) < 0) && (EINTR != errno))
                {
                    CcspTraceError(("%s:%d: poll on mq failed errno:%d, errorMsg:%s\n", __FUNCTION__, __LINE__, errno, strerror(errno)));
                    if (PresenceWaitOrStopMs(PRESENCE_MQ_POLL_MS))
                    {
                        break;
                    }
                }
                continue;
            }
            if (EINTR == errno)
            {
                continue;
            }
            CcspTraceError(("%s:%d: failed to read from mq errno:%d, errorMsg:%s\n", __FUNCTION__, __LINE__, errno, strerror(errno)));
            break;
        }

        cBuffer[bytesRead] = '\0';

        memcpy(&sEventMsg,cBuffer,sizeof(sEventMsg));
        /* CID 339816 String not null terminated */
        sEventMsg.Msg[PRESENCE_MAX_SIZE_EVT-1] = '\0';

        if (MSG_TYPE_PRESENCE_NOTIFICATION == sEventMsg.MsgType)
        {
            LmPresenceNotifyInfo info;
            memset(&info, 0, sizeof(LmPresenceNotifyInfo));
            CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            pthread_mutex_lock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            memcpy(&info,sEventMsg.Msg,sizeof(LmPresenceNotifyInfo));
            info.physaddress[sizeof(info.physaddress) - 1] = '\0';
            pHost = Hosts_FindHostByPhysAddress(info.physaddress);
            if (pHost)
            {
                pthread_mutex_unlock(&LmHostObjectMutex);
                CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
                Hosts_PresenceHandling(pHost,info.status);
            }
            else
            {
                pthread_mutex_unlock(&LmHostObjectMutex);
                CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            }
        }
        else if (MSG_TYPE_PRESENCE_ADD == sEventMsg.MsgType)
        {
            Hosts_CheckAndUpdatePresenceDeviceMac (sEventMsg.Msg,TRUE);
        }
        else if (MSG_TYPE_PRESENCE_REMOVE == sEventMsg.MsgType)
        {
            Hosts_CheckAndUpdatePresenceDeviceMac (sEventMsg.Msg,FALSE);
        }
        else if (MSG_TYPE_PRESENCE_STOP == sEventMsg.MsgType)
        {
            CcspTraceInfo(("%s:%d, Received stop message\n", __FUNCTION__, __LINE__));
            break;
        }
    }while(!PresenceIsStopRequested());

    if (messageQueue != (mqd_t)-1)
    {
        int ret = mq_close(messageQueue);
        if (ret == 0)
        {
            mq_unlink(PROCESS_PRESENCE_NOTIFY_QUEUE);
        }
        else
        {
            CcspTraceError(("%s:%d: Failed to close the process presence nofify queue", __FUNCTION__, __LINE__));
            perror("mq close failed");
        }
    }
    return pArgs;
}

/* Never started by PresenceDetection_Start(); kept out of the build. */
#if 0
void RecvHCPv4ClientConnects()
{
    int sd, new_socket, valread;
    struct sockaddr_in address; 
    int opt = 1; 
    int addrlen = sizeof(address); 
    char buffer[1024] = {0}; 
    PLmDevicePresenceDetectionInfo pobject = NULL;
    pobject = GetPresenceDetectionObject();
    pthread_detach(pthread_self());
    //Opening socket connection
    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0) 
    { 
        printf("Failed to open socket descriptor\n"); 
        return; 
    } 
    // set reuse address flag
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                &opt, sizeof(opt)) < 0) 
    { 
        printf("Could not set reuse address option\n"); 
	close(sd);
        return; 
    } 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( PORT ); 
    /*CID: 73139 Uninitialized scalar variable*/
    memset(&address.sin_zero, 0, sizeof(address.sin_zero));

    // bind the socket
    if (bind(sd, (struct sockaddr *)&address,  
                sizeof(address))<0) 
    { 
        printf("socket bind failed");
	close(sd);
        return; 
    } 
    if (listen(sd, 3) < 0) 
    { 
        perror("listen");
	close(sd);
        return; 
    } 

    printf("sd = %d\n",sd);
    if ((new_socket = accept(sd, (struct sockaddr *)&address,  
                    (socklen_t*)&addrlen))<0) 
    { 
        perror("accept");
	close(sd);
        return; 
    } 
    if (pobject)
	    ++pobject->task_count;

    printf ("\n %s waiting to read socket \n",__FUNCTION__);
    while(pobject && (STATE_DETECTION_TASK_STOP != pobject->taskState))
    {
	valread = read( new_socket , buffer, 1024); 
	if (valread < 0){
		printf("\n %s Can not read the socket %d\n",__FUNCTION__, new_socket); 
		close(new_socket);
		close(sd);
		return;
	}
	/* CID: 135473 String not null terminated*/ 
	/* CID: 164055 Out-of-bounds write */
	buffer[valread - 1] = '\0';
        printf("\n %s\n",buffer );
        printf("\n Hello message sent\n");
        if(strlen(buffer) != 0)
        {
            char* st = NULL;
            char* token = strtok_r(buffer, " ", &st);
            char* ip = strtok_r(NULL, " ", &st);
            if(token != NULL)
            {
                CheckandupdatePresence(token,IPV4, ip,STATE_JOIN_DETECTED_DNSMASQ);
            }
        }
    }
    close(new_socket);
    close(sd);
    if (pobject && (pobject->task_count > 0))
	    --pobject->task_count;

}

#endif

// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.

uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}
#if 0
   /*Reading of NA from netlink sockets is commented currently. In feature it may be required to enable it.*/
int open_netlink(void)
{
    int sock;
    struct sockaddr_nl addr;
    int group = MYMGRP;

    sock = socket(AF_NETLINK, SOCK_RAW, MYPROTO);
    if (sock < 0) {
        printf("sock < 0.\n");
        return sock;
    }

    memset((void *) &addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    /* This doesn't work for some reason. See the setsockopt() below. */
    /* addr.nl_groups = MYMGRP; */

    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        printf("bind < 0.\n");
        close(sock);
        return -1;
    }

    /*
     * 270 is SOL_NETLINK. See
     * http://lxr.free-electrons.com/source/include/linux/socket.h?v=4.1#L314
     * and
     * http://stackoverflow.com/questions/17732044/
     */
    if (setsockopt(sock, 270, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
        printf("setsockopt < 0\n");
        /*CID:73081 Resource leak*/
        close(sock);
        return -1;
    }

    return sock;
}


void read_event(int sock)
{
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;
    int ret;
    int size = 65536;
    char *buffer = NULL;
    char *buffer1 = NULL;

    /*CID: 135612 Large stack use*/
    buffer = (char *) malloc(sizeof(char) * size);
    if(!buffer)
        return;

    buffer1 = (char *) malloc(sizeof(char) * size);

    if(!buffer1) {
       free(buffer);
       return;
    }

    iov.iov_base = (void *) buffer;
    iov.iov_len = size;
    msg.msg_name = (void *) &(nladdr);
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    /* CID: 54845 Uninitialized scalar variable*/
    msg.msg_control         = NULL;
    msg.msg_controllen      = 0;
    msg.msg_flags           = 0;

    ret = recvmsg(sock, &msg, MSG_DONTWAIT);
    if (ret < 0)
    {
        CcspTraceDebug(("ret < 0.\n"));
    }
    else
    {
        char* st = NULL;
        char* token = NULL;
        char *ip = NULL;

        CcspTraceDebug(("Received message payload: %p\n", NLMSG_DATA((struct nlmsghdr *) buffer)));
        /* LIMITATION
         * Following strcpy() can't modified to safec strcpy_s() api
         * Because, safec has the limitation of copying only 4k ( RSIZE_MAX ) to destination pointer
         * And here, we have destination and source pointer size more than 4k, i.e 65536
         */
        /* CID 57216 Calling risky function */
        strncpy(buffer1, NLMSG_DATA((struct nlmsghdr *) buffer), size);
        buffer1[size-1] = '\0';
        CcspTraceDebug(("buffer1: %s\n", buffer1));
        token = strtok_r(buffer1, ",", &st);
        if(token != NULL)
        {
            token = strtok_r(NULL, ",", &st);  // Mac
            ip = strtok_r(NULL, ",", &st); // ipv6 address
            CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
            pthread_mutex_lock(&PresenceDetectionMutex);
            CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
            CheckandupdatePresence(token,IPV6,ip,STATE_JOIN_DETECTED_ND);
            pthread_mutex_unlock(&PresenceDetectionMutex);
            CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
        }
    }
    free(buffer);
    free(buffer1);
}

void *RecvIPv6clientNotifications(void *args)
{
    UNREFERENCED_PARAMETER(args);
    int nls;
    PLmDevicePresenceDetectionInfo pobject = NULL;
    pobject = GetPresenceDetectionObject();
    pthread_detach(pthread_self());
    nls = open_netlink();
    if (nls < 0)
        return NULL;

    if (pobject)
    ++pobject->task_count;
    while (pobject && (pobject->taskState != STATE_DETECTION_TASK_STOP))
    {
        read_event(nls);
        sleep(3);
    }
    if (pobject && (pobject->task_count > 0))
    --pobject->task_count;

    close(nls);
    return args;
}
BOOL findMacAddrByLinkLocal (char * pLinkLocal, char * pMac)
{
    if (NULL == pLinkLocal || NULL == pMac)
    {
        return FALSE;
    }
    PLmDevicePresenceDetectionInfo pobject = NULL;
    pobject = GetPresenceDetectionObject();
    if (pobject)
    {
        for (int iVar = 0; iVar < pobject->numOfDevice; iVar++)
        {
            if (pobject->ppdevlist && pobject->ppdevlist[iVar])
            {
                PLmPresenceDeviceInfo pobj = pobject->ppdevlist[iVar];
                if (0 == strcmp(pobj->ipv6, pLinkLocal))
                {
                    strncpy(pMac, pobj->mac, MAC_SIZE);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}
#endif

BOOL  isHexChar(char c)
{
    return (isdigit(c) || (tolower(c) >= 'a' && tolower(c) <= 'f'));
}
BOOL isIpv6LinkLocal (const char *pIpv6)
{
    if (NULL == pIpv6)
    {
        return FALSE;
    }

    if (strncmp(pIpv6, "fe80:", 5) != 0)
    {
        return FALSE;
    }

    const char *pChar = pIpv6 + 5;
    int iColonCount = 0;

    while (*pChar && *pChar != '\0')
    {
        if (*pChar == ':')
        {
            iColonCount++;
        }
        else if (!isHexChar(*pChar))
        {
            return FALSE;
        }
        pChar++;
    }
    if (iColonCount > 7)
    {
        return FALSE;
    }
    return TRUE;
}

void parseNeighborMessage (struct nlmsghdr *nlh, int iIfaceIndex)
{
    if (NULL == nlh)
    {
        CcspTraceError (("%s:%d, Invalid input\n",__FUNCTION__,__LINE__));
        return;
    }

    struct ndmsg *pNeighDetectionMsg = (struct ndmsg *) NLMSG_DATA(nlh);

    if (pNeighDetectionMsg->ndm_family != AF_INET6)
    {
        return;
    }

    if (0 == pNeighDetectionMsg->ndm_ifindex)
    {
        return;
    }
    else if (iIfaceIndex != pNeighDetectionMsg->ndm_ifindex)
    {
        return;
    }

    struct rtattr *pRtAttr = (struct rtattr *)((char *) pNeighDetectionMsg + NLMSG_ALIGN(sizeof(struct ndmsg)));
    int iRtAttrLen = NLMSG_PAYLOAD(nlh, sizeof(struct ndmsg));
    char cIp [INET6_ADDRSTRLEN] = {0};
    char cMac [MAC_SIZE] = {0};

    while (RTA_OK(pRtAttr, iRtAttrLen))
    {
       switch (pRtAttr->rta_type)
       {
            case NDA_DST:
            {
                inet_ntop(AF_INET6, RTA_DATA(pRtAttr), cIp, sizeof(cIp));
                break;
            }
            case NDA_LLADDR:
            {
                if (RTA_PAYLOAD(pRtAttr) == 6)
                {
                    unsigned char *pMac = RTA_DATA(pRtAttr);
                    snprintf(cMac, sizeof(cMac), "%02x:%02x:%02x:%02x:%02x:%02x", pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5]);
                }
                break;
            }
            default:
                break;
        }
        pRtAttr = RTA_NEXT(pRtAttr, iRtAttrLen);
    }

    if ( cIp[0] != '\0' && isIpv6LinkLocal(cIp))
    {
        if ((cMac[0] != '\0') && (pNeighDetectionMsg->ndm_state == NUD_REACHABLE || pNeighDetectionMsg->ndm_state == NUD_STALE || pNeighDetectionMsg->ndm_state == NUD_PERMANENT))
        {
            CcspTraceDebug(("%s:%d, ipv6 join detected for mac %s\n",__FUNCTION__,__LINE__,cMac));
            CcspTraceDebug(("%s:%d, ipv6:%s\n",__FUNCTION__,__LINE__,cIp));
            CheckandupdatePresence(cMac,IPV6,cIp,STATE_JOIN_DETECTED_ND);
        }
#if 0
        else if (pNeighDetectionMsg->ndm_state == NUD_FAILED)
        {
            if (cMac[0] == '\0' && findMacAddrByLinkLocal(cIp, cMac))
            {
                CcspTraceInfo(("%s:%d, ipv6 leave detected for mac %s\n",__FUNCTION__,__LINE__,cMac));
                CheckandupdatePresence(cMac,IPV6,cIp,STATE_LEAVE_DETECTED);
            }
        }
#endif
    }
    return;
}

void *RecvIPv6clientNotifications(void *args)
{
    UNREFERENCED_PARAMETER(args);
    PLmDevicePresenceDetectionInfo pobject = NULL;
    pobject = GetPresenceDetectionObject();
    char cIfaceName [32]  = {0};
    char cBuffer [BUFF_SIZE] = {0};
    int iIfaceIndex;

    if (!pobject)
    {
        CcspTraceError(("%s:%d, Presence Detection Object is NULL, worker exiting\n",__FUNCTION__,__LINE__));
        return NULL;
    }

    syscfg_get(NULL, "lan_ifname", cIfaceName, sizeof(cIfaceName));
    if (strlen(cIfaceName) == 0)
    {
        snprintf(cIfaceName,sizeof(cIfaceName),"brlan0");
    }

    int iSocketFd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (iSocketFd < 0)
    {
        CcspTraceError(("%s:%d, Failed to open socket descriptor\n",__FUNCTION__,__LINE__));
        return NULL;
    }

    struct sockaddr_nl netLinkSockAddr;
    memset(&netLinkSockAddr, 0, sizeof(struct sockaddr_nl));
    netLinkSockAddr.nl_family = AF_NETLINK;
    netLinkSockAddr.nl_pid = getpid();
    netLinkSockAddr.nl_groups = RTMGRP_NEIGH;

    if (bind(iSocketFd, (struct sockaddr *)&netLinkSockAddr, sizeof(struct sockaddr_nl)) < 0)
    {
        CcspTraceError(("%s:%d, Failed to bind the socket\n",__FUNCTION__,__LINE__));
        close(iSocketFd);
        return NULL;
    }

    iIfaceIndex = if_nametoindex(cIfaceName);
    if (0 == iIfaceIndex)
    {
        CcspTraceError(("%s:%d, Failed to get the interface index\n",__FUNCTION__,__LINE__));
        close(iSocketFd);
        return NULL;
    }

    /* A blocking recv() would keep this thread from ever being joined when no neighbour events arrive. */
    struct timeval sRcvTimeout;
    sRcvTimeout.tv_sec = PRESENCE_IO_TIMEOUT_SECS;
    sRcvTimeout.tv_usec = 0;
    if (setsockopt(iSocketFd, SOL_SOCKET, SO_RCVTIMEO, &sRcvTimeout, sizeof(sRcvTimeout)) < 0)
    {
        CcspTraceError(("%s:%d, Failed to set receive timeout errno:%d, errorMsg:%s\n",__FUNCTION__,__LINE__,errno,strerror(errno)));
        close(iSocketFd);
        return NULL;
    }
    while (!PresenceIsStopRequested())
    {
        int iLen = recv(iSocketFd, cBuffer, sizeof(cBuffer) - 1, 0);
        if (iLen < 0)
        {
            if ((EAGAIN == errno) || (EWOULDBLOCK == errno) || (EINTR == errno))
            {
                continue;
            }
            CcspTraceError(("%s:%d, Failed to read from socket errno:%d, errorMsg:%s\n",__FUNCTION__,__LINE__,errno,strerror(errno)));
            PresenceWaitOrStop(1);
            continue;
        }
        cBuffer[iLen] = '\0';
        struct nlmsghdr *pNlMsgHdr = (struct nlmsghdr *)cBuffer;
        while (NLMSG_OK(pNlMsgHdr, iLen))
        {
            if (pNlMsgHdr->nlmsg_type == NLMSG_DONE)
            {
                break;
            }
            else if (pNlMsgHdr->nlmsg_type == NLMSG_ERROR)
            {
                CcspTraceError(("%s:%d, Error in netlink message\n",__FUNCTION__,__LINE__));
                break;
            }
            if (pNlMsgHdr->nlmsg_type == RTM_NEWNEIGH || pNlMsgHdr->nlmsg_type == RTM_DELNEIGH)
            {
                parseNeighborMessage(pNlMsgHdr, iIfaceIndex);
            }
            pNlMsgHdr = NLMSG_NEXT(pNlMsgHdr, iLen);
        }
        memset(cBuffer, 0, sizeof(cBuffer));
    }
    close(iSocketFd);
    return NULL;
}
typedef struct PresenceProbeTarget
{
    char ipv6[IPV6_SIZE];
    BOOL bSendProbe;
} PresenceProbeTarget;

/* Runs ndisc6 without a shell so lan_ifname is never parsed by /bin/sh. */
static int runNdisc6(const char *pIpv6, const char *pIface)
{
    int iStatus = 0;
    pid_t pid = fork();

    if (pid < 0)
    {
        return -1;
    }
    if (0 == pid)
    {
        char *argv[] = { "/usr/bin/ndisc6", (char *)pIpv6, (char *)pIface, "-r", "1", "-q", NULL };
        int iNull = open("/dev/null", O_WRONLY);

        if (iNull >= 0)
        {
            dup2(iNull, STDOUT_FILENO);
            dup2(iNull, STDERR_FILENO);
            close(iNull);
        }
        execv(argv[0], argv);
        _exit(127);
    }
    while (waitpid(pid, &iStatus, 0) < 0)
    {
        if (ECHILD == errno)
        {
            /* SIGCHLD is ignored, so the child was reaped by the kernel and its status is unavailable. */
            return 0;
        }
        if (EINTR != errno)
        {
            return -1;
        }
    }
    return (WIFEXITED(iStatus) && (0 == WEXITSTATUS(iStatus))) ? 0 : -1;
}

/* Allow-list [A-Za-z0-9._-]{1,15}, not starting with '-', so the name can never be read as an option. */
static BOOL isSafeIfaceName(const char *pIface)
{
    size_t len = 0;

    if (NULL == pIface)
    {
        return FALSE;
    }
    len = strlen(pIface);
    if ((0 == len) || (len > 15) || ('-' == pIface[0]))
    {
        return FALSE;
    }
    for (size_t i = 0; i < len; i++)
    {
        if (!isalnum((unsigned char)pIface[i]) && ('.' != pIface[i]) && ('_' != pIface[i]) && ('-' != pIface[i]))
        {
            return FALSE;
        }
    }
    return TRUE;
}

/* Runs the slow ndisc6 exec without PresenceDetectionMutex so it cannot stall list users or Stop. */
static void PresenceProbeIpv6Targets(PresenceProbeTarget *pTargets, unsigned int uiCount)
{
    char buf[64] = {0};
    unsigned int uiIndex = 0;

    syscfg_get( NULL, "lan_ifname", buf, sizeof(buf));
    if ( 0 == strlen(buf))
    {
        snprintf(buf,sizeof(buf),"%s","brlan0");
    }
    if (!isSafeIfaceName(buf) || (0 == if_nametoindex(buf)))
    {
        CcspTraceError(("%s:%d, Invalid lan interface name\n",__FUNCTION__,__LINE__));
        return;
    }
    for (uiIndex = 0; uiIndex < uiCount; uiIndex++)
    {
        struct in6_addr sIpv6;

        if (PresenceIsStopRequested())
        {
            break;
        }
        if (1 != inet_pton(AF_INET6, pTargets[uiIndex].ipv6, &sIpv6))
        {
            CcspTraceError(("%s:%d, Invalid IPv6 address, skipping ndisc6\n",__FUNCTION__,__LINE__));
            continue;
        }
        CcspTraceDebug(("cmd = ndisc6 %s %s -r 1 -q", pTargets[uiIndex].ipv6,buf));
        if (0 != runNdisc6(pTargets[uiIndex].ipv6, buf))
        {
            CcspTraceError(("%s:%d, Failed to execute ndisc6\n",__FUNCTION__,__LINE__));
        }
        if (TRUE == pTargets[uiIndex].bSendProbe)
        {
            sendProbeRequest (IPV6, pTargets[uiIndex].ipv6, buf);
        }
    }
}

/* Caller holds PresenceDetectionMutex; probe targets are collected and run later by PresenceProbeIpv6Targets(). */
int Send_ipv6_neighbourdiscovery(PLmDevicePresenceDetectionInfo pobject,BOOL bactiveclient, BOOL bSendProbe, PresenceProbeTarget *pTargets, unsigned int *puiCount)
{
    int i = 0;/*H007,H005*/
    if (pobject)
    {
        for(i = 0; i<pobject->numOfDevice; i++)
        {
            if (pobject->ppdevlist && pobject->ppdevlist[i])
            {
                PLmPresenceDeviceInfo pobj = pobject->ppdevlist[i];
                if ((!pobj->ipv6Active) || (pobj->currentActive != bactiveclient))
                    continue;
                ++pobj->ipv6_retry_count;
                if (pobj->ipv6_retry_count > pobject->ipv6_num_retries)
                {
                    /* Dual mode case, To identify accurate presence leave
                     * reset IPV4 status and remove IPV4 entry from ARP.
                     * If device is in connected state for ipv4 case, ARP will updated again.
                     * otherwise considered this device is in-active.
                     */
                    if (pobj->ipv4Active && (pobj->ipv4_state != STATE_LEAVE_DETECTED && pobj->ipv4_state != STATE_PRESENCE_DETECTION_NONE))
                    {
                        pobj->ipv6_state = STATE_LEAVE_DETECTED;
                        pobj->ipv6_retry_count = 0;

#if 0
                        char buf[64];
                        pobj->ipv4_retry_count = 0;
                        syscfg_get(NULL, "lan_ifname", buf, sizeof(buf));
                        CcspTraceInfo (("%s:%d, Mac:%s, ipv6 leave detected, deleting arp entry\n",__FUNCTION__,__LINE__,pobj->mac));
                        ret = v_secure_system("ip neigh del %s dev %s",pobj->ipv4,buf);
                        if(ret !=0)
                        {
                            CcspTraceDebug(("Failed in executing the command via v_secure_system ret: %d \n",ret));
                        }
#endif
                        continue;
                    }
                    if ((TRUE == pobj->currentActive) && (STATE_LEAVE_DETECTED != pobj->ipv6_state && STATE_PRESENCE_DETECTION_NONE != pobj->ipv6_state))
                    {
                        pobj->ipv6_state = STATE_LEAVE_DETECTED;
                        pobj->ipv6_retry_count = 0;
                        pobj->currentActive = FALSE;
                        // trigger leave callback
                        CcspTraceInfo(("%s:%d, Mac:%s, ipv6 leave detected\n",__FUNCTION__,__LINE__,pobj->mac));
                        presenceDetected(pobj);
                        continue;
                    }
                }
                if (*puiCount < MAX_NUM_OF_DEVICE)
                {
                    snprintf(pTargets[*puiCount].ipv6, sizeof(pTargets[*puiCount].ipv6), "%s", pobj->ipv6);
                    pTargets[*puiCount].bSendProbe = bSendProbe;
                    ++(*puiCount);
                }
                else
                {
                    CcspTraceError(("%s:%d, probe list full, skipping Mac:%s\n",__FUNCTION__,__LINE__,pobj->mac));
                }
            }
        }
    }
    return 0;

}
void *SendNS_Thread(void *args)
{
    UNREFERENCED_PARAMETER(args);
    PLmDevicePresenceDetectionInfo pobject = NULL;
    unsigned int ActiveClientsecs = 0;
    unsigned int InActiveClientsecs = 0;
    unsigned int uiNumberOfSecs = 0;
    pobject = GetPresenceDetectionObject();
    /*CID: 71755 Dereference after null check*/
    /*CID: 57809 Dereference before null check*/
    if (!pobject)
    {
        CcspTraceError(("%s:%d, Presence Detection Object is NULL, worker exiting\n",__FUNCTION__,__LINE__));
        return NULL;
    }
    BOOL bSendProbe = FALSE;
    PresenceProbeTarget *pTargets = malloc(MAX_NUM_OF_DEVICE * sizeof(*pTargets));
    if (!pTargets)
    {
        CcspTraceError(("%s:%d, failed to allocate probe list, worker exiting\n",__FUNCTION__,__LINE__));
        return NULL;
    }
    while(!PresenceIsStopRequested())
    {
        unsigned int uiProbeCount = 0;
        if (pobject)
        {
            CcspTraceDebug(("%s:%d, Acquiring PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
            pthread_mutex_lock(&PresenceDetectionMutex);
            CcspTraceDebug(("%s:%d, Acquired PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
            if (pobject->ipv6_leave_detection_interval == uiNumberOfSecs)
            {
                bSendProbe = TRUE;
            }
            if ((pobject->ipv6_num_retries * pobject->ipv6_leave_detection_interval) == uiNumberOfSecs)
            {
                uiNumberOfSecs = 0;
            }
            if (pobject->ipv6_leave_detection_interval)
            {
                if (ActiveClientsecs && (0 == (ActiveClientsecs % pobject->ipv6_leave_detection_interval)))
                {
                    Send_ipv6_neighbourdiscovery(pobject, TRUE, bSendProbe, pTargets, &uiProbeCount);
                    ActiveClientsecs = 0;
                    bSendProbe = FALSE;
                }
            }
            else
            {
                ActiveClientsecs = 0;
            }
            if (pobject->bkgnd_join_detection_interval)
            {
                if (InActiveClientsecs && (0 == (InActiveClientsecs % pobject->bkgnd_join_detection_interval)))
                {
                    Send_ipv6_neighbourdiscovery(pobject, FALSE, FALSE, pTargets, &uiProbeCount);
                    InActiveClientsecs = 0;
                }
            }
            else
            {
                InActiveClientsecs = 0;
            }
            pthread_mutex_unlock(&PresenceDetectionMutex);
            CcspTraceDebug(("%s:%d, unlocked PresenceDetectionMutex\n",__FUNCTION__,__LINE__));
            PresenceProbeIpv6Targets(pTargets, uiProbeCount);
        }

        PresenceWaitOrStop(1);
        ++ActiveClientsecs;
        ++InActiveClientsecs;
        ++uiNumberOfSecs;
    }
    free(pTargets);
    return args;
}

void PresenceDetection_Stop()
{
    pthread_mutex_lock(&PresenceDetectionLifecycleMutex);
    CcspTraceError(("\n %s enter \n",__FUNCTION__));
    if (PresenceDetection_StopWorkersLocked() != 0)
    {
        CcspTraceError(("%s:%d, Presence detection workers were not all joined\n",__FUNCTION__,__LINE__));
    }
    CcspTraceError(("\n %s exit \n",__FUNCTION__));
    pthread_mutex_unlock(&PresenceDetectionLifecycleMutex);
}

void PresenceDetection_Start()
{
    int res = 0;
    PLmDevicePresenceDetectionInfo pobject = NULL;

    pthread_mutex_lock(&PresenceDetectionLifecycleMutex);
    pobject = GetPresenceDetectionObject();
    if (!pobject || presenceDetectionRunning || presenceDetectionThreadCount != 0)
    {
        CcspTraceError(("%s:%d, not starting: object:%p running:%d workers:%u\n",__FUNCTION__,__LINE__,(void *)pobject,presenceDetectionRunning,presenceDetectionThreadCount));
        pthread_mutex_unlock(&PresenceDetectionLifecycleMutex);
        return;
    }
    pthread_mutex_lock(&PresenceDetectionMutex);
    gStopRequested = FALSE;
    pthread_mutex_unlock(&PresenceDetectionMutex);

    printf("\n %s enter \n",__FUNCTION__);
    res = PresenceDetection_CreateThread(processPresenceNotification);
    if(res != 0)
    {
        CcspTraceError(("Create processPresenceNotification error %d\n", res));
    }
    // Add sleep of 0.5 seconds
    usleep(500000);
    res = PresenceDetection_CreateThread(ReceiveIpv4ClientStatus);
    if(res != 0) {
        CcspTraceError(("Create ReceiveIpv4ClientStatus error %d\n", res));
    }

    res = PresenceDetection_CreateThread(Send_arp_ipv4_thread);
    if(res != 0) {
        CcspTraceError(("Create SendArp_Thread error %d\n", res));
    }

    res = PresenceDetection_CreateThread(ReceiveArp_Thread);
    if(res != 0) {
        CcspTraceError(("Create ReceiveArp_Thread error %d\n", res));
    }
    res = PresenceDetection_CreateThread(RecvIPv6clientNotifications);
    if(res != 0) {
        CcspTraceError(("Create RecvIPv6clientNotifications error %d\n", res));
    }

    res = PresenceDetection_CreateThread(SendNS_Thread);
    if(res != 0) {
        CcspTraceError(("Create SendNS_Thread error %d\n", res));
    }
    printf("\n %s exit \n",__FUNCTION__);
    pthread_mutex_unlock(&PresenceDetectionLifecycleMutex);
}

BOOL Presencedetection_DmlNotifyMac(char *mac,BOOL isNeedToAdd)
{
    PresenceQData EventMsg;
    mqd_t mq;
    struct mq_attr attr;
    char buffer[PRESENCE_MAX_SIZE];
    errno_t rc = -1;

    memset(buffer, 0, PRESENCE_MAX_SIZE);

    if (isNeedToAdd)
    {
        EventMsg.MsgType = MSG_TYPE_PRESENCE_ADD;
    }
    else
    {
        EventMsg.MsgType = MSG_TYPE_PRESENCE_REMOVE;
    }
    if (mac)
    {
        PLmObjectHost pHost = NULL;
        CcspTraceDebug(("%s:%d, Acquiring LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        pthread_mutex_lock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, Acquired LmHostObjectMutex\n",__FUNCTION__,__LINE__));
        if(!lmHosts.enablePresence)
        {
            pthread_mutex_unlock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            return FALSE;
        }
        pHost = Hosts_FindHostByPhysAddress(mac);
        if (!pHost)
        {
            pthread_mutex_unlock(&LmHostObjectMutex);
            CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));
            return FALSE;
        }
        pthread_mutex_unlock(&LmHostObjectMutex);
        CcspTraceDebug(("%s:%d, unlocked LmHostObjectMutex\n",__FUNCTION__,__LINE__));

        rc = strcpy_s(EventMsg.Msg, sizeof(EventMsg.Msg),mac);
        ERR_CHK(rc);
    }
    else
    {
        return FALSE;
    }

    mq = mq_open(PROCESS_PRESENCE_NOTIFY_QUEUE, O_WRONLY | O_NONBLOCK);
    if ((mqd_t)-1 == mq) {
        CcspTraceError(("%s:%d: ", __FUNCTION__, __LINE__));
        perror("mq_open");
        return FALSE;
    }

    // Get the attributes of the message queue
    if (mq_getattr(mq, &attr) == -1)
    {
        CcspTraceError(("%s:%d: ", __FUNCTION__, __LINE__));
        perror("mq_getattr");
        if (-1 == mq_close(mq))
        {
            CcspTraceError(("%s:%d: ", __FUNCTION__, __LINE__));
            perror("mq_close");
        }
        return FALSE;
    }

        // Ensure the message size does not exceed the maximum allowed size
    if (sizeof(EventMsg) >(unsigned long) attr.mq_msgsize)
    {
        CcspTraceError(("%s:%d: Message size exceeds the maximum allowed size\n", __FUNCTION__, __LINE__));
    }

    memcpy(buffer,&EventMsg,sizeof(EventMsg));

    int iRet = mq_send(mq, buffer, PRESENCE_MAX_SIZE, 0);

    if (-1 == iRet)
    {
        CcspTraceError(("%s: mq_send failed\n", __FUNCTION__));
        CcspTraceError(("%s:%d: errorno:%d, errorMsg:%s\n",__FUNCTION__,__LINE__,errno, strerror(errno)));
        perror("mq_send");
    }

    int iCloseRet = mq_close(mq);
    if (-1 == iCloseRet)
    {
        CcspTraceError(("%s:%d: ", __FUNCTION__, __LINE__));
        perror("mq_close");
    }

    return (-1 != iRet && -1 != iCloseRet) ? TRUE : FALSE;
}

void Hosts_PresenceNotify(PLmPresenceNotifyInfo pinfo)
{
    PresenceQData EventMsg;
    mqd_t mq;
    char cBuffer[PRESENCE_MAX_SIZE];
    if (!pinfo)
        return;
    mq = mq_open(PROCESS_PRESENCE_NOTIFY_QUEUE, O_WRONLY | O_NONBLOCK);
    CHECK((mqd_t)-1 != mq);

    memset(cBuffer, 0, PRESENCE_MAX_SIZE);
    EventMsg.MsgType = MSG_TYPE_PRESENCE_NOTIFICATION;

    memcpy(EventMsg.Msg,pinfo,sizeof(LmPresenceNotifyInfo));
    memcpy(cBuffer,&EventMsg,sizeof(EventMsg));
    int iRet = mq_send(mq, cBuffer, PRESENCE_MAX_SIZE, 0);
    if (-1 == iRet)
    {
        CcspTraceError(("%s: mq_send failed\n", __FUNCTION__));
        CcspTraceError(("%s:%d: errorno:%d, errorMsg:%s\n",__FUNCTION__,__LINE__,errno, strerror(errno)));
        perror("mq_send");
    }
    mq_close(mq);
}

static void presenceDetected(void *arg)
{
    if (arg)
    {
        LmPresenceNotifyInfo info;
        memset(&info, 0, sizeof(LmPresenceNotifyInfo));
        PLmPresenceDeviceInfo pobj = arg;
        BOOL bNotify = FALSE;
        strncpy (info.physaddress, pobj->mac,MAC_SIZE-1);
        info.physaddress[MAC_SIZE-1] = '\0';
        if (pobj->currentActive)
        {
            info.status = HOST_PRESENCE_JOIN;
            bNotify = TRUE;
        }
        else
        {
            if (pobj->ipv4Active && (STATE_LEAVE_DETECTED == pobj->ipv4_state))
            {
                info.status = HOST_PRESENCE_LEAVE;
                bNotify = TRUE;
            }
            if (pobj->ipv6Active && (STATE_LEAVE_DETECTED == pobj->ipv6_state))
            {
                info.status = HOST_PRESENCE_LEAVE;
                bNotify = TRUE;
            }

        }
        if (bNotify)
        {
            Hosts_PresenceNotify(&info);
        }
    }
}
