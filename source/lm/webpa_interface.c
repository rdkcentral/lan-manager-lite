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
#define _GNU_SOURCE
#include "ssp_global.h"
#include "stdlib.h"
#include "ccsp_dm_api.h"
#include "webpa_interface.h"
#include "ccsp_lmliteLog_wrapper.h"
#include "lm_util.h"
#include <sysevent/sysevent.h>
#include <libparodus/libparodus.h>
#include "webpa_pd.h"
#include <math.h>
#include "syscfg/syscfg.h"
#include "ccsp_memory.h"
#include "platform_hal.h"
#ifdef WAN_FAILOVER_SUPPORTED
#include "network_devices_traffic_avropack.h"
#endif

#ifdef MLT_ENABLED
#include "rpl_malloc.h"
#include "mlt_malloc.h"
#endif
#include "safec_lib_common.h"

#define MAX_PARAMETERNAME_LEN   512

#if defined(_SKY_HUB_COMMON_PRODUCT_REQ_) && !defined(_SCER11BEL_PRODUCT_REQ_)
#include <utctx/utctx.h>
#include <utctx/utctx_api.h>
#include <utapi/utapi.h>
#include <utapi/utapi_util.h>
#endif

#if defined(_SR300_PRODUCT_REQ_) || defined(_RDKB_GLOBAL_PRODUCT_REQ_)
#include <cosa_wantraffic_api.h>
extern pstWTCInfo_t WTCinfo;
#endif

extern ANSC_HANDLE bus_handle;
static pthread_mutex_t webpa_mutex = PTHREAD_MUTEX_INITIALIZER;
#if 0
static pthread_mutex_t device_mac_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static char deviceMAC[32]={'\0'}; 
static char fullDeviceMAC[32]={'\0'};
#define ETH_WAN_STATUS_PARAM "Device.Ethernet.X_RDKCENTRAL-COM_WAN.Enabled"
#define RDKB_ETHAGENT_COMPONENT_NAME                  "com.cisco.spvtg.ccsp.ethagent"
#define RDKB_ETHAGENT_DBUS_PATH                       "/com/cisco/spvtg/ccsp/ethagent"

static libpd_instance_t client_instance;

static void *handle_parodus();

#if 0
static void waitForEthAgentComponentReady();
static void checkComponentHealthStatus(char * compName, char * dbusPath, char *status, int *retStatus);
static int check_ethernet_wan_status();
#endif

#ifdef WAN_FAILOVER_SUPPORTED
#if defined(_SR300_PRODUCT_REQ_) || defined(_RDKB_GLOBAL_PRODUCT_REQ_)
rbusHandle_t rbus_handle;
#else
static rbusHandle_t rbus_handle;
#endif

static void eventReceiveHandler(
    rbusHandle_t rbus_handle,
    rbusEvent_t const* event,
    rbusEventSubscription_t* subscription);

static void subscribeAsyncHandler(
    rbusHandle_t rbus_handle,
    rbusEventSubscription_t* subscription,
    rbusError_t error);
#endif

int s_sysevent_connect(token_t *out_se_token);

#if 0
static int WebpaInterface_DiscoverComponent(char** pcomponentName, char** pcomponentPath )
{
    char CrName[256] = {0};
    int ret = 0;
    errno_t rc = -1;
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));

    rc = sprintf_s(CrName, sizeof(CrName), "eRT.%s", CCSP_DBUS_INTERFACE_CR);
    if(rc < EOK)
    {
        ERR_CHK(rc);
    }
    componentStruct_t **components = NULL;
    int compNum = 0;
    int res = CcspBaseIf_discComponentSupportingNamespace (
            bus_handle,
            CrName,
#ifndef _XF3_PRODUCT_REQ_
#ifdef _SKY_HUB_COMMON_PRODUCT_REQ_
            "Device.DeviceInfo.X_COMCAST-COM_WAN_MAC",
#else
            "Device.X_CISCO_COM_CableModem.MACAddress",
#endif // _SKY_HUB_COMMON_PRODUCT_REQ_
#else
            "Device.DPoE.Mac_address",
#endif      
            "",
            &components,
            &compNum);
    if(res != CCSP_SUCCESS || compNum < 1){
        CcspTraceError(("WebpaInterface_DiscoverComponent find eRT PAM component error %d\n", res));
        ret = -1;
    }
    else{
        *pcomponentName = AnscCloneString(components[0]->componentName);
        *pcomponentPath = AnscCloneString(components[0]->dbusPath);
        CcspTraceInfo(("WebpaInterface_DiscoverComponent find eRT PAM component %s--%s\n", *pcomponentName, *pcomponentPath));
    }
    free_componentStruct_t(bus_handle, compNum, components);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT\n", __FUNCTION__ ));

    return ret;
}
#endif

void sendWebpaMsg(char *serviceName, char *dest, char *trans_id, char *contentType, char *payload, unsigned int payload_len)
{
    pthread_mutex_lock(&webpa_mutex);
    wrp_msg_t *wrp_msg ;
    int retry_count = 0, backoffRetryTime = 0, c = 2;
    int sendStatus = -1;
    char source[MAX_PARAMETERNAME_LEN/2] = {'\0'};

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, <======== Start of sendWebpaMsg =======>\n"));
	CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, deviceMAC *********:%s\n",deviceMAC));
    if(serviceName!= NULL){
    	CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, serviceName :%s\n",serviceName));
		snprintf(source, sizeof(source), "mac:%s/%s", deviceMAC, serviceName);
	}
	if(dest!= NULL){
    	CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, dest :%s\n",dest));
	}
	if(trans_id!= NULL){
	    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, transaction_id :%s\n",trans_id));
	}
	if(contentType!= NULL){
	    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, contentType :%s\n",contentType));
    }
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, payload_len :%d\n",payload_len));

    

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Received DeviceMac from Atom side: %s\n",deviceMAC));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Source derived is %s\n", source));
    
    wrp_msg = (wrp_msg_t *)malloc(sizeof(wrp_msg_t));
    

    if(wrp_msg != NULL)
    {	
		memset(wrp_msg, 0, sizeof(wrp_msg_t));
        wrp_msg->msg_type = WRP_MSG_TYPE__EVENT;
        wrp_msg->u.event.payload = (void *)payload;
        wrp_msg->u.event.payload_size = payload_len;
        wrp_msg->u.event.source = source;
        wrp_msg->u.event.dest = dest;
        wrp_msg->u.event.content_type = contentType;

        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, wrp_msg->msg_type :%d\n",wrp_msg->msg_type));
        if(wrp_msg->u.event.payload!=NULL) 
        	CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, wrp_msg->u.event.payload :%s\n",(char *)(wrp_msg->u.event.payload)));
        	CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, wrp_msg->u.event.payload_size :%zu\n",(wrp_msg->u.event.payload_size)));
		if(wrp_msg->u.event.source != NULL)
	        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, wrp_msg->u.event.source :%s\n",wrp_msg->u.event.source));
		if(wrp_msg->u.event.dest!=NULL)
        	CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, wrp_msg->u.event.dest :%s\n",wrp_msg->u.event.dest));
		if(wrp_msg->u.event.content_type!=NULL)
	        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, wrp_msg->u.event.content_type :%s\n",wrp_msg->u.event.content_type));

        while(retry_count<=5)
        {
            backoffRetryTime = (int) pow(2, c) -1;

            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, retry_count : %d\n",retry_count));
            sendStatus = libparodus_send(client_instance, wrp_msg);
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, sendStatus is %d\n",sendStatus));
            if(sendStatus == 0)
            {
                retry_count = 0;
                CcspTraceInfo(("Sent message successfully to parodus\n"));
                break;
            }
            else
            {
                CcspTraceError(("Failed to send message: '%s', retrying ....\n",libparodus_strerror(sendStatus)));
                CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, backoffRetryTime %d seconds\n", backoffRetryTime));
                sleep(backoffRetryTime);
                c++;
                retry_count++;
            }
        }

        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Before freeing wrp_msg\n"));
        free(wrp_msg);
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, After freeing wrp_msg\n"));
    }

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG,  <======== End of sendWebpaMsg =======>\n"));

    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT\n", __FUNCTION__ ));

    pthread_mutex_unlock(&webpa_mutex);
}

void initparodusTask()
{
	int err = 0;
	pthread_t parodusThreadId;
	
	err = pthread_create(&parodusThreadId, NULL, handle_parodus, NULL);
	if (err != 0) 
	{
		CcspLMLiteConsoleTrace(("RDK_LOG_ERROR, Error creating messages thread :[%s]\n", strerror(err)));
	}
	else
	{
		CcspLMLiteConsoleTrace(("RDK_LOG_INFO, handle_parodus thread created Successfully\n"));
	}
}

static void *handle_parodus()
{
    int backoffRetryTime = 0;
    int backoff_max_time = 9;
    int max_retry_sleep;
    //Retry Backoff count shall start at c=2 & calculate 2^c - 1.
    int c =2;
    char *parodus_url = NULL;

    CcspLMLiteConsoleTrace(("RDK_LOG_INFO, ******** Start of handle_parodus ********\n"));

    pthread_detach(pthread_self());

    max_retry_sleep = (int) pow(2, backoff_max_time) -1;
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, max_retry_sleep is %d\n", max_retry_sleep ));

        get_parodus_url(&parodus_url);
	if(parodus_url != NULL)
	{
	
		libpd_cfg_t cfg1 = {.service_name = "lmlite",
						.receive = false, .keepalive_timeout_secs = 0,
						.parodus_url = parodus_url,
						.client_url = NULL
					   };
		            
		CcspLMLiteConsoleTrace(("RDK_LOG_INFO, Configurations => service_name : %s parodus_url : %s client_url : %s\n", cfg1.service_name, cfg1.parodus_url, (cfg1.client_url) ? cfg1.client_url : "" ));

		CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Call parodus library init api \n"));

		while(1)
		{
		    if(backoffRetryTime < max_retry_sleep)
		    {
		        backoffRetryTime = (int) pow(2, c) -1;
		    }

		    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, New backoffRetryTime value calculated as %d seconds\n", backoffRetryTime));
		    int ret =libparodus_init (&client_instance, &cfg1);
		    CcspLMLiteConsoleTrace(("RDK_LOG_INFO, ret is %d\n",ret));
		    if(ret ==0)
		    {
		        CcspTraceWarning(("LMLite: Init for parodus Success..!!\n"));
		        break;
		    }
		    else
		    {
		        CcspTraceError(("LMLite: Init for parodus (url %s) failed: '%s'\n", parodus_url, libparodus_strerror(ret)));
                        /*REVIST CID:67436 Logically dead code- parodus_url cant be NULL*/
			get_parodus_url(&parodus_url);
			cfg1.parodus_url = parodus_url;
			sleep(backoffRetryTime);
		        c++;
		    }
		libparodus_shutdown(client_instance);
		   
		}
	}
    return 0;
}

const char *rdk_logger_module_fetch(void)
{
    return "LOG.RDK.LM";
}

char * getFullDeviceMac()
{
    if(strlen(fullDeviceMAC) == 0)
    {
        getDeviceMac();
    }

    return fullDeviceMAC;
}

#if 0
static int check_ethernet_wan_status()
{
    int ret = -1;
    char isEthEnabled[8];

    if ((syscfg_get(NULL, "eth_wan_enabled", isEthEnabled, sizeof(isEthEnabled)) == 0) &&
        (strcmp(isEthEnabled, "true") == 0))
    {
        CcspTraceInfo(("Ethernet WAN is enabled\n"));
        ret = CCSP_SUCCESS;
    }

    return ret;
}
#endif

char * getDeviceMac()
{
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s ENTER\n", __FUNCTION__ ));

#if defined(_SKY_HUB_COMMON_PRODUCT_REQ_) && !defined(_SCER11BEL_PRODUCT_REQ_)
    char wanPhyName[32] = {0};
    char out_value[32] = {0};
    char deviceMACVal[32] = {0};
    errno_t ret_code = -1;

    if (syscfg_get(NULL, "wan_physical_ifname", out_value, sizeof(out_value)) == 0)
    {
        strncpy(wanPhyName, out_value, sizeof(wanPhyName));
        CcspTraceInfo(("%s %d - WanPhyName=%s \n", __FUNCTION__,__LINE__, wanPhyName));
    }
    else
    {
        strncpy(wanPhyName, "erouter0", sizeof(wanPhyName));
        CcspTraceInfo(("%s %d - WanPhyName=%s \n", __FUNCTION__,__LINE__, wanPhyName));
    }
    s_get_interface_mac(wanPhyName, deviceMACVal, sizeof(deviceMACVal));
    ret_code = STRCPY_S_NOCLOBBER(fullDeviceMAC, sizeof(fullDeviceMAC),deviceMACVal);
    ERR_CHK(ret_code);
    AnscMacToLower(deviceMAC, deviceMACVal, sizeof(deviceMAC));
#if defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
    if(strlen(deviceMAC) <=0)
    {
        CcspTraceInfo(("%s %d - deviceMAC is empty try with default wanInterface name \n", __FUNCTION__,__LINE__));
        strncpy(wanPhyName, "erouter0", sizeof(wanPhyName));
        s_get_interface_mac(wanPhyName, deviceMACVal, sizeof(deviceMACVal));
        ret_code = STRCPY_S_NOCLOBBER(fullDeviceMAC, sizeof(fullDeviceMAC),deviceMACVal);
        ERR_CHK(ret_code);
        AnscMacToLower(deviceMAC, deviceMACVal, sizeof(deviceMAC));
        CcspTraceInfo(("%s %d - WanPhyName=%s \n", __FUNCTION__,__LINE__, wanPhyName));
    }
#endif
    // Removing the \n at the end of mac
    if((strlen(deviceMAC) == 13) && (deviceMAC[12] == '\n'))
    {
        deviceMAC[12] = '\0';
        CcspTraceInfo(("%s %d - removed new line at the end of deviceMAC %s \n", __FUNCTION__,__LINE__, deviceMAC));
    }
    CcspTraceInfo(("%s %d -  deviceMAC is - %s \n", __FUNCTION__,__LINE__, deviceMAC));
    return deviceMAC;
#endif //_SKY_HUB_COMMON_PRODUCT_REQ_

    char deviceMACStr[32] = {0};
    if(!strlen(deviceMAC))
    {
        if(platform_hal_GetBaseMacAddress(deviceMACStr) != 0)
        {
            CcspTraceError(("%s Failed to get BaseMacAddress from HAL API\n",__FUNCTION__));
            return NULL;
        }
        strncpy(fullDeviceMAC, deviceMACStr, sizeof(fullDeviceMAC));
        AnscMacToLower(deviceMAC, deviceMACStr, sizeof(deviceMAC));
        CcspTraceInfo(("%s %d -  deviceMAC is - %s fullDeviceMAC %s\n", __FUNCTION__,__LINE__, deviceMAC, fullDeviceMAC));
    }
    return deviceMAC;
#if 0
    while(!strlen(deviceMAC))
    {
        pthread_mutex_lock(&device_mac_mutex);
        int ret = -1, val_size =0,cnt =0, fd = 0;
        char *pcomponentName = NULL, *pcomponentPath = NULL;
        parameterValStruct_t **parameterval = NULL;
        token_t  token;
        char deviceMACValue[32] = { '\0' };
        errno_t rc = -1;
#ifndef _XF3_PRODUCT_REQ_
        char *getList[] = {"Device.X_CISCO_COM_CableModem.MACAddress"};
#else
        char *getList[] = {"Device.DPoE.Mac_address"};
#endif

        if (strlen(deviceMAC))
        {
            pthread_mutex_unlock(&device_mac_mutex);
            break;
        }

        fd = s_sysevent_connect(&token);
        if(CCSP_SUCCESS == check_ethernet_wan_status() && sysevent_get(fd, token, "eth_wan_mac", deviceMACValue, sizeof(deviceMACValue)) == 0 && deviceMACValue[0] != '\0')
        {
            rc = STRCPY_S_NOCLOBBER(fullDeviceMAC, sizeof(fullDeviceMAC),deviceMACValue);
            ERR_CHK(rc);
            AnscMacToLower(deviceMAC, deviceMACValue, sizeof(deviceMAC));
            CcspTraceInfo(("deviceMAC is %s\n", deviceMAC));
        }
        else
        {
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Before WebpaInterface_DiscoverComponent ret: %d\n",ret));

            if(pcomponentPath == NULL || pcomponentName == NULL)
            {
                if(-1 == WebpaInterface_DiscoverComponent(&pcomponentName, &pcomponentPath)){
                    CcspTraceError(("%s ComponentPath or pcomponentName is NULL\n", __FUNCTION__));
            		pthread_mutex_unlock(&device_mac_mutex);
                    return NULL;
                }
                CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, WebpaInterface_DiscoverComponent ret: %d  ComponentPath %s ComponentName %s \n",ret, pcomponentPath, pcomponentName));
            }

            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Before GPV ret: %d\n",ret));
            ret = CcspBaseIf_getParameterValues(bus_handle,
                        pcomponentName, pcomponentPath,
                        getList,
                        1, &val_size, &parameterval);
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, After GPV ret: %d\n",ret));
            if(ret == CCSP_SUCCESS)
            {
                CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, val_size : %d\n",val_size));
                for (cnt = 0; cnt < val_size; cnt++)
                {
                    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, parameterval[%d]->parameterName : %s\n",cnt,parameterval[cnt]->parameterName));
                    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, parameterval[%d]->parameterValue : %s\n",cnt,parameterval[cnt]->parameterValue));
                    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, parameterval[%d]->type :%d\n",cnt,parameterval[cnt]->type));
                
                }
                CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Calling macToLower to get deviceMacId\n"));
                rc = STRCPY_S_NOCLOBBER(fullDeviceMAC, sizeof(fullDeviceMAC),parameterval[0]->parameterValue);
                ERR_CHK(rc);
                AnscMacToLower(deviceMAC, parameterval[0]->parameterValue, sizeof(deviceMAC));
                if(pcomponentName)
                {
                    AnscFreeMemory(pcomponentName);
                }
                if(pcomponentPath)
                {
                    AnscFreeMemory(pcomponentPath);
                }

            }
            else
            {
                CcspLMLiteTrace(("RDK_LOG_ERROR, Failed to get values for %s ret: %d\n",getList[0],ret));
                CcspTraceError(("RDK_LOG_ERROR, Failed to get values for %s ret: %d\n",getList[0],ret));
                sleep(10);
            }
         
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Before free_parameterValStruct_t...\n"));
            free_parameterValStruct_t(bus_handle, val_size, parameterval);
            CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, After free_parameterValStruct_t...\n"));
        }   
        pthread_mutex_unlock(&device_mac_mutex);
    
    }
        
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s EXIT\n", __FUNCTION__ ));

    return deviceMAC;
#endif
}

#ifdef WAN_FAILOVER_SUPPORTED
static bool isRbus = false ;
char newSource[512] = { '\0' };

//Checking the Rbus active status
bool checkRbusEnabled()
{
        if(RBUS_ENABLED == rbus_checkStatus())
	{
		isRbus = true;
	}
	else
	{
		isRbus = false;
	}
	CcspTraceInfo(("LMLite RBUS mode active status = %s\n", isRbus ? "true":"false"));
	return isRbus;
}

//Initiate Rbus
LMLITE_STATUS lmliteRbusInit(const char *pComponentName)
{
	int ret = RBUS_ERROR_SUCCESS;
        CcspTraceDebug(("rbus_open for component %s\n", pComponentName));
	ret = rbus_open(&rbus_handle, pComponentName);
	if(ret != RBUS_ERROR_SUCCESS)
	{
		CcspTraceError(("LMLiteRbusInit failed with error code %d\n", ret));
		return LMLITE_FAILURE;
	}
	CcspTraceInfo(("LMLiteRbusInit is success. ret is %d\n", ret));
	return LMLITE_SUCCESS;
}

//Filter the active Interfaces
char* get_ActiveInterface(char *interface) {
    char* token;
    int n = -1;
    char activeInterface[256] = { '\0' };
    char interfaceUp[10][16] = { '\0' };
    char c;
    char buffer[256] = { '\0' };
    int i;
    int len = 0;

    token = strtok(interface, "|"); // spliting with delimiter "|"
    while (token != NULL) {
	    CcspTraceDebug(("token : %s\n", token));
	    c = token[strlen(token)-1]; // last char in token
	    if(c == '1') { // checking last char in token is '1', means it is active interface
		    n++;
		    strncpy(interfaceUp[n], token, strlen(token)-2); // adding the active interfaces in InterfaceUp
		    CcspTraceDebug(("InterfaceUp : %s\n", interfaceUp[n]));
            }
	    token = strtok(NULL, "|");
    } 	    
    
    for(i=0; i<=n; i++)
    {
        snprintf(buffer, sizeof(buffer), "%s,", interfaceUp[i]); // appending all active interface with comma
        /* CID 281056 Calling risky function */
        if((strlen(buffer)+strlen(activeInterface)) < sizeof(activeInterface))
        {
            strncat(activeInterface, buffer,sizeof(activeInterface) - strlen(activeInterface));
        }
        else
        {
            CcspTraceInfo((" LMLite <%s> <%d > Error in coping %s\n",__FUNCTION__,__LINE__, buffer));
        }
    } 
    if(strlen(activeInterface) > 0) {
            len = strlen(activeInterface);
	    activeInterface[len-1] = '\0';  // Removing the last comma
            CcspTraceDebug(("Active Interfaces: %s\n", activeInterface));
            snprintf(newSource, sizeof(newSource), "LMLite/%s", activeInterface); // Adding all active interfaces in newSource
            CcspTraceInfo(("Source with Active Interfaces : %s\n", newSource)); // For ex: Source with Active Interfaces : LMLite/DOCSIS1,ETH3,REMOTE_LTE1
    }
    else {
	    CcspTraceDebug(("activeInterface is null\n"));
	    snprintf(newSource, sizeof(newSource), "LMLite"); // If all interface status are '0', add "LMLite" to newSurce
            CcspTraceInfo(("Source with Active Interfaces : %s\n", newSource));
    }
    return newSource;
}


static void eventReceiveHandler(
    rbusHandle_t rbus_handle,
    rbusEvent_t const* event,
    rbusEventSubscription_t* subscription)
{
    (void)rbus_handle;
    rbusValue_t newValue = rbusObject_GetValue(event->data, "value");
    rbusValue_t oldValue = rbusObject_GetValue(event->data, "oldValue");
    CcspTraceInfo(("Consumer received ValueChange event for param %s\n", event->name));

    if(newValue!=NULL && oldValue!=NULL) {
            CcspTraceInfo(("New Value: %s Old Value: %s\n", rbusValue_GetString(newValue, NULL), rbusValue_GetString(oldValue, NULL)));
    }
    else {
	    if(newValue == NULL) {
		    CcspTraceError(("NewValue is NULL\n"));
	    }
	    if(oldValue == NULL) {
		    CcspTraceError(("oldValue is NULL\n"));
	    }
     }    
     if(newValue) {
 	 char *newActiveInterface = NULL;
	 char * val = NULL;
	 val = (char *) rbusValue_GetString(newValue, NULL);
	 if(val != NULL) {  
		CcspTraceDebug(("%s value is : %s\n", subscription->eventName, val));
		newActiveInterface = get_ActiveInterface(val);
		if(newActiveInterface!=NULL) { 
        		set_ReportSourceNDT(newActiveInterface); // setting the new source with active interfaces
				if(get_ReportSourceNDT() != NULL) {
        	       			CcspTraceInfo(("ReportSourceNDT value is : %s\n", get_ReportSourceNDT()));
	 			}			
				else {	
		       			CcspTraceError(("ReportSourceNDT value is NULL\n"));
				}

                    #ifdef _SR300_PRODUCT_REQ_
                    if((strstr(newActiveInterface, "WANOE") != NULL) || 
                        (strstr(newActiveInterface, "DSL") != NULL ) ||
                         (strstr(newActiveInterface, "ADSL") != NULL )) 
                    {
                        CcspTraceInfo(("newActiveInterface is : %s\n", newActiveInterface));
                        if(WTCinfo)
                        {
                            pthread_mutex_lock(&WTCinfo->WanTrafficMutexVar);    
                            if((strstr(newActiveInterface, "WANOE")))
#if  defined (_SCER11BEL_PRODUCT_REQ_) || defined (_SCXF11BFL_PRODUCT_REQ_)
                                WTCinfo->WanMode = EWAN - 1;
#else
                                WTCinfo->WanMode = EWAN;
#endif
                            else
                                WTCinfo->WanMode = DSL;
                            WTCinfo->WTCConfigFlag[WTCinfo->WanMode-1] |= WTC_WANMODE_CHANGE;
                            pthread_mutex_unlock(&WTCinfo->WanTrafficMutexVar);
                            WTC_ApplyStateChange();
                            CcspTraceInfo(("Setting WAN mode change!!!\n"));
                        }
                        else
                        {
                            CcspTraceInfo(("WTCinfo is NULL!!!\n"));
                        }
                    }
                    #endif
		}
		else {
			CcspTraceError(("newActiveInterface is NULL\n"));
		}
         }      
         else {
		CcspTraceError(("val is NULL\n"));  	
         }
     }	 
}

static void subscribeAsyncHandler(
    rbusHandle_t rbus_handle,
    rbusEventSubscription_t* subscription,
    rbusError_t error)
{
  (void)rbus_handle;

  CcspTraceWarning(("subscribeAsyncHandler event %s, error %d - %s\n", subscription->eventName, error, rbusError_ToString(error)));
}

//To get the current value of Device.X_RDK_WanManager.InterfaceActiveStatus
void get_WanManager_ActiveInterface()
{
  rbusValue_t value;
  int rc = RBUS_ERROR_SUCCESS;
  char* val = NULL;
  char *newActiveInterface = NULL;
  rc = rbus_get(rbus_handle, LMLITE_INTERFACE_ACTIVESTATUS_PARAM, &value);
  if(rc == RBUS_ERROR_SUCCESS) 
  { 
	  val = rbusValue_ToString(value,0,0);
	  if(val != NULL) {
	  	CcspTraceDebug(("%s value is : %s\n", LMLITE_INTERFACE_ACTIVESTATUS_PARAM, val));  // For ex: LMLITE_INTERFACE_ACTIVESTATUS_PARAM value is : DOCSIS1,1|DSL1,0|ETH3,1|GPON1,0|REMOTE_LTE1,1
		newActiveInterface = get_ActiveInterface(val);
		if(newActiveInterface != NULL) {
	  	        set_ReportSourceNDT(newActiveInterface); // setting new source with active interfaces
	  	        CcspTraceInfo(("ReportSourceNDT value is : %s\n", get_ReportSourceNDT()));  // For ex: ReportSourceNDT value is : LMLite/DOCSIS1,ETH3,REMOTE_LTE1
		}
		else {
			CcspTraceError(("newActiveInterface is NULL\n"));
		}	
          }
          else {
		  CcspTraceError(("val is NULL\n"));
	  }			  
  } 	  
  else {
	   CcspTraceError(("rbus_get failed for param : %s, rc : %d - %s\n", LMLITE_INTERFACE_ACTIVESTATUS_PARAM, rc, rbusError_ToString(rc)));
  }  
}	

// Subscribe for Device.X_RDK_WanManager.InterfaceActiveStatus
int subscribeTo_InterfaceActiveStatus_Event()
{
      int rc = RBUS_ERROR_SUCCESS;
      CcspTraceDebug(("Subscribing to %s Event\n", LMLITE_INTERFACE_ACTIVESTATUS_PARAM));
      rc = rbusEvent_SubscribeAsync (
        rbus_handle,
        LMLITE_INTERFACE_ACTIVESTATUS_PARAM,
        eventReceiveHandler,
	subscribeAsyncHandler,
        "LMLite_InterfaceActiveStatus",
        10*20);
      if(rc != RBUS_ERROR_SUCCESS) {
	      CcspTraceError(("%s subscribe failed : %d - %s\n", LMLITE_INTERFACE_ACTIVESTATUS_PARAM, rc, rbusError_ToString(rc)));
      }
      else {
	      CcspTraceInfo((" %s subscribe success\n", LMLITE_INTERFACE_ACTIVESTATUS_PARAM));
      }	      
      return rc;
}
#endif
