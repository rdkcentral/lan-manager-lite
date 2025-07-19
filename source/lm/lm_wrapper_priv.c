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

/**************************************************************************

    module:

        lm_wrapper_priv.c

    -------------------------------------------------------------------

    description:

        stub out for rdk-b

    -------------------------------------------------------------------

    author: WSN


    -------------------------------------------------------------------

    revision:

        06/20/2014    initial revision.

**************************************************************************/

#include <utctx/utctx.h>
#include <utctx/utctx_api.h>
#include <utapi/utapi.h>
#include <utapi/utapi_util.h>
#include "ansc_platform.h"

#include "lm_api.h"

#define BUFLEN_256                  256

int Utopia_set_lan_host_comments(UtopiaContext *ctx, unsigned char *pMac, unsigned char *pComments);
int lm_wrapper_priv_stop_scan()
{
    UtopiaContext ctx = {0};
    bridgeInfo_t bridge_info = {0}; /*RDKB-7350, CID-33409, init before use*/
    
    if (Utopia_Init(&ctx))
    {
        Utopia_GetBridgeSettings(&ctx, &bridge_info);
        Utopia_Free(&ctx, 0);
        if(bridge_info.mode == BRIDGE_MODE_OFF)
            return 0;
        else
            return 1;
    }else
        return SUCCESS;
}



void lm_wrapper_priv_getLanHostComments(char *physAddress, char *pComments)
{

    char buffer[256] = {0};
    UtopiaContext ctx;

    if ( (physAddress == NULL) && (pComments == NULL) )
        return;

    pComments[0] = 0; /*RDKB-7350, CID-33555, use after null check */

    if( !Utopia_Init(&ctx) )
        return;

    Utopia_GetNamed(&ctx, UtopiaValue_USGv2_Lan_Clients_Mac, physAddress, buffer, sizeof(buffer));

    Utopia_Free(&ctx, 0);

	if(buffer[0])
    {
		char *p;

		p = strchr(buffer, '+');
		if(p!=NULL)
                {
		    /* CID 52991 Calling risky function */
		    snprintf(pComments, BUFLEN_256 -1, "%s", (p+1));
	        }
	}

    return;
}

// return 0 if success 
int lm_wrapper_priv_set_lan_host_comments( LM_cmd_comment_t *cmd)
{
    UtopiaContext ctx;

    if(!Utopia_Init(&ctx))
        return 1;

    Utopia_set_lan_host_comments(&ctx, cmd->mac, (unsigned char *)cmd->comment);
    Utopia_Free(&ctx, 1);

    return SUCCESS;
}

int lm_wrapper_priv_getEthernetPort(char *mac)
{
        UNREFERENCED_PARAMETER(mac);
#if 0
        int port;
        char tmp[6];
        mac_string_to_array(mac, tmp);
        if(SWCTL_OK == swctl_findMacAddress(tmp, &port))
            return port;
        else
#endif
            return -1;
}
