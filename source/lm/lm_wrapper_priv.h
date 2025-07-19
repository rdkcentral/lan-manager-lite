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

        lm_wrapper_priv.h

    -------------------------------------------------------------------

    description:

    -------------------------------------------------------------------

    author: WSN


    -------------------------------------------------------------------

    revision:

        06/20/2014    initial revision.

**************************************************************************/

#ifndef  _LM_WRAPPER_PRIV_H_
#define  _LM_WRAPPER_PRIV_H_


int lm_wrapper_priv_stop_scan();
void lm_wrapper_priv_getLanHostComments(char *physAddress, char *pComments);
int lm_wrapper_priv_set_lan_host_comments( LM_cmd_comment_t *cmd);
int lm_wrapper_priv_getEthernetPort(char *mac);

#endif		// _LM_WRAPPER_PRIV_H_
