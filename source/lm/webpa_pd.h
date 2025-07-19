/************************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
**************************************************************************/
/**
 * @file webpa_pd.h
 *
 * @description This header defines parodus log levels
 *
 */

#ifndef _WEBPA_PD_H_
#define _WEBPA_PD_H_

#ifdef __cplusplus
extern "C" {
#endif

/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
#define DEVICE_PROPS_FILE  "/etc/device.properties"

/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
/**
 *  Returns parodus URL.
 *
 *  @note The caller should ensure that size of url is URL_SIZE or more.
 *
 *  @param url   [out] URL where parodus is listening.
 */
void get_parodus_url(char **url);

#ifdef __cplusplus
}
#endif

#endif

