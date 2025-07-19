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

#include <stdlib.h>
#include <string.h>

#include "lm_util.h"

void LanManager_CheckCloneCopy (char **dest, const char *src)
{
	size_t src_len;

	if (src == NULL)
		return;

	src_len = strlen (src);

	/*
	   If src is an empty string then abort. This follows the original
	   implementation but it looks wrong (it means this function can't be
	   used to set dest to an empty string). There seem to be various
	   workarounds in the code for this limitation (e.g. passing src as
	   "empty" or " ") so leave it as-is for now, but it needs review.
	*/
	if (src_len == 0)
		return;

	/*
	   If dest has already been allocated and the new string is the same
	   length or shorter than the old one then reuse the old buffer. Else
	   free the buffer and allocate again.
	*/
	if (*dest) {
		size_t dest_len = strlen (*dest);
		if (src_len <= dest_len) {
			memcpy (*dest, src, src_len + 1);
			return;
		}
		free (*dest);
	}

	*dest = malloc (src_len + 1);

	if (*dest == NULL)
		return;

	memcpy (*dest, src, src_len + 1);
}
