##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
AM_CFLAGS =

ACLOCAL_AMFLAGS = -I m4

noinst_LTLIBRARIES = libCcspLM.la

libCcspLM_la_CPPFLAGS = -I$(top_srcdir)/source/Ssp

libCcspLM_la_SOURCES = cosa_hosts_dml.c \
                       plugin_main.c \
                       lm_wrapper_priv.c \
                       lm_api_test.c \
                       lm_main.c \
                       lm_wrapper.c \
                       lm_util.c \
                       network_devices_status_avropack.c  \
                       webpa_interface.c \
                       webpa_pd_with_seshat.c \
                       webpa_pd_without_seshat.c \
                       cosa_ndstatus_dml.c \
                       network_devices_status.c \
                       cosa_reports_internal.c \
                       network_devices_traffic_avropack.c  \
                       cosa_ndtraffic_dml.c \
                       network_devices_traffic.c \
                       network_devices_interface.c \
                       device_presence_detection.c

if !FEATURE_RESOURCE_OPTIMIZATION
libCcspLM_la_SOURCES += cosa_xhosts_dml.c \
                        cosa_managementserver_apis.c \
                        cosa_managementserver_dml.c
endif

libCcspLM_la_LDFLAGS = -lhal_platform -lccsp_common -lsyscfg -lsysevent -lutapi -lutctx -lulog -ltelemetry_msgsender -lavro -lmsgpackc -ltrower-base64 -luuid -lm -lrt -pthread -lnanomsg -lwrp-c -llibparodus -lsecure_wrapper
if ENABLE_SESHAT
libCcspLM_la_LDFLAGS += -llibseshat
endif

if WAN_TRAFFIC_COUNT_SUPPORT
libCcspLM_la_SOURCES += cosa_wantraffic_api.c \
                        cosa_wantraffic_utils.c \
                        wtc_rbus_handler_apis.c \
                        wtc_rbus_apis.c
endif

if CORE_NET_LIB_FEATURE_SUPPORT
    libCcspLM_la_LDFLAGS += -lnet
endif