##########################################################################
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
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
AM_CFLAGS = -fPIC -fno-exceptions -Os -Wall -Wextra

AM_CXXFLAGS = -std=c++11

ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = CcspLMLite_gtest.bin

CcspLMLite_gtest_bin_CPPFLAGS = -I$(top_srcdir)/../hal/include \
                                -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/include/ \
                                -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/include/ \
                                -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/ccsp \
                                -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/dbus-1.0 \
                                -I$(PKG_CONFIG_SYSROOT_DIR)$(libdir)/dbus-1.0/include \
                                -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/libsafec \
                                -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus \
                                -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rtmessage \
                                -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/gtest \
                                -I${top_srcdir}/gtest/include \
                                -I${top_srcdir}/source \
                                -I${top_srcdir}/source/include \
                                -I${top_srcdir}/source/lm \
                                -I${top_srcdir}/source/Ssp \
                                -DUTC_ENABLE \
                                -DUSE_NOTIFY_COMPONENT \
                                -DWAN_FAILOVER_SUPPORTED \
                                -DUNIT_TEST_DOCKER_SUPPORT


CcspLMLite_gtest_bin_SOURCES = gtest_main.cpp \
                               $(top_srcdir)/source/lm/lm_wrapper.c \
                               $(top_srcdir)/source/lm/lm_api.c \
                               $(top_srcdir)/source/lm/cosa_hosts_dml.c \
                               $(top_srcdir)/source/lm/lm_main.c \
                               $(top_srcdir)/source/lm/network_devices_status_avropack.c \
                               $(top_srcdir)/source/lm/network_devices_traffic.c \
                               $(top_srcdir)/source/lm/webpa_interface.c \
                               $(top_srcdir)/source/lm/network_devices_traffic_avropack.c \
                               $(top_srcdir)/source/lm/lm_wrapper_priv.c \
                               $(top_srcdir)/source/lm/lm_api_test.c \
                               $(top_srcdir)/source/lm/device_presence_detection.c \
                               $(top_srcdir)/source/lm/network_devices_interface.c \
                               $(top_srcdir)/source/lm/cosa_reports_internal.c \
                               $(top_srcdir)/source/lm/cosa_ndtraffic_dml.c \
                               $(top_srcdir)/source/lm/wtc_rbus_apis.c \
                               $(top_srcdir)/source/lm/webpa_pd_without_seshat.c \
                               $(top_srcdir)/source/lm/lm_util.c \
                               $(top_srcdir)/source/lm/wtc_rbus_handler_apis.c \
                               $(top_srcdir)/source/lm/cosa_wantraffic_utils.c \
                               $(top_srcdir)/source/lm/cosa_wantraffic_api.c \
                               $(top_srcdir)/source/lm/plugin_main.c \
                               $(top_srcdir)/source/lm/cosa_ndstatus_dml.c \
                               $(top_srcdir)/source/lm/network_devices_status.c \
                               $(top_srcdir)/source/lm/webpa_pd_with_seshat.c \
                               lm_api_test.cpp \
                               network_device_statustest.cpp \
                               network_devices_traffic_test.cpp \
                               webpa_interfaceTest.cpp \
                               lmlite_mock.cpp

if !FEATURE_RESOURCE_OPTIMIZATION
CcspLMLite_gtest_bin_SOURCES += $(top_srcdir)/source/lm/cosa_xhosts_dml.c \
                        $(top_srcdir)/source/lm/cosa_managementserver_apis.c \
                        $(top_srcdir)/source/lm/cosa_managementserver_dml.c
endif

CcspLMLite_gtest_bin_LDFLAGS = -lgtest -lgmock -lgcov -lpthread -lrt -luuid

# Enabling RESOURCE_OPTIMIZATION for docker environment as it is defined in lm-lite recipe file in jenkins
if FEATURE_RESOURCE_OPTIMIZATION
CcspLMLite_gtest_bin_CPPFLAGS += -DRESOURCE_OPTIMIZATION
endif

CcspLMLite_gtest_bin_LDADD = $(HOME)/usr/local/lib/libmock_ccsp_common.la \
                             $(HOME)/usr/local/lib/libmock_platform_hal.la \
                             $(HOME)/usr/local/lib/libmock_socket.la \
                             $(HOME)/usr/local/lib/libmock_secure_wrapper.la \
                             $(HOME)/usr/local/lib/libmock_safec_lib.la \
                             $(HOME)/usr/local/lib/libmock_psm.la \
                             $(HOME)/usr/local/lib/libmock_file_io.la \
                             $(HOME)/usr/local/lib/libmock_syscfg.la \
                             $(HOME)/usr/local/lib/libmock_utopia.la \
                             $(HOME)/usr/local/lib/libmock_telemetry.la \
                             $(HOME)/usr/local/lib/libmock_parodus.la \
                             $(HOME)/usr/local/lib/libmock_rbus.la

# Adding Code Coverage Flags
AM_CFLAGS += -fprofile-arcs -ftest-coverage
AM_CXXFLAGS += -fprofile-arcs -ftest-coverage
CcspLMLite_gtest_bin_LDFLAGS += --coverage
