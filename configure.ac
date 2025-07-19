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
#                                              -*- Autoconf -*-
# Process this file with autoconf to produce configure script.
#

AC_PREREQ([2.65])
AC_INIT([lmapi], [1.0], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE([subdir-objects])
LT_INIT
AC_PREFIX_DEFAULT(`pwd`)
AC_ENABLE_SHARED
AC_DISABLE_STATIC

AC_ARG_ENABLE([seshat],
[  --enable-seshat    Turn on seshat],
[case "${enableval}" in
  yes) ENABLE_SESHAT=true ;;
  no)  ENABLE_SESHAT=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-seshat]) ;;
esac],[ENABLE_SESHAT=false])
AM_CONDITIONAL([ENABLE_SESHAT], [test x$ENABLE_SESHAT = xtrue])

# Checks for Wan traffic count Feature Support
AC_ARG_ENABLE([wan_traffic_count_support],
[  --enable-wan_traffic_count_support=val Turn on wan traffic count Feature, val=true or false],
[case "${enableval}" in
  yes) wan_traffic_count_support=true ;;
  no)  wan_traffic_count_support=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-wan_traffic_count_support]) ;;
esac],[wan_traffic_count_support=false])
AM_CONDITIONAL(WAN_TRAFFIC_COUNT_SUPPORT, test x"$wan_traffic_count_support" = x"true")

AC_ARG_ENABLE([resourceoptimization],
             AS_HELP_STRING([--enable-resourceoptimization],[enable resource optimization (default is no)]),
             [
              case "${enableval}" in
               yes) RESOURCE_OPTIMIZATION_ENABLED=true;;
               no)  RESOURCE_OPTIMIZATION_ENABLED=false;;
               *) AC_MSG_ERROR([bad value ${enableval} for --enable-resourceoptimization]);;
              esac
             ],
             [echo "resourceoptimization is disabled"])
AM_CONDITIONAL(FEATURE_RESOURCE_OPTIMIZATION, test "x$RESOURCE_OPTIMIZATION_ENABLED" = xtrue)

AC_ARG_ENABLE([unitTestDockerSupport],
             AS_HELP_STRING([--enable-unitTestDockerSupport],[enable docker support for unit testing (default is no)]),
             [
              UNIT_TEST_DOCKER_SUPPORT=""
               case "${enableval}" in
                yes) UNIT_TEST_DOCKER_SUPPORT=true
                     m4_if(m4_sysval,[0],[AC_CONFIG_FILES([source/test/Makefile])]);;
                no) UNIT_TEST_DOCKER_SUPPORT=false;;
                 *) AC_MSG_ERROR([bad value ${enableval} for --enable-unitTestDockerSupport ]);;
               esac
             ],
             [echo "Docker support is disabled"])
AM_CONDITIONAL([UNIT_TEST_DOCKER_SUPPORT], [test x$UNIT_TEST_DOCKER_SUPPORT = xtrue])

AC_ARG_ENABLE([core_net_lib_feature_support],
  [  --enable-core_net_lib_feature_support=val Turn on core_net_lib Feature, val=true or false],
  [ case "${enableval}" in
      yes)
        core_net_lib_feature_support=true
        ;;
      no)
        core_net_lib_feature_support=false
        ;;
      *)
        AC_MSG_ERROR([bad value ${enableval} for --enable-core_net_lib_feature_support])
        ;;
    esac
  ],
  [ core_net_lib_feature_support=false ]
)
AM_CONDITIONAL(CORE_NET_LIB_FEATURE_SUPPORT, test x"$core_net_lib_feature_support" = x"true")


AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_CC_C_O
AM_PROG_LIBTOOL(libtool)

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC

AC_CONFIG_FILES(
	source/Makefile
	source/lm/Makefile
	source/Ssp/Makefile
	Makefile
)

AC_SUBST(UNIT_TEST_DOCKER_SUPPORT)

AC_OUTPUT

