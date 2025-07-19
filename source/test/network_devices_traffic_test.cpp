/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2024 RDK Management
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

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <experimental/filesystem>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>

#include "lmlite_mock.h"

extern "C" {
    #include "network_devices_traffic.h"
    #include "network_devices_traffic_avropack.h"
    #include "ccsp_lmliteLog_wrapper.h"
    #include "lm_main.h"
    #include <rbus/rbus.h>
    #include "report_common.h"
}

extern SecureWrapperMock * g_securewrapperMock;
extern AnscDebugMock* g_anscDebugMock;

extern ULONG NetworkDeviceTrafficPeriods[];
extern ULONG NDTPollingPeriod;
extern ULONG NDTPollingPeriodDefault;
extern ULONG NDTReportingPeriod;
extern ULONG NDTReportingPeriodDefault;
extern BOOL NDTReportStatus;
extern ULONG NDTOverrideTTL;
extern ULONG NDTOverrideTTLDefault;

extern struct networkdevicetrafficdata *headnode;
extern struct networkdevicetrafficdata *currnode;

using namespace std;
using std::experimental::filesystem::exists;
using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::HasSubstr;
using ::testing::SetArrayArgument;

TEST_F(CcspLMLiteTestFixture, ResetEBTablesSuccess) {
    char expectedCmd[] = "sta.sh";
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(HasSubstr(expectedCmd),_))
        .Times(1)
        .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_anscDebugMock, Ccsplog3(_, _))
        .Times(1);

    EXPECT_EQ(0, ResetEBTables());
}

TEST_F(CcspLMLiteTestFixture, ResetEBTablesFailure) {
    char expectedCmd[] = "sta.sh";
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(HasSubstr(expectedCmd),_))
        .Times(1)
        .WillOnce(::testing::Return(-1));

    EXPECT_CALL(*g_anscDebugMock, Ccsplog3(_, _))
        .Times(1);

    EXPECT_EQ(-1, ResetEBTables());
}

TEST_F(CcspLMLiteTestFixture, GetIPTableDataSystemCallFailure) {
    char expectedCmd[] = "cur.sh";

    EXPECT_CALL(*g_securewrapperMock, v_secure_system(HasSubstr(expectedCmd),_))
        .Times(1)
        .WillOnce(::testing::Return(1));
    
    EXPECT_CALL(*g_anscDebugMock, Ccsplog3(_, _))
        .Times(1);
    
    GetIPTableData();
}

TEST_F(CcspLMLiteTestFixture, IsValueInArrayNDTValueFound) {
    ULONG ExistingValue = NetworkDeviceTrafficPeriods[0];
    EXPECT_TRUE(isvalueinarray_ndt(ExistingValue, NetworkDeviceTrafficPeriods, 10));
}

TEST_F(CcspLMLiteTestFixture, IsValueInArrayNDTValueNotFound) {
    ULONG nonExistingValue = NetworkDeviceTrafficPeriods[0] + 1;
    EXPECT_FALSE(isvalueinarray_ndt(nonExistingValue, NetworkDeviceTrafficPeriods, 10));
}

TEST_F(CcspLMLiteTestFixture, ValidateNDTPeriod_ValidPeriod) {
    ULONG validPeriod = NetworkDeviceTrafficPeriods[0];
    EXPECT_TRUE(ValidateNDTPeriod(validPeriod));
}

TEST_F(CcspLMLiteTestFixture, ValidateNDTPeriod_InvalidPeriod) {
    ULONG invalidPeriod = NetworkDeviceTrafficPeriods[0] + 1;
    EXPECT_FALSE(ValidateNDTPeriod(invalidPeriod));
}

TEST_F(CcspLMLiteTestFixture, GetNDTPollingPeriod_NewValue) {
    ULONG newValue = 900;
    NDTPollingPeriod = newValue;
    EXPECT_EQ(newValue, GetNDTPollingPeriod());
}

TEST_F(CcspLMLiteTestFixture, GetNDTPollingPeriodDefault_DefaultValue) {
    EXPECT_EQ(NDTPollingPeriodDefault, GetNDTPollingPeriodDefault());
}

TEST_F(CcspLMLiteTestFixture, SetNDTPollingPeriod_NewValue) {
    ULONG originalValue = NDTPollingPeriod;
    ULONG newPeriod = 1200;
    EXPECT_EQ(0, SetNDTPollingPeriod(newPeriod));
    EXPECT_EQ(newPeriod, NDTPollingPeriod);
    EXPECT_NE(originalValue, NDTPollingPeriod);
}

TEST_F(CcspLMLiteTestFixture, SetNDTPollingPeriod_DefaultValue) {
    ULONG currentPeriod = NDTPollingPeriod;
    EXPECT_EQ(0, SetNDTPollingPeriod(currentPeriod));
    EXPECT_EQ(currentPeriod, NDTPollingPeriod);
}

TEST_F(CcspLMLiteTestFixture, SetNDTPollingPeriodDefault_NewValue) {
    ULONG originalValue = NDTPollingPeriodDefault;
    ULONG newPeriod = 600;
    EXPECT_EQ(0, SetNDTPollingPeriodDefault(newPeriod));
    EXPECT_EQ(newPeriod, NDTPollingPeriodDefault);
    EXPECT_NE(originalValue, NDTPollingPeriodDefault);
}

TEST_F(CcspLMLiteTestFixture, SetNDTPollingPeriodDefault_DefaultValue) {
    ULONG currentPeriod = NDTPollingPeriodDefault;
    EXPECT_EQ(0, SetNDTPollingPeriodDefault(currentPeriod));
    EXPECT_EQ(currentPeriod, NDTPollingPeriodDefault);
}

TEST_F(CcspLMLiteTestFixture, GetNDTReportingPeriodValue) {
    ULONG expectedValue = 300;
    NDTReportingPeriod = expectedValue;
    EXPECT_EQ(expectedValue, GetNDTReportingPeriod());
}

TEST_F(CcspLMLiteTestFixture, GetNDTReportingPeriodDefaultValue) {
    EXPECT_EQ(DEFAULT_TRAFFIC_REPORTING_INTERVAL, GetNDTReportingPeriodDefault());
}

TEST_F(CcspLMLiteTestFixture, SetNDTReportingPeriod_NewValue) {
    ULONG originalValue = NDTReportingPeriod;
    ULONG newPeriod = 1200;
    EXPECT_EQ(0, SetNDTReportingPeriod(newPeriod));
    EXPECT_EQ(newPeriod, NDTReportingPeriod);
    EXPECT_NE(originalValue, NDTReportingPeriod);
}

TEST_F(CcspLMLiteTestFixture, SetNDTReportingPeriod_DefaultValue) {
    ULONG currentPeriod = NDTReportingPeriod;
    EXPECT_EQ(0, SetNDTReportingPeriod(currentPeriod));
    EXPECT_EQ(currentPeriod, NDTReportingPeriod);
}

TEST_F(CcspLMLiteTestFixture, SetNDTReportingPeriodDefault_NewValue) {
    ULONG originalValue = NDTReportingPeriodDefault;
    ULONG newPeriod = 600;
    EXPECT_EQ(0, SetNDTReportingPeriodDefault(newPeriod));
    EXPECT_EQ(newPeriod, NDTReportingPeriodDefault);
    EXPECT_NE(originalValue, NDTReportingPeriodDefault);
}

TEST_F(CcspLMLiteTestFixture, SetNDTReportingPeriodDefault_DefaultValue) {
    ULONG currentPeriod = NDTReportingPeriodDefault;
    EXPECT_EQ(0, SetNDTReportingPeriodDefault(currentPeriod));
    EXPECT_EQ(currentPeriod, NDTReportingPeriodDefault);
}

TEST_F(CcspLMLiteTestFixture, GetNDTOverrideTTLValue) {
    ULONG expectedValue = 500;
    NDTOverrideTTL = expectedValue;
    EXPECT_EQ(expectedValue, GetNDTOverrideTTL());
}

TEST_F(CcspLMLiteTestFixture, GetNDTOverrideTTLDefaultValue) {
    EXPECT_EQ(NDTOverrideTTLDefault, GetNDTOverrideTTLDefault());
}

TEST_F(CcspLMLiteTestFixture, SetNDTOverrideTTL_NewValue) {
    ULONG originalValue = NDTOverrideTTL;
    ULONG newTTL = 600;
    EXPECT_EQ(0, SetNDTOverrideTTL(newTTL));
    EXPECT_EQ(newTTL, NDTOverrideTTL);
    EXPECT_NE(originalValue, NDTOverrideTTL);
}

TEST_F(CcspLMLiteTestFixture, GetNDTHarvestingStatus_True) {
    BOOL expectedStatus = TRUE;
    NDTReportStatus = expectedStatus;
    EXPECT_EQ(expectedStatus, GetNDTHarvestingStatus());
}

TEST_F(CcspLMLiteTestFixture, GetNDTHarvestingStatus_False) {
    BOOL expectedStatus = FALSE;
    NDTReportStatus = expectedStatus;
    EXPECT_EQ(expectedStatus, GetNDTHarvestingStatus());
}

TEST_F(CcspLMLiteTestFixture, SetNDTHarvestingStatus_False) {
    ULONG newValue = FALSE;
    EXPECT_EQ(0, SetNDTPollingPeriod(newValue));
    EXPECT_EQ(newValue, NDTPollingPeriod);
}

TEST_F(CcspLMLiteTestFixture, SetNDTHarvestingStatus_True) {
    ULONG newValue = TRUE;
    EXPECT_EQ(0, SetNDTPollingPeriod(newValue));
    EXPECT_EQ(newValue, NDTPollingPeriod);
}

TEST_F(CcspLMLiteTestFixture, PrintListWithTestData) {

    // add test data to list
    add_to_list_ndt(strdup("00:11:22:33:44:55|1000|2000|3000|4000"));

    /* check if test data is added to list.
        if headnode is NULL, data is not added */
    ASSERT_NE(headnode, nullptr);

    // verify data added to list
    EXPECT_STREQ(headnode->device_mac, "00:11:22:33:44:55");
    EXPECT_EQ(headnode->external_bytes_down, 2000);
    EXPECT_EQ(headnode->external_bytes_up, 4000);
    EXPECT_STREQ(headnode->parent, NDT_DEFAULT_PARENT_MAC);
    EXPECT_STREQ(headnode->device_type, NDT_DEFAULT_DEVICE_TYPE);

    /*  check if there is only one node in the list
        headnode->next should be NULL
        headnode should be equal to currnode   */ 
    EXPECT_EQ(headnode->next, nullptr);
    EXPECT_EQ(headnode, currnode);

    print_list_ndt();

    // CleanUp - delete the test data by calling delete_list_ndt()
    delete_list_ndt();

    // check if list is deleted
    EXPECT_EQ(headnode, nullptr);
    EXPECT_EQ(currnode, nullptr);
}

TEST_F(CcspLMLiteTestFixture, DeleteListWithTestData) {

    // add test data to list
    add_to_list_ndt(strdup("00:11:22:33:44:55|1000|2000|3000|4000"));
    add_to_list_ndt(strdup("AA:BB:CC:DD:EE:FF|5000|6000|7000|8000"));

    /* check if test data is added to list.
        if headnode is NULL, data is not added */
    ASSERT_NE(headnode, nullptr);

    delete_list_ndt();

    // check if list is deleted
    EXPECT_EQ(headnode, nullptr);
    EXPECT_EQ(currnode, nullptr);
}


TEST_F(CcspLMLiteTestFixture, AddDataToList) {

    // add test data to list
    add_to_list_ndt(strdup("00:11:22:33:44:55|1000|2000|3000|4000"));
    
    /* check if test data is added to list.
        if headnode is NULL, data is not added */

    ASSERT_NE(headnode, nullptr);

    // verify the data added to list
    EXPECT_STREQ(headnode->device_mac, "00:11:22:33:44:55");
    EXPECT_EQ(headnode->external_bytes_down, 2000);
    EXPECT_EQ(headnode->external_bytes_up, 4000);
    EXPECT_STREQ(headnode->parent, NDT_DEFAULT_PARENT_MAC);
    EXPECT_STREQ(headnode->device_type, NDT_DEFAULT_DEVICE_TYPE);

    // check if there is only one node in the list
    EXPECT_EQ(headnode->next, nullptr);
    EXPECT_EQ(headnode, currnode);
}

// end of file

