/*
* If not stated otherwise in this file or this component's LICENSE file the
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
#include "lmlite_mock.h"

using namespace std;
using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;

extern "C"
{
#include "../lm/webpa_interface.h"
#include "../lm/network_devices_traffic_avropack.h"
#include <rbus/rbus.h>  
}

extern rbusMock * g_rbusMock;


TEST_F(CcspLMLiteTestFixture, checkRbusEnabledSuccess) {
    EXPECT_CALL(*g_rbusMock, rbus_checkStatus()).WillOnce(::testing::Return(RBUS_ENABLED));
    bool isEnabled = checkRbusEnabled();
    EXPECT_TRUE(isEnabled);
}

TEST_F(CcspLMLiteTestFixture, checkRbusEnabledFailure) {
    EXPECT_CALL(*g_rbusMock, rbus_checkStatus()).WillOnce(::testing::Return(RBUS_DISABLED)); 
    bool isEnabled = checkRbusEnabled();
    EXPECT_FALSE(isEnabled);
}

TEST_F(CcspLMLiteTestFixture, lmliteRbusInitSuccess) {
    EXPECT_CALL(*g_rbusMock, rbus_open(_, _)).WillOnce(::testing::Return(RBUS_ERROR_SUCCESS));
    ASSERT_EQ(lmliteRbusInit("_"), LMLITE_SUCCESS);
}

TEST_F(CcspLMLiteTestFixture, lmliteRbusInitFailure) {
    EXPECT_CALL(*g_rbusMock, rbus_open(_, _)).WillOnce(::testing::Return(RBUS_ERROR_BUS_ERROR));
    ASSERT_EQ(lmliteRbusInit("_"), LMLITE_FAILURE);
}

TEST_F(CcspLMLiteTestFixture, rdk_logger_module_fetchSuccess) {
    const char* result = rdk_logger_module_fetch();
    EXPECT_STREQ("LOG.RDK.LM", result);
}


TEST_F(CcspLMLiteTestFixture, get_ActiveInterfaceSuccess) {
    char input[] = "DOCSIS1,0|DSL1,0|ETH3,0|GPON1,0";
    char* result = get_ActiveInterface(input);
    EXPECT_STREQ(result, "LMLite");
}

TEST_F(CcspLMLiteTestFixture, OneActiveInterface) {
    char input[] = "DOCSIS1,0|DSL1,0|ETH3,1|GPON1,0";
    char* result = get_ActiveInterface(input);
    EXPECT_STREQ(result, "LMLite/ETH3");
}

TEST_F(CcspLMLiteTestFixture, MultipleActiveInterfaces) {
    char input[] = "DOCSIS1,1|DSL1,0|ETH3,1|GPON1,0|REMOTE_LTE1,1";
    char* result = get_ActiveInterface(input);
    EXPECT_STREQ(result, "LMLite/DOCSIS1,ETH3,REMOTE_LTE1");
}

TEST_F(CcspLMLiteTestFixture, EmptyString) {
    char input[] = "";
    char* result = get_ActiveInterface(input);
    EXPECT_STREQ(result, "LMLite");
}

TEST_F(CcspLMLiteTestFixture, NullString) {
    char* result = get_ActiveInterface(NULL); 
    EXPECT_STREQ(result, "LMLite"); 
}

TEST_F(CcspLMLiteTestFixture, subscribeTo_InterfaceActiveStatus_Event_SubscribeSuccess) {
    EXPECT_CALL(*g_rbusMock, rbusEvent_SubscribeAsync(_, _, _, _, _, _))
        .WillOnce(testing::Return(RBUS_ERROR_SUCCESS));

    int result = subscribeTo_InterfaceActiveStatus_Event();
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(CcspLMLiteTestFixture, SubscribeFailure) {
    EXPECT_CALL(*g_rbusMock, rbusEvent_SubscribeAsync(_, _, _, _, _, _))
        .WillOnce(testing::Return(RBUS_ERROR_BUS_ERROR)); 

    int result = subscribeTo_InterfaceActiveStatus_Event();
    EXPECT_NE(result, RBUS_ERROR_SUCCESS);
}

TEST_F(CcspLMLiteTestFixture, RbusGetSuccess_ValidString) {
    static char returnValueBuffer[256];
    strcpy(returnValueBuffer, "DOCSIS1,1|DSL1,0|ETH3,1|GPON1,0|REMOTE_LTE1,1");
    EXPECT_CALL(*g_rbusMock, rbus_get(_, _, _)).WillOnce(Return(RBUS_ERROR_SUCCESS));
    EXPECT_CALL(*g_rbusMock, rbusValue_ToString(_,_,_)).WillOnce(Return(returnValueBuffer));

    char input[] = "DOCSIS1,1|DSL1,0|ETH3,1|GPON1,0|REMOTE_LTE1,1";
    char* result = get_ActiveInterface(input);
    EXPECT_STREQ(result, "LMLite/DOCSIS1,ETH3,REMOTE_LTE1");

    set_ReportSourceNDT(result);

    char* expectedValue = get_ReportSourceNDT();
    EXPECT_STREQ(expectedValue, result);

    get_WanManager_ActiveInterface();
}

TEST_F(CcspLMLiteTestFixture, RbusGetFails) {
    EXPECT_CALL(*g_rbusMock, rbus_get(_, _, _)).WillOnce(Return(RBUS_ERROR_BUS_ERROR));

    get_WanManager_ActiveInterface();
}

TEST_F(CcspLMLiteTestFixture, RbusValueToStringReturnsNull) {
    EXPECT_CALL(*g_rbusMock, rbus_get(_, _, _)).WillOnce(Return(RBUS_ERROR_SUCCESS));
    EXPECT_CALL(*g_rbusMock, rbusValue_ToString(_,_,_)).WillOnce(Return(nullptr));

    get_WanManager_ActiveInterface();
}
