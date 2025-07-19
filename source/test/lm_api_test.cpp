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
#include <sys/socket.h>
#include <pthread.h>
#include <semaphore.h>

#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include "lmlite_mock.h"

#include "lm_api.h"
#include "ccsp_lmliteLog_wrapper.h"
#include "report_common.h"

extern "C"
{
  #include <rbus/rbus.h>
}
 
using namespace std;
using std::experimental::filesystem::exists;

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;

extern SocketMock * g_socketMock;
extern SafecLibMock * g_safecLibMock;
extern FileIOMock * g_fileIOMock;

TEST_F(CcspLMLiteTestFixture, InitClientSocketSuccess) {
    int expectedFd;
    EXPECT_CALL(*g_socketMock, socket(_, _, _))
        .Times(1)
        .WillOnce(Return(10));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_socketMock, connect(10, _, _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(LM_RET_SUCCESS, init_client_socket(&expectedFd));
}

TEST_F(CcspLMLiteTestFixture, InitClientSocketFailure) {
    int expectedFd;
    EXPECT_CALL(*g_socketMock, socket(_, _, _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_EQ(LM_RET_ERR, init_client_socket(&expectedFd));
}

TEST_F(CcspLMLiteTestFixture, InitClientSocketConnectFailure) {
    int expectedFd;
    EXPECT_CALL(*g_socketMock, socket(_, _, _))
        .Times(1)
        .WillOnce(Return(10));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_socketMock, connect(10, _, _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_socketMock, close(_))
        .Times(1)
        .WillOnce(Return(0));
    
    EXPECT_EQ(LM_RET_ERR, init_client_socket(&expectedFd));
}

TEST_F(CcspLMLiteTestFixture, LMSendReceiveSuccess) {
    int expectedFd = 10;
    void* expectedCmd[64];
    void* expectedBuff[64];
    memset(expectedCmd,0,sizeof(expectedCmd));
    memset(expectedBuff,0,sizeof(expectedCmd));

    EXPECT_CALL(*g_socketMock, socket(_, _, _))
        .Times(1)
        .WillOnce(Return(1));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _,_))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_socketMock, connect(_, _, _))
        .Times(1)
        .WillOnce(Return(1));
    
    EXPECT_CALL(*g_fileIOMock, write(_, _, _))
        .Times(1)
        .WillRepeatedly(Return(1));

    EXPECT_CALL(*g_socketMock, recv(_, _, _, _))
        .Times(1)
        .WillOnce(Return(1));

    EXPECT_CALL(*g_socketMock, close(_))
        .Times(1)
        .WillOnce(Return(0));
        
    ASSERT_EQ(LM_RET_SUCCESS, lm_send_rev(expectedCmd, 64, expectedBuff, 64)) << "Failed to send/receive data";
}

TEST_F(CcspLMLiteTestFixture, LMSendReceive_WriteFailure) {
    int expectedFd = 10;
    void* expectedCmd[64];
    void* expectedBuff[64];
    memset(expectedCmd,0,sizeof(expectedCmd));
    memset(expectedBuff,0,sizeof(expectedCmd));

    EXPECT_CALL(*g_socketMock, socket(_, _, _))
        .Times(1)
        .WillOnce(Return(1));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _,_))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_socketMock, connect(_, _, _))
        .Times(1)
        .WillOnce(Return(1));
    
    EXPECT_CALL(*g_fileIOMock, write(_, _, _))
        .Times(1)
        .WillRepeatedly(Return(-1));

    EXPECT_CALL(*g_socketMock, close(_))
        .Times(1)
        .WillOnce(Return(0));
        
    EXPECT_EQ(LM_RET_ERR, lm_send_rev(expectedCmd, 64, expectedBuff, 64));
}

TEST_F(CcspLMLiteTestFixture, LMSendReceive_SocketFailure) {
    int expectedFd = 10;
    void* expectedCmd[64];
    void* expectedBuff[64];
    memset(expectedCmd,0,sizeof(expectedCmd));
    memset(expectedBuff,0,sizeof(expectedCmd));

    EXPECT_CALL(*g_socketMock, socket(_, _, _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_EQ(LM_RET_ERR, lm_send_rev(expectedCmd, 64, expectedBuff, 64));
}

TEST_F(CcspLMLiteTestFixture, LMSendReceive_SocketConnectFailure) {
    int expectedFd = 10;
    void* expectedCmd[64];
    void* expectedBuff[64];
    memset(expectedCmd,0,sizeof(expectedCmd));
    memset(expectedBuff,0,sizeof(expectedCmd));

    EXPECT_CALL(*g_socketMock, socket(_, _, _))
        .Times(1)
        .WillOnce(Return(1));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _,_))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_socketMock, connect(_, _, _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_socketMock, close(_))
        .Times(1)
        .WillOnce(Return(0));
    
    EXPECT_EQ(LM_RET_ERR, lm_send_rev(expectedCmd, 64, expectedBuff, 64));
}

TEST_F(CcspLMLiteTestFixture, LMSendReceive_RecvFailure) {
    int expectedFd = 10;
    void* expectedCmd[64];
    void* expectedBuff[64];
    memset(expectedCmd,0,sizeof(expectedCmd));
    memset(expectedBuff,0,sizeof(expectedCmd));

    EXPECT_CALL(*g_socketMock, socket(_, _, _))
        .Times(1)
        .WillOnce(Return(1));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _,_))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_socketMock, connect(_, _, _))
        .Times(1)
        .WillOnce(Return(1));
    
    EXPECT_CALL(*g_fileIOMock, write(_, _, _))
        .Times(1)
        .WillRepeatedly(Return(1));

    EXPECT_CALL(*g_socketMock, recv(_, _, _, _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_socketMock, close(_))
        .Times(1)
        .WillOnce(Return(0));
        
    EXPECT_EQ(LM_RET_ERR, lm_send_rev(expectedCmd, 64, expectedBuff, 64));
}

