/*
* If not stated otherwise in this file or this component's LICENSE file the
* following copyright and licenses apply:
*
* Copyright 2020 RDK Management
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

#ifndef LMLITE_MOCK_H
#define LMLITE_MOCK_H

#include "gtest/gtest.h"

#include <mocks/mock_securewrapper.h>
#include <mocks/mock_socket.h>
#include <mocks/mock_safec_lib.h>
#include <mocks/mock_ansc_debug.h>
#include <mocks/mock_usertime.h>
#include <mocks/mock_base_api.h>
#include <mocks/mock_syscfg.h>
#include <mocks/mock_rbus.h>
#include <mocks/mock_psm.h>
#include <mocks/mock_parodus.h>
#include <mocks/mock_utopia.h>
#include <mocks/mock_ansc_memory.h>
#include <mocks/mock_ansc_wrapper_api.h>
#include <mocks/mock_platform_hal.h>
#include <mocks/mock_user_runtime.h>
#include <mocks/mock_ccsp_dmapi.h>
#include <mocks/mock_telemetry.h>
#include <mocks/mock_dslh_dmagnt_exported.h>
#include <mocks/mock_trace.h>
#include <mocks/mock_file_io.h>

class CcspLMLiteTestFixture : public ::testing::Test {
  protected:
        PlatformHalMock mockedPlatformHal;
        SecureWrapperMock mockedsecurewrapper;
        SocketMock mockedSocket;
        SafecLibMock mockedSafecLibMock;
        AnscDebugMock mockedAnscDebug;
        UserTimeMock mockedUserTime;
        BaseAPIMock mockedBaseAPI;
        SyscfgMock mockedSyscfg;
        rbusMock mockedRbus;
        PsmMock mockedPsm;
        parodusMock mockedParodus;
        utopiaMock mockedUtopia;
        AnscMemoryMock mockedAnscMemory;
        AnscWrapperApiMock mockedAnscWrapperApi;
        UserRuntimeMock mockedUserRuntime;
        CcspDmApiMock mockedCcspDmApi;
        telemetryMock mockedTelemetry;
        DslhDmagntExportedMock mockedDslhDmagntExported;
        TraceMock mockedTrace;
        FileIOMock mockedFileIO;
        
        CcspLMLiteTestFixture();
        virtual ~CcspLMLiteTestFixture();
        virtual void SetUp() override;
        virtual void TearDown() override;

        void TestBody() override;
};

#endif // LMLITE_MOCK_H


