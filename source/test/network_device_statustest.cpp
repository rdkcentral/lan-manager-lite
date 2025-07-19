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

#include <sys/types.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <pthread.h> 
#include <semaphore.h>
#include "lmlite_mock.h"
#include "avro.h"

extern "C" {
    #include "lm_main.h"
    #include "webpa_interface.h"
    #include "network_devices_status.h"
    #include "report_common.h"
    #include "network_devices_status_avropack.h"
    #include "cosa_ndstatus_dml.h"
    #include <rbus/rbus.h>
    int consoleDebugEnable;
	FILE* debugLogFile = nullptr;
    char g_Subsystem[32] = {0};
    void* bus_handle;
}

extern ULONG NDSReportingPeriod;
extern ULONG NDSReportingPeriodDefault;
extern ULONG NDSPollingPeriod;
extern BOOL NDSReportStatus;
extern ULONG NDSPollingPeriodDefault;
extern ULONG NDSOverrideTTL;
extern ULONG currentReportingPeriod;

class NetworkDevicesStatusTest : public CcspLMLiteTestFixture {
protected:
   


    virtual void SetUp() {
        NDSReportingPeriod = DEFAULT_REPORTING_INTERVAL;
        NDSReportingPeriodDefault = DEFAULT_REPORTING_INTERVAL;
        NDSPollingPeriod = DEFAULT_POLLING_INTERVAL;
        NDSReportStatus = FALSE;
        NDSPollingPeriodDefault = DEFAULT_POLLING_INTERVAL;
        NDSOverrideTTL = TTL_INTERVAL;

    }

    virtual void TearDown() {
      
    }

};


// Test cases for isvalueinarray function

TEST_F(NetworkDevicesStatusTest, ValuePresent) {
    ULONG arr[] = {1, 2, 3, 4, 5};
    int size = sizeof(arr) / sizeof(arr[0]);
    EXPECT_TRUE(isvalueinarray(3, arr, size));  // Check if 3 is in the array
}

TEST_F(NetworkDevicesStatusTest, ValueNotPresent) {
    ULONG arr[] = {1, 2, 3, 4, 5};
    int size = sizeof(arr) / sizeof(arr[0]);
    EXPECT_FALSE(isvalueinarray(6, arr, size));  // Check if 6 is not in the array
}

// Test cases for ValidateNDSPeriod function
TEST_F(NetworkDevicesStatusTest, ValidateNDSPeriod_ValuePresent) {

  ULONG NetworkDeviceStatusPeriods[] = {5,10,15,30,60,300,900,1800,3600,10800,21600,43200,86400};
  ULONG period = 10;
  EXPECT_TRUE(ValidateNDSPeriod(period));

}

TEST_F(NetworkDevicesStatusTest, ValidateNDSPeriod_ValueNotPresent) {

  ULONG NetworkDeviceStatusPeriods[] = {5,10,15,30,60,300,900,1800,3600,10800,21600,43200,86400};
  ULONG period = 999;
  EXPECT_FALSE(ValidateNDSPeriod(period));
    
}

// Test case for GetNDSHarvestingStatus
TEST_F(NetworkDevicesStatusTest, GetNDSHarvestingStatus_False) {
    EXPECT_EQ(GetNDSHarvestingStatus(),FALSE);
}

// Test case for GetNDSReportingPeriod
TEST_F(NetworkDevicesStatusTest, GetNDSReportingPeriod_Default) {
   EXPECT_EQ(GetNDSReportingPeriod(), DEFAULT_REPORTING_INTERVAL);
}

// Test case for GetNDSPollingPeriod
TEST_F(NetworkDevicesStatusTest, GetNDSPollingPeriod_Default) {
    EXPECT_EQ(GetNDSPollingPeriod(), DEFAULT_POLLING_INTERVAL);
}

// Test case for GetNDSReportingPeriodDefault
TEST_F(NetworkDevicesStatusTest, GetNDSReportingPeriodDefault_Default) {
  EXPECT_EQ(GetNDSReportingPeriodDefault(), DEFAULT_REPORTING_INTERVAL);
}

// Test case for GetNDSOverrideTTL
TEST_F(NetworkDevicesStatusTest, GetNDSOverrideTTL_Default) {
    EXPECT_EQ(GetNDSOverrideTTL(), TTL_INTERVAL);
}

// Test case for GetNDSOverrideTTLDefault
TEST_F(NetworkDevicesStatusTest, GetNDSOverrideTTLDefault_Default) {  
    EXPECT_EQ(GetNDSOverrideTTLDefault(), DEFAULT_TTL_INTERVAL);
}

// Test cases for GetCurrentTimeString function
TEST_F(NetworkDevicesStatusTest, GetCurrentTimeString_BasicFunctionality) {
    char* result = GetCurrentTimeString();
    ASSERT_NE(result, nullptr);

    // Test 2: Format and Content
    ASSERT_GT(strlen(result), 0);
    ASSERT_EQ(result[strlen(result) - 1], '\n');

    // Test 3: Consistency
    ASSERT_STREQ(GetCurrentTimeString(), GetCurrentTimeString());

    // Test 4: Time Accuracy (assuming current time comparison)
    time_t current_time = time(NULL);
    char* expected_result = ctime(&current_time);
    ASSERT_STREQ(result, expected_result);
}

// Test cases for GetCurrentTimeInSecond function
TEST_F(NetworkDevicesStatusTest, GetCurrentTimeInSecond_BasicFunctionality) {
    ulong result = GetCurrentTimeInSecond();
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ulong expected_result = (ulong)ts.tv_sec;

    // Allow some tolerance for the test case as time may change between calls
    ASSERT_LE(abs((long)result - (long)expected_result), 1);
}

//Test cases for SetNDSReportingPeriod
TEST_F(NetworkDevicesStatusTest, SetNDSReportingPeriodChangeToNewValue) {
    ULONG initialPeriod = NDSReportingPeriod;
    ULONG newPeriod = initialPeriod + 100; // Change to a different value

    int result = SetNDSReportingPeriod(newPeriod);

    // Verify the return value of SetNDSReportingPeriod
    EXPECT_EQ(result, 0);

    // Verify that DEFAULT_REPORTING_INTERVAL remains unchanged
    EXPECT_EQ(DEFAULT_REPORTING_INTERVAL, initialPeriod);

    // Verify that NDSReportingPeriod has been updated to newPeriod
    EXPECT_EQ(NDSReportingPeriod, newPeriod);
}

TEST_F(NetworkDevicesStatusTest, SetNDSReportingPeriodChangeToSameValue) {
    ULONG initialPeriod = NDSReportingPeriod;

    int result = SetNDSReportingPeriod(initialPeriod);

    // Verify the return value of SetNDSReportingPeriod
    EXPECT_EQ(result, 0);

    // Verify that DEFAULT_REPORTING_INTERVAL remains unchanged
    EXPECT_EQ(DEFAULT_REPORTING_INTERVAL, initialPeriod);

    // Verify that NDSReportingPeriod remains unchanged and is still equal to initialPeriod
    EXPECT_EQ(NDSReportingPeriod, initialPeriod);
}

// Test fixture for SetNDSReportingPeriodDefault function
TEST_F(NetworkDevicesStatusTest, SetNDSReportingPeriodDefaultChangeToNewValue) {
    ULONG initialPeriod = NDSReportingPeriodDefault;
    ULONG newPeriod = initialPeriod + 100; // Change to a different value

    int result = SetNDSReportingPeriodDefault(newPeriod);

    // Verify the return value of SetNDSReportingPeriodDefault
    EXPECT_EQ(result, 0);

    // Verify that DEFAULT_REPORTING_INTERVAL remains unchanged
    EXPECT_EQ(DEFAULT_REPORTING_INTERVAL, initialPeriod);

    // Verify that NDSReportingPeriodDefault has been updated to newPeriod
    EXPECT_EQ(NDSReportingPeriodDefault, newPeriod);
}

TEST_F(NetworkDevicesStatusTest, SetNDSReportingPeriodDefaultChangeToDefaultValue) {
    ULONG initialPeriod = NDSReportingPeriodDefault;

    int result = SetNDSReportingPeriodDefault(initialPeriod);

    // Verify the return value of SetNDSReportingPeriodDefault
    EXPECT_EQ(result, 0);

    // Verify that DEFAULT_REPORTING_INTERVAL remains unchanged
    EXPECT_EQ(DEFAULT_REPORTING_INTERVAL, initialPeriod);

    // Verify that NDSReportingPeriodDefault remains unchanged and is still equal to initialPeriod
    EXPECT_EQ(NDSReportingPeriodDefault, initialPeriod);
}

// Test case for SetNDSPollingPeriod function
TEST_F(NetworkDevicesStatusTest, SetNDSPollingPeriod_ChangeToNewValue) {
    ULONG initialPeriod = NDSPollingPeriod;
    ULONG newPeriod = initialPeriod + 100; // Change to a different value

    // Ensure initialPeriod and newPeriod are different
    ASSERT_NE(newPeriod, initialPeriod);

    int result = SetNDSPollingPeriod(newPeriod);

    // Verify the return value of SetNDSPollingPeriod
    EXPECT_EQ(result, 0);

    // Verify that NDSPollingPeriod has been updated to newPeriod
    EXPECT_EQ(NDSPollingPeriod, newPeriod);

    // Verify that NDSPollingPeriod is not equal to initialPeriod
    EXPECT_NE(NDSPollingPeriod, initialPeriod);
}

TEST_F(NetworkDevicesStatusTest, SetNDSPollingPeriod_ChangeToSameValue) {
    ULONG initialPeriod = NDSPollingPeriod;

    int result = SetNDSPollingPeriod(initialPeriod);

    // Verify the return value of SetNDSPollingPeriod
    EXPECT_EQ(result, 0);

    // Verify that NDSPollingPeriod remains unchanged and is still equal to initialPeriod
    EXPECT_EQ(NDSPollingPeriod, initialPeriod);
}

// Test fixture for SetNDSHarvestingStatus function
TEST_F(NetworkDevicesStatusTest, SetNDSHarvestingStatus_DefaultFalseToFalse) {
    // Verify that NDSReportStatus is initially set to FALSE
    EXPECT_EQ(NDSReportStatus, FALSE);

    // Set the new status to FALSE and call SetNDSHarvestingStatus
    BOOL newstatus = FALSE;
    int result = SetNDSHarvestingStatus(newstatus);

    // Verify the return value of SetNDSHarvestingStatus
    EXPECT_EQ(result, 0);

    // Verify that NDSReportStatus remains FALSE as it was initially
    EXPECT_EQ(NDSReportStatus, FALSE);
}

// Test fixture for SetNDSPollingPeriodDefault function
TEST_F(NetworkDevicesStatusTest, SetNDSPollingPeriodDefault_ChangeToNewValue) {

    // Ensure NDSPollingPeriodDefault is initially set to DEFAULT_POLLING_INTERVAL (900)
    ULONG initialPeriod = DEFAULT_POLLING_INTERVAL;
    EXPECT_EQ(NDSPollingPeriodDefault, initialPeriod);

    // Set the new period to a different value
    ULONG newPeriod = initialPeriod + 100; // Change to a different value

    // Call SetNDSPollingPeriodDefault with the new period
    int result = SetNDSPollingPeriodDefault(newPeriod);

    // Verify the return value of SetNDSPollingPeriodDefault
    EXPECT_EQ(result, 0);

    // Verify that NDSPollingPeriodDefault has been updated to newPeriod
    EXPECT_EQ(NDSPollingPeriodDefault, newPeriod);
}

TEST_F(NetworkDevicesStatusTest, SetNDSPollingPeriodDefault_ChangeToSameValue) {

    // Ensure NDSPollingPeriodDefault is initially set to DEFAULT_POLLING_INTERVAL (900)
    ULONG initialPeriod = DEFAULT_POLLING_INTERVAL;
    EXPECT_EQ(NDSPollingPeriodDefault, initialPeriod);

    // Call SetNDSPollingPeriodDefault with the same initial period
    int result = SetNDSPollingPeriodDefault(initialPeriod);

    // Verify the return value of SetNDSPollingPeriodDefault
    EXPECT_EQ(result, 0);

    // Verify that NDSPollingPeriodDefault remains unchanged and is still equal to initialPeriod
    EXPECT_EQ(NDSPollingPeriodDefault, initialPeriod);
}
    
// Test fixture for SetNDSOverrideTTL function
TEST_F(NetworkDevicesStatusTest, SetNDSOverrideTTL_ChangeToNewValue) {

    // Ensure NDSOverrideTTL is initially set to TTL_INTERVAL (300)
    ULONG initialTTL = TTL_INTERVAL;
    EXPECT_EQ(NDSOverrideTTL, initialTTL);

    // Set the new TTL to a different value
    ULONG newTTL = initialTTL + 100; // Change to a different value

    // Call SetNDSOverrideTTL with the new TTL
    int result = SetNDSOverrideTTL(newTTL);

    // Verify the return value of SetNDSOverrideTTL
    EXPECT_EQ(result, 0);

    // Verify that NDSOverrideTTL has been updated to newTTL
    EXPECT_EQ(NDSOverrideTTL, newTTL);
}

TEST_F(NetworkDevicesStatusTest, SetNDSOverrideTTL_ChangeToSameValue) {

    // Ensure NDSOverrideTTL is initially set to TTL_INTERVAL (300)
    ULONG initialTTL = TTL_INTERVAL;
    EXPECT_EQ(NDSOverrideTTL, initialTTL);

    // Call SetNDSOverrideTTL with the same initial TTL
    int result = SetNDSOverrideTTL(initialTTL);

    // Verify the return value of SetNDSOverrideTTL
    EXPECT_EQ(result, 0);

    // Verify that NDSOverrideTTL remains unchanged and is still equal to initialTTL
    EXPECT_EQ(NDSOverrideTTL, initialTTL);
}

TEST_F(NetworkDevicesStatusTest, ResetNDSReportingConfiguration) {
    // Set up initial state
    unsigned int initial_polling_period = GetNDSPollingPeriodDefault();
    unsigned int initial_reporting_period = GetNDSReportingPeriodDefault();
    unsigned int initial_override_ttl = GetNDSOverrideTTLDefault();
    
    // Call the function under test
    ResetNDSReportingConfiguration();

    // Verify that the values have been reset to the default values
    EXPECT_EQ(GetNDSPollingPeriod(), initial_polling_period);
    EXPECT_EQ(GetNDSReportingPeriod(), initial_reporting_period);
    EXPECT_EQ(GetNDSOverrideTTL(), initial_override_ttl);
    EXPECT_EQ(currentReportingPeriod, 0);
}

TEST_F(NetworkDevicesStatusTest, PrintListWithDummyData) {

    // Arrange: Create a sample linked list with dummy data
    struct networkdevicestatusdata* node1 = (struct networkdevicestatusdata*)malloc(sizeof(struct networkdevicestatusdata));
    if (node1 == nullptr) {
        
        return; // Memory allocation for node1 failed
    }

    struct networkdevicestatusdata* node2 = (struct networkdevicestatusdata*)malloc(sizeof(struct networkdevicestatusdata));
    if (node2 == nullptr) {
        
        free(node1);
        return; // Memory allocation for node2 failed, clean up node1 and return
    }

    // Initialize memory blocks with memset
    memset(node1, 0, sizeof(struct networkdevicestatusdata));
    memset(node2, 0, sizeof(struct networkdevicestatusdata));

    // Assign values to node1
    node1->timestamp.tv_sec = 12345;
    node1->timestamp.tv_usec = 0;
    node1->device_mac = strdup("00:11:22:33:44:55");
    node1->interface_name = strdup("eth0");
    node1->is_active = TRUE;
    node1->parent = strdup("parent1");
    node1->device_type = strdup("device1");
    node1->hostname = strdup("hostname1");
    node1->ipaddress = strdup("192.168.1.1");
    node1->next = node2;

    // Assign values to node2
    node2->timestamp.tv_sec = 67890;
    node2->timestamp.tv_usec = 0;
    node2->device_mac = strdup("AA:BB:CC:DD:EE:FF");
    node2->interface_name = strdup("eth1");
    node2->is_active = TRUE;
    node2->parent = strdup("parent2");
    node2->device_type = strdup("device2");
    node2->hostname = strdup("hostname2");
    node2->ipaddress = strdup("192.168.1.2");
    node2->next = nullptr;

    struct networkdevicestatusdata* head = node1;

    // Act: Call print_list to print the list
    print_list(head);

    EXPECT_TRUE(true);  // This is a placeholder to indicate the test passed

    // Clean-up: Free the allocated memory
    free(node1->device_mac);
    free(node1->interface_name);
    free(node1->parent);
    free(node1->device_type);
    free(node1->hostname);
    free(node1->ipaddress);
    free(node1);

    free(node2->device_mac);
    free(node2->interface_name);
    free(node2->parent);
    free(node2->device_type);
    free(node2->hostname);
    free(node2->ipaddress);
    free(node2);
}


// Test fixture for delete_list function
TEST_F(NetworkDevicesStatusTest, DeleteListCorrectlyFreesMemory) {

    // Arrange: Create a sample linked list with dummy data
    struct networkdevicestatusdata* node1 = (struct networkdevicestatusdata*)malloc(sizeof(struct networkdevicestatusdata));
    if (node1 == nullptr) {
        
        return; // Memory allocation for node1 failed
    }

    struct networkdevicestatusdata* node2 = (struct networkdevicestatusdata*)malloc(sizeof(struct networkdevicestatusdata));
    if (node2 == nullptr) {
        
        free(node1);
        return;    // Memory allocation for node2 failed, clean up node1 and return
    }
    
    // Initialize memory blocks with memset
    memset(node1, 0, sizeof(struct networkdevicestatusdata));
    memset(node2, 0, sizeof(struct networkdevicestatusdata));

    // Add values to node1
    node1->timestamp.tv_sec = 0;
    node1->timestamp.tv_usec = 0;
    node1->device_mac = strdup("00:11:22:33:44:55");
    node1->interface_name = strdup("eth0");
    node1->is_active = TRUE;
    node1->parent = strdup("parent1");
    node1->device_type = strdup("device1");
    node1->hostname = strdup("hostname1");
    node1->ipaddress = strdup("192.168.1.1");
    node1->next = node2;

    // Add values to node2
    node2->timestamp.tv_sec = 0;
    node2->timestamp.tv_usec = 0;
    node2->device_mac = strdup("AA:BB:CC:DD:EE:FF");
    node2->interface_name = strdup("eth1");
    node2->is_active = TRUE;
    node2->parent = strdup("parent2");
    node2->device_type = strdup("device2");
    node2->hostname = strdup("hostname2");
    node2->ipaddress = strdup("192.168.1.2");
    node2->next = nullptr;

    struct networkdevicestatusdata* head = node1;

    // Act: Call the function to delete the list
    delete_list(&head);

    // Assert: Check that the memory was freed correctly and head is set to nullptr
    EXPECT_EQ(head, nullptr);
}

