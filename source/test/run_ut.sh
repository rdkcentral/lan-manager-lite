#!/bin/bash
####################################################################################
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:
#
# Copyright 2024 RDK Management
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
####################################################################################
# Define the logging function
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo " "
    echo "[$timestamp] $level: $message"
    echo " "
}

# Initialize branch variable with an if-else statement
branch=${BRANCH:-stable2}
log "INFO" "Using branch: $branch"

# Check if RdkbGMock directory already exists
if [ -d "RdkbGMock" ]; then
    log "INFO" "RdkbGMock directory already exists. Skipping clone."
    cd RdkbGMock
else
    log "INFO" "RdkbGMock directory does not exist. Cloning repository..."
    if git clone ssh://gerrit.teamccp.com:29418/rdk/rdkb/components/opensource/ccsp/RdkbGMock/generic RdkbGMock -b "$branch"; then
        log "INFO" "Entering into RdkbGMock directory..."
        cd RdkbGMock
    else
        log "ERROR" "Failed to clone RdkbGMock repository."
        exit 1
    fi
fi

# Check if change number/revision is provided for RdkbGMock
if [ -n "$1" ]; then
    change_revision=$1
    change_number=$(echo $change_revision | cut -d'/' -f1)
    revision=$(echo $change_revision | cut -d'/' -f2)
    last_two_digits=${change_number: -2}

    log "INFO" "Fetching and cherry-picking changes..."
    if git fetch ssh://gerrit.teamccp.com:29418/rdk/rdkb/components/opensource/ccsp/RdkbGMock/generic refs/changes/"$last_two_digits"/"$change_number"/"$revision" && git cherry-pick FETCH_HEAD; then
        log "INFO" "Changes fetched and cherry-picked successfully."
    else
        log "ERROR" "Failed to fetch and cherry-pick changes."
        exit 1
    fi
else
    log "INFO" "No change number/revision provided, skipping git fetch and cherry-pick."
fi

log "INFO" "Start Running RdkbGMock Dependency Component Script..."
if ./docker_scripts/run_dependency.sh; then
    log "INFO" "Done Running RdkbGMock Dependency Component Script."
else
    log "ERROR" "Failed to run RdkbGMock Dependency Component Script."
    cd ..
    exit 1
fi

log "INFO" "Coming out of RdkbGMock directory"
cd ..

log "INFO" "Start Running UT Script..."
# Run autogen.sh
log "INFO" "Running autogen.sh..."
if ./autogen.sh; then
    log "INFO" "autogen.sh executed successfully."
else
    log "ERROR" "Failed to run autogen.sh"
    exit 1
fi

# Run configure with specific options
log "INFO" "Running configure with option --enable-unitTestDockerSupport..."
if ./configure --enable-unitTestDockerSupport; then
    log "INFO" "Configuration successful."
else
    log "ERROR" "Configuration failed."
    exit 1
fi

# Check if the export_var.sh file exists in the current working directory
if [ ! -f "${PWD}/RdkbGMock/docker_scripts/export_var.sh" ]; then
    log "ERROR" "RdkbGMock/docker_scripts/export_var.sh does not exist in the directory $PWD."
    exit 1
else
    # Source the export_var.sh script from the current working directory
    source "RdkbGMock/docker_scripts/export_var.sh"

    # Log the paths set by the sourced script
    log "INFO" "C_INCLUDE_PATH is set to: $C_INCLUDE_PATH"
    log "INFO" "CPLUS_INCLUDE_PATH is set to: $CPLUS_INCLUDE_PATH"
fi

# Run make for specific target
log "INFO" "Running make for CcspLMLite_gtest.bin..."
if make -C source/test; then
    log "INFO" "Make operation completed successfully."
else
    log "ERROR" "Make operation failed."
    exit 1
fi
log "INFO" "Completed running UT script."

log "INFO" "Preparing to run the Gtest Binary"
if [ -f "./source/test/CcspLMLite_gtest.bin" ]; then
    log "INFO" "Running CcspLMLite_gtest.bin"
    ./source/test/CcspLMLite_gtest.bin
    log "INFO" "Completed Test Execution"
else
    log "ERROR" "CcspLMLite_gtest.bin does not exist, cannot run tests"
    exit 1
fi

log "INFO" "Starting Gcov for code coverage analysis"
# Capture initial coverage data
if lcov --directory . --capture --output-file coverage.info; then
    log "INFO" "Initial coverage data captured successfully"
else
    log "ERROR" "Failed to capture initial coverage data"
    exit 1
fi

# Removing unwanted coverage paths
if lcov --remove coverage.info "${PWD}/source/test/*" --output-file coverage.info && \
   lcov --remove coverage.info "$HOME/usr/*" --output-file coverage.info && \
   lcov --remove coverage.info "/usr/*" --output-file coverage.info; then
    log "INFO" "Filtered out test and system library coverage data"
else
    log "ERROR" "Failed to filter coverage data"
    exit 1
fi

log "INFO" "List the coverage.info"
if lcov --list coverage.info; then
    log "INFO" "coverage.info list"
else
    log "ERROR" "Failed to list the coverage data"
    exit 1
fi

# Generating HTML report
if genhtml coverage.info --output-directory out; then
    log "INFO" "Gcov report generated in 'out' directory"
else
    log "ERROR" "Failed to generate Gcov report"
    exit 1
fi
log "INFO" "Completed Gcov report analysis"

log "INFO" "All operations completed for UT successfully"
