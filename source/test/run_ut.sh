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

# Clone or enter RdkbGMock
if [ -d "RdkbGMock" ]; then
    log "INFO" "RdkbGMock directory already exists. Skipping clone."
    cd RdkbGMock
else
    log "INFO" "Cloning RdkbGMock repository from GitHub..."
    # Use token for authentication if provided
    if git clone -b "develop" "https://github.com/rdkcentral/gmock-broadband.git" RdkbGMock; then
        cd RdkbGMock
    else
        log "ERROR" "Failed to clone repository with branch: develop"
        exit 1
    fi
fi

# Check if a pull request ID is provided in argument 1
if [ -n "$1" ]; then
    pr_id="$1"
    log "INFO" "Fetching PR ID: $pr_id and checking out FETCH_HEAD"
    if git fetch "https://github.com/rdkcentral/gmock-broadband.git" pull/"$pr_id"/head && git checkout FETCH_HEAD; then
        log "INFO" "Successfully checked out PR #$pr_id"
    else
        log "ERROR" "Failed to fetch or checkout PR #$pr_id"
        exit 1
    fi
else
    log "INFO" "No PR ID provided. Fetching latest from branch: develop"
    if git fetch "https://github.com/rdkcentral/gmock-broadband.git" develop && git checkout develop; then
        log "INFO" "Checked out latest branch: develop"
    else
        log "ERROR" "Failed to fetch or checkout branch: develop"
        exit 1
    fi
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
log "INFO" "Running configure with options --enable-unitTestDockerSupport..."
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
    source "RdkbGMock/docker_scripts/export_var.sh"
    log "INFO" "C_INCLUDE_PATH is set to: $C_INCLUDE_PATH"
    log "INFO" "CPLUS_INCLUDE_PATH is set to: $CPLUS_INCLUDE_PATH"
fi

log "INFO" "Preparing to run the Gtest Binary"
# Generic function to build and run all gtest binaries under source/test and its subfolders
run_all_gtests() {
    local test_dirs
    local make_dir
    local bin_files
    local bin_file

    # Only include directories that contain a Makefile and do not contain makefile or GNUmakefile
    test_dirs=( $(find source/test -type f -name 'Makefile' -exec dirname {} \; | sort -u) )

    for make_dir in "${test_dirs[@]}"; do
        log "INFO" "Running make in $make_dir..."
        if make -C "$make_dir"; then
            log "INFO" "Make operation completed successfully in $make_dir."
        else
            log "ERROR" "Make operation failed in $make_dir."
            exit 1
        fi
    done

    log "INFO" "Completed running all make operations."

    # Find all .bin files under source/test and its subfolders
    bin_files=( $(find source/test -type f -name "*.bin") )

    if [[ ${#bin_files[@]} -eq 0 ]]; then
        log "ERROR" "No .bin files found under source/test, cannot run tests"
        exit 1
    fi

    for bin_file in "${bin_files[@]}"; do
        if [[ -x "$bin_file" ]]; then
            log "INFO" "Running $(basename "$bin_file")"
            "$bin_file"
            log "INFO" "Completed Test Execution for $(basename "$bin_file")"
        else
            log "ERROR" "$(basename "$bin_file") is not executable, skipping"
        fi
    done
}

# Call the generic function to build and run all gtest binaries
run_all_gtests
log "INFO" "Completed running all Gtest Binaries"

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
