#!/usr/bin/env bash
set -e

################################################################################
# External Build Wrapper Script
# Verifies build tools and runs common_external_build.sh
# Usage: ./run_external_build.sh
# Note: run_setup_dependencies.sh should be executed first
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NATIVE_COMPONENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_TOOLS_REPO_URL="https://github.com/rdkcentral/build_tools_workflows"
BUILD_TOOLS_DIR="$NATIVE_COMPONENT_DIR/build_tools_workflows"

# Basic logging functions
log() { echo "[INFO] $*"; }
ok() { echo "[OK] $*"; }
err() { echo "[ERROR] $*" >&2; }

echo ""
echo "===== External Build Pipeline ====="
echo ""

# Clone build_tools_workflows if it doesn't exist
if [[ ! -d "$BUILD_TOOLS_DIR" ]]; then
    log "build_tools_workflows not found, cloning repository..."
    cd "$NATIVE_COMPONENT_DIR"
    git clone -b develop "$BUILD_TOOLS_REPO_URL" || { err "Clone failed"; exit 1; }
    ok "Repository cloned successfully"
else
    log "build_tools_workflows already exists"
fi

if [[ ! -f "$BUILD_TOOLS_DIR/cov_docker_script/common_external_build.sh" ]]; then
    err "common_external_build.sh not found in build_tools_workflows. Please run run_setup_dependencies.sh first."
    exit 1
fi

log "Build script found, proceeding with build..."

# Run common_external_build.sh from build_tools_workflows
echo ""
log "Running common_external_build.sh from build_tools_workflows..."
cd "$NATIVE_COMPONENT_DIR"
"$BUILD_TOOLS_DIR/cov_docker_script/common_external_build.sh" "$SCRIPT_DIR/component_config.json" "$NATIVE_COMPONENT_DIR"

echo ""
ok "External build completed successfully!"

echo ""
