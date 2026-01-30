#!/usr/bin/env bash
set -e

################################################################################
# Native Build Wrapper Script
# Verifies build tools and runs build_native.sh
# Usage: ./run_native_build.sh
# Note: run_setup_dependencies.sh should be executed first
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NATIVE_COMPONENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_TOOLS_DIR="$NATIVE_COMPONENT_DIR/build_tools_workflows"

# Basic logging functions
log() { echo "[INFO] $*"; }
ok() { echo "[OK] $*"; }
err() { echo "[ERROR] $*" >&2; }

echo ""
echo "===== Native Build Pipeline ====="
echo ""

# Verify build_tools_workflows exists (should be cloned by run_setup_dependencies.sh)
if [[ ! -d "$BUILD_TOOLS_DIR" ]]; then
    err "build_tools_workflows directory not found. Please run run_setup_dependencies.sh first."
    exit 1
fi

if [[ ! -f "$BUILD_TOOLS_DIR/cov_docker_script/build_native.sh" ]]; then
    err "build_native.sh not found in build_tools_workflows. Please run run_setup_dependencies.sh first."
    exit 1
fi

log "Build script found, proceeding with build..."

# Run build_native.sh from build_tools_workflows
echo ""
log "Running build_native.sh from build_tools_workflows..."
cd "$NATIVE_COMPONENT_DIR"
"$BUILD_TOOLS_DIR/cov_docker_script/build_native.sh" "$SCRIPT_DIR/component_config.json" "$NATIVE_COMPONENT_DIR"

echo ""
ok "Native build completed successfully!"

# Cleanup build_tools_workflows directory
log "Cleaning up build_tools_workflows directory..."
rm -rf "$BUILD_TOOLS_DIR"
ok "Cleanup completed"

echo ""
