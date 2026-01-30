#!/usr/bin/env bash
set -e

################################################################################
# Setup Dependencies Wrapper Script
# Sets up build tools and runs setup_dependencies.sh
# Usage: ./run_setup_dependencies.sh
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NATIVE_COMPONENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_TOOLS_REPO_URL="https://github.com/rdkcentral/build_tools_workflows"
BUILD_TOOLS_DIR="$NATIVE_COMPONENT_DIR/build_tools_workflows"
REQUIRED_SCRIPTS=("build_native.sh" "common_build_utils.sh" "common_external_build.sh" "setup_dependencies.sh")

# Basic logging functions
log() { echo "[INFO] $*"; }
ok() { echo "[OK] $*"; }
err() { echo "[ERROR] $*" >&2; }

echo ""
echo "===== Setup Dependencies Pipeline ====="
echo ""

# Setup build tools
log "Setting up build tools..."

# Clone build_tools_workflows
if [[ -d "$BUILD_TOOLS_DIR" ]]; then
    log "build_tools_workflows already exists, skipping clone"
else
    log "Cloning build_tools_workflows (develop)"
    cd "$NATIVE_COMPONENT_DIR"
    git clone -b develop "$BUILD_TOOLS_REPO_URL" || { err "Clone failed"; exit 1; }
    ok "Repository cloned"
fi

# Verify required scripts
[[ ! -d "$BUILD_TOOLS_DIR/cov_docker_script" ]] && { err "cov_docker_script not found"; exit 1; }

log "Verifying required scripts..."
MISSING=()
for script in "${REQUIRED_SCRIPTS[@]}"; do
    [[ -f "$BUILD_TOOLS_DIR/cov_docker_script/$script" ]] || MISSING+=("$script")
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    err "Missing scripts: ${MISSING[*]}"
    exit 1
fi
ok "All required scripts found"

# Verify setup_dependencies.sh exists before running
if [[ ! -f "$BUILD_TOOLS_DIR/cov_docker_script/setup_dependencies.sh" ]]; then
    err "setup_dependencies.sh not found in build_tools_workflows"
    exit 1
fi

# Run setup_dependencies.sh from build_tools_workflows
echo ""
log "Running setup_dependencies.sh from build_tools_workflows..."
cd "$NATIVE_COMPONENT_DIR"
"$BUILD_TOOLS_DIR/cov_docker_script/setup_dependencies.sh" "$SCRIPT_DIR/component_config.json"

echo ""
echo "[OK] Dependencies setup completed successfully!"
echo ""
