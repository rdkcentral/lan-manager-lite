# Component Native Build Configuration

**Coverity/Native build configuration for RDK-B components.**

---

## 📋 Overview

This directory contains the configuration and wrapper scripts necessary for building RDK-B components in a native (non-Yocto) environment. This setup enables Coverity static analysis and validates that components can be built with explicitly declared dependencies.

### Directory Contents

```
<your-component>/cov_docker_script/
├── README.md                      # This file
├── component_config.json          # Dependency & build configuration
├── configure_options.conf         # Autotools configure flags (optional)
├── run_setup_dependencies.sh      # Wrapper: Setup build tools & dependencies
└── run_native_build.sh           # Wrapper: Setup build tools & build component
```

### Important: Add to .gitignore

Add the following to your component's `.gitignore` to exclude temporary build artifacts:

```gitignore
# Build tools (downloaded by wrapper scripts)
build_tools_workflows/

# Dependency build artifacts
build/
```

---

## 🚀 Quick Start

### Prerequisites

- Docker container with [docker-rdk-ci](https://github.com/rdkcentral/docker-rdk-ci) image
- All wrapper scripts have execute permissions

### Build Commands

#### Complete Build Pipeline

```bash
# From your component root directory
cd /path/to/your-component

# Run complete build pipeline
./cov_docker_script/run_setup_dependencies.sh
./cov_docker_script/run_native_build.sh

# Clean build (removes previous artifacts)
CLEAN_BUILD=true ./cov_docker_script/run_setup_dependencies.sh
./cov_docker_script/run_native_build.sh
```

#### Individual Steps

```bash
# Step 1: Setup dependencies only
./cov_docker_script/run_setup_dependencies.sh

# Step 2: Build component only (requires Step 1 completed)
./cov_docker_script/run_native_build.sh
```

---

## 📖 Scripts Reference

### 1. run_setup_dependencies.sh

**Purpose:** Sets up build tools and runs dependency setup.

**What it does:**
1. Clones `build_tools_workflows` repository (develop branch)
2. Verifies required scripts are present
3. Runs `setup_dependencies.sh` from build_tools_workflows with config path to:
   - Clone all dependency repositories
   - Copy headers to `$HOME/usr/include/rdkb/`
   - Build and install dependency libraries
4. Leaves build_tools_workflows in place for run_native_build.sh

**Usage:**
```bash
./run_setup_dependencies.sh

# Clean build
CLEAN_BUILD=true ./run_setup_dependencies.sh
```

**Required files:**
- `component_config.json` (defines dependencies)

**Outputs:**
- Downloads: `$HOME/build/` (dependency repositories)
- Headers: `$HOME/usr/include/rdkb/`
- Libraries: `$HOME/usr/local/lib/`, `$HOME/usr/lib/`
- build_tools_workflows: Remains in place for run_native_build.sh

**Environment Variables:**
- `BUILD_DIR` - Override build directory (default: `$HOME/build`)
- `USR_DIR` - Override install directory (default: `$HOME/usr`)
- `CLEAN_BUILD` - Set to `true` to remove previous builds

---

### 2. run_native_build.sh

**Purpose:** Verifies build tools and builds the component.

**What it does:**
1. Verifies `build_tools_workflows` directory exists (cloned by `run_setup_dependencies.sh`)
2. Verifies `build_native.sh` is present
3. Runs `build_native.sh` from build_tools_workflows with config and component paths to:
   - Apply patches to source code
   - Configure build environment
   - Build component
   - Install libraries
4. Cleans up build_tools_workflows directory

**Usage:**
```bash
./run_native_build.sh
```

**Prerequisites:**
- `run_setup_dependencies.sh` must be run first (to clone build_tools_workflows)
- All dependency headers/libraries must be available

**Required files:**
- `component_config.json` (defines component build settings)
- `configure_options.conf` (autotools configuration)

**Outputs:**
- Component libraries in `$HOME/usr/local/lib/`
- Build artifacts in component root directory

---

## 📝 Configuration Files

### component_config.json

**JSON configuration defining all dependencies and build settings.**

**Key Sections:**

1. **dependencies.repos[]** - External dependencies required by your component
   ```json
   {
     "name": "rbus",
     "repo": "https://github.com/rdkcentral/rbus.git",
     "branch": "v2.7.0",
     "header_paths": [...],
     "build": {...}
   }
   ```

2. **native_component** - Component build configuration
   ```json
   {
     "name": "your-component",
     "build": {
       "type": "autotools",
       "configure_options_file": "cov_docker_script/configure_options.conf"
     }
   }
   ```

**Example Dependencies:**
Your component may require dependencies such as:
- rbus
- rdk_logger
- safec
- common-library
- halinterface
- And other component-specific dependencies

See [component_config.json](component_config.json) for your component's specific dependency configuration.

---

### configure_options.conf

**Autotools configuration file with preprocessor, compiler, and linker flags.**

**Format:**
```properties
[CPPFLAGS]
-I$HOME/usr/include/rdkb/
-DFEATURE_FLAG

[CFLAGS]
-Wall -Wextra

[LDFLAGS]
-L$HOME/usr/local/lib/
```

**Sections:**
- `[CPPFLAGS]` - Preprocessor flags (includes `-I`, defines `-D`)
- `[CFLAGS]` - C compiler flags
- `[CXXFLAGS]` - C++ compiler flags
- `[LDFLAGS]` - Linker flags (library paths `-L`, linker options `-Wl`)

**Component-Specific Flags:**
Customize flags based on your component's requirements:
- Platform defines: `_COSA_INTEL_USG_ARM_`, `_COSA_BCM_ARM_`, etc.
- Product defines: `_XB6_PRODUCT_REQ_`, `_XB7_PRODUCT_REQ_`, etc.
- Feature flags: `FEATURE_SUPPORT_RDKLOG`, component-specific features, etc.

See [configure_options.conf](configure_options.conf) for your component's complete flag list.

---

## 🔧 Build System Architecture

```
┌─────────────────────────────────────────────────────┐
│         run_setup_dependencies.sh                   │
│  ┌──────────────────────────────────────────────┐   │
│  │ 1. Clone build_tools_workflows               │   │
│  │    (develop branch)                       │   │
│  │                                               │   │
│  │ 2. Verify required scripts present           │   │
│  │                                               │   │
│  │ 3. Run setup_dependencies.sh from            │   │
│  │    build_tools_workflows with config path    │   │
│  │    - Read component_config.json              │   │
│  │    - Clone dependency repos                  │   │
│  │    - Copy headers                            │   │
│  │    - Build & install libraries               │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│         run_native_build.sh                         │
│  ┌──────────────────────────────────────────────┐   │
│  │ 1. Verify build_tools_workflows exists       │   │
│  │    (cloned by run_setup_dependencies.sh)     │   │
│  │                                               │   │
│  │ 2. Run build_native.sh from                  │   │
│  │    build_tools_workflows with config and     │   │
│  │    component directory paths                 │   │
│  │    - Process component headers               │   │
│  │    - Apply source patches (if configured)    │   │
│  │    - Read configure_options.conf             │   │
│  │    - Configure build (autogen/configure)     │   │
│  │    - Build component (make/cmake/meson)      │   │
│  │    - Install libraries                       │   │
│  │                                               │   │
│  │ 3. Cleanup build_tools_workflows directory   │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

---

## 🐛 Troubleshooting

### Build Failures

**Problem:** Missing headers

```bash
# Solution: Check if dependencies were installed
ls -la $HOME/usr/include/rdkb/

# Verify component_config.json has correct header_paths
cat component_config.json | jq '.dependencies.repos[].header_paths'

# Re-run dependency setup
CLEAN_BUILD=true ./cov_docker_script/run_setup_dependencies.sh
```

**Problem:** Missing libraries

```bash
# Solution: Check library installation
ls -la $HOME/usr/local/lib/
ls -la $HOME/usr/lib/

# Verify PKG_CONFIG_PATH
echo $PKG_CONFIG_PATH

# Check if dependency build failed
cd $HOME/build/<dependency-name>
cat config.log  # For autotools
cat build/meson-log.txt  # For meson
```

**Problem:** Configure errors

```bash
# Solution: Check configure_options.conf syntax
cat cov_docker_script/configure_options.conf

# Verify flags are valid
./configure --help
```

### Script Errors

**Problem:** Script not found

```bash
# Solution: Ensure scripts are executable
chmod +x cov_docker_script/*.sh

# Check if build_tools_workflows was cloned
ls -la ../build_tools_workflows/
```

**Problem:** Permission denied

```bash
# Solution: Fix container permissions
# (Run on host, not in container)
sudo docker exec rdkb-builder groupadd $USER --gid=$(id -g $USER)
sudo docker exec rdkb-builder useradd -m $USER -G users \
  --uid=$(id -u $USER) --gid=$(id -g $USER)
```

---

## 📚 Related Documentation

- **Build Tools Repository:** [build_tools_workflows](https://github.com/rdkcentral/build_tools_workflows/tree/develop)
- **Docker Environment:** [docker-rdk-ci](https://github.com/rdkcentral/docker-rdk-ci)
- **Example Component:** [moca-agent](https://github.com/rdkcentral/moca-agent) (reference implementation)
- **Detailed Build Guide:** See `build_tools_workflows/cov_docker_script/README.md`

---

## ⚠️ Important Notes

### DO NOT Modify

The following scripts are automatically copied from `build_tools_workflows` and **must not be modified locally**:

- ❌ `build_native.sh`
- ❌ `common_build_utils.sh`
- ❌ `common_external_build.sh`
- ❌ `setup_dependencies.sh`

Any changes will be overwritten when wrapper scripts run.

### DO Modify

The following files are component-specific and **should be customized**:

- ✅ `component_config.json` - Dependency and build configuration
- ✅ `configure_options.conf` - Autotools flags
- ✅ `run_setup_dependencies.sh` - Wrapper script (if needed)
- ✅ `run_native_build.sh` - Wrapper script (if needed)

---

## 🔄 Workflow Integration

### Local Development

```bash
# Make changes to source code
vim source/your_component.c

# Rebuild component
CLEAN_BUILD=true ./cov_docker_script/run_native_build.sh
```

### CI/CD Integration

This configuration is used by GitHub Actions to validate builds:

```yaml
- name: Setup Dependencies
  run: ./cov_docker_script/run_setup_dependencies.sh

- name: Build Component
  run: ./cov_docker_script/run_native_build.sh
```

See `.github/workflows/` for complete CI configuration.

---

## 📞 Support

For issues or questions:

1. Check [Troubleshooting](#troubleshooting) section
2. Review [build_tools_workflows README](https://github.com/rdkcentral/build_tools_workflows/blob/develop/cov_docker_script/README.md)
3. Raise issue in your component repository or [build_tools_workflows](https://github.com/rdkcentral/build_tools_workflows/issues)

---

**Last Updated:** January 2026
