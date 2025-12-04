# CcspLMLite Documentation

CcspLMLite (LAN Manager Lite) is the RDK-B component responsible for managing and monitoring LAN-side network devices and hosts connected to the gateway. This component serves as the primary interface for discovering, tracking, and reporting network connectivity status, device information, and traffic analytics for connected devices across WiFi, Ethernet, and MoCA interfaces. LMLite provides comprehensive host management capabilities including device discovery, presence detection, network traffic monitoring, and telemetry reporting. It implements TR-181 data model parameters for hosts management and integrates with WebPA for cloud-based management and monitoring. CcspLMLite acts as a centralized hub for collecting network device information from various sources and presenting a unified view through standardized TR-181 interfaces.

CcspLMLite enables features like parental controls, device management, network analytics, and presence-based automation by maintaining real-time awareness of all connected devices and their network activity patterns.

```mermaid
graph LR
    subgraph "External Systems"
        RemoteMgmt["Remote Management"]
        LocalUI["Local Web UI"]
    end

    subgraph "RDK-B Platform"
        subgraph "Remote Management Agents"
            ProtocolAgents["Protocol Agents<br>( TR-069, WebPA, USP etc.)"]
        end

        PNM["CCSP P&M"]
        PSM["CCSP PSM"]
		Lmlite["LMLite"]
        Onewifi["One Wi-Fi"]
        WanMgr["WAN Manager"]

        subgraph "Platform Layer"
            HAL["Platform HAL"]
            Linux["Linux"]
        end
    end

    %% External connections
    RemoteMgmt -->|TR-069/WebPA/TR-369| ProtocolAgents
    LocalUI -->|HTTP/HTTPS| ProtocolAgents

    %% Upper layer to LM Lite
    ProtocolAgents -->|IPC| Lmlite

    %% Lmlite to Other RDK-B Components
    Lmlite -->|IPC| PNM
    Lmlite -->|IPC| PSM
    Lmlite -->|IPC| Onewifi
    Lmlite -->|IPC| WanMgr

    %% Interface Managers to HAL
    Lmlite <-->|HAL APIs| HAL

    %% System integration
    HAL <-->|Driver Interfaces| Linux
    Lmlite <-->|System Events| Linux

    classDef external fill:#fff3e0,stroke:#ef6c00,stroke-width:2px;
    classDef LmLite fill:#e3f2fd,stroke:#1976d2,stroke-width:3px;
    classDef rdkbComponent fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px;
    classDef system fill:#fce4ec,stroke:#c2185b,stroke-width:2px;

    class RemoteMgmt,LocalUI external;
    class Lmlite LmLite;
    class ProtocolAgents,PNM,PSM,Onewifi,WanMgr rdkbComponent;
    class HAL,Linux system;
```

**Key Features & Responsibilities**: 

- **Host Discovery & Management**: Automatically discovers and tracks all devices connected to LAN interfaces including WiFi, Ethernet, and MoCA with real-time status monitoring and device profiling capabilities
- **Network Traffic Analytics**: Collects and reports detailed network traffic statistics per device including bandwidth usage, connection patterns, and performance metrics for capacity planning and troubleshooting
- **Device Presence Detection**: Implements presence detection algorithms using multiple detection methods to determine device online/offline status with configurable sensitivity and notification capabilities  
- **TR-181 Data Model Implementation**: Provides comprehensive TR-181 compliant interface for Device.Hosts object hierarchy enabling standardized access to host information through BBF-specified parameters
- **Cross-Interface Synchronization**: Coordinates device information across multiple network interfaces ensuring consistent device tracking and preventing duplicate entries across WiFi, MoCA, and Ethernet connections


## Design

CcspLMLite follows a modular, event-driven architecture designed to efficiently manage network device discovery, monitoring, and reporting across network interfaces. The design emphasizes scalability, real-time responsiveness, and data consistency while maintaining minimal system resource utilization. The architecture separates ownership between device discovery, data model management, telemetry reporting, and external communications through well-defined interfaces and protocols.

The component operates as a central aggregation point for network device information, collecting data from multiple sources including WiFi association events, DHCP lease notifications, ARP table monitoring, and interface-specific discovery mechanisms. The design implements intelligent caching and synchronization strategies to maintain accurate device state information while minimizing network scanning overhead. Event-driven updates ensure real-time responsiveness to network changes while batch processing optimizes telemetry data transmission and reduces system load.

The northbound interface provides TR-181 compliant access through RBus messaging, enabling seamless integration with other RDK-B components and external management systems. The southbound interface abstracts network interface interactions through HAL APIs and system-level networking calls. Data persistence is achieved through integration with the Persistent Storage Manager (PSM) ensuring device information survives system reboots. WebPA integration enables cloud-based management and telemetry reporting following industry-standard protocols and data formats including Avro serialization for efficient data transmission.

```mermaid
graph TD
    subgraph LmLite ["CCSP LMLite"]
        subgraph MainManager ["LM Core Engine"]
            LMMain[Device Discovery & Management]
            LMUtil[Utility & Helper Functions]
        end
        
        subgraph DataModel ["Data Models"]
            MgmtDML[DML Management]
        end

        subgraph ReportsModule ["Network Reports & Analytics"]
            ReportsInternal[Reports Module]
            NDStatus[NW Device Status]
            NDTraffic[NW Device Traffix]
            WANTraffic[WAN Traffic]
        end

    end

    subgraph ExternalSystems ["External Systems"]
        rdkbComponents[Other RDK-B Components]
        PSM[(CCSP PSM)]
    end

    LMMain --> DataModel
    DataModel <--> rdkbComponents
    
    PSM --> LMMain  
    
    LMMain --> ReportsInternal
    ReportsInternal --> NDStatus
    ReportsInternal --> NDTraffic
    ReportsInternal --> WANTraffic

```

### Prerequisites and Dependencies

**Build-Time Flags and Configuration:**

| Configure Option | DISTRO Feature | Build Flag | Purpose | Default |
|------------------|----------------|------------|---------|---------|
| `--enable-core-net-lib-feature-support` | N/A | `CORE_NET_LIB_FEATURE_SUPPORT` | Enable advanced networking library support | Disabled |

<br>

**RDK-B Platform and Integration Requirements:**

* **RDK-B Components**: `CcspPandM` , `CcspPsm` , `CcspCommonLibrary`
* **HAL Dependencies**: WiFi HAL APIs, Ethernet HAL interfaces
* **Systemd Services**: `CcspCrSsp.service`, `CcspPsmSsp.service` must be active before `CcspLMLite.service` starts
* **Message Bus**: RBus registration under `com.cisco.spvtg.ccsp.lmlite` namespace for performance optimization and inter-component communication
* **TR-181 Data Model**: `Device.Hosts` object hierarchy and `Device.ManagementServer.ManageableDevice` support for device management and reporting
* **Configuration Files**: `LMLite.xml` for TR-181 parameter definitions; component configuration files located in `/usr/ccsp/lmlite/`
* **Startup Order**: Initialize after network interfaces are active and PSM services are running

<br>

**Threading Model:** 

CcspLMLite implements a multi-threaded architecture designed to handle concurrent network monitoring, data processing, and external communications without blocking critical operations.

- **Threading Architecture**: Multi-threaded with main event loop and specialized worker threads for different operational domains
- **Main Thread**: Handles TR-181 parameter requests, RBus message processing, and component lifecycle management
- **Main worker Threads**: 
  - **Network Scanner Thread**: Performs periodic network interface scanning and device discovery operations
  - **Presence Detection Thread**: Monitors device connectivity status and triggers presence change notifications
- **Synchronization**: Uses mutex locks for shared data structures, condition variables for thread communication, and atomic operations for counters

### Component State Flow

**Initialization to Active State**

CcspLMLite follows a structured initialization sequence ensuring all dependencies are properly established before entering active monitoring mode. The component performs configuration loading, TR-181 parameter registration, network interface discovery, and external service connections in a predetermined order to guarantee system stability and data consistency.


```mermaid
sequenceDiagram
    autonumber
    participant System
    participant ConfigLoader
    participant TR181
    participant DependencyManager
    participant EventHandler
    participant NetworkMonitor

    System->>System: Start [*] → Initializing
    Note right of System: Initialize logging system<br>Load component configuration<br>Setup IPC connections

    System->>ConfigLoader: Component Start → LoadingConfig
    Note right of ConfigLoader: Load LMLite.XML<br>Parse configuration files<br>Initialize default values<br>Validate settings

    ConfigLoader->>TR181: Configuration Loaded → RegisteringTR181
    Note right of TR181: Register Device.Hosts objects<br>Create TR-181 data model<br>Setup parameter bindings<br>Initialize DML handlers

    TR181->>DependencyManager: Data Models Registered → ConnectingDeps
    Note right of DependencyManager: Connect to PSM<br>Establish RBus connection<br>Connect to WiFi/MoCA HAL<br>Initialize network interfaces

    DependencyManager->>System: All Systems Ready → Active
    Note right of System: Process TR-181 requests<br>Monitor network devices<br>Generate telemetry data<br>Handle device discovery<br>Monitor device health

    System->>EventHandler: Network Event → RuntimeStateChange
    EventHandler->>NetworkMonitor: Process Device Event
    NetworkMonitor->>NetworkMonitor: Update Device State
    NetworkMonitor->>EventHandler: State Update Complete
    EventHandler->>System: State Updated → Active

    System->>System: Component Stop → Shutdown → [*]
```

**Runtime State Changes and Context Switching**

During normal operation, CcspLMLite responds to various network events and configuration changes that may affect its operational context and device tracking behavior.

**State Change Triggers:**

- Network interface up/down events causing rescan of device discovery mechanisms
- Configuration parameter changes affecting scanning intervals, presence detection sensitivity, or telemetry settings  
- External service availability changes (PSM reconnection, WebPA service restart) requiring connection re-establishment
- Resource constraint conditions triggering degraded mode operation with reduced scanning frequency

**Context Switching Scenarios:**

- Interface priority changes when primary network interface fails, switching to backup scanning methods
- Discovery mode transitions between active scanning and passive monitoring based on network load conditions
- Telemetry reporting context switches between real-time and batch modes based on cloud connectivity status

### Call Flow

**Initialization Call Flow:**

```mermaid
sequenceDiagram
    participant Init as Initialization Process
    participant Comp as CcspLMLite
    participant DM as Data Model
    participant Deps as Dependencies

    Init->>Comp: Start Component
    Comp->>Comp: Load Configuration
    Comp->>DM: Register TR-181 Parameters
    DM-->>Comp: Registration Complete
    Comp->>Deps: Connect to Dependencies
    Deps-->>Comp: Connection Established
    Comp->>Init: Initialization Complete (Active State)
```

**Request Processing Call Flow:**

```mermaid
sequenceDiagram
    participant Client as External Client
    participant LMWrapper as LM Wrapper
    participant LMMain as LM Main Engine  
    participant HostsDML as Hosts DML
    participant NetworkScan as Network Scanner
    participant AvroTelemetry as Avro Telemetry

    Client->>LMWrapper: Get Device.Hosts.HostNumberOfEntries
    LMWrapper->>LMMain: Process Host Count Request
    LMMain->>HostsDML: GetHostCount()
    HostsDML->>NetworkScan: Scan Network Interfaces
    NetworkScan->>NetworkScan: Discover Active Devices
    NetworkScan-->>HostsDML: Return Device List
    HostsDML->>HostsDML: Update Host Entries
    HostsDML->>AvroTelemetry: Send Network Status Event
    HostsDML-->>LMMain: Return Host Count
    LMMain-->>LMWrapper: Host Count Result
    LMWrapper-->>Client: Response (Host Count)
```

## TR‑181 Data Models

### Supported TR-181 Parameters

CcspLMLite implements comprehensive TR-181 data model support for device and host management following BBF TR-181 Issue 2 specifications. The component provides both standard BBF-defined parameters and vendor-specific extensions to support advanced RDK-B features including presence detection, network analytics, and cross-interface device correlation.

### Object Hierarchy

```
Device.
└── Hosts.
    ├── HostNumberOfEntries (unsignedInt, R)
    ├── X_CISCO_COM_ConnectedDeviceNumber (unsignedInt, R)
    ├── X_CISCO_COM_ConnectedWiFiNumber (unsignedInt, R)
    ├── X_RDKCENTRAL-COM_HostVersionId (unsignedInt, R)
    ├── X_RDKCENTRAL-COM_HostCountPeriod (unsignedInt, R/W)
    ├── X_RDKCENTRAL-COM_LMHost_Sync (unsignedInt, R/W)
    ├── X_RDKCENTRAL-COM_LMHost_Sync_From_MoCA (string, R/W)
    ├── X_RDKCENTRAL-COM_LMHost_Sync_From_WiFi (string, R/W)
    ├── X_RDKCENTRAL-COM_EthHost_Sync (string, R/W)
    ├── X_RDK_PresenceDetectEnable (boolean, R/W)
    ├── X_RDKCENTRAL-COM_WebPA_PresenceNotificationEnable (boolean, R/W)
    └── Host.{i}.
        ├── Alias (string, R/W)
        ├── PhysAddress (string, R)
        ├── IPAddress (string, R) 
        ├── DHCPClient (string, R)
        ├── AssociatedDevice (string, R)
        ├── Layer1Interface (string, R)
        ├── Layer3Interface (string, R)
        ├── HostName (string, R)
        ├── Active (boolean, R)
        ├── X_CISCO_COM_LastChange (dateTime, R)
        ├── X_CISCO_COM_RSSILevel (int, R)
        ├── X_RDKCENTRAL-COM_DeviceType (string, R)
        ├── X_RDKCENTRAL-COM_NetworkInterface (string, R)
        ├── X_RDKCENTRAL-COM_ConnectionStatus (string, R)
        ├── X_RDKCENTRAL-COM_OSType (string, R)
        └── X_RDKCENTRAL-COM_Parent (string, R)

Device.
└── ManagementServer.
    └── ManageableDevice.{i}.
        ├── Alias (string, R/W)
        ├── ManufacturerOUI (string, R)
        ├── SerialNumber (string, R)
        ├── ProductClass (string, R)
        └── Host (string, R)
```


## Internal Modules

CcspLMLite is organized into specialized modules responsible for different aspects of network device management, data model implementation, and external communications. Each module encapsulates specific functionality while maintaining clear interfaces for inter-module communication and data sharing.

| Module/Class | Description | Key Files |
|-------------|------------|-----------|
| **LM Core Engine** | Main orchestration engine managing device discovery, host tracking, and component lifecycle with centralized state management and event coordination | `lm_main.c`, `lm_main.h`, `lm_util.c`, `lm_wrapper.c` |
| **Hosts Data Model** | TR-181 Device.Hosts object implementation providing standardized interface for device information access with parameter validation and change notifications | `cosa_hosts_dml.c`, `cosa_hosts_dml.h`, `cosa_xhosts_dml.c` |
| **Network Analytics** | Traffic monitoring and device behavior analysis module collecting bandwidth statistics, connection patterns, and performance metrics for telemetry reporting | `network_devices_traffic.c`, `network_devices_status.c`, `cosa_reports_internal.c` |
| **Management Server** | ManageableDevice TR-181 object implementation tracking devices eligible for remote management with capability discovery and configuration synchronization | `cosa_managementserver_dml.c`, `cosa_managementserver_apis.c` |
| **Service Support Platform** | Process lifecycle management and message bus initialization providing component entry point, configuration loading, and system integration services | `ssp_main.c`, `ssp_messagebus_interface.c`, `ssp_action.c` |

## Component Interactions

CcspLMLite maintains extensive interactions with RDK-B middleware components, system services, and external management systems to provide comprehensive network device management and monitoring capabilities. These interactions span multiple protocols and communication patterns including synchronous API calls, asynchronous event notifications, and data synchronization mechanisms.

### Interaction Matrix

| Target Component/Layer | Interaction Purpose | Key APIs/Endpoints |
|------------------------|-------------------|------------------|
| **RDK-B Middleware Components** |
| CcspPandM | TR-181 parameter registration and access control, configuration management | `registerCapabilities`, `getParameterValues`, `setParameterValues` |
| OneWifi | WiFi device association/disassociation events, wireless client enumeration | `Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.*`, WiFi HAL callbacks |
| CcspMoCAAgent | MoCA network topology changes, node status updates, device discovery | `Device.MoCA.Interface.{i}.AssociatedDevice.{i}.*` |
| CcspPsm | Persistent device information storage, configuration parameter backup | `PSM_Set_Record_Value2()`, `PSM_Get_Record_Value2()` |
| **System & HAL Layers** |
| Network HAL | Network interface enumeration, device discovery, link status monitoring | `hal_get_dhcp_clients()`, `hal_get_arp_table()`, interface status APIs |
| Linux Network Stack | ARP table monitoring, network interface status, routing table access | `/proc/net/arp`, `ioctl(SIOCGARP)`, netlink sockets |


**Major events Published by CcspLMLite:**

| Event Name | Event Topic/Path | Trigger Condition | Subscriber Components |
|------------|-----------------|-------------------|---------------------|
| Device_Discovery | `Device.Hosts.HostNumberOfEntriesChange` | New device detected on network | CcspPandM, WebPA, Telemetry Services |
| Device_Presence | `Device.Hosts.Host.{i}.ActiveChange` | Device online/offline status change | Parental Control, OneWifi, WebPA |
| Network_Analytics | `LMLite.NetworkDeviceTraffic` | Periodic traffic statistics collection | Telemetry Collection, Analytics Services |
| Configuration_Change | `LMLite.ConfigurationUpdate` | Runtime configuration parameter modification | Configuration Management, Logging Services |

### IPC Flow Patterns

**Primary IPC Flow - Device Discovery and Status Update:**

```mermaid
sequenceDiagram
    participant WiFiAgent as OneWifi
    participant LMLite as CcspLMLite
    participant PSM as CcspPsm
    participant WebPA as WebPA Service
    participant Telemetry as Telemetry

   OneWifi->>LMLite: Device Association Event (RBus)
    LMLite->>LMLite: Update Device Table
    LMLite->>PSM: Store Device Information
    PSM-->>LMLite: Storage Confirmation
    LMLite->>WebPA: Presence Notification
    LMLite->>Telemetry: Device Analytics Data
    LMLite-->>OneWifi: Event Processing Complete
```

**Event Notification Flow:**

```mermaid
sequenceDiagram
    participant HAL as Network HAL
    participant LMLite as CcspLMLite
    participant PandM as CcspPandM
    participant Sub1 as Subscriber 1
    participant Sub2 as Subscriber 2

    HAL->>LMLite: Network Interface Event
    LMLite->>LMLite: Process Device Discovery
    LMLite->>PandM: Publish Parameter Change Event
    PandM->>Sub1: Event Notification (RBus)
    PandM->>Sub2: Event Notification (RBus)
    Sub1-->>LMLite: Ack (if required)
    Sub2-->>LMLite: Ack (if required)
```

## Implementation Details

### Major HAL APIs Integration

CcspLMLite integrates with multiple HAL interfaces to collect comprehensive network device information across different interface types. The component abstracts hardware-specific implementations through standardized HAL APIs while maintaining flexibility for platform-specific optimizations.

**Core HAL APIs:**

| HAL API | Purpose | Implementation File |
|---------|---------|-------------------|
| `wifi_getAssociatedDeviceDetail()` | Retrieve detailed information about WiFi-connected devices including signal strength, capabilities, and connection statistics | `lm_main.c`, network interface handlers |
| `moca_GetAssociatedDevices()` | Enumerate MoCA network nodes and retrieve topology information including preferred network coordinator and transmission rates | `lm_main.c`, MoCA discovery functions |
| `dhcp_get_client_info()` | Access DHCP server lease table for IP address assignments, hostname information, and lease duration data | `lm_util.c`, DHCP client enumeration |
| `ethernet_hal_get_param()` | Query Ethernet interface status, link speed, duplex mode, and physical connection state | `network_devices_interface.c` |


### Key Implementation Logic

- **Device Discovery Engine**: Multi-threaded scanning system combining active probing, passive monitoring, and event-driven updates with intelligent caching to minimize network overhead while maintaining real-time device tracking accuracy. Periodic ARP table scanning with configurable intervals (15-300 seconds). DHCP lease monitoring through file system watchers and HAL callbacks. Interface-specific discovery protocols (WiFi association events, MoCA topology changes). State transition handlers implementing device lifecycle management with timeout-based cleanup.
  
- **Event Processing**: Asynchronous event handling system managing device state changes, network topology updates, and external service communications with guaranteed delivery and retry mechanisms. Event queue management with priority-based processing for critical network changes. Rate limiting and deduplication for high-frequency events (WiFi roaming, signal fluctuations). Asynchronous telemetry data transmission with batching and compression optimization.
  
- **Error Handling Strategy**: Comprehensive error detection and recovery mechanisms ensuring system stability during network disruptions, HAL failures, and resource constraints. Automatic retry logic with exponential backoff for transient network errors. Graceful degradation during resource exhaustion with priority-based service reduction. Health monitoring and self-recovery capabilities including automatic component restart. Timeout handling and retry logic with configurable parameters for different operation types.
  
- **Logging & Debugging**: Multi-level logging system with runtime verbosity control and specialized debugging tools for network device tracking and performance analysis. Structured logging with JSON formatting for automated log analysis and monitoring. Real-time debugging interfaces for troubleshooting device discovery issues and network connectivity problems. Debug hooks providing detailed trace information for device state transitions, HAL interactions, and IPC communications. Performance monitoring with metrics collection for response times, memory usage, and network scanning efficiency.

### Key Configuration Files

| Configuration File | Purpose | Override Mechanisms |
|--------------------|---------|---------------------|
| `LMLite.XML`       | TR-181 parameter definitions and DML function mappings | Component compilation flags, runtime XML updates |
| `lmlite.conf`      | Runtime configuration parameters and operational settings | Environment variables, systemd overrides |
| `presence_detection.ini` | Advanced presence detection algorithm parameters | TR-181 parameter interface, configuration API |
