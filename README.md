# DCO Analytics Repository

[![Wiki.js](https://img.shields.io/badge/Platform-Wiki.js-green.svg)](https://js.wiki/)
[![Threat Intelligence](https://img.shields.io/badge/Type-Threat%20Intelligence-red.svg)](https://attack.mitre.org/)

> **Defense Cyber Operations (DCO) Analytics Repository** - A comprehensive collection of threat intelligence, detection rules, and hunting methodologies for advanced persistent threat (APT) actors and malware families.

## 🎯 Overview

This repository serves as a centralized knowledge base for cybersecurity professionals, providing actionable intelligence and detection capabilities for sophisticated threat actors including **Bazooka Tiger**, **Shotgun Tiger**, and **Steel Stoat**. The repository is designed to be deployed with Wiki.js for interactive documentation and analytics.

## 🏗️ Complete Repository Structure

```
wikijs-dco-analytics/
├── 📁 Artifacts/                    # Security tool artifacts and configurations
│   ├── 📁 Elastic Kibana/          # Kibana dashboards and queries
│   │   ├── 📁 Dashboards/          # Dashboard configurations
│   │   └── 📁 Queries/             # Elasticsearch queries
│   ├── 📁 Splunk/                  # Splunk dashboards and queries
│   │   ├── 📁 Dashboards/          # Dashboard configurations
│   │   └── 📁 Queries/             # SPL queries
│   ├── 📁 Suricata/                # Suricata rules and configurations
│   ├── 📁 Sysmon/                  # Sysmon configurations and rules
│   ├── 📁 YARA/                    # YARA rules for malware detection
│   └── 📁 Zeek/                    # Zeek scripts and configurations
├── 📁 Detections/                  # Detection rules and dashboards
│   ├── 📁 Dashboards/              # Splunk dashboards for APT hunting
│   ├── 📁 Host/                    # Host-based detection rules
│   │   └── 📁 Windows/             # Windows host detection rules
│   ├── 📁 Network/                 # Network detection rules (Suricata)
│   └── 📁 TA0001-TA0011/           # MITRE ATT&CK technique-based detections
├── 📁 Hunt_Playbooks/              # Threat hunting methodologies
│   ├── 📁 Active-Mission/          # Current hunting operations
│   ├── 📁 Pre-Mission/             # Pre-mission planning materials
│   └── 📁 Post-Mission/            # Post-mission analysis and reporting
├── 📁 IOCs/                        # Indicators of Compromise
├── 📁 Malware_Tools/               # Malware analysis and tools
│   ├── 📁 Malware/                 # Malware family analysis
│   └── 📁 Tools/                   # Attack tool analysis
├── 📁 Reference/                   # Reference materials and mappings
│   └── 📁 MITRE_Mappings/          # MITRE ATT&CK technique mappings
├── 📁 Repository_Data/             # Supporting datasets and materials
│   ├── 📁 datasets/                # Training and testing datasets
│   ├── 📁 images/                  # Screenshots and visual materials
│   ├── 📁 misc/                    # Miscellaneous supporting files
│   ├── 📁 pcaps/                   # Network packet captures
│   ├── 📁 pdfs/                    # PDF documents and reports
│   ├── 📁 suricata/                # Suricata rule files
│   └── 📁 yara/                    # YARA rule files
├── 📁 Threat_Intelligence/         # Threat actor profiles and intelligence
│   ├── 📁 Actors/                  # APT group profiles
│   ├── 📁 Campaigns/                # Campaign intelligence
│   └── 📁 Clusters/                # Threat cluster intelligence
├── 📁 Validation/                  # Validation materials and testing
│   ├── 📁 Datasets/                # Validation datasets
│   ├── 📁 Sample Data/             # Sample data for testing
│   └── 📁 Unit Tests/              # Unit tests for components
└── 📁 home/                        # Wiki.js homepage content
    └── index.md                    # Main homepage for Wiki.js instance
```

## 🚀 Wiki.js Deployment

### Deployment Options

#### Option 1: Git Sync (Recommended for Collaborative Editing)
1. **Install Wiki.js** on your server
2. **Configure Git Sync** in Wiki.js settings:
   - Set repository URL to this GitHub repository
   - Enable bidirectional sync for collaborative editing
   - Configure authentication if needed
3. **Set Homepage**: Copy `home/index.md` to project root and rename to `home.html`
4. **Configure Database**: Enable PostgreSQL for enhanced search capabilities
5. **Deploy Detection Rules** from the appropriate folders

#### Option 2: Local File System Hosting
1. **Install Wiki.js** on your server
2. **Clone Repository** to your local file system
3. **Configure Wiki.js** to use local file system storage
4. **Set Homepage**: Copy `home/index.md` to project root and rename to `home.html`
5. **Configure Database**: Enable PostgreSQL for enhanced search capabilities

### For Analysts
1. **Start with Hunt Playbooks** - Review active mission reports
2. **Deploy Detection Rules** - Import Suricata rules and Splunk dashboards  
3. **Use Reference Materials** - Consult MITRE mappings and actor profiles
4. **Monitor Dashboards** - Set up real-time monitoring with provided dashboards

### For Administrators
1. **Configure Wiki.js** - Set up proper authentication and permissions
2. **Deploy Detection Rules** - Import rules into security tools
3. **Set Up Monitoring** - Configure alerts and dashboards
4. **Manage Content** - Update and maintain repository content

## 📊 Key Features

### 🎭 Threat Actor Coverage
- **Bazooka Tiger** - Critical infrastructure targeting
- **Shotgun Tiger** - Maritime and logistics targeting  
- **Steel Stoat** - Cryptocurrency and financial targeting

### 🛡️ Detection Capabilities
- **Network Detection** - Suricata rules for network monitoring
- **Host Detection** - Windows event log analysis
- **SIEM Integration** - Splunk dashboards and queries
- **Cloud Support** - KQL queries for Microsoft Sentinel

### 🦠 Malware Analysis
- **15+ Malware Families** - Comprehensive analysis
- **Custom Tools** - Attack tool documentation
- **IOCs** - Indicators of compromise

## 📚 Navigation Guide

### 🏹 Hunt Playbooks
- **[Bazooka Tiger Hunt Report](Hunt_Playbooks/Active-Mission/Bazooka_Tiger/Hunt_Report.md)** - Complete hunting guide for BT activities
- **[Shotgun Tiger Hunt Report](Hunt_Playbooks/Active-Mission/Shotgun_Tiger/Hunt_Report.md)** - Maritime and logistics targeting detection
- **[Steel Stoat Hunt Report](Hunt_Playbooks/Active-Mission/Steel_Stoat/Hunt_Report.md)** - North Korean threat actor hunting

### 🛡️ Detections
- **[Network Detections](Detections/Network/)** - Suricata rules for network traffic analysis
- **[Host Detections](Detections/Host/)** - Windows host-based detection rules
- **[Dashboards](Detections/Dashboards/)** - Splunk dashboards for APT hunting

### 🦠 Malware & Tools
- **[Malware Families](Malware_Tools/Malware/)** - In-depth analysis of APT malware
- **[Tools](Malware_Tools/Tools/)** - Analysis of commonly used attack tools

### 🎭 Threat Intelligence
- **[Threat Actors](Threat_Intelligence/Actors/)** - Detailed profiles of APT groups

### 📖 Reference Materials
- **[MITRE Mappings](Reference/MITRE_Mappings/)** - MITRE ATT&CK technique mappings
- **[Generic References](Reference/)** - General reference materials

## 🛠️ Tools & Technologies

### Detection Platforms
- **Suricata** - Network intrusion detection
- **Splunk** - Security information and event management
- **Microsoft Sentinel** - Cloud-native SIEM
- **Windows Event Logs** - Host-based detection

### Analysis Tools
- **YARA** - Malware detection rules
- **MITRE ATT&CK** - Threat modeling framework
- **MISP** - Threat intelligence sharing

## 📈 Repository Statistics

- **Threat Actors**: 3 major APT groups
- **Malware Families**: 15+ analyzed malware families
- **Detection Rules**: 50+ Suricata rules
- **Hunting Queries**: 30+ Splunk and KQL queries
- **MITRE Techniques**: 100+ mapped techniques

## 🔧 Wiki.js Integration

> **Note**: The `home/index.md` file serves as the homepage for the Wiki.js instance. This repository is designed to be deployed with Wiki.js using Git Sync functionality, allowing for real-time updates and collaborative editing.

### Setup Instructions
1. **Install Wiki.js** on your server
2. **Configure Git Sync** to point to this repository
3. **Set Homepage** to `/home/index.md`
4. **Enable Auto-sync** for real-time updates

## 🤝 Contributing

This repository is designed to be a living document that evolves with the threat landscape. Contributions are welcome in the following areas:
- New threat actor profiles
- Additional detection rules
- Enhanced hunting methodologies
- Updated IOCs and TTPs

> **Security Notice**: This repository contains sensitive threat intelligence. Please ensure proper handling and distribution controls are in place before sharing.
