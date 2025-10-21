# DCO Analytics Repository

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Wiki.js](https://img.shields.io/badge/Platform-Wiki.js-green.svg)](https://js.wiki/)
[![Threat Intelligence](https://img.shields.io/badge/Type-Threat%20Intelligence-red.svg)](https://attack.mitre.org/)

> **Defense Cyber Operations (DCO) Analytics Repository** - A comprehensive collection of threat intelligence, detection rules, and hunting methodologies for advanced persistent threat (APT) actors and malware families.

## 🎯 Overview

This repository serves as a centralized knowledge base for cybersecurity professionals, providing actionable intelligence and detection capabilities for sophisticated threat actors including **Bazooka Tiger**, **Shotgun Tiger**, and **Steel Stoat**. The repository is designed to be deployed with Wiki.js for interactive documentation and analytics.

## 🏗️ Repository Structure

```
wikijs-dco-analytics/
├── 📁 Detections/                    # Detection rules and dashboards
│   ├── 📁 Dashboards/               # Splunk dashboards for APT hunting
│   ├── 📁 Host/                     # Host-based detection rules
│   └── 📁 Network/                 # Network detection rules (Suricata)
├── 📁 Hunt_Playbooks/              # Active threat hunting methodologies
│   └── 📁 Active-Mission/          # Current hunting operations
├── 📁 Malware_Tools/               # Malware analysis and tools
│   ├── 📁 Malware/                 # Malware family analysis
│   └── 📁 Tools/                   # Attack tool analysis
├── 📁 Reference/                   # Reference materials and mappings
│   └── 📁 MITRE_Mappings/          # MITRE ATT&CK technique mappings
├── 📁 Threat_Intelligence/         # Threat actor profiles
│   └── 📁 Actors/                  # APT group profiles
└── 📁 home/                        # Wiki.js homepage content
    └── index.md                    # Main homepage for Wiki.js instance
```

## 🚀 Quick Start

### For Wiki.js Deployment
1. **Clone this repository** to your Wiki.js instance
2. **Configure Git Sync** in Wiki.js to pull from this repository
3. **Access the homepage** at `/home/index.md` for the main navigation
4. **Deploy detection rules** from the appropriate folders

### For Analysts
1. **Start with Hunt Playbooks** - Review active mission reports
2. **Deploy Detection Rules** - Import Suricata rules and Splunk dashboards  
3. **Use Reference Materials** - Consult MITRE mappings and actor profiles

### For Hunters
1. **Review Threat Actor Profiles** - Understand TTPs and capabilities
2. **Deploy Hunting Queries** - Use provided Splunk and KQL queries
3. **Monitor Dashboards** - Set up real-time monitoring

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

## 📞 Support

For questions, issues, or contributions, please refer to the documentation in each section or contact the DCO Analytics Team.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Last Updated**: January 20, 2025  
**Version**: 1.0.0  
**Maintainer**: DCO Analytics Team

> **Security Notice**: This repository contains sensitive threat intelligence. Please ensure proper handling and distribution controls are in place before sharing.
