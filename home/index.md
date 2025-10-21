---
title: DCO Analytics Repository
type: homepage
last_reviewed: 2025-01-20
---

# DCO Analytics Repository

Welcome to the Defense Cyber Operations (DCO) Analytics Repository, a comprehensive collection of threat intelligence, detection rules, and hunting methodologies for advanced persistent threat (APT) actors and malware families.

## 🎯 Mission

This repository serves as a centralized knowledge base for cybersecurity professionals, providing actionable intelligence and detection capabilities for sophisticated threat actors including Bazooka Tiger, Shotgun Tiger, and Steel Stoat.

## 📚 Repository Structure

### 🏹 Hunt Playbooks
Comprehensive hunting methodologies and playbooks for active threat actor missions:
- **[Bazooka Tiger Hunt Report](../Hunt_Playbooks/Active-Mission/Bazooka_Tiger/Hunt_Report.md)** - Complete hunting guide for BT activities
- **[Shotgun Tiger Hunt Report](../Hunt_Playbooks/Active-Mission/Shotgun_Tiger/Hunt_Report.md)** - Maritime and logistics targeting detection
- **[Steel Stoat Hunt Report](../Hunt_Playbooks/Active-Mission/Steel_Stoat/Hunt_Report.md)** - North Korean threat actor hunting

### 🛡️ Detections
Network and host-based detection rules and dashboards:
- **[Network Detections](../Detections/Network/)** - Suricata rules for network traffic analysis
- **[Host Detections](../Detections/Host/)** - Windows host-based detection rules
- **[Dashboards](../Detections/Dashboards/)** - Splunk dashboards for APT hunting
- **[Catalogs](../Detections/Catalogs/)** - Reference catalogs for security tools

### 🦠 Malware & Tools
Detailed analysis of malware families and tools:
- **[Malware Families](../Malware_Tools/Malware/)** - In-depth analysis of APT malware
- **[Tools](../Malware_Tools/Tools/)** - Analysis of commonly used attack tools

### 🎭 Threat Intelligence
Actor profiles and threat intelligence:
- **[Threat Actors](../Threat_Intelligence/Actors/)** - Detailed profiles of APT groups

### 📖 Reference Materials
Comprehensive reference documentation:
- **[MITRE Mappings](../Reference/MITRE_Mappings/)** - MITRE ATT&CK technique mappings
- **[Generic References](../Reference/)** - General reference materials

## 🚀 Quick Start

### For Analysts
1. **Start with Hunt Playbooks** - Review active mission reports for your target threat actors
2. **Deploy Detection Rules** - Import Suricata rules and Splunk dashboards
3. **Use Reference Materials** - Consult MITRE mappings and actor profiles

### For Administrators
1. **Review Threat Actor Profiles** - Understand TTPs and capabilities
2. **Deploy Hunting Queries** - Use provided Splunk and KQL queries
3. **Monitor Dashboards** - Set up real-time monitoring with provided dashboards
4. **Implement Detection Rules** - Deploy network and host detection rules
5. **Review Mitigation Strategies** - Apply recommended security controls
6. **Monitor IOCs** - Track indicators of compromise

## 🔍 Key Features

### Comprehensive Coverage
- **Multiple Threat Actors**: Bazooka Tiger, Shotgun Tiger, Steel Stoat
- **Diverse Malware**: Custom malware families and commodity tools
- **Full Attack Lifecycle**: From initial access to data exfiltration

### Actionable Intelligence
- **Ready-to-Deploy Rules**: Suricata rules and Splunk queries
- **Hunting Playbooks**: Step-by-step hunting methodologies
- **IOCs**: Indicators of compromise for immediate deployment

### Cross-Platform Support
- **Network Detection**: Suricata rules for network monitoring
- **Host Detection**: Windows event log analysis
- **SIEM Integration**: Splunk dashboards and queries
- **Cloud Support**: KQL queries for Microsoft Sentinel

## 📊 Repository Statistics

- **Threat Actors**: 3 major APT groups
- **Malware Families**: 15+ analyzed malware families
- **Detection Rules**: 50+ Suricata rules
- **Hunting Queries**: 30+ Splunk and KQL queries
- **MITRE Techniques**: 100+ mapped techniques

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

## 📈 Getting Started

### 1. Choose Your Target
Select the threat actor or malware family you want to hunt for:
- **Bazooka Tiger** - Critical infrastructure targeting
- **Shotgun Tiger** - Maritime and logistics targeting
- **Steel Stoat** - Cryptocurrency and financial targeting

### 2. Deploy Detection Rules
Import the appropriate detection rules for your environment:
- Network detection rules for Suricata
- Host detection rules for Windows systems
- SIEM queries for Splunk or Sentinel

### 3. Set Up Monitoring
Deploy dashboards and alerts for continuous monitoring:
- Real-time APT hunting dashboards
- Automated alerting for suspicious activities
- Regular reporting and analysis

### 4. Conduct Hunting
Use the provided hunting playbooks to conduct targeted threat hunting:
- Follow step-by-step methodologies
- Use provided queries and rules
- Document findings and share intelligence

## 🤝 Contributing

This repository is designed to be a living document that evolves with the threat landscape. Contributions are welcome in the following areas:
- New threat actor profiles
- Additional detection rules
- Enhanced hunting methodologies
- Updated IOCs and TTPs

> **Note**: This repository contains sensitive threat intelligence. Please ensure proper handling and distribution controls are in place before sharing.
