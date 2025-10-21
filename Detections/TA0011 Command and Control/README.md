# TA0011 - Command and Control

This directory contains detection rules and hunting queries for MITRE ATT&CK technique TA0011 (Command and Control).

## Overview

Command and Control consists of techniques that adversaries may use to communicate with systems under their control within a victim network.

## Techniques Covered

- **T1071** - Application Layer Protocol
- **T1090** - Proxy
- **T1092** - Communication Through Removable Media
- **T1102** - Web Service
- **T1104** - Multi-Stage Channels

## Detection Rules

This directory contains:
- **Suricata Rules** - Network-based detection
- **Splunk Queries** - SIEM-based detection
- **YARA Rules** - Malware detection
- **Sysmon Rules** - Host-based detection

## Usage

1. **Deploy Detection Rules** - Import rules into your security tools
2. **Configure Monitoring** - Set up alerts and dashboards
3. **Conduct Hunting** - Use provided queries for threat hunting
4. **Review IOCs** - Monitor for known indicators

## Contributing

When adding new detection rules:
1. Test rules in lab environment
2. Include rule documentation
3. Provide false positive guidance
4. Update technique mappings

