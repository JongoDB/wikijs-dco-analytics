# TA0007 - Discovery

This directory contains detection rules and hunting queries for MITRE ATT&CK technique TA0007 (Discovery).

## Overview

Discovery consists of techniques an adversary may use to gain knowledge about the system and internal network.

## Techniques Covered

- **T1083** - File and Directory Discovery
- **T1016** - System Network Configuration Discovery
- **T1049** - System Network Connections Discovery
- **T1033** - System Owner/User Discovery
- **T1018** - Remote System Discovery

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

