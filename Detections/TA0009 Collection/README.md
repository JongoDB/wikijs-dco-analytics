# TA0009 - Collection

This directory contains detection rules and hunting queries for MITRE ATT&CK technique TA0009 (Collection).

## Overview

Collection consists of techniques adversaries may use to gather information and the sources information is collected from.

## Techniques Covered

- **T1005** - Data from Local System
- **T1039** - Data from Network Shared Drive
- **T1025** - Data from Removable Media
- **T1114** - Email Collection
- **T1115** - Clipboard Data

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
