# TA0003 - Persistence

This directory contains detection rules and hunting queries for MITRE ATT&CK technique TA0003 (Persistence).

## Overview

Persistence consists of techniques that adversaries use to maintain access to systems across restarts, changed credentials, and other interruptions that could cut off their access.

## Techniques Covered

- **T1543** - Create or Modify System Process
- **T1547** - Boot or Logon Autostart Execution
- **T1136** - Create Account
- **T1053** - Scheduled Task/Job
- **T1505** - Server Software Component
- **T1098** - Account Manipulation

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

