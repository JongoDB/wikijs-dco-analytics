# TA0006 - Credential Access

This directory contains detection rules and hunting queries for MITRE ATT&CK technique TA0006 (Credential Access).

## Overview

Credential Access consists of techniques for stealing credentials like account names and passwords.

## Techniques Covered

- **T1003** - OS Credential Dumping
- **T1555** - Credentials from Password Stores
- **T1110** - Brute Force
- **T1056** - Input Capture
- **T1552** - Unsecured Credentials

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

