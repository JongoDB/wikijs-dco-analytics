# TA0008 - Lateral Movement

This directory contains detection rules and hunting queries for MITRE ATT&CK technique TA0008 (Lateral Movement).

## Overview

Lateral Movement consists of techniques that adversaries use to enter and control remote systems on a network.

## Techniques Covered

- **T1021** - Remote Services
- **T1078** - Valid Accounts
- **T1550** - Use Alternate Authentication Material
- **T1021.001** - Remote Desktop Protocol
- **T1021.002** - SMB/Windows Admin Shares

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
