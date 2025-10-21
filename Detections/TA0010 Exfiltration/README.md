# TA0010 - Exfiltration

This directory contains detection rules and hunting queries for MITRE ATT&CK technique TA0010 (Exfiltration).

## Overview

Exfiltration consists of techniques that adversaries may use to steal data from your network.

## Techniques Covered

- **T1041** - Exfiltration Over C2 Channel
- **T1048** - Exfiltration Over Alternative Protocol
- **T1020** - Automated Exfiltration
- **T1011** - Exfiltration Over Other Network Medium
- **T1052** - Exfiltration Over Physical Medium

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

