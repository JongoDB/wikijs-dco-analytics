# TA0005 - Defense Evasion

This directory contains detection rules and hunting queries for MITRE ATT&CK technique TA0005 (Defense Evasion).

## Overview

Defense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise.

## Techniques Covered

- **T1562** - Impair Defenses
- **T1070** - Indicator Removal
- **T1027** - Obfuscated Files or Information
- **T1055** - Process Injection
- **T1218** - Signed Binary Proxy Execution

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

