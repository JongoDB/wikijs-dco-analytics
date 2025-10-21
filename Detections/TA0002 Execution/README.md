# TA0002 - Execution

This directory contains detection rules and hunting queries for MITRE ATT&CK technique TA0002 (Execution).

## Overview

Execution consists of techniques that result in adversary-controlled code running on a local or remote system. Techniques that run malicious code are often paired with techniques from all other tactics to achieve broader goals.

## Techniques Covered

- **T1059** - Command and Scripting Interpreter
- **T1059.001** - PowerShell
- **T1059.003** - Windows Command Shell
- **T1059.005** - Visual Basic
- **T1059.006** - Python
- **T1059.007** - JavaScript
- **T1106** - Native API
- **T1569** - System Services
- **T1204** - User Execution
- **T1047** - Windows Management Instrumentation

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
