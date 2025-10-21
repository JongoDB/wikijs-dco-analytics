# YARA Artifacts

This directory contains YARA rules for malware detection and classification.

## Structure

- **Rules/** - YARA rule files (.yar)
- **Categories/** - Rule categories and organization
- **Scripts/** - YARA utility scripts

## Usage

### Rules
YARA rules provide malware detection capabilities:
- Deploy rules to YARA scanner
- Configure rule categories and priorities
- Monitor detection performance

### Categories
Rule organization includes:
- Malware family rules
- Behavioral detection rules
- Packer and obfuscation detection
- Threat actor specific rules

## Contributing

When adding new artifacts:
1. Test rules against known samples
2. Include rule documentation
3. Follow YARA syntax standards
4. Provide false positive considerations
