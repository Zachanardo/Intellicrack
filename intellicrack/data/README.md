# Data Directory

This directory contains data files used by Intellicrack for analysis,
signatures, templates, and persistent storage.

## Contents

### Signature Files

- `protocol_signatures.json` - Protocol signatures for network analysis
- `signature_templates.py` - Template system for signature generation

### Database Files

- `c2_sessions.db` - SQLite database for C2 session storage

### Rule Files

- `yara_rules/` - Directory containing YARA rules for malware detection and
  analysis

### Templates

- `templates/` - Analysis and report templates

## Purpose

These files support various Intellicrack features:

- Network protocol analysis
- C2 session management
- Malware detection using YARA rules
- Template-based analysis and reporting

## Security Note

Some files may contain sensitive data. Ensure proper permissions and backup
important databases regularly.
