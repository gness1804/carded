# CFS Initialization

This project uses CFS (Cursor File Structure) to manage instruction documents.

## Structure

- `.cursor/rules/` - Cursor rules documents (.mdc files)
- `.cursor/features/` - Feature request documents
- `.cursor/bugs/` - Bug report documents
- `.cursor/refactors/` - Refactoring task documents
- `.cursor/docs/` - Documentation task documents
- `.cursor/research/` - Research task documents
- `.cursor/progress/` - Progress and handoff documents
- `.cursor/qa/` - QA task documents
- `.cursor/security/` - Security-related documents
- `.cursor/tmp/` - Temporary documents

## Usage

```bash
cfs instructions features create  # Create a feature request
cfs instructions bugs create       # Create a bug report
cfs instructions view              # View all documents
cfs gh sync                        # Sync with GitHub issues
```
