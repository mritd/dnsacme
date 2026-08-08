# Project Guidance

## Project Memory System

This project maintains institutional knowledge in `docs/project_notes/` for consistency across sessions.

### Memory Files

- `bugs.md`: Bug log with dates, solutions, and prevention notes
- `decisions.md`: Architectural Decision Records with context and trade-offs
- `key_facts.md`: Non-sensitive project configuration and constants
- `issues.md`: Work log with ticket references

### Memory-Aware Protocols

- Before proposing architectural changes, check `docs/project_notes/decisions.md` and acknowledge any conflicting decision.
- When diagnosing bugs, search `docs/project_notes/bugs.md` for related issues and record durable solutions after they are verified.
- When looking up project configuration, prefer documented facts in `docs/project_notes/key_facts.md` over assumptions.
- When completing ticketed work, add a concise dated entry to `docs/project_notes/issues.md`.
- When the user requests a memory update, update the appropriate file using its existing format.

### Style Guidelines

- Prefer concise bullet lists over tables.
- Include dates for temporal context.
- Include issue or documentation URLs when available.
- Never store credentials or other secret values in project memory.
