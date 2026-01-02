# Comprehensive GUI Analysis Prompt

Launch **5 parallel agents** to perform a comprehensive audit of the Intellicrack GUI codebase. Each agent will focus on a specific logical section and produce a detailed findings report.

---

## Agent Assignments

| Agent | Section | Primary Focus Areas |
|-------|---------|---------------------|
| **Agent 1** | **Main Window & Core UI** | `main_window.py`, `main_app.py`, `ui_manager.py`, menu systems, toolbar, status bars |
| **Agent 2** | **Dialogs & Wizards** | All files in `ui/dialogs/` - dialog functionality, wizard flows, modal windows |
| **Agent 3** | **Widgets & Components** | All files in `ui/widgets/` - custom widgets, reusable components, data displays |
| **Agent 4** | **Tabs & Panels** | All files in `ui/tabs/` - tab implementations, panel layouts, content areas |
| **Agent 5** | **Integration & Handlers** | UI integration files, event handlers, backend connections (`*_integration.py`, `*_handlers.py`) |

---

## Analysis Criteria (Each Agent Must Check)

### 1. Dead Code & Placeholders
- Buttons/actions with `pass`, `...`, or empty handlers
- Menu items that do nothing when clicked
- Functions returning hardcoded/dummy values
- Comments like `TODO`, `FIXME`, `NotImplemented`, `placeholder`
- Methods that only log/print without actual functionality

### 2. Frontend-Backend Disconnections
- UI elements not connected to any backend logic
- Backend functions with no UI trigger points
- Signal/slot connections that are defined but never used
- Event handlers that don't call core functionality

### 3. Broken Bindings & Missing Implementations
- Buttons bound to non-existent methods
- Missing method definitions referenced in UI setup
- Incomplete inheritance chains
- Abstract methods not implemented in subclasses

### 4. UI/UX Issues
- Widgets that never get updated/refreshed
- Progress bars that don't reflect actual progress
- Status displays showing static/fake data
- Dialogs that can't be closed properly
- Missing error handling for user actions

### 5. Import & Dependency Issues
- Circular imports affecting UI
- Unused imports cluttering files
- Missing imports causing runtime failures
- Incorrect import paths

---

## Output Requirements

Each agent writes findings to `GUI{AgentNumber}.md` in the project root with the following format:

```markdown
# GUI Analysis Report - Agent {N}: {Section Name}

## Summary
- Total files analyzed: X
- Critical issues: X
- Major issues: X
- Minor issues: X

## Critical Issues (Broken/Non-functional)

### Issue 1: [Title]
- **File**: `path/to/file.py`
- **Line(s)**: XX-XX
- **Description**: What's wrong
- **Code snippet**: The problematic code
- **Recommended fix**: How to resolve

## Major Issues (Placeholders/Disconnected)
...

## Minor Issues (Code quality/cleanup)
...

## Files Analyzed
- List of all files reviewed with status
```

---

## Final Compilation

After all agents complete, compile all findings into `GUI_MASTER_TODO.md`:

- Deduplicated list of all issues
- Prioritized by severity (Critical > Major > Minor)
- Grouped by fix type:
  - Backend connection needed
  - Implementation needed
  - Cleanup required
- Estimated effort indicators:
  - Quick fix (< 30 min)
  - Moderate (1-4 hours)
  - Complex (> 4 hours)
- Cross-references to original agent reports

---

## Execution Command

```
Launch 5 parallel agents using the Task tool with subagent_type="Explore" or "general-purpose".
Each agent receives their specific section assignment and analysis criteria.
All agents run concurrently for maximum efficiency.
```
