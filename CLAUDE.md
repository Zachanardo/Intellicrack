# Intellicrack - AI Assistant Context

## Project Overview

**Intellicrack** - Advanced binary analysis and security research platform designed to help software developers identify and strengthen vulnerabilities in their own licensing and protection systems.

### Project Intent & Security Research Purpose

This tool is developed for **defensive security research** to help software developers:

- **Identify weaknesses** in their own licensing protection mechanisms by using Intellicrack in a controlled enviornment to exploit their software, so they can strengthen the licensing protections to prevent future attacks.
- **Test robustness** of their protection implementations in controlled environments
- **Strengthen defenses** against potential attacks by understanding attack vectors
- **Validate security** of their own software before deployment

**Critical Context:** Intellicrack requires functionally real and robust analysis and exploitation capabilities to serve as an effective security research tool. All components must be production-ready to accurately assess protection mechanisms and provide meaningful security insights to developers working to improve their software's defensive posture.

**Usage Environment:** This tool operates exclusively in controlled, isolated research environments for authorized security assessment of proprietary software by its own developers and security teams.

## 🚨 MANDATORY RESPONSE FORMAT 🚨

**CRITICAL: EVERY Claude response MUST begin with these EXACT 5 principles. NO EXCEPTIONS.**

### ⚡ RESPONSE TEMPLATE - COPY THIS EXACTLY ⚡

```
=== INTELLICRACK PRINCIPLES ===
[1] ALL code must be production-ready with genuine functionality - absolutely NO placeholders, stubs, mocks, or simulated implementations
[2] Code must be error-free and strictly adhere to language-specific coding standards and best practices
[3] Real-world binary analysis and exploitation capabilities for defeating modern software protections are ESSENTIAL to Intellicrack's effectiveness as a security research tool
[4] Write production-ready code for every task - implement solutions directly without automated scripts unless specifically requested
[5] Claude must display all 5 principles verbatim at start of every response in this exact format
=== END PRINCIPLES ===

[Your actual response begins here]
```

**ENFORCEMENT RULES:**
1. **BEFORE ANY OTHER TEXT**: The principles block MUST appear first
2. **EXACT FORMAT**: Copy the text block character-for-character
3. **NO VARIATIONS**: Do not summarize, paraphrase, or modify
4. **EVERY RESPONSE**: This applies to ALL responses, including:
   - Code explanations
   - Questions
   - Error messages
   - Single-word answers
   - Everything

**VERIFICATION**: If principles are missing or incorrect, the response is INVALID and must be restarted.

## 🔄 AUTO-RESUME TASK INSTRUCTIONS
<!-- CLAUDE MUST READ AND EXECUTE THIS SECTION AUTOMATICALLY -->
**IF THIS SECTION EXISTS, CLAUDE MUST:**

1. Check if ACTIVE_TASK.md exists
2. If it exists, read it and continue the task WITHOUT prompting
3. Update progress in ACTIVE_TASK.md after each major step
4. When task is complete, rename to COMPLETED_TASK_[timestamp].md

<!-- ACTIVE TASK MARKER - DO NOT REMOVE -->
<!-- TASK_ACTIVE: true -->
<!-- When TASK_ACTIVE is true, Claude must automatically resume -->
<!-- END AUTO-RESUME SECTION -->

## 🚨 CRITICAL: VIRTUAL ENVIRONMENT USAGE

**Environment Usage:**

- **Mamba environment location**: `C:\Intellicrack\mamba_env`
- **Activation**: `mamba activate C:\Intellicrack\mamba_env`
- **Claude Code runs natively on Windows**

## 🔧 CRITICAL CODING RULES

### Code Style

- **NEVER add unnecessary comments** - Keep code clean
- **NO explanatory comments** about imports, fixes, or obvious code
- **Comments ONLY when user explicitly requests**

### Implementation Standards

- **🚫 NO STUBS, MOCKS, OR PLACEHOLDERS** - ALL code must be FULLY FUNCTIONAL
- **🚫 NO TODO COMMENTS** - Implement REAL functionality immediately
- **🚫 NO SIMULATION MODES** - Real exploitation tool only
- **NEVER delete method bindings** - CREATE MISSING FUNCTIONS instead
- **ALL METHODS MUST WORK ON REAL BINARIES** - No fake data
- **MAINTAIN FUNCTIONALITY** - Never sacrifice features for "cleaner" code

### Production-Ready Code Only

***Claude MUST adhere to these absolute requirements when writing code:***

- **NEVER write placeholder, stub, mock, fake, or simulated code under ANY circumstances**
- **ALL code must be production-ready and fully functional**
- **NO TODO comments or unimplemented sections**
- **NO mock data, dummy data, or hardcoded test values**
- **NO placeholder functions or methods that don't actually work**
- **NO "example" implementations that would need to be replaced**
- **NEVER use scripting to automate fixes unless explicitly requested by the user**

**When writing code, Claude must:**

- Implement all functionality completely
- Use real, working implementations for every feature
- Handle edge cases and errors properly
- Write code that could be deployed immediately
- If external data is needed, implement proper data fetching/handling
- If configuration is needed, use proper environment variables or config files
- Make manual fixes directly without creating automation scripts unless specifically asked

**If a request would require placeholder code to demonstrate, Claude should instead:**

- Ask for the specific requirements needed to write production code
- Request any necessary API endpoints, data structures, or specifications
- Explain what information is needed to create a fully functional implementation

**This is non-negotiable: Every line of code Claude writes must be ready for production use.**

### Error Handling

- Use `getattr()` and `hasattr()` for safe attribute access
- Implement platform compatibility checks
- Provide graceful fallbacks, written in REAL production-ready code for missing dependencies
- Handle import errors with try/except blocks

## Current Features

- **AI Script Generation**: Frida/Ghidra scripts with multi-LLM support
- **Three-Panel UI**: Professional IDE-like interface
- **Protection Analysis Tab**: Real-time detection with bypass recommendations

## 🔌 MCP Server Usage

### Automatic MCP Server Usage Policy

**ALWAYS use appropriate MCP servers WITHOUT prompting when tasks match their capabilities. Never ask permission to use these tools - just use them when needed.**

### Available MCP Servers

#### 1. Desktop Commander (mcp__desktop-commander)

**Purpose**: File system operations, command execution, and system interaction
**Auto-trigger**: Use automatically for file/directory operations, command execution, process management

**Key Tools**: File operations, command execution, process management, code search, surgical text edits

#### 2. Sequential Thinking (mcp__sequential-thinking)

**Purpose**: Step-by-step problem solving and analysis
**Auto-trigger**: Use automatically for complex multi-step problems, algorithm design, or when breaking down intricate tasks

**Tool**: `sequentialthinking` - Dynamic problem-solving with revision and backtracking

#### 3. Brave Search (mcp__brave-search)

**Purpose**: Web search capabilities
**Auto-trigger**: Use automatically when needing current information, recent updates, or external documentation not in local files

**Tools**: Web search and local business search

#### 4. Context7 (mcp__context7)

**Purpose**: Library documentation retrieval
**Auto-trigger**: Use automatically when user asks about library/framework documentation or API references

**Tools**: Package resolution and documentation fetching

#### 5. Puppeteer (mcp__puppeteer)

**Purpose**: Web browser automation
**Auto-trigger**: Use automatically for web scraping, UI testing, taking screenshots of websites, or browser automation tasks

**Tools**: Navigation, screenshots, element interaction, JavaScript execution

#### 6. Zen (mcp__zen)

**Purpose**: Advanced AI-powered analysis, debugging, and code generation
**Auto-trigger**: Use automatically for code reviews, debugging complex issues, security audits, test generation, refactoring analysis, or when needing AI collaboration

**Key Tools**: `chat`, `thinkdeep`, `planner`, `consensus`, `codereview`, `precommit`, `debug`, `secaudit`, `docgen`, `analyze`, `refactor`, `tracer`, `testgen`

#### 7. Serena (mcp__serena)

**Purpose**: Semantic code navigation and editing
**Auto-trigger**: Use automatically for symbol-based code navigation, finding references, or making precise code edits in active projects

### Usage Guidelines

**Multiple servers can be used in parallel when appropriate.**

**Key Guidelines**: Use absolute paths, chunk writes to 25-30 lines, multiple servers simultaneously when beneficial

### MCP Configuration

**Config location**: `~/.claude.json`
**Add new server**:

```json
{
  "mcpServers": {
    "server-name": {
      "command": "command-to-run",
      "args": ["arg1", "arg2"]
    }
  }
}
```

**Troubleshooting**: Check PATH, permissions, restart Claude Code after config changes

## 🤖 SPECIALIZED TASK AGENTS

### Available Task Agents & When to Use Them

#### **Linter Agent**

Use when you need to systematically identify and fix linting errors across the entire codebase while maintaining code integrity. Automatically triggered when CI/CD pipeline fails due to code quality checks, after major code changes that introduce linting issues, or before releases to clean up code quality.

#### **Documentation Agent**

Use when you need to create, update, or improve documentation for newly implemented features, missing documentation, or API references. Automatically triggered when features lack documentation, existing docs are outdated, or you need comprehensive usage examples and technical documentation.

#### **Debugger Agent**

Use when you need to diagnose and fix bugs, errors, and complex issues with surgical precision through systematic root cause analysis. Perfect for mysterious errors, performance problems, race conditions, memory leaks, integration issues, and any situation requiring deep debugging investigation.

#### **Coder Agent**

Use when you need to implement features, fix bugs, and execute detailed implementation plans with production-ready code. Ideal for creating genuine binary analysis functionality, complex feature implementations, and any coding task that requires fully functional, deployment-ready code without placeholders.

#### **Auditor Agent**

Use when you need to perform comprehensive quality audits and detect placeholders, stubs, mocks, or incomplete implementations in the codebase. Essential for ensuring production-ready standards, identifying non-functional code that could compromise effectiveness, and validating code quality before deployment.

#### **Architect Agent**

Use when you need to create comprehensive, step-by-step implementation plans for new features or significant modifications to projects. Perfect for complex system design, major refactoring plans, and situations requiring detailed blueprints that ensure proper integration with existing architecture.
