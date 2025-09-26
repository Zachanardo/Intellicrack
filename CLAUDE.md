# Intellicrack

## Project Overview

**Intellicrack** - Advanced binary analysis platform **SPECIFICALLY AND EXCLUSIVELY** designed for analyzing software and cracking licensing protections. This tool focuses **SOLELY** on defeating software licensing mechanisms, registration systems, trial limitations, and copy protection schemes.

### EXPLICIT TOOL SCOPE - CRITICAL

**What Intellicrack IS:**
- **SOFTWARE LICENSING CRACKER** - Defeats licensing protections, serial validation, and registration systems
- **PROTECTION ANALYZER** - Analyzes and bypasses copy protection, trial limitations, and activation mechanisms
- **BINARY PATCHER** - Modifies binaries to remove licensing checks and protection routines
- **LICENSE KEYGEN CREATOR** - Generates valid license keys and registration codes

**What Intellicrack IS NOT:**
- **NOT a malware creation tool** - No malware injection, payload delivery, or virus creation
- **NOT a system exploit framework** - No OS exploitation, privilege escalation, or system compromise
- **NOT a network attack tool** - No network intrusion, packet injection, or remote exploitation
- **NOT a data theft tool** - No credential harvesting, data exfiltration, or information stealing

**SCOPE LIMITATION:** This tool is **EXCLUSIVELY** for analyzing and defeating software licensing protections. Any functionality must be directly related to cracking software protections, NOT creating other types of exploits.

### Project Intent & Security Research Purpose

This tool is developed for **defensive security research** to help software developers:

- **Identify weaknesses** in their own licensing protection mechanisms by using Intellicrack in a controlled enviornment to crack their software, so they can strengthen the licensing protections to prevent future attacks.
- **Test robustness** of licensing, registration, and activation systems in controlled environments
- **Strengthen licensing defenses** against cracking attempts by understanding bypass techniques
- **Validate protection effectiveness** of their own software's licensing mechanisms before deployment

**Critical Context:** Intellicrack requires functionally real and robust licensing cracking capabilities to serve as an effective security research tool. All components must be production-ready to accurately defeat protection mechanisms and provide meaningful security insights to developers working to improve their software's licensing security.

**Usage Environment:** This tool operates exclusively in controlled, isolated research environments for authorized security assessment of proprietary software licensing systems by their own developers and security teams.

**TOOLS**

## USE THESE TOOLS
1. rg instead of grep
2. fd instead of find
3. tree is installed

## CRITICAL: VIRTUAL ENVIRONMENT USAGE

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

- **ALL CODE MUST BE WRITTEN FOR FULL COMPATIBLITY WITH WINDOWS PLATFORMS AS A PRIORITY.**
- **NO STUBS, MOCKS, OR PLACEHOLDERS** - ALL code must be FULLY FUNCTIONAL
- **NO TODO COMMENTS** - Implement REAL functionality immediately
- **NO SIMULATION MODES** - Real licensing cracking tool only
- **NEVER delete method bindings** - CREATE MISSING FUNCTIONS instead
- **ALL METHODS MUST WORK ON REAL BINARIES** - Specifically for cracking licensing protections
- **MAINTAIN FUNCTIONALITY** - Never sacrifice features for "cleaner" code
- **SCOPE ENFORCEMENT** - Every feature must relate to SOFTWARE LICENSING CRACKING
- **NO MALWARE CAPABILITIES** - No injection, payload delivery, or system exploitation code
- **LICENSING FOCUS ONLY** - All analysis must target registration, activation, and protection systems

### Production-Ready Code Only

***Claude MUST adhere to these absolute requirements when writing code:***

- **NEVER write placeholder, stub, mock, fake, or simulated code under ANY circumstances**
- **ALL code must be production-ready and fully functional**
- **NO TODO comments or unimplemented sections**
- **NO mock data, dummy data, or hardcoded values**
- **NO placeholder functions or methods that don't actually work**
- **NO "example" implementations that would need to be replaced**
- **NO simple implementations that would be ineffective in real world scenarios**
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

### MCP Configuration

**Config location**: `~/.claude.json`
