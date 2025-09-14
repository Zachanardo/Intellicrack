# INTELLICRACK TOOL INTEGRATION IMPLEMENTATION PROMPT

## CRITICAL REQUIREMENTS

You are implementing production-ready offensive binary analysis tool integrations for Intellicrack. Every line of code must provide genuine functionality that works against real binaries and commercial protections. NO placeholders, stubs, mocks, or simulations are acceptable.

## TASK MANAGEMENT PROTOCOL

1. **Working Document**: Use `C:\Intellicrack\ToolIntegrationTODO.md` as your active scratch pad
2. **Task Tracking**: Mark each task with [x] immediately upon completion
3. **Progress Updates**: After completing each major section, update the completion metrics at the bottom
4. **Verification**: Test each implementation against real binaries before marking complete

## MANDATORY TOOL USAGE

Use Serena tools exclusively for all file operations:
- `find_symbol` - Locate specific functions/classes before editing
- `replace_symbol_body` - Replace entire function implementations
- `insert_after_symbol` - Add new code after existing symbols
- `insert_before_symbol` - Add imports or code before symbols
- `get_symbols_overview` - Understand file structure before editing
- `search_for_pattern` - Find specific code patterns or comments

NEVER use basic read/write operations when Serena symbolic tools are available.

## CODE STANDARDS

### REQUIRED - Production Code Example:
```python
class GhidraOutputParser:
    def parse_functions(self, stdout_text: str) -> List[Dict]:
        """Parse actual Ghidra output into structured data."""
        functions = []
        for line in stdout_text.split('\n'):
            match = re.match(r'Function: (\w+) @ (0x[0-9a-fA-F]+)', line)
            if match:
                functions.append({
                    'name': match.group(1),
                    'address': int(match.group(2), 16),
                    'size': self._extract_function_size(stdout_text, match.group(2))
                })
        return functions
```

### FORBIDDEN - Placeholder Code:
```python
def parse_functions(self, output):
    # TODO: Implement parsing
    return []  # NEVER DO THIS
```

## IMPLEMENTATION PROCESS

For each task in ToolIntegrationTODO.md:

1. **Navigate** to the specified file using Serena's `find_symbol`
2. **Implement** complete, working functionality
3. **Test** against real data (not mocks)
4. **Mark** the checkbox [x] in the TODO file
5. **Commit** changes if working with git

## PHASE-SPECIFIC INSTRUCTIONS

### PHASE 1: Ghidra Integration
- Parse REAL Ghidra headless output format
- Extract actual function addresses, strings, imports
- Store in structured format for GUI consumption
- Test with actual PE/ELF binaries

### PHASE 2: Frida Integration
- Implement REAL memory read/write operations via Frida
- Connect to actual running processes
- Display real memory contents in hex viewer
- Monitor actual hook effectiveness metrics

### PHASE 3: Radare2 Integration
- Implement REAL binary diffing between two executables
- Parse actual r2pipe JSON output
- Display real performance metrics from r2
- Generate actual control flow graphs

### PHASE 4: Cross-Tool Integration
- Normalize REAL data from all three tools
- Implement actual event-driven communication
- Decouple GUI from direct tool calls with real orchestration
- Test with actual multi-tool analysis workflows

### PHASE 5: Dashboard
- Display REAL analysis metrics and findings
- Update in real-time from actual tool events
- Show actual CPU/memory usage
- List real discovered functions/strings/protections

### PHASE 6: Testing
- Write tests that use REAL binaries
- Measure ACTUAL performance metrics
- Validate against REAL malware samples
- Ensure sub-100ms latency with real data

## EXAMPLE IMPLEMENTATIONS

### Example 1: Ghidra Parser (CORRECT)
```python
def parse_functions(self, stdout_text: str) -> List[Dict]:
    functions = []
    # Parse actual Ghidra output format
    for line in stdout_text.split('\n'):
        if 'Function:' in line:
            parts = line.split()
            addr_idx = parts.index('@') + 1
            functions.append({
                'name': parts[1],
                'address': int(parts[addr_idx], 16),
                'size': self._get_function_size(stdout_text, parts[addr_idx])
            })
    return functions
```

### Example 2: Frida Memory Operation (CORRECT)
```python
def read_memory_dialog(self):
    address = self.address_input.text()
    size = int(self.size_input.text())

    # Read actual process memory via Frida
    script = self.frida_session.create_script(f"""
        var ptr = ptr('{address}');
        var data = ptr.readByteArray({size});
        send({{'type': 'memory', 'data': Array.from(new Uint8Array(data))}});
    """)
    script.load()

    # Display real memory contents
    self.hex_viewer.set_data(script.exports.get_memory())
```

### Example 3: Radare2 Binary Diff (CORRECT)
```python
def get_function_diffs(self) -> List[Dict]:
    # Compare actual functions between binaries
    funcs1 = self.r2_primary.cmdj('aflj')
    funcs2 = self.r2_secondary.cmdj('aflj')

    diffs = []
    for f1 in funcs1:
        matched = next((f2 for f2 in funcs2 if f2['name'] == f1['name']), None)
        if not matched:
            diffs.append({'type': 'removed', 'function': f1})
        elif f1['size'] != matched['size']:
            diffs.append({'type': 'modified', 'function': f1, 'new': matched})

    return diffs
```

## PROGRESS TRACKING

After completing each phase:
1. Count completed tasks
2. Update the metrics section in ToolIntegrationTODO.md
3. Report: "Phase X complete: Y/Z tasks done"

## SUCCESS FACTORS

Your implementation is successful when:
- All 118 tasks have [x] checkmarks
- Every function works with real binaries
- No placeholders or TODOs remain
- GUI fully integrates all three tools
- Cross-tool correlation produces real insights
- Dashboard shows live analysis data
- Tests pass with actual malware samples

## IMPLEMENTATION ORDER

Follow the phases in sequence:
1. Ghidra Integration (16 tasks)
2. Frida Integration (20 tasks)
3. Radare2 Integration (18 tasks)
4. Cross-tool Integration (22 tasks)
5. Dashboard (16 tasks)
6. Testing (10 tasks)
7. Remaining setup (16 tasks)

Begin immediately with Phase 1, Task 1.1. Use Serena's `find_symbol` to locate the ghidra_analyzer.py file and implement the GhidraOutputParser class with complete, production-ready parsing logic that handles real Ghidra output.

Remember: Every implementation must work against real binaries with genuine offensive capabilities. This is Intellicrack - build tools that actually crack.