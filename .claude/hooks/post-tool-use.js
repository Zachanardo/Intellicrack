#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

// Log file path - use proper OS temp directory
const LOG_FILE = path.join(os.tmpdir(), 'hook-validation.log');

// Ensure log file exists
if (!fs.existsSync(LOG_FILE)) {
    fs.writeFileSync(LOG_FILE, '');
}

function logToFile(message) {
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    fs.appendFileSync(LOG_FILE, `[${timestamp}] ${message}\n`);
}

function detectViolations(filePath) {
    const violations = [];
    
    // Skip validation for hook files themselves
    const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();
    if (normalizedPath.includes('.claude/hooks') || normalizedPath.endsWith('post-tool-use.js')) {
        return violations;
    }
    
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        
        // Check for TODO comments
        lines.forEach((line, index) => {
            if (line.includes('TODO')) {
                violations.push(`TODO comment found at: ${index + 1}`);
            }
        });
        
        // Check for FIXME comments
        lines.forEach((line, index) => {
            if (line.includes('FIXME')) {
                violations.push(`FIXME comment found at: ${index + 1}`);
            }
        });
        
        // Check for NotImplementedError
        lines.forEach((line, index) => {
            if (line.includes('NotImplementedError')) {
                violations.push(`NotImplementedError found at: ${index + 1}`);
            }
        });
        
        // Check for placeholder (case insensitive)
        lines.forEach((line, index) => {
            if (line.toLowerCase().includes('placeholder')) {
                violations.push(`placeholder code found at: ${index + 1}`);
            }
        });
        
        // Check for stub (case insensitive)
        lines.forEach((line, index) => {
            if (line.toLowerCase().includes('stub')) {
                violations.push(`stub implementation found at: ${index + 1}`);
            }
        });
        
        // Check for mock (case insensitive)
        lines.forEach((line, index) => {
            if (line.toLowerCase().includes('mock')) {
                violations.push(`mock implementation found at: ${index + 1}`);
            }
        });
        
        // Check for HACK comments
        lines.forEach((line, index) => {
            if (line.includes('HACK')) {
                violations.push(`HACK comment found at: ${index + 1}`);
            }
        });
        
        // Check for XXX markers
        lines.forEach((line, index) => {
            if (line.includes('XXX')) {
                violations.push(`XXX marker found at: ${index + 1}`);
            }
        });
        
        // Check for ellipsis as function body
        lines.forEach((line, index) => {
            if (line.trim() === '...') {
                violations.push(`Ellipsis-only function body found at: ${index + 1}`);
            }
        });
        
        // Check for return NotImplemented
        lines.forEach((line, index) => {
            if (line.includes('return NotImplemented')) {
                violations.push(`return NotImplemented found at: ${index + 1}`);
            }
        });
        
        // Check for unimplemented panic/todo macros (Rust)
        lines.forEach((line, index) => {
            if (line.includes('todo!()') || line.includes('unimplemented!()')) {
                violations.push(`Rust unimplemented macro found at: ${index + 1}`);
            }
        });
        
        // Check for dummy/fake implementations
        lines.forEach((line, index) => {
            if (line.toLowerCase().includes('dummy') || line.toLowerCase().includes('fake')) {
                violations.push(`Dummy/fake implementation found at: ${index + 1}`);
            }
        });
        
        // Check for simulation/simulated code
        lines.forEach((line, index) => {
            if (line.toLowerCase().includes('simulat')) {
                violations.push(`Simulation code found at: ${index + 1}`);
            }
        });
        
        // Check for NOT_IMPLEMENTED constants
        lines.forEach((line, index) => {
            if (line.includes('NOT_IMPLEMENTED') || line.includes('UNIMPLEMENTED')) {
                violations.push(`NOT_IMPLEMENTED constant found at: ${index + 1}`);
            }
        });
        
        // Check for throw/raise with "not implemented" messages
        lines.forEach((line, index) => {
            if ((line.includes('throw') || line.includes('raise')) &&
                line.toLowerCase().includes('not implemented')) {
                violations.push(`Not implemented exception found at: ${index + 1}`);
            }
        });

        // Check for exact phrase "a real implementation"
        lines.forEach((line, index) => {
            if (line.toLowerCase().includes('a real implementation')) {
                violations.push(`"a real implementation" phrase found at: ${index + 1}`);
            }
        });

        // Check for exact phrase "implementation would"
        lines.forEach((line, index) => {
            if (line.toLowerCase().includes('implementation would')) {
                violations.push(`"implementation would" phrase found at: ${index + 1}`);
            }
        });

        // Check for empty Python functions/classes
        if (filePath.endsWith('.py')) {
            try {
                const pythonCheck = `
import ast
import sys

try:
    with open('${filePath}', 'r') as f:
        content = f.read()
        if content.strip():
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and len(node.body) == 1:
                    if isinstance(node.body[0], ast.Pass):
                        print(f'Empty function: {node.name}', file=sys.stderr)
                        sys.exit(1)
except:
    pass
`;
                execSync(`python3 -c "${pythonCheck}"`, { stdio: 'pipe' });
            } catch (e) {
                if (e.status === 1) {
                    violations.push('empty function implementation found');
                }
            }
        }
    } catch (error) {
        logToFile(`Error reading file ${filePath}: ${error.message}`);
    }
    
    // Return only first violation of each type to avoid duplicates
    const uniqueViolations = [];
    const seenTypes = new Set();
    
    violations.forEach(violation => {
        const type = violation.split(' ')[0];
        if (!seenTypes.has(type)) {
            seenTypes.add(type);
            uniqueViolations.push(violation);
        }
    });
    
    return uniqueViolations;
}

function main() {
    let jsonInput = '';
    
    // Read JSON input from stdin
    process.stdin.setEncoding('utf8');
    
    process.stdin.on('data', (chunk) => {
        jsonInput += chunk;
    });
    
    process.stdin.on('end', () => {
        logToFile(`Hook triggered with JSON: ${jsonInput}`);
        
        let toolName = 'unknown';
        let filePath = '';
        
        try {
            const input = JSON.parse(jsonInput);
            toolName = input.tool_name || 'unknown';
            
            // Extract file path based on tool
            if (input.tool_input) {
                filePath = input.tool_input.file_path || input.tool_input.path || '';
            }
        } catch (error) {
            // Fallback parsing if JSON parsing fails
            if (jsonInput.includes('"tool_name":"Edit"')) {
                toolName = 'Edit';
            } else if (jsonInput.includes('"tool_name":"Write"')) {
                toolName = 'Write';
            }
            
            // Try to extract file path with regex
            const fileMatch = jsonInput.match(/"file_path":"([^"]+)"/);
            if (fileMatch) {
                filePath = fileMatch[1];
            }
        }
        
        logToFile(`Detected tool: ${toolName}`);
        
        // Only validate code modification tools
        const codeTools = [
            'Write', 'Edit', 'MultiEdit',
            'mcp__filesystem__write_file', 'mcp__filesystem__edit_file',
            'mcp__desktop-commander__write_file', 'mcp__desktop-commander__edit_block'
        ];
        
        if (!codeTools.includes(toolName)) {
            logToFile(`Skipping validation for non-code tool: ${toolName}`);
            process.exit(0);
        }
        
        logToFile(`Target file: ${filePath}`);
        
        // Skip if no file or file doesn't exist
        if (!filePath || !fs.existsSync(filePath)) {
            logToFile('File not found or empty path, allowing operation');
            process.exit(0);
        }
        
        // Skip non-code files
        const codeExtensions = ['.py', '.js', '.ts', '.java', '.cpp', '.c', '.rs', '.go', '.rb'];
        const fileExt = path.extname(filePath).toLowerCase();
        
        if (!codeExtensions.includes(fileExt)) {
            logToFile(`Skipping non-code file: ${filePath}`);
            process.exit(0);
        }
        
        // Detect violations
        const violations = detectViolations(filePath);
        
        if (violations.length > 0) {
            const violationString = violations.join(', ');
            logToFile(`VIOLATIONS FOUND: ${violationString}`);
            
            // Output JSON to provide feedback to Claude for automatic fixing
            const response = {
                decision: 'block',  // This prompts Claude to automatically fix violations
                reason: `VIOLATIONS DETECTED at lines: ${violationString}\nFile: ${filePath}\nFix these violations with production-ready code immediately. If it's a comment, provide real production ready code. DO NOT simply just delete the comment.`,
                hookSpecificOutput: {
                    hookEventName: 'PostToolUse',
                    additionalContext: `Violations found: ${violationString}. All code must be production-ready. Full log at: ${LOG_FILE}`
                }
            };
            
            console.log(JSON.stringify(response));
            
            logToFile(`STOPPING Claude workflow due to production code violations: ${violationString}`);
            process.exit(0); // Use exit 0 with JSON response
        } else {
            logToFile('No violations found, allowing operation');
            process.exit(0);
        }
    });
}

// Run main function
main();