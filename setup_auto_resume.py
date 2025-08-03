#!/usr/bin/env python3
"""
Auto-Resume Setup for Claude Code
This script sets up automatic task resumption without manual intervention
"""

import json
import os
from pathlib import Path

def setup_auto_resume():
    """Configure CLAUDE.md for automatic task resumption"""
    
    # Create the task template
    task_template = """# ACTIVE TASK - AUTO RESUME ENABLED

## Task Status: IN_PROGRESS

## Original Prompt
```
{prompt}
```

## Progress Checkpoints
- [ ] Step 1: {current_step}
- [ ] Step 2: 
- [ ] Step 3: 

## Current Context
{context}

## Next Action
{next_action}

## Important State
{state}
"""

    # Create an example active task
    active_task_content = task_template.format(
        prompt="[Your exact task prompt goes here]",
        current_step="[Current step description]",
        context="[Any important context]",
        next_action="[What to do next]",
        state="[Any state information]"
    )
    
    # Write the active task file
    active_task_path = Path("C:/Intellicrack/ACTIVE_TASK.md")
    active_task_path.write_text(active_task_content)
    
    # Update CLAUDE.md to enable auto-resume
    claude_md_path = Path("C:/Intellicrack/CLAUDE.md")
    content = claude_md_path.read_text()
    
    # Enable the task active flag
    content = content.replace("<!-- TASK_ACTIVE: false -->", "<!-- TASK_ACTIVE: true -->")
    claude_md_path.write_text(content)
    
    print("✅ Auto-resume configured successfully!")
    print("📝 Edit ACTIVE_TASK.md with your task details")
    print("🚀 Claude will automatically resume on next session")

if __name__ == "__main__":
    setup_auto_resume()