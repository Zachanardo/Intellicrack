# Terminal Tab User Guide

## Overview

The **Terminal Tab** provides an embedded terminal interface within Intellicrack, eliminating the need for external CMD windows. All analysis tools, activation scripts, and system commands now run within the application for a seamless experience.

## Location

The Terminal tab is the **7th tab** in the main Intellicrack interface, located between **Tools** and **Settings**.

## Features

### Multiple Terminal Sessions

- **Create New Session**: Click the "+" button or use Ctrl+T
- **Switch Sessions**: Click on session tabs
- **Close Session**: Click the "×" button on the tab or use Ctrl+W
- **Rename Session**: Right-click tab → Rename

### Terminal Controls

- **Copy Text**: Select text and use Ctrl+C or right-click → Copy
- **Paste Text**: Use Ctrl+V or right-click → Paste
- **Clear Output**: Click "Clear" button or use Ctrl+L
- **Export Log**: Click "Export" button to save terminal output
- **Terminate Process**: Click "Stop" button or use Ctrl+C

### Process Management

- **View PID**: Process ID displayed in status bar
- **Monitor Output**: Real-time output display with ANSI color support
- **Scrollback**: Up to 1000 lines of history
- **Auto-scroll**: Automatically scrolls to newest output

---

## Using Windows Activation

### Interactive Activation

1. Navigate to **Tools tab** → **Activation Tools** sub-tab
2. Click **"Activate Windows (Interactive)"** button
3. Application automatically switches to Terminal tab
4. WindowsActivator.cmd menu appears
5. Type option number (e.g., "1" for HWID activation)
6. Press Enter to execute
7. Follow on-screen prompts

### Checking Activation Status

1. Navigate to **Tools tab** → **Activation Tools** sub-tab
2. Click **"Check Windows Activation Status"** button
3. Status displayed in the activation panel
4. No external windows required

### Features

- **No External Windows**: Everything runs in embedded terminal
- **Interactive Menu**: Full keyboard interaction support
- **Color Output**: ANSI colors preserved for clarity
- **Copy/Paste**: Easily copy activation keys or error messages
- **Session History**: Review past activation attempts

---

## Using Adobe Activation

### Auto-Injector

1. Navigate to **Tools tab** → **Adobe Tools** sub-tab
2. Click **"Start Adobe Auto-Injector"**
3. Terminal tab shows injection status
4. Real-time feedback as Adobe processes are detected
5. Success/failure messages displayed with color coding

### Manual Injection

1. Open Terminal tab
2. Run custom Frida scripts with terminal output
3. Monitor injection progress in real-time

### Features

- **Process Discovery**: Automatically finds running Adobe apps
- **Status Display**: Green = success, Red = error, Yellow = in progress
- **Process List**: Shows all detected Adobe processes
- **Injection Count**: Displays number of successful injections

---

## Using Analysis Tools

### Ghidra Analysis

When running Ghidra scripts, enable terminal output to see:
- Analysis progress
- Function discovery status
- Decompilation progress
- Error messages

### Radare2 Commands

Run r2 commands with real-time output:
- Disassembly views
- Symbol information
- Analysis results

### Frida Scripts

Execute Frida instrumentation with live feedback:
- Process spawn/attach status
- Hook installation
- Runtime modifications

---

## Common Tasks

### Running a Command

1. Click Terminal tab
2. Type command or select from history
3. Press Enter to execute
4. View output in terminal

### Creating Multiple Sessions

1. Click "+" button for new session
2. Name the session (e.g., "Analysis", "Build", "Test")
3. Switch between sessions using tabs
4. Each session maintains independent state

### Exporting Terminal Output

1. Run your commands/analysis
2. Click "Export" button
3. Choose save location
4. Terminal output saved as text file

### Stopping Long-Running Processes

1. Click "Stop" button, or
2. Press Ctrl+C in terminal
3. Process terminates gracefully
4. Terminal remains open for next command

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+T | New terminal session |
| Ctrl+W | Close current session |
| Ctrl+C | Copy selected text (or interrupt process) |
| Ctrl+V | Paste from clipboard |
| Ctrl+L | Clear terminal output |
| Ctrl+F | Find in output |
| Ctrl+Shift+C | Force copy (when process running) |

---

## Tips & Tricks

### Color Coding

Terminal output uses colors for clarity:
- **Green**: Success messages
- **Red**: Errors
- **Yellow**: Warnings or in-progress
- **White**: Standard output

### Scrollback

- Terminal keeps last 1000 lines
- Scroll up to view history
- Auto-scrolls to bottom on new output
- Use scrollbar or mouse wheel

### Process Interaction

- Some processes require input (press Enter after typing)
- Interactive menus work fully (WindowsActivator, etc.)
- Ctrl+C interrupts running process
- Terminal shows exit code when process finishes

### Session Management

- Keep multiple analyses running in separate sessions
- Name sessions descriptively ("Ghidra Analysis", "Windows Activation")
- Close unused sessions to free resources

---

## Troubleshooting

### Terminal Not Displaying Output

1. Check if process is still running (view PID in status bar)
2. Try clicking in terminal area to focus
3. If frozen, stop process and restart

### Cannot Type Input

1. Ensure a process is running that accepts input
2. Click in terminal area to focus
3. Check if process is waiting for specific input

### Copy/Paste Not Working

1. Ensure text is selected before copying
2. Use right-click context menu as alternative
3. Try Ctrl+Shift+C for force copy

### Process Won't Stop

1. Try Ctrl+C first (graceful termination)
2. Use Stop button (sends SIGTERM)
3. Close session as last resort (force kill)

---

## Advanced Usage

### Custom Scripts

Run your own scripts in the terminal:

```batch
REM Windows batch script
C:\path\to\script.bat
```

```bash
# Shell script
./path/to/script.sh
```

### Piping Commands

Use command-line piping:

```cmd
dir | findstr ".exe"
```

### Environment Variables

Set environment for terminal session:

```cmd
set PATH=%PATH%;C:\Tools
tool.exe
```

---

## FAQ

**Q: Why use embedded terminal instead of external CMD?**
A: Integrated terminal provides:
- Better UI integration
- No window management hassles
- Copy/paste convenience
- Session history
- Multi-session support

**Q: Can I use PowerShell instead of CMD?**
A: Yes! Run `powershell` in the terminal to switch shells.

**Q: Does it work with all Intellicrack tools?**
A: Yes, all major tools support terminal output:
- Windows Activation ✓
- Adobe Activation ✓
- Ghidra Analysis ✓
- Radare2 ✓
- Frida Scripts ✓

**Q: Can I customize terminal appearance?**
A: Current version uses fixed dark theme. Customization may be added in future updates.

---

*Last Updated: 2025-01-10*
