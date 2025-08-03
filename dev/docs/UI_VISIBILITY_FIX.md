# Intellicrack UI Visibility Fix

## Issue
Dashboard tab content was barely visible due to dark theme styling issues - dark text on dark background.

## Changes Made

### 1. Dashboard Tab Styling
Fixed visibility issues in `/intellicrack/ui/tabs/dashboard_tab.py`:

- Added proper styling to all QGroupBox widgets:
  - Dark background color (#2b2b2b)
  - White text for titles
  - Light border (#cccccc)
  - Proper padding and margins

- Changed project label color from #666666 to #cccccc for better contrast

### 2. Tab Loading System
Added lazy loading trigger in `/intellicrack/ui/main_app.py`:

- Connected `tabs.currentChanged` signal to `on_tab_changed` handler
- Added `on_tab_changed` method to trigger lazy loading when tabs are selected
- Dashboard tab now loads content on startup since it's the first tab

### 3. Affected GroupBoxes
- Project Management
- Binary Management
- Recent Files
- Activity Log
- Project Files

## Result
All text and UI elements in the Dashboard tab are now properly visible with good contrast against the dark background theme.

## Testing
Run `run_intellicrack.bat` to verify the Dashboard tab content is now visible and readable.
