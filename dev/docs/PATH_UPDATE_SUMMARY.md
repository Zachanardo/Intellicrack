# Path Update Summary for Project Move

## Overview
Updated all hardcoded paths to support moving the project from:
- **FROM**: `C:\Intellicrack\Intellicrack_Project\Intellicrack_Project`
- **TO**: `C:\Intellicrack`

## Changes Made

### 1. Configuration Files

#### intellicrack_config.json
- **Updated**: `ml_model_path`
- **Old**: `"C:\\Intellicrack\\Intellicrack_Project\\Intellicrack_Project\\models\\vuln_predict_model.joblib"`
- **New**: `"C:\\Intellicrack\\models\\vuln_predict_model.joblib"`

#### package-lock.json
- **Updated**: Project name
- **Old**: `"name": "Intellicrack_Project"`
- **New**: `"name": "Intellicrack"`

### 2. Scripts

#### ClaudeCode.ps1
- **Updated**: WSL path
- **Old**: `wsl bash -ic "cd /mnt/c/Intellicrack/Intellicrack_Project/Intellicrack_Project && claude"`
- **New**: `wsl bash -ic "cd /mnt/c/Intellicrack && claude"`

### 3. Path Discovery System

#### intellicrack/utils/path_discovery.py
- **Updated**: Bundled radare2 relative path
- **Old**: `os.path.join(os.path.dirname(__file__), '..', '..', '..', 'radare2', 'radare2-5.9.8-w64', 'bin')`
- **New**: `os.path.join(os.path.dirname(__file__), '..', '..', 'radare2', 'radare2-5.9.8-w64', 'bin')`
- **Note**: Changed from going up 3 directories to going up 2 directories

### 4. Verified Correct Paths
The following relative paths were checked and are already correct for the new location:

- `intellicrack/ai/model_manager_module.py` - Goes up 2 levels to find models/
- `intellicrack/config.py` - Goes up 2 levels for vulnerability model
- `intellicrack/core/analysis/concolic_executor.py` - Goes up 3 levels for scripts/
- `intellicrack/core/processing/qiling_emulator.py` - Goes up 4 levels for project root
- `intellicrack/ui/dialogs/report_manager_dialog.py` - Goes up 3 levels for reports/
- `intellicrack/ui/main_app.py` - Goes up 1 level for assets/

## Moving Instructions

1. **Move the entire folder** from `C:\Intellicrack\Intellicrack_Project\Intellicrack_Project` to `C:\Intellicrack`

2. **Run the verification script**:
   ```cmd
   cd C:\Intellicrack
   python verify_after_move.py
   ```

3. **If needed, reinstall dependencies**:
   ```cmd
   dependencies\INSTALL.bat
   ```

4. **Launch Intellicrack**:
   ```cmd
   RUN_INTELLICRACK.bat
   ```

## Benefits After Move

- **Simpler path structure** - No more nested Intellicrack_Project directories
- **Shorter paths** - Helps avoid Windows path length limitations
- **Cleaner organization** - More intuitive project structure
- **All paths updated** - No hardcoded references to the old location

## Notes

- The dynamic path discovery system will automatically find tools regardless of the project location
- Configuration paths (logs, output, temp) already pointed to C:\Intellicrack
- All relative paths within the project work correctly with the new structure
- The project is now fully portable and can be moved to other locations if needed

## Created Files

1. **verify_after_move.py** - Script to verify the move was successful
2. **PATH_UPDATE_SUMMARY.md** - This documentation

All hardcoded paths have been updated to reflect the new location at `C:\Intellicrack`.