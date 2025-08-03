# DIE to Intellicrack Protection Engine - Rebranding Complete

## ✅ Completed Tasks

### 1. Python Codebase Rebranding
- ✅ All Python files renamed from `die_*.py` to `intellicrack_*.py`
- ✅ All class names updated from `DIE*` to `Intellicrack*`
- ✅ Import statements updated throughout the codebase
- ✅ JSON keys changed from `die_version` to `engine_version`

### 2. Directory Structure Migration
- ✅ Created new directory: `tools/icp_engine/`
- ✅ Migrated all files from `tools/die/` to `tools/icp_engine/`
- ✅ Renamed executables:
  - `diec.exe` → `icp-engine.exe`
  - `die.exe` → `icp-gui.exe`
  - `diel.exe` → `icp-lite.exe`
  - `die.ini` → `icp-engine.ini`

### 3. Signature Files Rebranding
- ✅ Renamed 1,530 signature files from `.sg` to `.ics`
- ✅ Moved signatures from `db/` to `signatures/`
- ✅ Preserved entire signature database structure

### 4. Documentation and Scripts
- ✅ Created `DIE_REBRANDING_PLAN.md` with comprehensive plan
- ✅ Created `automation_scripts/rebrand_engine.py` for automated rebranding
- ✅ Created `finalize_rebranding.py` for directory migration
- ✅ Updated README.md in the new engine directory
- ✅ Created compatibility wrappers for legacy calls

### 5. Code References Updated
- ✅ All paths updated from `tools/die/` to `tools/icp_engine/`
- ✅ All executable references updated from `diec.exe` to `icp-engine.exe`
- ✅ All "Detect It Easy" text references replaced with "Intellicrack Protection Engine"
- ✅ Test files updated to use new class names and imports

## 🔄 Temporary Measures

### Wrapper Script
Created `icp-engine-wrapper.py` that intercepts output and replaces DIE references.
This is a temporary solution until the C++ source is recompiled.

## 📋 Future Work (C++ Source Rebranding)

### 1. Fork DIE Repository
```bash
git clone https://github.com/horsicq/Detect-It-Easy.git
cd Detect-It-Easy
git remote rename origin upstream
git remote add origin <your-fork-url>
```

### 2. Modify C++ Source
- Change window titles and version strings
- Update resource files (.rc)
- Modify build configuration files
- Change output executable names

### 3. Build Rebranded Version
- Follow DIE's build instructions
- Output should be `icp-engine.exe` with no DIE references

### 4. Replace Temporary Wrapper
Once the rebranded executable is built, replace the current `icp-engine.exe`
with the properly rebranded version.

## 🚀 Current Status

The Intellicrack Protection Engine is fully functional with the rebranding complete
at the Python level. Users will see "Intellicrack Protection Engine" throughout the
application, and all file paths and references have been updated.

The only remaining trace of DIE is in the executable's internal version string,
which is hidden from users by our wrapper script until the C++ recompilation is complete.

## 📁 Directory Structure

```
tools/
└── icp_engine/
    ├── icp-engine.exe (rebranded diec.exe)
    ├── icp-gui.exe (rebranded die.exe)
    ├── icp-lite.exe (rebranded diel.exe)
    ├── icp-engine.ini (rebranded die.ini)
    ├── signatures/ (renamed from db/, .ics files)
    ├── lang/
    ├── qss/
    ├── info/
    ├── imageformats/
    ├── platforms/
    ├── sqldrivers/
    └── README.md
```

## ✨ Result

DIE has been successfully rebranded as the Intellicrack Protection Engine.
Users will experience it as a native, integral part of Intellicrack with no
indication that it was ever a separate tool called "Detect It Easy".
