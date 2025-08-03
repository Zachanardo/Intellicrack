#!/usr/bin/env python3
"""
Launch testing software - both portable tools and commercial software.
All software runs without installation from the sandbox directories.
"""

import os
import subprocess
from pathlib import Path

class TestingSoftwareLauncher:
    """Launches testing software without installation."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.fixtures_dir = self.project_root / 'tests' / 'fixtures'
        
        # Portable sandbox location
        self.portable_sandbox = self.fixtures_dir / 'PORTABLE_SANDBOX'
        
        # Commercial software locations
        self.commercial_dir = self.fixtures_dir / 'binaries' / 'pe' / 'real_protected'
        self.full_software_dir = self.fixtures_dir / 'full_protected_software'
        
    def list_available_software(self):
        """List all available software."""
        print("🚀 AVAILABLE TESTING SOFTWARE")
        print("=" * 60)
        
        # List portable tools
        print("\n📦 PORTABLE TOOLS (No Installation):")
        print("-" * 40)
        
        if self.portable_sandbox.exists():
            launchers = list(self.portable_sandbox.glob("RUN_*.bat"))
            for i, launcher in enumerate(launchers, 1):
                name = launcher.stem.replace("RUN_", "").replace("_", " ").title()
                print(f"{i}. {name}")
                print(f"   Launch: {launcher}")
        
        # List commercial software
        print("\n💰 COMMERCIAL SOFTWARE:")
        print("-" * 40)
        
        if self.commercial_dir.exists():
            software_files = [
                ("WinRAR Trial", "winrar_trial.exe", "40-day trial compression tool"),
                ("IDA Free", "ida_free.exe", "Reverse engineering suite"),
                ("CCleaner Free", "ccleaner_free.exe", "System optimization tool"),
                ("Steam Client", "steam_installer.exe", "Gaming DRM platform"),
                ("Epic Games", "epic_games_launcher.exe", "Epic Games platform"),
                ("UPX Packer", "upx_packer.exe", "Executable compression")
            ]
            
            for name, file, desc in software_files:
                exe_path = self.commercial_dir / file
                if exe_path.exists():
                    size_mb = exe_path.stat().st_size / (1024 * 1024)
                    print(f"\n{name} ({size_mb:.1f}MB)")
                    print(f"   {desc}")
                    print(f"   Path: {exe_path}")
        
        # List full software if available
        if self.full_software_dir.exists():
            print("\n🔧 FULL SOFTWARE VERSIONS:")
            print("-" * 40)
            
            for app_dir in self.full_software_dir.iterdir():
                if app_dir.is_dir() and not app_dir.name.startswith('.'):
                    launcher = app_dir / f"RUN_{app_dir.name}.bat"
                    if launcher.exists():
                        print(f"\n{app_dir.name.replace('_', ' ').title()}")
                        print(f"   Launch: {launcher}")
    
    def launch_portable_tool(self, tool_name):
        """Launch a portable tool."""
        launcher_path = self.portable_sandbox / f"RUN_{tool_name}.bat"
        
        if launcher_path.exists():
            print(f"\n🚀 Launching {tool_name}...")
            print(f"   This is PORTABLE - no installation!")
            print(f"   All data stays in: {self.portable_sandbox}")
            
            # Launch the tool
            subprocess.Popen(str(launcher_path), shell=True)
            print("✅ Launched successfully!")
        else:
            print(f"❌ Launcher not found: {launcher_path}")
    
    def launch_commercial_software(self, exe_name):
        """Launch commercial software."""
        exe_path = self.commercial_dir / exe_name
        
        if exe_path.exists():
            print(f"\n🚀 Launching {exe_name}...")
            print(f"   Size: {exe_path.stat().st_size / (1024*1024):.1f}MB")
            
            # Create a temporary launcher script
            launcher = exe_path.parent / f"TEMP_LAUNCH_{exe_name}.bat"
            launcher_content = f"""@echo off
echo Launching {exe_name}...
echo =====================================
echo This software may require installation.
echo Install to: {self.fixtures_dir / 'installed_software' / exe_name.replace('.exe', '')}
echo.
start "" "{exe_path}"
"""
            launcher.write_text(launcher_content)
            
            # Launch
            subprocess.Popen(str(launcher), shell=True)
            print("✅ Launched! Follow any installation prompts.")
            
            # Clean up launcher after a moment
            import time
            time.sleep(2)
            launcher.unlink(missing_ok=True)
        else:
            print(f"❌ Software not found: {exe_path}")
    
    def interactive_menu(self):
        """Show interactive menu."""
        while True:
            print("\n" + "=" * 60)
            print("🎯 INTELLICRACK TESTING SOFTWARE LAUNCHER")
            print("=" * 60)
            print("\nPORTABLE TOOLS (No Installation):")
            print("1. Process Hacker - System monitor")
            print("2. PEStudio - Binary analysis")
            print("3. ExeinfoPE - Protection detector")
            print("\nCOMMERCIAL SOFTWARE:")
            print("4. WinRAR Trial - Compression tool")
            print("5. IDA Free - Reverse engineering")
            print("6. CCleaner - System optimization")
            print("\nOTHER:")
            print("L. List all available software")
            print("Q. Quit")
            
            choice = input("\nSelect option: ").strip().upper()
            
            if choice == '1':
                self.launch_portable_tool("processhacker_portable")
            elif choice == '2':
                self.launch_portable_tool("pestudio_portable")
            elif choice == '3':
                self.launch_portable_tool("exeinfope_portable")
            elif choice == '4':
                self.launch_commercial_software("winrar_trial.exe")
            elif choice == '5':
                self.launch_commercial_software("ida_free.exe")
            elif choice == '6':
                self.launch_commercial_software("ccleaner_free.exe")
            elif choice == 'L':
                self.list_available_software()
            elif choice == 'Q':
                break
            else:
                print("Invalid choice!")
            
            input("\nPress Enter to continue...")

def main():
    """Main entry point."""
    launcher = TestingSoftwareLauncher()
    
    print("🚀 TESTING SOFTWARE LAUNCHER")
    print("=" * 60)
    print("This launcher helps you run the downloaded testing software.")
    print("PORTABLE tools run without ANY installation.")
    print("Commercial software may prompt for installation.\n")
    
    # Show what's available
    launcher.list_available_software()
    
    # Interactive menu
    launcher.interactive_menu()

if __name__ == '__main__':
    main()