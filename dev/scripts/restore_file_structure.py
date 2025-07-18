#!/usr/bin/env python3
"""
Restore proper file structure for corrupted Python files.
This fixes the fundamental license header and import structure issues.
"""

import sys
import subprocess
from pathlib import Path

def restore_file_structure(filepath: Path) -> bool:
    """Restore proper file structure for a corrupted file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.splitlines()
        
        # Check if the file starts with a license header without proper docstring quotes
        if lines and not lines[0].startswith('"""') and 'Copyright' in content[:500]:
            print(f"  Fixing license header structure in {filepath.name}")
            
            # Find where the license header ends and code begins
            import_start = None
            for i, line in enumerate(lines):
                if line.strip().startswith(('import ', 'from ')):
                    import_start = i
                    break
            
            if import_start is not None:
                # Reconstruct the file
                new_lines = ['"""']
                
                # Add the license header content  
                for i in range(import_start):
                    line = lines[i].strip()
                    if line:  # Skip empty lines at the start
                        new_lines.append(line)
                
                new_lines.append('"""')
                new_lines.append('')  # Empty line after docstring
                
                # Add the imports and rest of the code
                for i in range(import_start, len(lines)):
                    line = lines[i]
                    # Fix indentation of imports
                    if line.lstrip().startswith(('import ', 'from ')):
                        new_lines.append(line.lstrip())
                    else:
                        new_lines.append(line)
                
                # Write the reconstructed content
                new_content = '\n'.join(new_lines)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                
                return True
        
        return False
        
    except Exception as e:
        print(f"  Error restoring {filepath}: {e}")
        return False

def main():
    root_dir = Path(r"C:\Intellicrack")
    
    # Files that need structure restoration
    critical_files = [
        "intellicrack/core/config_manager.py",
        "intellicrack/core/analysis/symbolic_executor.py",
        "intellicrack/core/analysis/binary_similarity_search.py", 
        "intellicrack/core/analysis/firmware_analyzer.py",
        "intellicrack/core/analysis/memory_forensics_engine.py",
        "intellicrack/core/analysis/rop_generator.py",
        "intellicrack/core/analysis/yara_pattern_engine.py",
    ]
    
    fixed_count = 0
    
    for file_path in critical_files:
        full_path = root_dir / file_path
        if full_path.exists():
            print(f"Restoring structure for {file_path}...")
            
            if restore_file_structure(full_path):
                fixed_count += 1
                
                # Test syntax after each fix
                result = subprocess.run([sys.executable, '-m', 'py_compile', str(full_path)], capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"  ✓ Structure restored successfully")
                    
                    # Test import for critical files
                    if 'config_manager' in str(full_path):
                        import_test = subprocess.run([sys.executable, '-c', 'import intellicrack'], capture_output=True, text=True)
                        if import_test.returncode == 0:
                            print("🎉 SUCCESS: intellicrack imports correctly after fixing config_manager!")
                            return
                        
                else:
                    print(f"  ⚠ Still has syntax issues: {result.stderr.split(':')[-1].strip()}")
            else:
                print(f"  - No structure changes needed")
    
    print(f"\nRestored structure for {fixed_count} files")
    
    # Final import test
    print("\nFinal import test...")
    result = subprocess.run([sys.executable, '-c', 'import intellicrack'], capture_output=True, text=True)
    if result.returncode == 0:
        print("🎉 SUCCESS: intellicrack imports correctly!")
    else:
        print("❌ Import still has errors:")
        lines = result.stderr.split('\n')
        for i, line in enumerate(lines):
            if 'File "' in line and 'intellicrack' in line:
                print(f"  {line}")
                if i + 1 < len(lines) and lines[i + 1].strip():
                    print(f"  {lines[i + 1]}")
                break

if __name__ == '__main__':
    main()