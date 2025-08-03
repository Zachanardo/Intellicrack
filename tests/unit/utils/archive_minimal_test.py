import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from intellicrack.utils.system.lnk_parser import parse_lnk_file
    result = parse_lnk_file(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad++.lnk")
    print(f"Target: {result.get('target_path', 'None')}")
    print("SUCCESS")
except Exception as e:
    print(f"ERROR: {e}")