import subprocess
import sys

result = subprocess.run(
    ["pixi", "run", "mypy", "--strict", "tests/core/analysis/test_analysis_orchestrator.py"],
    capture_output=True,
    text=True,
    cwd="D:\\Intellicrack"
)

print(result.stdout)
print(result.stderr, file=sys.stderr)
sys.exit(result.returncode)
