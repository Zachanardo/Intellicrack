import subprocess
import sys

result = subprocess.run(
    [sys.executable, "-m", "mypy", "--strict", "tests/core/certificate/test_cert_chain_generator_production.py"],
    capture_output=True,
    text=True,
    cwd=r"D:\Intellicrack"
)

print(result.stdout)
print(result.stderr)
sys.exit(result.returncode)
